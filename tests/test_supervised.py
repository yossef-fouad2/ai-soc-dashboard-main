"""Controlled supervised experiment checks, not measurements of attack accuracy."""

import json
import pickle
from types import SimpleNamespace

import numpy as np
import pandas as pd
import pytest

import supervised
from ingestion import IngestedDataset, file_hash


def flow(index=0, **changes):
    row = {
        "dataset_id": "capture", "clock_id": "capture", "source_ip": "192.0.2.10",
        "destination_ip": "198.51.100.20", "source_port": 40000 + index,
        "destination_port": 80, "protocol": "TCP", "connection_state": "complete",
        "event_time": float(index), "end_time": float(index), "duration_ms": 0,
        "client_bytes": 100, "server_bytes": 200, "client_packets": 2, "server_packets": 3,
        "client_syn": 1, "server_syn": 1, "client_fin": 1, "server_fin": 1,
        "client_reset": 0, "server_reset": 0, "evaluation_label": "HTTP",
        "source_id": "f" * 64, "source_name": "fixture.csv", "source_line": index + 2,
        "event_time_display": "2022-01-24T00:00:00Z", "observation_hash": f"flow-{index}",
    }
    row.update(changes)
    return row


def dataset(name, offset=0):
    rows = []
    for index in range(40):
        attack = index % 2 == 0
        rows.append(flow(index + offset, dataset_id=name, clock_id=name,
                         observation_hash=f"{name}-{index}", evaluation_label="dirb_scan" if attack else "HTTP",
                         client_bytes=10000 if attack else 20, server_bytes=1 if attack else 200))
    return IngestedDataset(pd.DataFrame(rows), {
        "fingerprint": name, "raw_count": 40, "duplicate_count": 0, "rejected_count": 0,
        "sources": [{"name": name, "sha256": name, "bytes": 1, "schema": "tcp_complete"}],
    }, [])


def test_feature_order_and_zero_safe_ratios_preserve_input():
    events = pd.DataFrame([flow(client_packets=0, server_packets=0, client_bytes=0, server_bytes=0)])
    original = events.copy(deep=True)
    result = supervised.features(events)
    assert tuple(result.columns) == supervised.FEATURE_NAMES
    assert np.isfinite(result.to_numpy()).all()
    assert result.iloc[0]["log1p_prior_service_flows_60s"] == 0
    pd.testing.assert_frame_equal(events, original)


def test_history_is_strictly_prior_and_uses_completion_not_start_time():
    events = pd.DataFrame([
        flow(0, event_time=0, end_time=10), flow(1, event_time=1, end_time=10),
        flow(2, event_time=2, end_time=70), flow(3, event_time=3, end_time=70.001),
        flow(4, event_time=0, end_time=100),
    ])
    result = supervised.features(events)
    np.testing.assert_allclose(np.expm1(result["log1p_prior_service_flows_60s"]), [0, 0, 2, 1, 2])
    pd.testing.assert_frame_equal(result.iloc[:4], supervised.features(events.iloc[:4]))
    shuffled = events.sample(frac=1, random_state=7)
    pd.testing.assert_frame_equal(result, supervised.features(shuffled).loc[events.index])


@pytest.mark.parametrize("field,value", [
    ("dataset_id", "other"), ("clock_id", "other"), ("source_ip", "192.0.2.11"),
    ("destination_ip", "198.51.100.30"), ("destination_port", 443),
])
def test_service_history_cannot_borrow_other_capture_or_service(field, value):
    events = pd.DataFrame([flow(0), flow(1, **{field: value})])
    assert supervised.features(events).iloc[1]["log1p_prior_service_flows_60s"] == 0


def test_unknown_labels_still_contribute_visible_history_without_target_leakage():
    events = pd.DataFrame([flow(0, evaluation_label="unknown", server_packets=0), flow(1)])
    result = supervised.features(events)
    assert result.iloc[1]["prior_service_no_response_fraction_60s"] == 1
    changed = events.copy()
    for column in ("evaluation_label", "evaluation_role_client", "evaluation_role_server", "source_name", "source_id"):
        changed[column] = "untrusted attacker label"
    pd.testing.assert_frame_equal(result, supervised.features(changed))


def test_renamed_identities_and_shifted_clock_are_not_numeric_predictors():
    events = pd.DataFrame([flow(0), flow(1), flow(2)])
    renamed = events.copy()
    renamed["source_ip"], renamed["destination_ip"] = "203.0.113.10", "203.0.113.20"
    renamed["dataset_id"], renamed["clock_id"] = "renamed", "renamed"
    renamed[["event_time", "end_time"]] += 100000
    pd.testing.assert_frame_equal(supervised.features(events), supervised.features(renamed))


def test_transport_isolation_and_missing_udp_tcp_counters():
    tcp = flow(0)
    udp = flow(1, protocol="UDP", connection_state="datagram", **{key: np.nan for key in supervised.TCP_COUNTERS})
    result = supervised.features(pd.DataFrame([tcp, udp]))
    assert result.iloc[1]["log1p_prior_source_flows_60s"] == 0
    assert result.iloc[1]["log1p_client_syn"] == 0


@pytest.mark.parametrize("changes", [
    {"event_time": -1}, {"end_time": -1}, {"event_time": 2, "end_time": 1},
    {"end_time": np.inf}, {"destination_port": 65536}, {"destination_port": 1.5},
    {"clock_id": ""}, {"source_ip": None}, {"client_syn": np.nan},
    {"connection_state": "datagram"}, {"protocol": "ICMP"}, {"client_bytes": -1},
])
def test_invalid_feature_inputs_fail_instead_of_fabricating_normal(changes):
    with pytest.raises(ValueError):
        supervised.features(pd.DataFrame([flow(**changes)]))


def test_missing_context_and_duplicate_index_fail():
    with pytest.raises(ValueError, match="missing"):
        supervised.features(pd.DataFrame([flow()]).drop(columns="end_time"))
    with pytest.raises(ValueError, match="unique event index"):
        supervised.features(pd.DataFrame([flow(), flow()], index=[1, 1]))


def test_threshold_never_splits_equal_scores_to_meet_false_alert_budget():
    targets, scores = np.array([1, 1, 0, 0, 0, -1]), np.array([0.9, 0.8, 0.8, 0.7, 0.2, 1])
    selected = supervised.select_threshold(targets, scores, 0, 0.5)
    assert selected["threshold"] == 0.9
    assert selected["validation_metrics"]["true_positive"] == 1
    assert selected["validation_metrics"]["false_positive"] == 0
    assert selected["validation_metrics"]["unknown_excluded"] == 1


@pytest.mark.parametrize("budget", [0, 0.2, 0.5])
@pytest.mark.parametrize("minimum_precision", [0, 0.5, 0.9])
def test_threshold_matches_exhaustive_constrained_f1_search(budget, minimum_precision):
    rng = np.random.default_rng(73)
    targets = np.array([0, 1] * 20 + [-1])
    scores = rng.integers(0, 10, len(targets)) / 10
    feasible = []
    for threshold in np.unique(scores[targets >= 0]):
        result = supervised.metrics(targets, scores >= threshold)
        if result["true_positive"] and result["false_positive_rate"] <= budget and result["precision"] >= minimum_precision:
            feasible.append((result["f1"], result["precision"], threshold))
    selected = supervised.select_threshold(targets, scores, budget, minimum_precision)
    if feasible:
        assert selected["threshold"] == max(feasible)[2]
    else:
        assert selected["status"] == "no_feasible_threshold"
        assert selected["threshold"] > 1


@pytest.mark.parametrize("targets,scores", [([0, 0], [0, 1]), ([1, 1], [0, 1]), ([-1, -1], [0, 1]),
                                            ([0, 1], [0, np.nan]), ([0, 1], [-0.1, 1]),
                                            ([0, 1], [0, 1.1]), ([0, 2], [0, 1]), ([0, 1], [0])])
def test_invalid_calibration_fails_explicitly(targets, scores):
    with pytest.raises(ValueError):
        supervised.select_threshold(targets, scores)


def test_cross_capture_file_or_observation_reuse_is_rejected():
    first, second = dataset("first"), dataset("second")
    supervised.assert_disjoint({"train": first, "validation": second})
    second.events.loc[0, "observation_hash"] = first.events.loc[0, "observation_hash"]
    with pytest.raises(ValueError, match="Duplicate exporter"):
        supervised.assert_disjoint({"train": first, "validation": second})
    second = dataset("second")
    second.profile["sources"][0]["sha256"] = "first"
    with pytest.raises(ValueError, match="Shared source"):
        supervised.assert_disjoint({"train": first, "validation": second})


def test_unknown_labels_do_not_inflate_metrics():
    result = supervised.metrics([0, 1, -1], [False, True, True])
    assert result["units"] == 2
    assert result["precision"] == result["recall"] == result["f1"] == 1
    assert result["unknown_excluded"] == 1
    assert supervised.metrics([-1], [True])["accuracy"] is None


def test_end_to_end_freezes_before_test_and_preserves_baseline(tmp_path, monkeypatch):
    import sources

    baseline_path = tmp_path / "baseline.pkl"
    baseline_path.write_bytes(b"immutable baseline fixture")
    baseline_hash = file_hash(baseline_path)
    original = SimpleNamespace(artifact_sha256=baseline_hash)
    monkeypatch.setattr(supervised, "MODEL_PATH", baseline_path)
    monkeypatch.setattr(supervised, "load_model", lambda: original)
    monkeypatch.setattr(supervised, "predict", lambda events, artifact: (np.ones(len(events)), np.zeros(len(events))))
    monkeypatch.setattr(supervised, "MODEL_PARAMETERS", {**supervised.MODEL_PARAMETERS, "n_estimators": 8, "n_jobs": 1})
    datasets = {"train": dataset("train"), "validation": dataset("validation", 100), "test": dataset("test", 200)}
    output = tmp_path / "experiment"
    calls = []

    def load(paths=None):
        role = "train" if paths is None else str(paths[0])
        calls.append(role)
        return datasets[role]

    def install():
        assert (output / "candidate.pkl").exists()
        assert (output / "model_metadata.json").exists()
        assert "test" not in calls
        return ["test"]

    monkeypatch.setattr(supervised, "load_network", load)
    monkeypatch.setattr(sources, "ensure_santos", install)
    supervised.main(["--validation", "validation", "--output-dir", str(output), "--test-santos"])
    report = json.loads((output / "comparison.json").read_text())
    assert calls == ["train", "validation", "test"]
    assert report["baseline_preserved"] and report["candidate_preserved_after_test"]
    assert not report["dashboard_model_changed"]
    assert file_hash(baseline_path) == baseline_hash
    with (output / "candidate.pkl").open("rb") as handle:
        artifact = pickle.load(handle)
    scores = supervised.candidate_scores(datasets["test"].events, artifact)
    assert len(scores) == 40
    original_candidate_hash = file_hash(output / "candidate.pkl")
    monkeypatch.setattr(supervised.RandomForestClassifier, "fit", lambda *args, **kwargs: pytest.fail("Score-only mode must never fit"))
    scored = tmp_path / "scored"
    supervised.main(["--score-only", "test", "--candidate", str(output / "candidate.pkl"), "--output-dir", str(scored)])
    scored_report = json.loads((scored / "scoring.json").read_text())
    pd_scores = pd.read_csv(scored / "predictions.csv")
    np.testing.assert_allclose(pd_scores["supervised_score"], scores)
    assert scored_report["comparison"]["supervised"] == report["test"]["supervised"]
    assert scored_report["comparison"]["isolation_forest"] == report["test"]["isolation_forest"]
    assert file_hash(output / "candidate.pkl") == original_candidate_hash
    wrong = datasets["test"].events.copy()
    wrong["protocol"] = "UDP"
    with pytest.raises(ValueError, match="TCP only"):
        supervised.candidate_scores(wrong, artifact)
    artifact["metadata"]["feature_names"] = []
    with pytest.raises(ValueError, match="incompatible"):
        supervised.candidate_scores(datasets["test"].events, artifact)
    with pytest.raises(SystemExit):
        supervised.main(["--validation", "validation", "--output-dir", str(output)])
    with pytest.raises(SystemExit):
        supervised.main(["--score-only", "test", "--minimum-precision", "0.9"])


def test_failed_validation_does_not_consume_final_capture(tmp_path, monkeypatch):
    import sources

    baseline_path = tmp_path / "baseline.pkl"
    baseline_path.write_bytes(b"baseline")
    monkeypatch.setattr(supervised, "MODEL_PATH", baseline_path)
    monkeypatch.setattr(supervised, "load_model", lambda: SimpleNamespace(artifact_sha256=file_hash(baseline_path)))
    monkeypatch.setattr(supervised, "predict", lambda events, artifact: (np.ones(len(events)), np.zeros(len(events))))
    monkeypatch.setattr(supervised, "MODEL_PARAMETERS", {**supervised.MODEL_PARAMETERS, "n_estimators": 2, "n_jobs": 1})
    monkeypatch.setattr(supervised, "load_network", lambda paths=None: dataset("train" if paths is None else "validation"))
    select = supervised.select_threshold
    monkeypatch.setattr(supervised, "select_threshold", lambda targets, scores, *args: select(targets, np.zeros(len(scores)), 0, 1))
    monkeypatch.setattr(sources, "ensure_santos", lambda: pytest.fail("Rejected candidate must not consume the test capture"))
    output = tmp_path / "rejected"
    supervised.main(["--validation", "validation", "--output-dir", str(output), "--test-santos"])
    report = json.loads((output / "comparison.json").read_text())
    assert not report["validation_goal_met"]
    assert report["test"] is None and "remains unused" in report["test_skip_reason"]
