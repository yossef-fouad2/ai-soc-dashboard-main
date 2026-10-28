"""Controlled network unit cases, not real-preset or authentication accuracy claims."""

import hashlib
import pickle
from types import SimpleNamespace

import numpy as np
import pandas as pd
import pytest
import sklearn
from sklearn.ensemble import IsolationForest

import detection
import train
from evaluation import binary_metrics, evaluate_network, partition_events, publisher_targets
from preprocessing import FEATURE_NAMES, FEATURE_VERSION, MAGNITUDES, preprocess


EXPECTED_FEATURE_NAMES = (
    "log1p_client_bytes", "log1p_server_bytes", "log1p_client_packets",
    "log1p_server_packets", "log1p_duration_ms", "protocol_code",
)
EXPECTED_PARTITIONS = {
    "train": ["2022-01-21T00:00:00Z", "2022-01-23T00:00:00Z"],
    "validation": ["2022-01-23T00:00:00Z", "2022-01-24T00:00:00Z"],
    "test": ["2022-01-24T00:00:00Z", "2022-01-25T00:00:00Z"],
}


@pytest.fixture(autouse=True)
def isolated_model_cache(monkeypatch):
    monkeypatch.setattr(detection, "_cache", {})


@pytest.fixture(scope="module")
def normal_flows():
    values = np.arange(32, dtype=np.float64)
    return pd.DataFrame({
        "client_bytes": 20 + values * 17,
        "server_bytes": 100 + values ** 2 * 11,
        "client_packets": 1 + values % 9,
        "server_packets": 2 + values % 13,
        "duration_ms": values ** 2 * 25,
        "protocol": np.where(values % 2 == 0, "TCP", "UDP"),
    })


@pytest.fixture(scope="module")
def fitted_forest(normal_flows):
    return IsolationForest(
        n_estimators=16, max_samples=32, contamination="auto", random_state=42, n_jobs=1,
    ).fit(train.preprocess(normal_flows))


@pytest.fixture
def metadata(fitted_forest, normal_flows):
    scores = fitted_forest.score_samples(train.preprocess(normal_flows))
    return {
        "feature_version": FEATURE_VERSION,
        "feature_names": list(EXPECTED_FEATURE_NAMES),
        "sklearn_version": sklearn.__version__,
        "threshold": float(np.quantile(scores, 0.01, method="lower")),
        "threshold_policy": "lower normal-validation quantile; strict threshold-score margin",
        "model_version": "unit-test-network-v1",
        "seed": 42,
        "source_hashes": {
            "in-memory-unit-fixture": hashlib.sha256(
                normal_flows.to_csv(index=False).encode("ascii")
            ).hexdigest(),
        },
        "partitions": {"date_partitions_utc": EXPECTED_PARTITIONS},
    }


@pytest.fixture
def artifact(tmp_path, fitted_forest, metadata):
    return detection.save_model(fitted_forest, metadata, tmp_path / "trusted-network.pkl")


def network_event(start="2022-01-24T12:00:00Z", end=None, **overrides):
    start = pd.Timestamp(start)
    finish = start if end is None else pd.Timestamp(end)
    row = {
        "dataset_id": "controlled-network-fixture", "kind": "network",
        "source_id": "1" * 64, "source_name": "fixture-tcp.csv",
        "source_line": 101, "source_end_line": 101, "duplicate_refs": (),
        "event_time": start.timestamp(), "end_time": finish.timestamp(),
        "event_time_display": start.isoformat(), "recorded_time": start.isoformat(),
        "source_ip": "192.0.2.10", "destination_ip": "198.51.100.20",
        "source_port": 40000, "destination_port": 443, "protocol": "TCP",
        "connection_state": "complete", "client_bytes": 100, "server_bytes": 200,
        "client_packets": 2, "server_packets": 3,
        "duration_ms": (finish - start).total_seconds() * 1000,
        "evaluation_label": "HTTP", "evaluation_role_client": "benign",
        "evaluation_role_server": "server",
    }
    row.update(overrides)
    return row


def test_log1p_magnitudes_zero_duration_and_protocol_codes():
    flows = pd.DataFrame({
        "client_bytes": [0, 9, 10**12], "server_bytes": [99, 0, 10**9],
        "client_packets": [1, 0, 9999], "server_packets": [0, 4, 10**6],
        "duration_ms": [0, 0.25, 60000], "protocol": ["TCP", "UDP", "TCP"],
        "evaluation_label": ["clear", "HTTP", ""],
    }, index=[18, 2, 71])
    original = flows.copy(deep=True)
    transformed = preprocess(flows)
    expected = pd.DataFrame([
        [0, np.log1p(99), np.log1p(1), 0, 0, 0],
        [np.log1p(9), 0, 0, np.log1p(4), np.log1p(0.25), 1],
        [np.log1p(10**12), np.log1p(10**9), np.log1p(9999), np.log1p(10**6), np.log1p(60000), 0],
    ], index=flows.index, columns=EXPECTED_FEATURE_NAMES, dtype=np.float64)
    assert FEATURE_NAMES == EXPECTED_FEATURE_NAMES
    assert MAGNITUDES == (
        "client_bytes", "server_bytes", "client_packets", "server_packets", "duration_ms",
    )
    pd.testing.assert_frame_equal(transformed, expected, check_exact=True)
    pd.testing.assert_frame_equal(flows, original)
    assert np.isfinite(transformed.to_numpy()).all()


def test_training_and_inference_share_transform_and_named_feature_order(
    normal_flows, fitted_forest, artifact,
):
    reordered = normal_flows.loc[:, list(reversed(normal_flows.columns))].copy()
    reordered["evaluation_label"] = "data exfiltration"
    pd.testing.assert_frame_equal(train.preprocess(normal_flows), preprocess(reordered))
    assert train.preprocess is preprocess
    assert detection.preprocess is preprocess
    assert list(fitted_forest.feature_names_in_) == list(EXPECTED_FEATURE_NAMES)
    assert artifact.estimator.n_features_in_ == 6
    assert artifact.metadata["feature_names"] == list(EXPECTED_FEATURE_NAMES)
    assert artifact.metadata["feature_version"] == train.FEATURE_VERSION == FEATURE_VERSION
    assert artifact.metadata["sklearn_version"] == sklearn.__version__
    predictions, margins = detection.predict(reordered, artifact=artifact)
    training_scores = fitted_forest.score_samples(train.preprocess(normal_flows))
    np.testing.assert_array_equal(margins, artifact.metadata["threshold"] - training_scores)
    np.testing.assert_array_equal(predictions, np.where(training_scores < artifact.metadata["threshold"], -1, 1))


@pytest.mark.parametrize("position", [0, 37, 128])
@pytest.mark.parametrize("protocol", ["TCP", "UDP"])
def test_row_score_and_prediction_are_identical_alone_or_in_unrelated_batches(
    artifact, position, protocol,
):
    row = pd.DataFrame([network_event(protocol=protocol, duration_ms=0)])
    baseline_predictions, baseline_margins = detection.predict(row, artifact=artifact)
    neighbors = pd.DataFrame({
        **{name: np.resize([0, 1, 10**15, 7, 10**9], 128) for name in MAGNITUDES},
        "protocol": np.resize(["UDP", "TCP"], 128),
    })
    batch = pd.concat([neighbors.iloc[:position], row, neighbors.iloc[position:]], ignore_index=True)
    batch_predictions, batch_margins = detection.predict(batch, artifact=artifact)
    pd.testing.assert_frame_equal(preprocess(row).reset_index(drop=True), preprocess(batch).iloc[[position]].reset_index(drop=True))
    assert batch_predictions[position] == baseline_predictions[0]
    assert batch_margins[position] == baseline_margins[0]


@pytest.mark.parametrize("column,value", [
    ("evaluation_label", "data exfiltration"), ("label", "clear"),
    ("evaluation_role_client", "attacker"), ("evaluation_role_server", "attacker"),
    ("role_cli", "attacker"), ("role_serv", "attacker"),
    ("source_ip", "203.0.113.200"), ("destination_ip", "203.0.113.201"),
    ("ipv4_address_cli", "203.0.113.202"), ("ipv4_address_serv", "203.0.113.203"),
    ("event_time", -10**12), ("end_time", 10**15),
    ("timestamp", "untrusted timestamp"), ("recorded_time", "Jan 01 00:00:00"),
    ("event_time_display", "2099-01-01T00:00:00Z"),
    ("source_id", "unrelated source"), ("source_name", "attacker-udp-export.csv"),
    ("source_filename", "benign-tcp-export.csv"),
])
def test_annotations_identities_times_and_filenames_cannot_change_predictions(
    artifact, column, value,
):
    flows = pd.DataFrame([network_event(), network_event(protocol="UDP", client_bytes=10**8)])
    modified = flows.copy(deep=True)
    modified[column] = value
    pd.testing.assert_frame_equal(preprocess(flows), preprocess(modified), check_exact=True)
    original_predictions, original_margins = detection.predict(flows, artifact=artifact)
    modified_predictions, modified_margins = detection.predict(modified, artifact=artifact)
    np.testing.assert_array_equal(modified_predictions, original_predictions)
    np.testing.assert_array_equal(modified_margins, original_margins)


@pytest.mark.parametrize("column", [
    "client_bytes", "server_bytes", "client_packets", "server_packets", "duration_ms",
])
@pytest.mark.parametrize("value", [-1, np.nan, np.inf, -np.inf, None, "not-numeric"])
def test_invalid_magnitudes_fail_preprocessing_and_prediction(artifact, column, value):
    flows = pd.DataFrame([network_event()])
    flows[column] = value
    with pytest.raises(ValueError, match="finite, nonnegative"):
        preprocess(flows)
    with pytest.raises(ValueError, match="finite, nonnegative"):
        detection.predict(flows, artifact=artifact)


@pytest.mark.parametrize("protocol", ["ICMP", "tcp", "udp", "TCP ", "", None, np.nan])
def test_unknown_or_unvalidated_transport_explicitly_fails(artifact, protocol):
    flows = pd.DataFrame([network_event(protocol=protocol)])
    with pytest.raises(ValueError, match="validated TCP/UDP"):
        preprocess(flows)
    with pytest.raises(ValueError, match="validated TCP/UDP"):
        detection.predict(flows, artifact=artifact)


@pytest.mark.parametrize("column", [
    "client_bytes", "server_bytes", "client_packets", "server_packets", "duration_ms", "protocol",
])
def test_missing_required_feature_explicitly_fails(artifact, column):
    flows = pd.DataFrame([network_event()]).drop(columns=column)
    with pytest.raises(ValueError, match=f"missing: {column}"):
        preprocess(flows)
    with pytest.raises(ValueError, match=f"missing: {column}"):
        detection.predict(flows, artifact=artifact)


def test_centered_calibrated_margin_is_not_probability_or_default_forest_decision(
    tmp_path, normal_flows, fitted_forest, metadata,
):
    scores = fitted_forest.score_samples(train.preprocess(normal_flows))
    metadata["threshold"] = float((scores.min() + scores.max()) / 2)
    assert metadata["threshold"] != fitted_forest.offset_
    path = tmp_path / "trusted-centered-margin.pkl"
    artifact = detection.save_model(fitted_forest, metadata, path)
    predictions, margins = detection.predict(normal_flows, path=path)
    np.testing.assert_array_equal(margins, metadata["threshold"] - scores)
    np.testing.assert_array_equal(predictions, np.where(margins > 0, -1, 1))
    assert (margins < 0).any() and (margins > 0).any()
    assert artifact.version == metadata["model_version"]
    health = detection.model_health(path)
    assert health["available"] is True
    assert health["threshold"] == metadata["threshold"]
    assert "not an attack probability" in health["message"]


@pytest.mark.parametrize("boundary,expected_prediction", [("below", 1), ("equal", 1), ("above", -1)])
def test_anomaly_threshold_is_strict_at_adjacent_float_boundary(
    tmp_path, fitted_forest, metadata, boundary, expected_prediction,
):
    row = pd.DataFrame([network_event()])
    score = fitted_forest.score_samples(train.preprocess(row))[0]
    threshold = {
        "below": np.nextafter(score, -np.inf), "equal": score,
        "above": np.nextafter(score, np.inf),
    }[boundary]
    metadata["threshold"] = float(threshold)
    artifact = detection.save_model(fitted_forest, metadata, tmp_path / "trusted-boundary.pkl")
    predictions, margins = detection.predict(row, artifact=artifact)
    assert margins[0] == threshold - score
    assert predictions[0] == expected_prediction
    if boundary == "equal":
        assert margins[0] == 0


@pytest.mark.parametrize("legacy_format", ["bare-estimator", "old-artifact-version", "missing-artifact-version"])
def test_legacy_artifacts_are_rejected(tmp_path, fitted_forest, metadata, legacy_format):
    payload = fitted_forest if legacy_format == "bare-estimator" else {
        "estimator": fitted_forest, "metadata": metadata,
    }
    if legacy_format == "old-artifact-version":
        payload["artifact_version"] = 0
    path = tmp_path / "trusted-legacy-format.pkl"
    path.write_bytes(pickle.dumps(payload, protocol=pickle.HIGHEST_PROTOCOL))
    with pytest.raises(detection.ModelUnavailable, match="legacy|Incompatible"):
        detection.load_model(path)


@pytest.mark.parametrize("field,value,message", [
    ("feature_version", "old-transform", "feature/transform"),
    ("feature_version", None, "feature/transform"),
    ("feature_names", list(reversed(EXPECTED_FEATURE_NAMES)), "feature/transform"),
    ("feature_names", list(EXPECTED_FEATURE_NAMES[:-1]), "feature/transform"),
    ("feature_names", ["wrong_feature"] * 6, "feature/transform"),
    ("sklearn_version", "0.0.0-incompatible", "scikit-learn version"),
    ("sklearn_version", None, "scikit-learn version"),
    ("threshold", None, "threshold"), ("threshold", "-0.5", "threshold"),
    ("threshold", np.nan, "threshold"), ("threshold", np.inf, "threshold"),
    ("threshold", -np.inf, "threshold"), ("threshold", -1.000001, "threshold"),
    ("threshold", 0.000001, "threshold"), ("threshold", False, "threshold"),
    ("model_version", "", "version is missing"),
    ("model_version", None, "version is missing"),
])
def test_incompatible_metadata_artifacts_are_rejected(
    tmp_path, fitted_forest, metadata, field, value, message,
):
    metadata[field] = value
    payload = {"artifact_version": detection.ARTIFACT_VERSION, "estimator": fitted_forest, "metadata": metadata}
    path = tmp_path / "trusted-incompatible-metadata.pkl"
    path.write_bytes(pickle.dumps(payload, protocol=pickle.HIGHEST_PROTOCOL))
    with pytest.raises(detection.ModelUnavailable, match=message):
        detection.load_model(path)
    assert path.resolve() not in detection._cache


@pytest.mark.parametrize("feature_layout,message", [
    ("two-features", "six required features"),
    ("reversed-six", "feature order"), ("unnamed-six", "feature order"),
    ("unfitted", "six required features"),
])
def test_estimator_feature_count_fit_and_order_must_match_metadata(
    tmp_path, normal_flows, metadata, feature_layout, message,
):
    estimator = IsolationForest(n_estimators=2, random_state=42, n_jobs=1)
    features = train.preprocess(normal_flows)
    if feature_layout == "two-features":
        estimator.fit(features.iloc[:, :2])
    elif feature_layout == "reversed-six":
        estimator.fit(features.loc[:, list(reversed(EXPECTED_FEATURE_NAMES))])
    elif feature_layout == "unnamed-six":
        estimator.fit(features.to_numpy())
    payload = {"artifact_version": detection.ARTIFACT_VERSION, "estimator": estimator, "metadata": metadata}
    path = tmp_path / "trusted-incompatible-estimator.pkl"
    path.write_bytes(pickle.dumps(payload, protocol=pickle.HIGHEST_PROTOCOL))
    with pytest.raises(detection.ModelUnavailable, match=message):
        detection.load_model(path)


def test_missing_model_is_explicitly_unavailable_and_never_fabricates_predictions(tmp_path):
    path = tmp_path / "absent-network.pkl"
    with pytest.raises(detection.ModelUnavailable, match="unavailable"):
        detection.load_model(path)
    with pytest.raises(detection.ModelUnavailable, match="unavailable"):
        detection.predict(pd.DataFrame([network_event()]), path=path)
    health = detection.model_health(path)
    assert health["available"] is False
    assert health["version"] is None
    assert "rules remain operational" in health["message"]
    assert not path.exists()


def test_cache_reloads_changed_estimator_and_version_at_same_configured_path(
    tmp_path, normal_flows, fitted_forest, metadata,
):
    path = tmp_path / "configured-network.pkl"
    first = detection.save_model(fitted_forest, metadata, path)
    assert detection.load_model(path) is first
    original_predictions, original_margins = detection.predict(normal_flows, path=path)
    changed_flows = normal_flows.copy(deep=True)
    changed_flows.loc[:, list(MAGNITUDES)] *= 10000
    changed_estimator = IsolationForest(
        n_estimators=12, max_samples=32, random_state=17, n_jobs=1,
    ).fit(train.preprocess(changed_flows))
    changed_metadata = {
        **metadata, "model_version": "unit-test-network-v2-retrained-at-the-same-path", "seed": 17,
    }
    second = detection.save_model(changed_estimator, changed_metadata, path)
    assert second is not first
    assert detection.load_model(path) is second
    assert second.version == changed_metadata["model_version"]
    assert first.version == "unit-test-network-v1"
    assert second.artifact_sha256 != first.artifact_sha256
    assert second.estimator.random_state == 17
    assert detection.model_health(path)["version"] == second.version
    predictions, margins = detection.predict(normal_flows, path=path)
    expected_margins = changed_metadata["threshold"] - changed_estimator.score_samples(preprocess(normal_flows))
    np.testing.assert_array_equal(margins, expected_margins)
    np.testing.assert_array_equal(predictions, np.where(expected_margins > 0, -1, 1))
    assert not np.array_equal(margins, original_margins)
    assert len(predictions) == len(original_predictions)


@pytest.mark.parametrize("label", [
    "browsing/update", "benign_share", "mail", "monitoring", "HTTP(S) intra", "HTTP(S) DMZ",
    "SSH", "proxy", "HTTPS", "HTTP", "DNS", "update/command on unassigned port",
    "broken flow - benign", "NTP", "bootp", "OpenVPN", "STUN VoIP", "NetBIOS", "QUIC",
    "mDNS", "mDNSv6", "GoogleDNS", "systemd-resolver (local)", "benign DNS",
    "benign DNS - attacker requesting updates",
])
def test_exact_publisher_benign_labels_including_attacker_requesting_updates(label):
    np.testing.assert_array_equal(publisher_targets([label]), np.array([0], dtype=np.int8))


@pytest.mark.parametrize("label", [
    "data exfiltration", "dirb_scan", "dns_brute_force_start", "host_discover_dmz",
    "host_discover_local", "online_cracking", "service_scan", "upload_rce_shell", "wpscan",
    "check_cpuinfo", "check_date", "check_df", "check_id", "check_last", "check_meminfo",
    "check_netstat_l", "check_netstat_nat", "check_netstat_t", "check_network_config",
    "check_ps_a", "check_release", "check_uname_a", "check_uname_r", "check_uptime",
    "check_user_id", "check_who", "check_whoami", "check_wp_config", "clear", "dump_wp_users",
    "list_home", "list_web_dir", "list_www", "read_group", "read_passwd", "read_profile",
    "read_resolv", "vpn_connect", "traceroute", "run_cracking",
])
def test_exact_publisher_attack_related_labels_including_clear_and_check_commands(label):
    np.testing.assert_array_equal(publisher_targets([label]), np.array([1], dtype=np.int8))


@pytest.mark.parametrize("label", [
    "", " ", None, np.nan, pd.NA, "check_unfamiliar", "read_unfamiliar", "list_unfamiliar",
    "clear_extra", "benign DNS - unfamiliar", "data exfiltration extra", "HTTP ", "http", "attacker",
])
def test_blank_missing_or_unfamiliar_prefix_labels_remain_unknown(label):
    np.testing.assert_array_equal(publisher_targets([label]), np.array([-1], dtype=np.int8))


def test_utc_partitions_select_only_known_normal_labels_for_training_and_validation():
    cases = [
        ("2022-01-20T23:59:59.999Z", "HTTP", "outside", 0),
        ("2022-01-21T00:00:00Z", "HTTP", "train", 0),
        ("2022-01-21T00:00:09Z", "data exfiltration", "train", 1),
        ("2022-01-21T12:00:00Z", "check_unfamiliar", "train", -1),
        ("2022-01-22T00:00:00Z", "DNS", "train", 0),
        ("2022-01-22T23:59:59.999Z", "mail", "train", 0),
        ("2022-01-23T00:00:00Z", "HTTPS", "validation", 0),
        ("2022-01-23T01:00:00Z", "clear", "validation", 1),
        ("2022-01-23T12:00:00Z", "", "validation", -1),
        ("2022-01-23T23:59:59.999Z", "benign DNS - attacker requesting updates", "validation", 0),
        ("2022-01-24T00:00:00Z", "data exfiltration", "test", 1),
        ("2022-01-24T12:00:00Z", "HTTP", "test", 0),
        ("2022-01-24T13:00:00Z", "check_unfamiliar", "test", -1),
        ("2022-01-24T23:59:59.999Z", "clear", "test", 1),
        ("2022-01-25T00:00:00Z", "HTTP", "outside", 0),
    ]
    events = pd.DataFrame([
        network_event(start, source_port=40000 + index, evaluation_label=label)
        for index, (start, label, _, _) in enumerate(cases)
    ], index=np.arange(100, 100 + len(cases)) * 3)
    parts, targets, report = partition_events(events)
    assert parts.index.equals(events.index)
    assert parts.tolist() == [case[2] for case in cases]
    np.testing.assert_array_equal(targets, [case[3] for case in cases])
    assert events.loc[(parts == "train") & (targets == 0), "evaluation_label"].tolist() == ["HTTP", "DNS", "mail"]
    assert events.loc[(parts == "validation") & (targets == 0), "evaluation_label"].tolist() == [
        "HTTPS", "benign DNS - attacker requesting updates",
    ]
    assert events.loc[parts == "test", "evaluation_label"].tolist() == [
        "data exfiltration", "HTTP", "check_unfamiliar", "clear",
    ]
    assert report["date_partitions_utc"] == EXPECTED_PARTITIONS
    assert report["excluded_overlap_flow_count"] == 0
    assert report["unknown_label_count"] == 3
    assert report["partition_counts"]["train"] == {
        "total": 5, "publisher_benign": 3, "publisher_attack_related": 1, "unknown": 1,
    }
    assert report["partition_counts"]["validation"] == {
        "total": 4, "publisher_benign": 2, "publisher_attack_related": 1, "unknown": 1,
    }
    assert report["partition_counts"]["test"] == {
        "total": 4, "publisher_benign": 1, "publisher_attack_related": 2, "unknown": 1,
    }


@pytest.mark.parametrize("boundary", [
    "2022-01-21T00:00:00Z", "2022-01-23T00:00:00Z",
    "2022-01-24T00:00:00Z", "2022-01-25T00:00:00Z",
])
@pytest.mark.parametrize("end_offset_seconds", [0, 1])
def test_every_partition_boundary_excludes_flows_ending_at_or_spanning_it(boundary, end_offset_seconds):
    boundary = pd.Timestamp(boundary)
    events = pd.DataFrame([
        network_event(boundary - pd.Timedelta(seconds=1), boundary + pd.Timedelta(seconds=end_offset_seconds)),
        network_event(boundary, source_port=40001),
    ])
    parts, _, report = partition_events(events)
    assert parts.iloc[0] == "excluded_overlap"
    assert parts.iloc[1] != "excluded_overlap"
    assert report["boundary_spanning_flow_count"] == 1
    assert report["cross_partition_overlapping_connection_count"] == 0
    assert report["excluded_overlap_flow_count"] == 1


@pytest.mark.parametrize("boundary,before_part,after_part", [
    ("2022-01-23T00:00:00Z", "train", "validation"),
    ("2022-01-24T00:00:00Z", "validation", "test"),
])
def test_entire_transitive_overlapping_five_tuple_component_is_excluded_but_reuse_retained(
    boundary, before_part, after_part,
):
    boundary = pd.Timestamp(boundary)
    intervals = [(8, 20), (-100, -90), (4, 9), (-30, -10), (60, 70), (-15, 5), (20, 21)]
    events = pd.DataFrame([
        network_event(boundary + pd.Timedelta(seconds=start), boundary + pd.Timedelta(seconds=end))
        for start, end in intervals
    ], index=[91, 7, 40, 13, 55, 22, 88])
    parts, _, report = partition_events(events)
    assert parts.to_dict() == {
        91: "excluded_overlap", 7: before_part, 40: "excluded_overlap",
        13: "excluded_overlap", 55: after_part, 22: "excluded_overlap", 88: "excluded_overlap",
    }
    assert report["boundary_spanning_flow_count"] == 1
    assert report["cross_partition_overlapping_connection_count"] == 5
    assert report["excluded_overlap_flow_count"] == 5
    assert report["partition_counts"][before_part]["publisher_benign"] == 1
    assert report["partition_counts"][after_part]["publisher_benign"] == 1


@pytest.mark.parametrize("key,value", [
    ("dataset_id", "another-dataset"), ("source_ip", "192.0.2.11"),
    ("destination_ip", "198.51.100.21"), ("source_port", 40001),
    ("destination_port", 444), ("protocol", "UDP"),
])
def test_overlap_components_do_not_cross_dataset_or_five_tuple_identity(key, value):
    events = pd.DataFrame([
        network_event("2022-01-23T23:59:59Z", "2022-01-24T00:00:02Z"),
        network_event("2022-01-24T00:00:01Z", "2022-01-24T00:00:03Z", **{key: value}),
    ])
    parts, _, report = partition_events(events)
    assert parts.tolist() == ["excluded_overlap", "test"]
    assert report["boundary_spanning_flow_count"] == 1
    assert report["cross_partition_overlapping_connection_count"] == 0


@pytest.fixture
def evaluation_case():
    labels = [
        "HTTP", "HTTP", "DNS", "clear", "data exfiltration", "data exfiltration",
        "benign DNS - attacker requesting updates", "read_passwd", "check_unfamiliar", "HTTP", "",
    ]
    sources = [10, 10, 10, 11, 11, 12, 12, 13, 13, 14, 15]
    protocols = ["TCP"] * 5 + ["UDP", "UDP"] + ["TCP"] * 3 + ["UDP"]
    rows = [network_event(
        pd.Timestamp("2022-01-24T12:00:00Z") + pd.Timedelta(seconds=index),
        evaluation_label=label, source_ip=f"192.0.2.{source}", protocol=protocol,
        source_line=101 + index * 17, source_end_line=101 + index * 17,
    ) for index, (label, source, protocol) in enumerate(zip(labels, sources, protocols))]
    rows[5].update({
        "source_name": "fixture-udp.csv", "source_line": 431, "source_end_line": 433,
        "client_bytes": np.int64(1000000), "server_bytes": np.int64(0),
        "duplicate_refs": (("2" * 64, 811, 813, "fixture-duplicate-export.csv"),),
    })
    events = pd.DataFrame(rows, index=np.arange(11) * 7 + 300)
    predictions = np.array([-1, 1, 1, -1, 1, -1, 1, -1, -1, 1, -1], dtype=np.int8)
    margins = np.array([0.2, -0.1, -0.1, 0.8, -0.1, 0.35, -0.2, 0.95, 0.9, -0.2, 1.0])
    # Explicit support masks isolate reporting from separately tested rule windows.
    detections = [SimpleNamespace(indices={index}) for index in (4, 9, 10)]
    return events, predictions, margins, detections


def test_per_flow_and_fixed_unit_metrics_use_distinct_denominators_and_unknown_exclusions(evaluation_case):
    report = evaluate_network(*evaluation_case)
    assert report["per_flow_ml"] == {
        "units": 9, "true_positive": 3, "false_positive": 1, "false_negative": 1,
        "true_negative": 4, "precision": 0.75, "recall": 0.75, "f1": 0.75,
        "false_positive_rate": 0.2,
    }
    assert report["unknown_flows_excluded"] == 2
    assert report["ml_anomaly_flow_count"] == 6
    assert report["rule_supported_flow_count"] == 3
    comparison = report["fixed_unit_comparison"]
    assert comparison["unit"] == "60-second UTC source/destination/transport groups"
    assert comparison["total_groups"] == 6
    assert comparison["unknown_groups_excluded"] == 2
    assert comparison["rules_only"] == {
        "units": 4, "true_positive": 1, "false_positive": 1, "false_negative": 1,
        "true_negative": 1, "precision": 0.5, "recall": 0.5, "f1": 0.5,
        "false_positive_rate": 0.5,
    }
    assert comparison["ml_only"] == {
        "units": 4, "true_positive": 2, "false_positive": 1, "false_negative": 0,
        "true_negative": 1, "precision": 2 / 3, "recall": 1.0, "f1": 0.8,
        "false_positive_rate": 0.5,
    }
    assert comparison["combined"] == {
        "units": 4, "true_positive": 2, "false_positive": 2, "false_negative": 0,
        "true_negative": 0, "precision": 0.5, "recall": 1.0, "f1": 2 / 3,
        "false_positive_rate": 1.0,
    }
    assert comparison["ml_only_attack_related_groups"] == 1
    tcp = report["counts_by_protocol"]["TCP"]
    assert (tcp["flows"], tcp["known_flows"], tcp["ml_flagged"], tcp["attack_related_missed_by_ml"]) == (8, 7, 4, 1)
    assert tcp["metrics"]["units"] == 7
    udp = report["counts_by_protocol"]["UDP"]
    assert (udp["flows"], udp["known_flows"], udp["ml_only_flagged"]) == (3, 2, 1)
    assert udp["metrics"]["units"] == 2
    assert report["counts_by_label"]["data exfiltration"]["attack_related_missed_by_ml"] == 1
    for unknown in ("check_unfamiliar", ""):
        group = report["counts_by_label"][unknown]
        assert (group["flows"], group["known_flows"], group["ml_flagged"]) == (1, 0, 1)
        assert group["metrics"]["units"] == 0
        assert group["metrics"]["precision"] is None
        assert group["metrics"]["recall"] is None
    assert "not independently adjudicated" in report["ground_truth"]


def test_complementary_ml_examples_preserve_original_evidence_outside_entire_rule_groups(evaluation_case):
    report = evaluate_network(*evaluation_case)
    assert report["complementary_behavior_demonstrated"] is True
    assert len(report["complementary_ml_examples"]) == 1
    example = report["complementary_ml_examples"][0]
    assert example["publisher_annotation"] == "data exfiltration"
    assert example["centered_margin"] == 0.35
    assert example["implemented_rule_covered_flow_or_group"] is False
    evidence = example["raw_evidence"]
    assert evidence["source_id"] == "1" * 64
    assert evidence["source_name"] == "fixture-udp.csv"
    assert (evidence["source_line"], evidence["source_end_line"]) == (431, 433)
    assert evidence["source_ip"] == "192.0.2.12"
    assert evidence["protocol"] == "UDP"
    assert evidence["client_bytes"] == 1000000
    assert evidence["server_bytes"] == 0
    assert evidence["duration_ms"] == 0
    assert "evaluation_label" not in evidence
    assert example["source_references"] == [
        {"source_id": "1" * 64, "name": "fixture-udp.csv", "line_ranges": [[431, 433]]},
        {"source_id": "2" * 64, "name": "fixture-duplicate-export.csv", "line_ranges": [[811, 813]]},
    ]
    assert "not a model-predicted attack name" in example["interpretation"]
    # The higher-margin attack flow in a rule-supported group and the known attack
    # sharing a group with an unknown label must not become complementary examples.
    assert all(item["raw_evidence"]["source_ip"] not in {"192.0.2.11", "192.0.2.13"}
               for item in report["complementary_ml_examples"])


def test_absent_rule_free_ml_example_reports_complementary_gap(evaluation_case):
    events, predictions, margins, detections = evaluation_case
    report = evaluate_network(events, predictions, margins, detections + [SimpleNamespace(indices={5})])
    assert report["complementary_behavior_demonstrated"] is False
    assert report["complementary_ml_examples"] == []
    assert report["fixed_unit_comparison"]["ml_only_attack_related_groups"] == 0
    assert any("scores are not probabilities" in limitation for limitation in report["limitations"])
    assert any("Authentication detection" in limitation and "not these network labels" in limitation
               for limitation in report["limitations"])


@pytest.mark.parametrize("key,value,expected_groups", [
    ("dataset_id", "other-dataset", 2), ("source_ip", "192.0.2.99", 2),
    ("destination_ip", "198.51.100.99", 2), ("protocol", "UDP", 2),
    ("source_port", 45000, 1), ("destination_port", 22, 1),
])
def test_fixed_evaluation_units_group_by_dataset_ips_transport_not_flow_ports(key, value, expected_groups):
    events = pd.DataFrame([network_event(), network_event(**{key: value})])
    report = evaluate_network(events, [1, 1], [-0.1, -0.1], [])
    assert report["per_flow_ml"]["units"] == 2
    assert report["fixed_unit_comparison"]["total_groups"] == expected_groups
    for method in ("rules_only", "ml_only", "combined"):
        assert report["fixed_unit_comparison"][method]["units"] == expected_groups


def test_fixed_evaluation_units_use_utc_floor_at_exact_sixty_second_boundary():
    events = pd.DataFrame([
        network_event("2022-01-24T12:00:00Z"),
        network_event("2022-01-24T12:00:59.999Z"),
        network_event("2022-01-24T12:01:00Z"),
    ])
    report = evaluate_network(events, [1, 1, 1], [-0.1] * 3, [])
    assert report["per_flow_ml"]["units"] == 3
    assert report["fixed_unit_comparison"]["total_groups"] == 2
    assert report["fixed_unit_comparison"]["combined"]["units"] == 2


@pytest.mark.parametrize("truth,detected,counts,rates", [
    ([], [], (0, 0, 0, 0), (None, None, None, None)),
    ([False, False], [False, False], (0, 0, 0, 2), (None, None, None, 0.0)),
    ([True, True], [False, False], (0, 0, 2, 0), (None, 0.0, 0.0, None)),
    ([False, False], [True, True], (0, 2, 0, 0), (0.0, None, 0.0, 1.0)),
    ([True, True], [True, True], (2, 0, 0, 0), (1.0, 1.0, 1.0, None)),
])
def test_metric_zero_denominators_are_undefined_not_fabricated_accuracy(truth, detected, counts, rates):
    metrics = binary_metrics(truth, detected)
    assert metrics["units"] == len(truth)
    assert tuple(metrics[name] for name in (
        "true_positive", "false_positive", "false_negative", "true_negative",
    )) == counts
    assert tuple(metrics[name] for name in ("precision", "recall", "f1", "false_positive_rate")) == rates
