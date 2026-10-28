import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pandas as pd
import pytest
import sklearn
from sklearn.ensemble import IsolationForest

import agents
from agents import analyze_logs
from detection import NetworkModel
from ingestion import IngestedDataset, load_authentication
from preprocessing import FEATURE_NAMES, FEATURE_VERSION, preprocess
from rules import DetectionConfig
from sources import OPENSSH_PATH
from storage import ALERT_STATUSES, INCIDENT_STATUSES, Storage, StorageError


def network_events(count=20):
    epoch = pd.Timestamp("2022-01-24T03:00:00Z").timestamp()
    return pd.DataFrame([{
        "dataset_id": "network-unit", "clock_id": "network-unit", "source_id": "a" * 64,
        "source_name": "unit.csv", "source_line": index + 2, "source_end_line": index + 2,
        "duplicate_refs": (), "kind": "network", "time_basis": "utc",
        "event_time": epoch + index, "end_time": epoch + index,
        "event_time_display": pd.Timestamp(epoch + index, unit="s", tz="UTC").isoformat(),
        "recorded_time": pd.Timestamp(epoch + index, unit="s", tz="UTC").isoformat(),
        "source_ip": "10.1.0.1", "destination_ip": "10.1.0.2", "source_port": 50000,
        "destination_port": index, "protocol": "TCP", "connection_state": "incomplete",
        "client_bytes": 0, "server_bytes": 0, "client_packets": 1, "server_packets": 0,
        "duration_ms": 0.0, "hostname": "", "account": "", "outcome": "", "evaluation_label": "",
    } for index in range(count)])


def all_anomaly_model():
    normal = network_events(32)
    normal["client_bytes"], normal["server_bytes"] = 500, 1000
    forest = IsolationForest(n_estimators=8, max_samples=32, random_state=42).fit(preprocess(normal))
    metadata = {
        "feature_version": FEATURE_VERSION, "feature_names": list(FEATURE_NAMES),
        "sklearn_version": sklearn.__version__, "threshold": -0.2, "model_version": "controlled-v1",
    }
    return NetworkModel(forest, metadata, "b" * 64)


@pytest.fixture
def completed_auth(tmp_path):
    dataset = load_authentication(OPENSSH_PATH)
    storage = Storage(tmp_path / "soc.sqlite3")
    registered, reused = storage.register_dataset(dataset, "OpenSSH sample", [OPENSSH_PATH])
    assert not reused
    config = DetectionConfig()
    run, reused = storage.reserve_run(registered["id"], config.model_dump())
    storage.start_run(run["id"])
    analysis = analyze_logs(dataset.events, config)
    storage.complete_run(run["id"], analysis["alerts"], {**run["counts"], **analysis["counts"]}, dataset.warnings + analysis["warnings"], analysis["metrics"])
    assert len(analysis["alerts"]) >= 2
    return storage, dataset, registered, storage.get_run(run["id"])


def test_model_outage_does_not_suppress_zero_payload_scan():
    result = analyze_logs(network_events(), artifact=None)
    assert len(result["alerts"]) == 1
    alert = result["alerts"][0]
    assert alert["activity_type"] == "port_scan" and alert["methods"] == ["rule"]
    assert alert["occurrence_count"] == 20
    assert len(alert["raw_events"]) == 20
    assert alert["evidence"]["ml"] is None
    assert alert["evidence"]["raw_feature_summary"]["client_bytes"]["maximum"] == 0
    assert result["counts"]["ml_evaluated"] == result["counts"]["ml_anomalies"] == 0
    assert result["metrics"]["ml_inlier_flow_count"] is None
    assert result["warnings"] and all("error" not in item for item in result["alerts"])
    json.dumps(result, allow_nan=False)


def test_rule_and_ml_merge_without_double_counting_evidence():
    events = network_events(21)
    events.loc[20, "destination_ip"] = "10.1.0.3"
    events.loc[20, "protocol"] = "UDP"
    events.loc[20, "client_bytes"] = 100_000_000
    result = analyze_logs(events, artifact=all_anomaly_model())
    assert result["counts"]["ml_evaluated"] == result["counts"]["ml_anomalies"] == 21
    assert result["counts"]["rule_supported_events"] == 20
    assert len(result["alerts"]) == 2
    scan = next(alert for alert in result["alerts"] if alert["activity_type"] == "port_scan")
    ml = next(alert for alert in result["alerts"] if alert["activity_type"] == "network_anomaly")
    assert set(scan["methods"]) == {"rule", "ml"}
    assert scan["occurrence_count"] == len(scan["raw_events"]) == 20
    assert scan["evidence"]["ml"]["anomaly_flow_count"] == 20
    assert ml["methods"] == ["ml"] and ml["occurrence_count"] == 1
    assert all(alert["evidence"]["source_references"] for alert in result["alerts"])
    assert all("probability" in alert["evidence"]["ml"]["score_meaning"] for alert in result["alerts"])


def test_authentication_bypasses_network_model(monkeypatch):
    def prohibited(*args, **kwargs):
        raise AssertionError("Authentication must never load or call the network model")
    monkeypatch.setattr(agents, "load_model", prohibited)
    monkeypatch.setattr(agents, "predict", prohibited)
    result = analyze_logs(load_authentication(OPENSSH_PATH).events)
    assert result["alerts"] and not result["warnings"]
    assert result["counts"]["authentication"] == 519
    assert result["counts"]["network"] == result["counts"]["ml_evaluated"] == 0
    assert not result["metrics"]["ml_applicable"]
    assert all(alert["time_basis"] == "source_relative" for alert in result["alerts"])
    assert all(alert["first_recorded_time"].startswith("Dec 10 ") for alert in result["alerts"])
    assert not any(alert["activity_type"] == "suspicious_login" for alert in result["alerts"])


def test_completed_identical_snapshots_and_duplicate_imports_are_reused(completed_auth):
    storage, dataset, registered, run = completed_auth
    imported, reused = storage.register_dataset(dataset, "An uploaded alias", [OPENSSH_PATH])
    assert reused and imported["id"] == registered["id"]
    repeated, reused = storage.reserve_run(registered["id"], DetectionConfig().model_dump())
    assert reused and repeated["id"] == run["id"]
    assert storage.list_datasets()["total"] == storage.list_runs()["total"] == 1
    assert storage.list_alerts({"run_id": run["id"]})["total"] == run["counts"]["alerts"]
    assert run["counts"]["raw"] == 2000 and run["counts"]["eligible"] == 519 and run["counts"]["skipped"] == 1481
    assert run["counts"]["alerts"] != run["counts"]["eligible"]


def test_distinct_config_and_active_run_conflict(completed_auth):
    storage, _, dataset, first = completed_auth
    config = DetectionConfig(failure_threshold=6)
    new, reused = storage.reserve_run(dataset["id"], config.model_dump())
    assert not reused and new["id"] != first["id"] and new["snapshot_id"] != first["snapshot_id"]
    with pytest.raises(StorageError) as failure:
        storage.reserve_run(dataset["id"], DetectionConfig(failure_threshold=7).model_dump())
    assert failure.value.status_code == 409 and failure.value.code == "active_run"
    assert failure.value.details["run_id"] == new["id"]
    storage.fail_run(new["id"], "Controlled failure")
    assert storage.get_run(new["id"])["state"] == "failed"
    retry, reused = storage.reserve_run(dataset["id"], config.model_dump())
    assert not reused and retry["id"] != new["id"]


@pytest.mark.parametrize("state", ["pending", "running"])
def test_restart_marks_orphaned_runs_failed_and_allows_retry(completed_auth, state):
    storage, _, dataset, completed = completed_auth
    config = DetectionConfig(failure_threshold=6).model_dump()
    orphan, _ = storage.reserve_run(dataset["id"], config)
    if state == "running":
        storage.start_run(orphan["id"])
    restarted = Storage(storage.path)
    assert restarted.recover_orphans() == 1
    assert restarted.get_run(orphan["id"])["state"] == "failed"
    assert "restart" in restarted.get_run(orphan["id"])["error"]
    assert restarted.get_run(completed["id"])["state"] == "completed"
    retry, reused = restarted.reserve_run(dataset["id"], config)
    assert not reused and retry["id"] != orphan["id"]


def test_atomic_completion_rolls_back_every_alert_on_failure(completed_auth):
    storage, dataset, registered, _ = completed_auth
    run, _ = storage.reserve_run(registered["id"], DetectionConfig(failure_threshold=6).model_dump())
    storage.start_run(run["id"])
    result = analyze_logs(dataset.events)
    broken = {**result["alerts"][1], "severity": "Invalid", "dedup_key": "bad-alert"}
    with pytest.raises(sqlite3.IntegrityError):
        storage.complete_run(run["id"], [result["alerts"][0], broken], result["counts"], [], result["metrics"])
    assert storage.list_alerts({"run_id": run["id"]})["total"] == 0
    assert storage.get_run(run["id"])["state"] == "running"
    storage.fail_run(run["id"], "Atomic completion rejected invalid output")
    assert storage.get_run(run["id"])["state"] == "failed"


@pytest.mark.parametrize("status", ALERT_STATUSES)
def test_alert_status_and_full_raw_evidence_persist(completed_auth, status):
    storage, _, _, run = completed_auth
    alert = storage.list_alerts({"run_id": run["id"]}, limit=1)["items"][0]
    storage.update_alert_status(alert["id"], status)
    restarted = Storage(storage.path)
    full = restarted.get_alert(alert["id"])
    assert full["status"] == status and full["evidence"]["source_references"]
    evidence = restarted.alert_events(alert["id"], limit=1)
    assert evidence["total"] == full["evidence"]["raw_event_count"] == full["occurrence_count"]
    assert len(evidence["items"]) == 1 and "raw_message" in evidence["items"][0]
    assert "evidence" not in restarted.list_alerts({"run_id": run["id"]}, limit=1)["items"][0]


@pytest.mark.parametrize("status", INCIDENT_STATUSES)
def test_incident_notes_membership_and_status_persist(completed_auth, status):
    storage, _, _, run = completed_auth
    members = storage.list_alerts({"run_id": run["id"]}, limit=2)["items"]
    incident = storage.create_incident(run["id"], "Investigate password bursts", "Retain source evidence", [members[0]["id"]])
    storage.update_incident(incident["id"], {"status": status, "notes": "Reviewed with retained line references", "alert_ids": [member["id"] for member in members]})
    reopened = Storage(storage.path).get_incident(incident["id"])
    assert reopened["status"] == status and reopened["notes"] == "Reviewed with retained line references"
    assert set(reopened["alert_ids"]) == {member["id"] for member in members}


def test_incidents_reject_other_runs_and_membership_update_rolls_back(completed_auth):
    storage, dataset, registered, first = completed_auth
    first_member = storage.list_alerts({"run_id": first["id"]}, limit=1)["items"][0]
    incident = storage.create_incident(first["id"], "Coherent investigation", "Original notes", [first_member["id"]])
    second, _ = storage.reserve_run(registered["id"], DetectionConfig(failure_threshold=6).model_dump())
    storage.start_run(second["id"])
    result = analyze_logs(dataset.events, DetectionConfig(failure_threshold=6))
    storage.complete_run(second["id"], result["alerts"], {**second["counts"], **result["counts"]}, dataset.warnings, result["metrics"])
    other = storage.list_alerts({"run_id": second["id"]}, limit=1)["items"][0]
    with pytest.raises(StorageError) as failure:
        storage.update_incident(incident["id"], {"notes": "Must roll back", "alert_ids": [other["id"]]})
    assert failure.value.code == "incoherent_incident"
    unchanged = storage.get_incident(incident["id"])
    assert unchanged["notes"] == "Original notes" and unchanged["alert_ids"] == [first_member["id"]]
    with pytest.raises(StorageError):
        storage.create_incident(first["id"], "Empty", "", [])
    assert storage.list_incidents()["total"] == 1


def test_pagination_summary_search_and_finite_serialization(completed_auth):
    storage, _, _, run = completed_auth
    first = storage.list_alerts({"run_id": run["id"]}, limit=1, offset=0)
    second = storage.list_alerts({"run_id": run["id"]}, limit=1, offset=1)
    assert first["total"] == second["total"] == run["counts"]["alerts"]
    assert first["items"][0]["id"] != second["items"][0]["id"]
    storage.update_alert_status(first["items"][0]["id"], "investigating")
    filters = {"run_id": run["id"], "status": "investigating", "method": "rule"}
    summary = storage.summary(filters)
    assert summary["alert_count"] == 1 == sum(summary["severity_counts"].values())
    assert summary["event_counts"]["eligible"] == 519
    assert storage.list_alerts({"search": "' OR 1=1 --"})["total"] == 0
    assert storage.list_alerts({"search": "%"})["total"] == 0
    json.dumps(summary, allow_nan=False)


def test_task_local_connections_enforce_one_active_run(completed_auth):
    storage, _, dataset, _ = completed_auth
    def reserve(threshold):
        try:
            return storage.reserve_run(dataset["id"], DetectionConfig(failure_threshold=threshold).model_dump())[0]
        except StorageError as exc:
            return exc
    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(reserve, (6, 7)))
    assert sum(isinstance(outcome, dict) for outcome in outcomes) == 1
    assert sum(isinstance(outcome, StorageError) and outcome.code == "active_run" for outcome in outcomes) == 1


def test_model_version_creates_a_distinct_comparable_snapshot(tmp_path):
    events = network_events(1)
    profile = {
        "fingerprint": "network-unit", "kind": "network", "time_basis": "utc",
        "raw_count": 1, "eligible_count": 1, "skipped_count": 0, "duplicate_count": 0,
        "rejected_count": 0, "ignored_count": 0,
        "sources": [{"source_id": "a" * 64, "sha256": "a" * 64, "name": "unit.csv", "bytes": 1}],
    }
    storage = Storage(tmp_path / "soc.sqlite3")
    dataset, _ = storage.register_dataset(IngestedDataset(events, profile, []), "Unit network", [tmp_path / "unit.csv"])
    artifact = all_anomaly_model()
    first, _ = storage.reserve_run(dataset["id"], DetectionConfig().model_dump(), artifact)
    storage.start_run(first["id"])
    result = analyze_logs(events, artifact=artifact)
    storage.complete_run(first["id"], result["alerts"], {**first["counts"], **result["counts"]}, [], result["metrics"])
    second_artifact = replace(artifact, metadata={**artifact.metadata, "model_version": "controlled-v2"}, artifact_sha256="c" * 64)
    second, reused = storage.reserve_run(dataset["id"], DetectionConfig().model_dump(), second_artifact)
    assert not reused and second["snapshot_id"] != first["snapshot_id"]
