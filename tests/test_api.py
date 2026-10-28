"""Route acceptance tests using real parsers, detectors, and temporary SQLite state."""

import asyncio
import csv
import hashlib
import io
import json
import re
import sqlite3
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock

import httpx
import pytest
import requests
from fastapi.testclient import TestClient
from sklearn.ensemble import IsolationForest

import agents
import detection
import main
import train
from ingestion import TCP_COLUMNS, UDP_COLUMNS
from rules import DetectionConfig
from sources import OPENSSH_PATH, OPENSSH_SHA256


UNKNOWN_ID = "00000000-0000-0000-0000-000000000000"
BASE_MS = 1_642_723_200_000
SCHEMAS = ("tcp_complete", "tcp_incomplete", "udp_complete")
TABLES = ("datasets", "imports", "runs", "alerts", "alert_events", "incidents", "incident_alerts")


def _flow(schema="tcp_complete", second=0, port=443, source_ip="192.0.2.10", **changes):
    start = BASE_MS + second * 1000
    values = {
        "source_ip": source_ip, "source_port": 40000,
        "destination_ip": "198.51.100.20", "destination_port": port,
        "client_bytes": 0, "server_bytes": 0,
        "client_packets": 0, "server_packets": 0,
    }
    if schema == "udp_complete":
        mapping = UDP_COLUMNS
        values.update(client_start_ms=start, client_duration_ms=0,
                      server_start_ms=0, server_duration_ms="")
    else:
        mapping = TCP_COLUMNS
        values.update(start_ms=start, end_ms=start, duration_ms=0,
                      client_syn=0, server_syn=0, client_fin=0, server_fin=0,
                      client_reset=0, server_reset=0)
    row = {mapping[key]: value for key, value in values.items()}
    row.update(timestamp=datetime.fromtimestamp(start / 1000, timezone.utc).isoformat(),
               label="controlled annotation", role_cli="fixture client", role_serv="fixture server")
    row.update(changes)
    return row


def _csv(schema="tcp_complete", rows=None):
    mapping = UDP_COLUMNS if schema == "udp_complete" else TCP_COLUMNS
    signatures = {
        "tcp_complete": ("c_rtt_avg:45", "s_rtt_avg:52"),
        "tcp_incomplete": ("con_t:42", "http_t:44"),
        "udp_complete": (),
    }
    columns = [*mapping.values(), *signatures[schema], "timestamp", "label", "role_cli", "role_serv"]
    handle = io.StringIO(newline="")
    writer = csv.writer(handle)
    writer.writerow(columns)
    for row in [_flow(schema)] if rows is None else rows:
        if row is None:
            writer.writerow([])
        elif isinstance(row, dict):
            writer.writerow([row.get(column, "0") for column in columns])
        else:
            writer.writerow(row)
    return handle.getvalue().encode("utf-8")


def _scan_rows(schema="tcp_complete", groups=1):
    return [
        _flow(schema, second=group * 120 + index, port=10000 + index,
              source_ip=f"192.0.2.{10 + group}")
        for group in range(groups) for index in range(20)
    ]


def _auth_line(second=0, outcome="Failed", account="audit_user", ip="192.0.2.40"):
    recorded = (datetime(2000, 12, 10) + timedelta(seconds=second)).strftime("%b %d %H:%M:%S")
    return f"{recorded} test-host sshd[123]: {outcome} password for {account} from {ip} port 40000 ssh2"


def _auth_burst():
    return "\n".join([*(_auth_line(index) for index in range(5)),
                      _auth_line(5, outcome="Accepted")]).encode("utf-8") + b"\n"


@pytest.fixture(autouse=True)
def no_external_work(monkeypatch):
    guards = []
    for owner, name in (
        (urllib.request, "urlopen"), (requests.sessions.Session, "request"),
        (main, "explain"), (train, "main"), (IsolationForest, "fit"),
        (detection, "save_model"),
    ):
        guard = Mock(side_effect=AssertionError(f"Automatic/external work is forbidden: {name}"))
        monkeypatch.setattr(owner, name, guard)
        guards.append(guard)
    yield
    # Detectors catch some failures, so an unexpected call must also fail teardown.
    for guard in guards:
        guard.assert_not_called()


@pytest.fixture
def network_sources(tmp_path):
    paths = []
    for schema in SCHEMAS:
        path = tmp_path / f"private-{schema}.csv"
        rows = _scan_rows(schema) if schema == "tcp_incomplete" else [
            _flow(schema, source_ip="192.0.2.30")
        ]
        path.write_bytes(_csv(schema, rows))
        paths.append(path)
    return tuple(paths)


@pytest.fixture
def app_factory(tmp_path, network_sources):
    def create(**overrides):
        options = {
            "database_path": tmp_path / "soc.sqlite3",
            "import_dir": tmp_path / "imports",
            "model_path": tmp_path / "missing.pkl",
            "network_files": network_sources,
            "auth_path": OPENSSH_PATH,
        }
        options.update(overrides)
        return main.create_app(**options)
    return create


@pytest.fixture
def client(app_factory):
    with TestClient(app_factory()) as test_client:
        assert test_client.app.state.recovered_runs == 0
        yield test_client


def _get(client, path, params=None):
    response = client.get(path, params=params)
    assert response.status_code == 200, response.text
    return response.json()


def _error(response, status, code):
    assert response.status_code == status, response.text
    body = response.json()
    assert isinstance(body["detail"], dict), body
    assert body["detail"]["code"] == code, body
    assert isinstance(body["detail"]["message"], str) and body["detail"]["message"]
    assert "items" not in body and "alerts" not in body
    return body["detail"]


def _import(client, content, name="controlled.csv", reused=False):
    response = client.post("/datasets/import", files={"file": (name, content)})
    assert response.status_code == (200 if reused else 201), response.text
    assert response.json()["reused"] is reused
    return response.json()["dataset"]


def _preset(client, preset_id, reused=False):
    response = client.post("/datasets/preset", json={"preset_id": preset_id})
    assert response.status_code == (200 if reused else 201), response.text
    assert response.json()["reused"] is reused
    return response.json()["dataset"]


def _analyze(client, dataset_id, config=None, reused=False):
    data = {"dataset_id": dataset_id}
    if config is not None:
        data["config"] = config
    response = client.post("/analyze", json=data)
    assert response.status_code == (200 if reused else 202), response.text
    body = response.json()
    assert body["reused"] is reused
    assert body["run"]["state"] == ("completed" if reused else "pending")
    # TestClient awaits background tasks; no polling or detector stubs are needed.
    run = _get(client, f"/runs/{body['run']['id']}")
    assert run["state"] == "completed", run
    assert run["error"] is None and run["completed_at"]
    return run


def _items(client, path, params=None, limit=100):
    filters = dict(params or {})
    first = _get(client, path, {**filters, "limit": limit, "offset": 0})
    assert first["limit"] == limit and first["offset"] == 0
    items = list(first["items"])
    for offset in range(limit, first["total"], limit):
        page = _get(client, path, {**filters, "limit": limit, "offset": offset})
        assert page["total"] == first["total"] and page["offset"] == offset
        items.extend(page["items"])
    assert len(items) == first["total"]
    return items


def _files(tmp_path):
    return sorted(path.name for path in (tmp_path / "imports").glob("*"))


def _sqlite_counts(client):
    with sqlite3.connect(client.app.state.storage.path) as connection:
        return {table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in TABLES}


def _sqlite_snapshot(client):
    with sqlite3.connect(client.app.state.storage.path) as connection:
        return {table: connection.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
                for table in TABLES}


def _assert_summary(summary, alerts):
    assert summary["alert_count"] == len(alerts)
    severities = Counter(alert["severity"] for alert in alerts)
    assert summary["severity_counts"] == {key: severities[key] for key in ("Low", "Medium", "High", "Critical")}
    assert summary["activity_counts"] == dict(Counter(alert["activity_type"] for alert in alerts))
    assert summary["status_counts"] == dict(Counter(alert["status"] for alert in alerts))
    assert summary["method_counts"] == dict(Counter(
        "both" if len(alert["methods"]) == 2 else alert["methods"][0] for alert in alerts
    ))
    json.dumps(summary, allow_nan=False)


def test_tiny_network_preset_is_an_import_preview_then_an_explicit_run(client, network_sources):
    hashes = [hashlib.sha256(path.read_bytes()).hexdigest() for path in network_sources]
    presets = _get(client, "/presets")["items"]
    assert {item["id"] for item in presets} == {"ait_network", "openssh"}
    assert all(item["available"] for item in presets)
    dataset = _preset(client, "ait_network")
    assert dataset["kind"] == "network" and dataset["time_basis"] == "utc"
    assert dataset["raw_count"] == dataset["eligible_count"] == 22
    assert dataset["profile"]["protocol_counts"] == {"TCP": 21, "UDP": 1}
    assert {source["schema"] for source in dataset["sources"]} == set(SCHEMAS)
    assert {source["sha256"] for source in dataset["sources"]} == set(hashes)
    assert all(source["source_url"] == main.AIT_URL for source in dataset["sources"])
    assert _get(client, "/runs")["total"] == _get(client, "/alerts")["total"] == 0
    assert client.get("/analyze", params={"dataset_id": dataset["id"]}).status_code == 405
    assert _get(client, "/runs")["total"] == 0
    run = _analyze(client, dataset["id"])
    assert run["counts"]["raw"] == run["counts"]["eligible"] == 22
    assert run["counts"]["alerts"] == 1 and run["counts"]["rule_supported_events"] == 20
    assert _preset(client, "ait_network", reused=True)["id"] == dataset["id"]
    assert _sqlite_counts(client)["imports"] == 3
    assert hashes == [hashlib.sha256(path.read_bytes()).hexdigest() for path in network_sources]


@pytest.mark.parametrize("schema,name,protocol,state", [
    ("tcp_complete", "looks-like-udp.csv", "TCP", "complete"),
    ("tcp_incomplete", "complete.csv", "TCP", "incomplete"),
    ("udp_complete", "looks-like-tcp.csv", "UDP", "datagram"),
])
def test_missing_model_keeps_real_zero_payload_scan_rules(client, schema, name, protocol, state):
    dataset = _import(client, _csv(schema, _scan_rows(schema)), name)
    assert dataset["sources"][0]["schema"] == schema
    assert dataset["sources"][0]["columns"][0].startswith("#")
    run = _analyze(client, dataset["id"])
    assert run["counts"]["raw"] == run["counts"]["eligible"] == 20
    assert run["counts"]["alerts"] == 1
    assert run["counts"]["ml_evaluated"] == run["counts"]["ml_anomalies"] == 0
    assert not run["model_available"] and run["model_version"] is None
    assert run["metrics"]["ml_applicable"] and not run["metrics"]["ml_available"]
    assert run["metrics"]["ml_inlier_flow_count"] is None
    assert any(warning.startswith("ML-unavailable:") for warning in run["warnings"])
    assert any("No normal predictions have been fabricated" in warning for warning in run["warnings"])
    alerts = _items(client, "/alerts", {"run_id": run["id"]})
    assert len(alerts) == 1 and "evidence" not in alerts[0] and "error" not in alerts[0]
    alert = _get(client, f"/alerts/{alerts[0]['id']}")
    assert alert["activity_type"] == "port_scan" and alert["methods"] == ["rule"]
    assert alert["protocol"] == protocol and alert["occurrence_count"] == 20
    evidence = alert["evidence"]
    assert evidence["ml"] is None and evidence["raw_event_count"] == 20
    rule = evidence["rules"][0]
    assert rule["id"] == "network.port_scan" and rule["peak_window_count"] == 20
    assert rule["unique_ports"] == list(range(10000, 10020))
    assert rule["thresholds"]["distinct_port_threshold"] == 20
    events = _items(client, evidence["raw_events_url"], limit=7)
    assert len(events) == 20 and all(event["connection_state"] == state for event in events)
    for event in events:
        assert event["source_name"] == name
        assert all(event[field] == 0 for field in (
            "client_bytes", "server_bytes", "client_packets", "server_packets", "duration_ms"
        ))
    health = _get(client, "/health")
    assert not health["model"]["available"] and health["active_run"] is None
    assert _sqlite_counts(client)["alerts"] == 1 and _sqlite_counts(client)["alert_events"] == 20


@pytest.mark.parametrize("schema", SCHEMAS)
def test_single_valid_network_event_is_not_an_error_or_fabricated_normal_alert(client, schema):
    dataset = _import(client, _csv(schema))
    run = _analyze(client, dataset["id"])
    assert run["counts"]["eligible"] == 1 and run["counts"]["alerts"] == 0
    assert run["metrics"]["ml_inlier_flow_count"] is None
    assert _get(client, "/alerts", {"run_id": run["id"]})["items"] == []
    _assert_summary(_get(client, "/summary", {"run_id": run["id"]}), [])


def test_partial_network_rejections_and_duplicates_keep_distinct_counts_and_lines(client, tmp_path):
    rows = _scan_rows()
    rows.extend([_flow(second=21, **{TCP_COLUMNS["source_ip"]: "not-an-ip"}),
                 ["structurally", "short"], None, rows[0]])
    content = _csv(rows=rows)
    dataset = _import(client, content, "partial.csv")
    assert {key: dataset[key] for key in (
        "raw_count", "eligible_count", "skipped_count", "rejected_count", "ignored_count", "duplicate_count"
    )} == {"raw_count": 24, "eligible_count": 20, "skipped_count": 4,
           "rejected_count": 2, "ignored_count": 1, "duplicate_count": 1}
    assert {item["source_line"] for item in dataset["sources"][0]["rejected_examples"]} == {22, 23}
    assert any("partial.csv: rejected 2" in warning for warning in dataset["warnings"])
    assert any("Removed 1" in warning for warning in dataset["warnings"])
    run = _analyze(client, dataset["id"])
    assert {key: run["counts"][key] for key in ("raw", "eligible", "skipped", "rejected", "ignored", "duplicate", "alerts")} == {
        "raw": 24, "eligible": 20, "skipped": 4, "rejected": 2, "ignored": 1, "duplicate": 1, "alerts": 1,
    }
    summary = _get(client, "/summary", {"run_id": run["id"], "status": "new"})
    assert summary["alert_count"] == 1 and summary["event_counts"] == run["counts"]
    alert = _get(client, f"/alerts/{_items(client, '/alerts')[0]['id']}")
    assert alert["evidence"]["source_references"] == [{
        "source_id": hashlib.sha256(content).hexdigest(), "name": "partial.csv",
        "line_ranges": [[2, 21], [25, 25]],
    }]
    assert {event["source_line"] for event in _items(client, alert["evidence"]["raw_events_url"])} == set(range(2, 22))
    public = json.dumps([dataset, _get(client, "/datasets"), _get(client, f"/datasets/{dataset['id']}")])
    private_source = client.app.state.storage.dataset_sources(dataset["id"])[0]
    assert "file_path" not in public and str(tmp_path) not in public and str(main.ROOT) not in public
    assert Path(private_source["file_path"]).name not in public
    assert len(_files(tmp_path)) == 1


@pytest.mark.parametrize("schema,changes", [
    ("tcp_complete", {TCP_COLUMNS["end_ms"]: "inf"}),
    ("tcp_incomplete", {TCP_COLUMNS["end_ms"]: "inf"}),
    ("udp_complete", {UDP_COLUMNS["client_start_ms"]: 0, UDP_COLUMNS["server_start_ms"]: 0}),
])
def test_invalid_epoch_rows_are_reported_without_aborting_real_route_detection(client, schema, changes):
    rows = [*_scan_rows(schema), _flow(schema, second=21, **changes)]
    dataset = _import(client, _csv(schema, rows), "invalid-epoch.csv")
    assert dataset["raw_count"] == 21 and dataset["eligible_count"] == 20
    assert dataset["rejected_count"] == dataset["skipped_count"] == 1
    assert dataset["sources"][0]["rejected_examples"][0]["source_line"] == 22
    assert any("rejected 1" in warning for warning in dataset["warnings"])
    run = _analyze(client, dataset["id"])
    assert run["counts"]["raw"] == 21 and run["counts"]["rejected"] == 1
    assert run["counts"]["eligible"] == run["counts"]["rule_supported_events"] == 20
    assert run["counts"]["alerts"] == 1 and _sqlite_counts(client)["alert_events"] == 20


def test_partial_authentication_rejections_do_not_count_pam_or_compressed_attempts(client):
    content = _auth_burst() + (
        _auth_line(6, ip="invalid-ip") + "\n"
        "Dec 10 00:00:07 test-host sshd[123]: pam_unix(sshd:auth): authentication failure\n"
        "Dec 10 00:00:08 test-host sshd[123]: message repeated 5 times: [ Failed password for audit_user ]\n"
    ).encode("utf-8")
    dataset = _import(client, content, "partial-auth.log")
    assert dataset["raw_count"] == 9 and dataset["eligible_count"] == 6
    assert dataset["rejected_count"] == 1 and dataset["ignored_count"] == 2
    assert dataset["skipped_count"] == 3 and dataset["duplicate_count"] == 0
    assert dataset["profile"]["outcome_counts"] == {"failed": 5, "accepted": 1}
    run = _analyze(client, dataset["id"])
    assert run["counts"]["authentication"] == run["counts"]["rule_supported_events"] == 6
    assert run["counts"]["alerts"] == 2 and not run["metrics"]["ml_applicable"]
    alerts = _items(client, "/alerts", {"run_id": run["id"]})
    assert {alert["activity_type"] for alert in alerts} == {"brute_force", "suspicious_login"}
    details = [_get(client, f"/alerts/{alert['id']}") for alert in alerts]
    assert sum(alert["evidence"]["raw_event_count"] for alert in details) == 11
    suspicious = next(alert for alert in details if alert["activity_type"] == "suspicious_login")
    rule = suspicious["evidence"]["rules"][0]
    assert rule["failed_authentication_count"] == 5 and rule["accepted_authentication_count"] == 1
    assert {event["source_line"] for event in _items(client, suspicious["evidence"]["raw_events_url"])} == set(range(1, 7))


def test_retained_real_openssh_preset_has_only_observed_authentication_evidence(client, monkeypatch):
    content = OPENSSH_PATH.read_bytes()
    assert hashlib.sha256(content).hexdigest() == OPENSSH_SHA256
    lines = content.decode("utf-8").splitlines()
    failed_lines = [index for index, line in enumerate(lines, 1) if re.search(r"sshd\[\d+\]: Failed password for ", line)]
    accepted_lines = [index for index, line in enumerate(lines, 1) if re.search(r"sshd\[\d+\]: Accepted (?:password|publickey) for ", line)]
    assert len(lines) == 2000 and len(failed_lines) == 518 and accepted_lines == [956]
    assert "Accepted password for fztu from 119.137.62.142" in lines[955]
    assert not any("Failed password for fztu from 119.137.62.142" in line for line in lines)
    guards = []
    for owner, name in ((main, "load_model"), (agents, "load_model"), (agents, "predict")):
        guard = Mock(side_effect=AssertionError("Authentication must bypass network ML"))
        monkeypatch.setattr(owner, name, guard)
        guards.append(guard)
    dataset = _preset(client, "openssh")
    assert dataset["raw_count"] == 2000 and dataset["eligible_count"] == 519
    assert dataset["ignored_count"] == dataset["skipped_count"] == 1481
    assert dataset["rejected_count"] == dataset["duplicate_count"] == 0
    assert dataset["time_basis"] == "source_relative"
    assert dataset["profile"]["outcome_counts"] == {"failed": 518, "accepted": 1}
    assert dataset["sources"][0]["sha256"] == OPENSSH_SHA256
    assert [(item["source_line"], item["represented_repetitions"]) for item in
            dataset["sources"][0]["compressed_retry_summaries"]] == [(30, 5), (285, 5)]
    assert any("year/timezone are unknown" in warning for warning in dataset["warnings"])
    assert any("no independent attack labels" in warning for warning in dataset["warnings"])
    run = _analyze(client, dataset["id"])
    assert run["counts"]["raw"] == 2000 and run["counts"]["eligible"] == 519
    assert run["counts"]["authentication"] == 519 and run["counts"]["network"] == 0
    assert run["counts"]["ml_evaluated"] == run["counts"]["ml_anomalies"] == 0
    assert not run["metrics"]["ml_applicable"] and not run["model_available"]
    assert not any(warning.startswith("ML-unavailable:") for warning in run["warnings"])
    alerts = _items(client, "/alerts", {"run_id": run["id"]}, limit=3)
    assert 1 < len(alerts) == run["counts"]["alerts"] < 519
    assert all(alert["activity_type"] == "brute_force" and alert["methods"] == ["rule"] for alert in alerts)
    supporting_lines = set()
    for alert in alerts:
        detail = _get(client, f"/alerts/{alert['id']}")
        assert detail["time_basis"] == "source_relative"
        assert detail["first_recorded_time"].startswith("Dec 10 ")
        assert detail["last_recorded_time"].startswith("Dec 10 ")
        rule = detail["evidence"]["rules"][0]
        assert rule["failed_authentication_count"] == detail["occurrence_count"]
        assert rule["accepted_authentication_count"] == 0
        events = _items(client, detail["evidence"]["raw_events_url"], limit=7)
        assert len(events) == detail["occurrence_count"] == detail["evidence"]["raw_event_count"]
        for event in events:
            number = event["source_line"]
            assert number == event["source_end_line"] and number in failed_lines
            assert event["raw_message"] == lines[number - 1].split(": ", 1)[1]
            assert event["recorded_time"] == lines[number - 1][:15]
            assert event["outcome"] == "failed" and event["source_name"] == OPENSSH_PATH.name
            assert event["source_id"] == OPENSSH_SHA256
            supporting_lines.add(number)
    assert 956 not in supporting_lines
    assert len(supporting_lines) == run["counts"]["rule_supported_events"]
    _assert_summary(_get(client, "/summary", {"run_id": run["id"]}), alerts)
    assert _preset(client, "openssh", reused=True)["id"] == dataset["id"]
    assert _analyze(client, dataset["id"], reused=True)["id"] == run["id"]
    assert OPENSSH_PATH.read_bytes() == content
    for guard in guards:
        guard.assert_not_called()


def test_refresh_is_read_only_and_never_reanalyzes_or_changes_investigation_state(client, monkeypatch):
    analyze = Mock(wraps=main.analyze_logs)
    parse = Mock(wraps=main.load_network)
    monkeypatch.setattr(main, "analyze_logs", analyze)
    monkeypatch.setattr(main, "load_network", parse)
    dataset = _import(client, _csv(rows=_scan_rows(groups=2)))
    assert _get(client, "/runs")["total"] == 0
    response = client.get("/analyze")
    assert response.status_code == 405 and "POST" in response.headers["allow"]
    analyze.assert_not_called()
    run = _analyze(client, dataset["id"])
    assert analyze.call_count == parse.call_count == 1
    alerts = _items(client, "/alerts", {"run_id": run["id"]})
    changed = client.patch(f"/alerts/{alerts[0]['id']}", json={"status": "investigating"})
    assert changed.status_code == 200
    incident = client.post("/incidents", json={
        "run_id": run["id"], "title": "Read-only refresh", "notes": "Retain analyst state",
        "alert_ids": [alert["id"] for alert in alerts],
    })
    assert incident.status_code == 201
    snapshot = _sqlite_snapshot(client)
    summary = _get(client, "/summary", {"run_id": run["id"]})
    reserve = Mock(wraps=client.app.state.storage.reserve_run)
    complete = Mock(wraps=client.app.state.storage.complete_run)
    monkeypatch.setattr(client.app.state.storage, "reserve_run", reserve)
    monkeypatch.setattr(client.app.state.storage, "complete_run", complete)
    for _ in range(3):
        for path in ("/health", "/presets", "/datasets", f"/datasets/{dataset['id']}",
                     "/runs", f"/runs/{run['id']}", "/alerts", "/incidents",
                     f"/incidents/{incident.json()['id']}"):
            _get(client, path)
        assert _get(client, "/summary", {"run_id": run["id"]}) == summary
        assert _get(client, "/alerts", {"run_id": run["id"], "status": "investigating", "limit": 1})["total"] == 1
        for alert in alerts:
            _get(client, f"/alerts/{alert['id']}")
            _get(client, f"/alerts/{alert['id']}/events", {"limit": 1, "offset": 1})
        assert client.get("/analyze").status_code == client.get("/explain").status_code == 405
    assert analyze.call_count == parse.call_count == 1
    reserve.assert_not_called()
    complete.assert_not_called()
    assert _sqlite_snapshot(client) == snapshot
    assert _get(client, "/runs")["total"] == 1


def test_duplicate_uploads_and_completed_snapshots_reuse_ids_and_clean_generated_files(client, tmp_path, monkeypatch):
    analyze = Mock(wraps=main.analyze_logs)
    monkeypatch.setattr(main, "analyze_logs", analyze)
    content = _csv(rows=_scan_rows())
    dataset = _import(client, content, "first.csv")
    files = _files(tmp_path)
    assert len(files) == 1
    run = _analyze(client, dataset["id"])
    alert = _items(client, "/alerts")[0]
    assert client.patch(f"/alerts/{alert['id']}", json={"status": "false_positive"}).status_code == 200
    snapshot = _sqlite_snapshot(client)
    duplicate = _import(client, content, "an-alias.csv", reused=True)
    assert duplicate == dataset
    assert _files(tmp_path) == files
    assert (tmp_path / "imports" / files[0]).read_bytes() == content
    repeated = _analyze(client, dataset["id"], DetectionConfig().model_dump(), reused=True)
    assert repeated["id"] == run["id"] and repeated["snapshot_id"] == run["snapshot_id"]
    assert _get(client, f"/alerts/{alert['id']}")["status"] == "false_positive"
    assert _sqlite_snapshot(client) == snapshot and analyze.call_count == 1


def test_changed_detection_config_creates_a_separate_comparable_run(client):
    dataset = _import(client, _csv(rows=_scan_rows()))
    first = _analyze(client, dataset["id"])
    first_alert = _items(client, "/alerts", {"run_id": first["id"]})[0]
    assert client.patch(f"/alerts/{first_alert['id']}", json={"status": "resolved"}).status_code == 200
    second = _analyze(client, dataset["id"], {"scan_port_threshold": 21})
    assert second["id"] != first["id"] and second["snapshot_id"] != first["snapshot_id"]
    assert first["config"]["scan_port_threshold"] == 20 and second["config"]["scan_port_threshold"] == 21
    assert second["counts"]["eligible"] == first["counts"]["eligible"] == 20
    assert second["counts"]["alerts"] == 0 and first["counts"]["alerts"] == 1
    assert second["model_version"] == first["model_version"] is None
    assert _get(client, "/runs", {"dataset_id": dataset["id"]})["total"] == 2
    assert _get(client, "/summary", {"run_id": first["id"]})["status_counts"] == {"resolved": 1}
    assert _get(client, "/summary", {"run_id": second["id"]})["alert_count"] == 0
    assert _analyze(client, dataset["id"], reused=True)["id"] == first["id"]
    assert _analyze(client, dataset["id"], {"scan_port_threshold": 21}, reused=True)["id"] == second["id"]


@pytest.mark.parametrize("state", ["pending", "running"])
def test_one_active_run_conflicts_across_datasets_and_retry_is_explicit(client, state, monkeypatch):
    dataset = _import(client, _csv(rows=_scan_rows()))
    other = _import(client, _auth_burst(), "controlled.log")
    storage = client.app.state.storage
    reserved, reused = storage.reserve_run(dataset["id"], DetectionConfig().model_dump())
    assert not reused
    if state == "running":
        storage.start_run(reserved["id"])
    analyze = Mock(wraps=main.analyze_logs)
    monkeypatch.setattr(main, "analyze_logs", analyze)
    for identifier in (dataset["id"], other["id"]):
        detail = _error(client.post("/analyze", json={"dataset_id": identifier}), 409, "active_run")
        assert detail["details"] == {"run_id": reserved["id"], "state": state}
    assert _get(client, "/health")["active_run"] == {"id": reserved["id"], "state": state}
    assert _get(client, "/runs")["total"] == 1 and _sqlite_counts(client)["alerts"] == 0
    analyze.assert_not_called()
    storage.fail_run(reserved["id"], "Controlled interruption for API retry acceptance")
    retry = _analyze(client, dataset["id"])
    assert retry["id"] != reserved["id"] and retry["snapshot_id"] == reserved["snapshot_id"]
    assert _get(client, f"/runs/{reserved['id']}")["state"] == "failed"
    assert _get(client, "/health")["active_run"] is None and analyze.call_count == 1


@pytest.mark.parametrize("state", ["pending", "running"])
def test_lifespan_restart_recovers_orphaned_runs_without_partial_alerts(app_factory, state):
    with TestClient(app_factory()) as first:
        dataset = _import(first, _csv(rows=_scan_rows()))
        storage = first.app.state.storage
        orphan, _ = storage.reserve_run(dataset["id"], DetectionConfig().model_dump())
        if state == "running":
            storage.start_run(orphan["id"])
        assert _get(first, f"/runs/{orphan['id']}")["state"] == state
        assert _sqlite_counts(first)["alerts"] == _sqlite_counts(first)["alert_events"] == 0
    with TestClient(app_factory()) as second:
        assert second.app.state.recovered_runs == 1
        recovered = _get(second, f"/runs/{orphan['id']}")
        assert recovered["state"] == "failed" and "restart" in recovered["error"]
        assert "Explicitly analyze again" in recovered["error"]
        assert recovered["counts"]["alerts"] == 0 and recovered["completed_at"]
        assert _get(second, "/health")["active_run"] is None
        assert _get(second, "/alerts", {"run_id": orphan["id"]})["total"] == 0
        retry = _analyze(second, dataset["id"])
        assert retry["id"] != orphan["id"] and retry["snapshot_id"] == orphan["snapshot_id"]
        assert {run["state"] for run in _items(second, "/runs")} == {"failed", "completed"}
        assert _sqlite_counts(second)["alerts"] == 1
        assert _analyze(second, dataset["id"], reused=True)["id"] == retry["id"]


@pytest.mark.parametrize("alert_status,incident_status", [
    ("new", "open"), ("investigating", "investigating"),
    ("resolved", "closed"), ("false_positive", "closed"),
])
def test_statuses_incident_notes_and_membership_survive_two_app_startups(app_factory, alert_status, incident_status):
    with TestClient(app_factory()) as first:
        dataset = _import(first, _csv(rows=_scan_rows(groups=2)))
        run = _analyze(first, dataset["id"])
        alerts = _items(first, "/alerts", {"run_id": run["id"]})
        ids = [alert["id"] for alert in alerts]
        changed = first.patch(f"/alerts/{ids[0]}", json={"status": alert_status})
        assert changed.status_code == 200
        saved_alert = changed.json()
        created = first.post("/incidents", json={
            "run_id": run["id"], "title": "  Controlled scan investigation  ",
            "notes": "Initial analyst note", "alert_ids": [ids[0], ids[0]],
        })
        assert created.status_code == 201 and created.json()["alert_ids"] == [ids[0]]
        assert created.json()["title"] == "Controlled scan investigation"
        updated = first.patch(f"/incidents/{created.json()['id']}", json={
            "title": "  Retained investigation  ", "status": incident_status,
            "notes": "Reviewed original line evidence.\nUntrusted text: <script>alert('x')</script>",
            "alert_ids": [*ids, ids[0]],
        })
        assert updated.status_code == 200
        saved_incident = updated.json()
        assert saved_incident["title"] == "Retained investigation"
        assert set(saved_incident["alert_ids"]) == set(ids)
        assert _sqlite_counts(first)["incident_alerts"] == 2
        snapshot = _sqlite_snapshot(first)
    with TestClient(app_factory()) as second:
        assert second.app.state.recovered_runs == 0
        assert _get(second, f"/datasets/{dataset['id']}") == dataset
        assert _get(second, f"/runs/{run['id']}") == run
        assert _get(second, f"/alerts/{ids[0]}") == saved_alert
        assert _get(second, f"/incidents/{saved_incident['id']}") == saved_incident
        assert _get(second, "/incidents", {"run_id": run["id"], "limit": 1})["total"] == 1
        assert _get(second, "/incidents", {"run_id": run["id"], "offset": 1})["items"] == []
        assert _analyze(second, dataset["id"], reused=True)["id"] == run["id"]
        assert _sqlite_snapshot(second) == snapshot
        current = _items(second, "/alerts", {"run_id": run["id"]})
        _assert_summary(_get(second, "/summary", {"run_id": run["id"]}), current)
        assert next(alert for alert in current if alert["id"] == ids[0])["status"] == alert_status
        assert _get(second, f"/alerts/{ids[0]}/events", {"limit": 1})["total"] == 20


def test_pagination_and_filtered_summaries_use_persisted_alert_not_event_counts(client):
    network = _import(client, _csv(rows=[*_scan_rows(groups=3), _flow(source_ip="192.0.2.90")]))
    network_run = _analyze(client, network["id"])
    auth = _import(client, _auth_burst() + b"Dec 10 00:00:06 test-host sshd[123]: pam_unix(sshd:auth): failure\n", "auth.log")
    auth_run = _analyze(client, auth["id"])
    network_alerts = _items(client, "/alerts", {"run_id": network_run["id"]})
    for alert, status in zip(network_alerts, ("investigating", "resolved", "false_positive")):
        assert client.patch(f"/alerts/{alert['id']}", json={"status": status}).status_code == 200
    all_alerts = _items(client, "/alerts", limit=2)
    assert len(all_alerts) == len({alert["id"] for alert in all_alerts}) == 5
    assert _get(client, "/alerts", {"limit": 2, "offset": 4})["total"] == 5
    assert len(_get(client, "/alerts", {"limit": 2, "offset": 4})["items"]) == 1
    assert _get(client, "/alerts", {"offset": 5})["items"] == []
    cases = [
        {}, {"run_id": network_run["id"]}, {"run_id": auth_run["id"]},
        {"severity": "High"}, {"severity": "Critical"}, {"severity": "Low"},
        {"activity_type": "port_scan"}, {"activity_type": "brute_force"},
        {"activity_type": "suspicious_login"}, {"method": "rule"}, {"method": "ml"},
        {"method": "both"}, {"status": "new"}, {"status": "investigating"},
        {"status": "resolved"}, {"status": "false_positive"}, {"search": "audit_user"},
        {"run_id": network_run["id"], "severity": "High", "activity_type": "port_scan",
         "method": "rule", "status": "investigating", "search": "192.0.2."},
    ]
    for filters in cases:
        matching = _items(client, "/alerts", filters, limit=1)
        expected_alerts = list(all_alerts)
        for key in ("run_id", "severity", "activity_type", "status"):
            if key in filters:
                expected_alerts = [alert for alert in expected_alerts if alert[key] == filters[key]]
        if "method" in filters:
            expected_alerts = [alert for alert in expected_alerts if (
                len(alert["methods"]) == 2 if filters["method"] == "both"
                else filters["method"] in alert["methods"]
            )]
        if "search" in filters:
            expected_alerts = [alert for alert in expected_alerts if any(
                filters["search"].lower() in alert[key].lower()
                for key in ("source_ip", "destination_ip", "account", "hostname", "title")
            )]
        assert {alert["id"] for alert in matching} == {alert["id"] for alert in expected_alerts}
        summary = _get(client, "/summary", filters)
        _assert_summary(summary, expected_alerts)
        if filters.get("run_id"):
            expected = network_run if filters["run_id"] == network_run["id"] else auth_run
            assert summary["event_counts"] == expected["counts"]
        else:
            assert summary["event_counts"] == {}
    assert network_run["counts"]["raw"] == network_run["counts"]["eligible"] == 61
    assert network_run["counts"]["alerts"] == 3 and network_run["counts"]["rule_supported_events"] == 60
    assert auth_run["counts"]["raw"] == 7 and auth_run["counts"]["eligible"] == 6
    assert auth_run["counts"]["alerts"] == 2 and auth_run["counts"]["rule_supported_events"] == 6
    for run in (network_run, auth_run):
        members = _items(client, "/alerts", {"run_id": run["id"]})
        created = client.post("/incidents", json={
            "run_id": run["id"], "title": "Coherent paginated investigation", "alert_ids": [members[0]["id"]],
        })
        assert created.status_code == 201
    for path in ("/datasets", "/runs", "/incidents"):
        items = _items(client, path, limit=1)
        assert len(items) == len({item["id"] for item in items}) == 2
        assert _get(client, path, {"limit": 1, "offset": 2})["items"] == []
    assert len(_items(client, "/runs", {"dataset_id": network["id"]}, limit=1)) == 1
    assert len(_items(client, "/incidents", {"run_id": network_run["id"]}, limit=1)) == 1


@pytest.mark.parametrize("search", ["%", "_", "\\", "' OR 1=1 --"])
def test_search_metacharacters_are_literal_and_parameterized(client, search):
    dataset = _import(client, _csv(rows=_scan_rows()))
    run = _analyze(client, dataset["id"])
    filters = {"run_id": run["id"], "search": search}
    assert _get(client, "/alerts", filters)["total"] == 0
    summary = _get(client, "/summary", filters)
    _assert_summary(summary, [])
    assert summary["event_counts"]["eligible"] == 20
    assert _sqlite_counts(client)["alerts"] == 1


def test_paginated_evidence_retains_original_physical_csv_lines_and_raw_values(client):
    rows = _scan_rows()
    rows[0]["label"] = "annotation spanning\ntwo physical lines"
    content = _csv(rows=[*rows, rows[0]])
    dataset = _import(client, content, "original-lines.csv")
    assert dataset["raw_count"] == 21 and dataset["eligible_count"] == 20 and dataset["duplicate_count"] == 1
    run = _analyze(client, dataset["id"])
    alert = _get(client, f"/alerts/{_items(client, '/alerts', {'run_id': run['id']})[0]['id']}")
    evidence = alert["evidence"]
    assert evidence["raw_events_url"] == f"/alerts/{alert['id']}/events"
    assert evidence["source_references"] == [{
        "source_id": hashlib.sha256(content).hexdigest(), "name": "original-lines.csv", "line_ranges": [[2, 24]],
    }]
    pages = [_get(client, evidence["raw_events_url"], {"limit": 7, "offset": offset}) for offset in (0, 7, 14)]
    assert [len(page["items"]) for page in pages] == [7, 7, 6]
    assert all(page["total"] == 20 for page in pages)
    events = [event for page in pages for event in page["items"]]
    for index, event in enumerate(events):
        assert event["source_line"] == (2 if index == 0 else index + 3)
        assert event["source_end_line"] == (3 if index == 0 else index + 3)
        assert event["source_name"] == "original-lines.csv" and event["destination_port"] == 10000 + index
        assert event["source_id"] == hashlib.sha256(content).hexdigest()
        assert event["client_bytes"] == event["server_bytes"] == event["duration_ms"] == 0
        assert event["recorded_time"] == rows[index]["timestamp"]
    assert _get(client, evidence["raw_events_url"], {"offset": 20})["items"] == []
    assert evidence["raw_event_count"] == alert["occurrence_count"] == 20
    assert _sqlite_counts(client)["alert_events"] == 20


@pytest.mark.parametrize("foreign", ["another_config", "another_dataset", "missing_alert"])
def test_incident_membership_must_be_same_run_and_rejected_updates_roll_back(client, foreign):
    dataset = _import(client, _csv(rows=_scan_rows(groups=2)))
    run = _analyze(client, dataset["id"])
    members = _items(client, "/alerts", {"run_id": run["id"]})
    created = client.post("/incidents", json={
        "run_id": run["id"], "title": "Original title", "notes": "Original notes",
        "alert_ids": [members[0]["id"]],
    })
    assert created.status_code == 201
    original = created.json()
    if foreign == "missing_alert":
        invalid_id = UNKNOWN_ID
    else:
        other_dataset = dataset if foreign == "another_config" else _import(client, _auth_burst(), "another-source.log")
        other_run = _analyze(client, other_dataset["id"], {"scan_port_threshold": 19})
        invalid_id = _items(client, "/alerts", {"run_id": other_run["id"]})[0]["id"]
    _error(client.post("/incidents", json={
        "run_id": run["id"], "title": "Must not be inserted", "alert_ids": [members[0]["id"], invalid_id],
    }), 422, "incoherent_incident")
    _error(client.patch(f"/incidents/{original['id']}", json={
        "title": "Must roll back", "notes": "Must roll back", "status": "closed",
        "alert_ids": [members[1]["id"], invalid_id],
    }), 422, "incoherent_incident")
    assert _get(client, f"/incidents/{original['id']}") == original
    assert _sqlite_counts(client)["incidents"] == _sqlite_counts(client)["incident_alerts"] == 1


def test_incident_creation_requires_a_completed_run(client):
    dataset = _import(client, _csv(rows=_scan_rows()))
    run = _analyze(client, dataset["id"])
    member = _items(client, "/alerts")[0]
    pending, _ = client.app.state.storage.reserve_run(dataset["id"], DetectionConfig(scan_port_threshold=21).model_dump())
    _error(client.post("/incidents", json={
        "run_id": pending["id"], "title": "Not completed", "alert_ids": [member["id"]],
    }), 409, "run_incomplete")
    assert _sqlite_counts(client)["incidents"] == 0
    assert _get(client, f"/runs/{run['id']}")["state"] == "completed"


@pytest.mark.parametrize("payload", [
    {}, {"preset_id": "unknown"}, {"preset_id": 1}, {"preset_id": None},
    {"preset_id": "openssh", "file_path": "../private.log"},
])
def test_preset_requests_have_typed_validation_failures(client, payload):
    _error(client.post("/datasets/preset", json=payload), 422, "validation_error")
    assert _sqlite_counts(client)["datasets"] == 0


@pytest.mark.parametrize("payload", [
    {}, [], {"logs": []}, {"dataset_id": None}, {"dataset_id": 1}, {"dataset_id": "not-a-uuid"},
    {"dataset_id": UNKNOWN_ID, "config": None}, {"dataset_id": UNKNOWN_ID, "config": []},
    {"dataset_id": UNKNOWN_ID, "model_path": "models/model.pkl"},
    {"dataset_id": UNKNOWN_ID, "config": {"unrecognized_threshold": 1}},
])
def test_analysis_inputs_are_strict_and_do_not_accept_legacy_logs_or_paths(client, payload):
    _error(client.post("/analyze", json=payload), 422, "validation_error")
    assert _sqlite_counts(client)["runs"] == 0


@pytest.mark.parametrize("field,minimum,maximum", [
    ("failure_threshold", 2, 1000), ("failure_window_seconds", 1, 86400),
    ("scan_port_threshold", 2, 65536), ("scan_window_seconds", 1, 3600),
    ("success_window_seconds", 1, 86400), ("auth_cooldown_seconds", 0, 86400),
    ("scan_cooldown_seconds", 0, 86400), ("ml_bucket_seconds", 1, 3600),
])
@pytest.mark.parametrize("invalid", ["below", "above", "string", "boolean", "fraction", "null"])
def test_detection_configuration_rejects_wrong_types_and_out_of_range_values(client, field, minimum, maximum, invalid):
    value = {"below": minimum - 1, "above": maximum + 1, "string": "5",
             "boolean": True, "fraction": 2.5, "null": None}[invalid]
    detail = _error(client.post("/analyze", json={"dataset_id": UNKNOWN_ID, "config": {field: value}}),
                    422, "validation_error")
    assert any(error["location"] == ["body", "config", field] for error in detail["details"])
    assert _sqlite_counts(client)["runs"] == 0


@pytest.mark.parametrize("path", ["/datasets", "/runs", "/alerts", "/incidents", f"/alerts/{UNKNOWN_ID}/events"])
@pytest.mark.parametrize("params", [{"limit": 0}, {"limit": 101}, {"limit": "invalid"}, {"offset": -1}, {"offset": "invalid"}])
def test_pagination_parameters_have_typed_failures(client, path, params):
    _error(client.get(path, params=params), 422, "validation_error")


@pytest.mark.parametrize("path", ["/alerts", "/summary"])
@pytest.mark.parametrize("params", [
    {"run_id": "invalid"}, {"severity": "high"}, {"activity_type": "udp_flood"},
    {"method": "llm"}, {"status": "open"}, {"search": "x" * 201},
])
def test_alert_and_summary_filters_have_typed_failures(client, path, params):
    _error(client.get(path, params=params), 422, "validation_error")


@pytest.mark.parametrize("method,path,payload,code", [
    ("GET", f"/datasets/{UNKNOWN_ID}", None, "dataset_not_found"),
    ("POST", "/analyze", {"dataset_id": UNKNOWN_ID}, "dataset_not_found"),
    ("GET", f"/runs/{UNKNOWN_ID}", None, "run_not_found"),
    ("GET", "/runs?dataset_id=" + UNKNOWN_ID, None, "dataset_not_found"),
    ("GET", "/alerts?run_id=" + UNKNOWN_ID, None, "run_not_found"),
    ("GET", "/summary?run_id=" + UNKNOWN_ID, None, "run_not_found"),
    ("GET", f"/alerts/{UNKNOWN_ID}", None, "alert_not_found"),
    ("GET", f"/alerts/{UNKNOWN_ID}/events", None, "alert_not_found"),
    ("PATCH", f"/alerts/{UNKNOWN_ID}", {"status": "resolved"}, "alert_not_found"),
    ("GET", f"/incidents/{UNKNOWN_ID}", None, "incident_not_found"),
    ("GET", "/incidents?run_id=" + UNKNOWN_ID, None, "run_not_found"),
    ("PATCH", f"/incidents/{UNKNOWN_ID}", {"status": "closed"}, "incident_not_found"),
    ("POST", "/incidents", {"run_id": UNKNOWN_ID, "title": "Missing run", "alert_ids": [UNKNOWN_ID]}, "run_not_found"),
    ("POST", "/explain", {"alert_id": UNKNOWN_ID}, "alert_not_found"),
])
def test_unknown_resources_return_typed_not_found_errors(client, method, path, payload, code):
    _error(client.request(method, path, json=payload), 404, code)
    assert not any(_sqlite_counts(client).values())


@pytest.mark.parametrize("path", ["/datasets/not-a-uuid", "/runs/not-a-uuid", "/alerts/not-a-uuid",
                                     "/alerts/not-a-uuid/events", "/incidents/not-a-uuid",
                                     "/runs?dataset_id=invalid", "/incidents?run_id=invalid"])
def test_malformed_resource_identifiers_are_validation_errors(client, path):
    _error(client.get(path), 422, "validation_error")


@pytest.mark.parametrize("payload", [{}, {"status": "open"}, {"status": "unknown"}, {"status": 1},
                                        {"status": None}, {"status": "resolved", "notes": "extra"}])
def test_alert_status_updates_have_typed_failures(client, payload):
    _error(client.patch(f"/alerts/{UNKNOWN_ID}", json=payload), 422, "validation_error")


@pytest.mark.parametrize("payload", [
    {"status": "new"}, {"status": 1}, {"title": "   "}, {"title": "x" * 161},
    {"notes": "x" * 10001}, {"notes": 1}, {"alert_ids": []}, {"alert_ids": ["invalid"]},
    {"alert_ids": [UNKNOWN_ID] * 1001}, {"run_id": UNKNOWN_ID},
])
def test_incident_updates_have_typed_failures(client, payload):
    _error(client.patch(f"/incidents/{UNKNOWN_ID}", json=payload), 422, "validation_error")


@pytest.mark.parametrize("changes", [
    {"run_id": "invalid"}, {"title": ""}, {"title": "   "}, {"title": 1},
    {"title": "x" * 161}, {"notes": "x" * 10001}, {"notes": False},
    {"alert_ids": []}, {"alert_ids": ["invalid"]}, {"alert_ids": [UNKNOWN_ID] * 1001},
    {"status": "open"},
])
def test_incident_creation_has_typed_failures(client, changes):
    payload = {"run_id": UNKNOWN_ID, "title": "Valid title", "alert_ids": [UNKNOWN_ID], **changes}
    _error(client.post("/incidents", json=payload), 422, "validation_error")
    assert _sqlite_counts(client)["incidents"] == 0


@pytest.mark.parametrize("content,name,code", [
    (b"", "empty.csv", "empty_input"), (b"", "empty.log", "empty_input"),
    (b"\n", "blank.csv", "empty_input"),
    (b"source,destination,bytes\n1,2,3\n", "unknown.csv", "unsupported_schema"),
    (b"duplicate,duplicate\n1,2\n", "duplicate-header.csv", "invalid_schema"),
    (b"ordinary text without security events\n", "unknown.txt", "all_invalid"),
    (b"Dec 10 00:00:00 host sshd[1]: Failed password for alice from invalid port 5 ssh2\n", "invalid.log", "all_invalid"),
    (b"\x80\x04pickle-not-a-csv", "disguised-model.csv", "invalid_text"),
])
def test_empty_unrecognized_and_all_invalid_uploads_fail_without_persistence_or_leftovers(client, tmp_path, content, name, code):
    _error(client.post("/datasets/import", files={"file": (name, content)}), 422, code)
    assert _files(tmp_path) == [] and not any(_sqlite_counts(client).values())


@pytest.mark.parametrize("schema", SCHEMAS)
@pytest.mark.parametrize("empty", [True, False])
def test_recognized_csv_with_no_eligible_rows_has_typed_rejection_details(client, tmp_path, schema, empty):
    mapping = UDP_COLUMNS if schema == "udp_complete" else TCP_COLUMNS
    rows = [] if empty else [_flow(schema, **{mapping["source_ip"]: "invalid"})]
    detail = _error(client.post("/datasets/import", files={"file": ("invalid.csv", _csv(schema, rows))}), 422, "all_invalid")
    source = detail["details"]["sources"][0]
    assert source["raw_count"] == (0 if empty else 1)
    assert source["rejected_count"] == (0 if empty else 1)
    assert _files(tmp_path) == [] and _sqlite_counts(client)["datasets"] == 0


@pytest.mark.parametrize("name", ["model.pkl", "network_model.pkl", "forest.pickle", "forest.joblib", "artifact.bin", "model.onnx"])
def test_model_artifacts_are_never_uploadable_even_with_recognized_csv_content(client, tmp_path, name):
    _error(client.post("/datasets/import", files={"file": (name, _csv())}), 415, "unsupported_format")
    assert _files(tmp_path) == [] and _sqlite_counts(client)["datasets"] == 0


@pytest.mark.parametrize("name", ["../flows.csv", "..\\flows.csv", "nested/flows.csv", "nested\\flows.csv",
                                    "/outside/flows.csv", "x" * 161 + ".csv"])
def test_traversal_and_overlong_filenames_are_rejected_before_private_file_creation(client, tmp_path, name):
    _error(client.post("/datasets/import", files={"file": (name, _csv())}), 422, "invalid_filename")
    assert _files(tmp_path) == [] and _sqlite_counts(client)["datasets"] == 0


def test_control_characters_in_raw_multipart_filename_are_rejected(client, tmp_path):
    body = (b'--boundary\r\nContent-Disposition: form-data; name="file"; filename="bad\x01.csv"\r\n'
            b'Content-Type: text/csv\r\n\r\n' + _csv() + b'\r\n--boundary--\r\n')
    _error(client.post("/datasets/import", content=body,
                       headers={"Content-Type": "multipart/form-data; boundary=boundary"}), 422, "invalid_filename")
    assert _files(tmp_path) == []


def test_upload_requires_the_file_field_and_json_is_not_an_import(client):
    _error(client.post("/datasets/import", files={"other": ("flows.csv", _csv())}), 422, "validation_error")
    _error(client.post("/datasets/import", json={"file_path": "data/tcp_complete.csv"}), 422, "validation_error")
    _error(client.post("/analyze", content=b'{"dataset_id":', headers={"Content-Type": "application/json"}), 422, "validation_error")


@pytest.mark.parametrize("over_limit", [False, True])
def test_upload_byte_limit_is_measured_and_inclusive(app_factory, tmp_path, over_limit):
    content = _csv()
    limit = len(content) - int(over_limit)
    with TestClient(app_factory(max_upload_bytes=limit)) as client:
        assert _get(client, "/health")["limits"]["max_upload_bytes"] == limit
        response = client.post("/datasets/import", files={"file": ("bounded.csv", content)})
        if over_limit:
            _error(response, 413, "size_limit")
            assert _files(tmp_path) == [] and _sqlite_counts(client)["datasets"] == 0
        else:
            assert response.status_code == 201, response.text
            assert response.json()["dataset"]["sources"][0]["bytes"] == limit
            assert len(_files(tmp_path)) == 1


@pytest.mark.parametrize("schema", SCHEMAS)
def test_upload_row_limit_counts_raw_rows_including_duplicates_and_cleans_rejection(app_factory, tmp_path, schema):
    rows = [_flow(schema), _flow(schema, second=1, port=80)]
    with TestClient(app_factory(max_rows=2)) as client:
        accepted = _import(client, _csv(schema, rows))
        assert accepted["raw_count"] == accepted["eligible_count"] == 2
        before = _files(tmp_path)
        _error(client.post("/datasets/import", files={"file": ("too-many.csv", _csv(schema, [*rows, rows[0]]))}), 413, "row_limit")
        assert _files(tmp_path) == before and _sqlite_counts(client)["datasets"] == 1
        assert _get(client, "/health")["limits"]["max_rows"] == 2


def test_authentication_row_limit_counts_non_attempt_lines(app_factory, tmp_path):
    content = (_auth_line() + "\nDec 10 00:00:01 test-host sshd[123]: pam_unix(sshd:auth): failure\n").encode()
    with TestClient(app_factory(max_rows=2)) as client:
        dataset = _import(client, content, "bounded.log")
        assert dataset["raw_count"] == 2 and dataset["eligible_count"] == 1
        before = _files(tmp_path)
        _error(client.post("/datasets/import", files={"file": ("too-many.log", content + b"ignored notice\n")}), 413, "row_limit")
        assert _files(tmp_path) == before and _sqlite_counts(client)["datasets"] == 1


@pytest.mark.parametrize("path,declared,status,code", [
    ("/analyze", str(256 * 1024 + 1), 413, "size_limit"),
    ("/datasets/import", str(1024 + 1024 * 1024 + 1), 413, "size_limit"),
    ("/analyze", "-1", 413, "size_limit"),
    ("/datasets/import", "invalid", 400, "invalid_length"),
])
def test_declared_request_body_is_bounded_before_parsing(app_factory, tmp_path, path, declared, status, code):
    with TestClient(app_factory(max_upload_bytes=1024)) as client:
        _error(client.post(path, content=b"{}", headers={"Content-Type": "application/json", "Content-Length": declared}), status, code)
        assert _files(tmp_path) == [] and not any(_sqlite_counts(client).values())


@pytest.mark.parametrize("multipart", [False, True])
@pytest.mark.parametrize("cooperative", [False, True], ids=["buffered", "backpressure"])
def test_chunked_asgi_body_is_bounded_without_content_length(app_factory, tmp_path, monkeypatch, multipart, cooperative):
    application = app_factory(max_upload_bytes=1024)
    yielded = []
    issued = []
    original_limit = main.BodyLimitMiddleware.__call__

    async def observe_limit(self, scope, receive, send):
        async def observe_send(message):
            if message["type"] == "http.response.start":
                issued.append((message["status"], len(yielded)))
            await send(message)
        await original_limit(self, scope, receive, observe_send)

    monkeypatch.setattr(main.BodyLimitMiddleware, "__call__", observe_limit)

    async def request():
        async def chunks():
            if multipart:
                yield (b'--boundary\r\nContent-Disposition: form-data; name="file"; filename="flows.csv"\r\n'
                       b'Content-Type: text/csv\r\n\r\n')
            for index in range(40):
                if cooperative:
                    await asyncio.sleep(0)
                yielded.append(index)
                yield b" " * (64 * 1024)
            yield b"\r\n--boundary--\r\n" if multipart else b"{}"

        # ASGITransport preserves separate receive chunks; TestClient owns lifespan.
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=application), base_url="http://testserver") as stream_client:
            return await stream_client.post(
                "/datasets/import" if multipart else "/analyze", content=chunks(),
                headers={"Content-Type": "multipart/form-data; boundary=boundary" if multipart else "application/json"},
            )

    with TestClient(application) as client:
        response = asyncio.run(request())
        assert "content-length" not in response.request.headers
        assert response.request.headers["transfer-encoding"] == "chunked"
        detail = _error(response, 413, "size_limit")
        assert "Request stream exceeds" in detail["message"]
        assert issued == [(413, 17 if multipart else 5)]
        assert len(yielded) < 40, {"response_issued_at": issued, "chunks_consumed": len(yielded)}
        assert _files(tmp_path) == [] and not any(_sqlite_counts(client).values())


def test_chunked_multipart_also_enforces_the_measured_file_byte_limit(app_factory, tmp_path):
    content = _csv()
    application = app_factory(max_upload_bytes=len(content) - 1)
    body = (b'--boundary\r\nContent-Disposition: form-data; name="file"; filename="flows.csv"\r\n'
            b'Content-Type: text/csv\r\n\r\n' + content + b'\r\n--boundary--\r\n')

    async def request():
        async def chunks():
            for offset in range(0, len(body), 32):
                yield body[offset:offset + 32]
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=application), base_url="http://testserver") as stream_client:
            return await stream_client.post("/datasets/import", content=chunks(),
                                            headers={"Content-Type": "multipart/form-data; boundary=boundary"})

    with TestClient(application) as client:
        response = asyncio.run(request())
        assert "content-length" not in response.request.headers
        detail = _error(response, 413, "size_limit")
        assert "Uploaded file exceeds" in detail["message"]
        assert _files(tmp_path) == [] and not any(_sqlite_counts(client).values())


@pytest.mark.parametrize("origin", ["http://attacker.invalid", "http://testserver.attacker.invalid", "null",
                                      "file://testserver", "https://testserver"])
def test_hostile_or_different_origin_mutations_are_blocked(client, tmp_path, origin):
    _error(client.post("/datasets/import", files={"file": ("flows.csv", _csv())}, headers={"Origin": origin}), 403, "cross_origin")
    assert _files(tmp_path) == [] and not any(_sqlite_counts(client).values())


@pytest.mark.parametrize("method,path,payload", [
    ("POST", "/datasets/preset", {"preset_id": "openssh"}),
    ("POST", "/analyze", {"dataset_id": UNKNOWN_ID}),
    ("PATCH", f"/alerts/{UNKNOWN_ID}", {"status": "resolved"}),
    ("POST", "/incidents", {"run_id": UNKNOWN_ID, "title": "Blocked", "alert_ids": [UNKNOWN_ID]}),
    ("PATCH", f"/incidents/{UNKNOWN_ID}", {"status": "closed"}),
    ("POST", "/explain", {"alert_id": UNKNOWN_ID}),
    ("PUT", "/analyze", {}), ("DELETE", f"/incidents/{UNKNOWN_ID}", None),
])
def test_all_mutation_methods_are_guarded_against_cross_origin_requests(client, method, path, payload):
    _error(client.request(method, path, json=payload, headers={"Origin": "http://hostile.invalid"}), 403, "cross_origin")
    assert not any(_sqlite_counts(client).values())


@pytest.mark.parametrize("origin", ["http://testserver", "https://testserver"])
def test_same_origin_import_is_allowed_and_read_responses_have_security_headers(app_factory, origin):
    with TestClient(app_factory(), base_url=origin) as client:
        response = client.post("/datasets/import", files={"file": ("flows.csv", _csv())}, headers={"Origin": origin})
        assert response.status_code == 201, response.text
        health = client.get("/health", headers={"Origin": "http://hostile.invalid"})
        assert health.status_code == 200
        assert health.headers["x-content-type-options"] == "nosniff"
        assert health.headers["referrer-policy"] == "no-referrer"
        assert health.headers["cross-origin-resource-policy"] == "same-origin"
        assert health.headers["cache-control"] == "no-store"
        assert "default-src 'self'" in health.headers["content-security-policy"]
        assert "frame-ancestors 'none'" in health.headers["content-security-policy"]


@pytest.mark.parametrize("path", [
    "/data", "/data/", "/data/tcp_complete.csv", "/data/OpenSSH_2k.log", "/data/imports/",
    "/models", "/models/", "/models/model.pkl", "/models/network_model.pkl",
    "/state/soc.sqlite3", "/backend/main.py", "/static/data/tcp_complete.csv",
])
def test_raw_data_models_and_backend_are_not_static_routes(client, path):
    response = client.get(path)
    assert response.status_code == 404, response.text


def test_generated_import_is_private_and_public_dataset_responses_never_reveal_paths(client, tmp_path):
    dataset = _import(client, _csv(), "analyst.csv")
    source = client.app.state.storage.dataset_sources(dataset["id"])[0]
    path = Path(source["file_path"])
    assert path.is_relative_to(tmp_path / "imports") and path.name != "analyst.csv"
    assert path.read_bytes() == _csv()
    bodies = [dataset, _get(client, "/datasets"), _get(client, f"/datasets/{dataset['id']}")]
    for body in bodies:
        public = json.dumps(body)
        assert "file_path" not in public and path.name not in public
        assert str(tmp_path) not in public and str(main.ROOT) not in public
        assert str(tmp_path).replace("\\", "/") not in public
    assert dataset["name"] == dataset["sources"][0]["name"] == "analyst.csv"
    for url in ("/data/imports/" + path.name, "/imports/" + path.name):
        assert client.get(url).status_code == 404


def test_changed_private_source_fails_atomically_then_reimport_allows_new_snapshot(client, tmp_path, monkeypatch):
    original_content = _csv(rows=_scan_rows())
    dataset = _import(client, original_content, "immutable-upload.csv")
    source = client.app.state.storage.dataset_sources(dataset["id"])[0]
    private_copy = Path(source["file_path"])
    assert private_copy.is_relative_to(tmp_path / "imports")
    changed_content = _csv(rows=[*_scan_rows(), _flow(second=20, port=10020)])
    private_copy.write_bytes(changed_content)
    analyze = Mock(wraps=main.analyze_logs)
    monkeypatch.setattr(main, "analyze_logs", analyze)
    failed_ids = []
    for _ in range(2):
        response = client.post("/analyze", json={"dataset_id": dataset["id"]})
        assert response.status_code == 202 and not response.json()["reused"]
        run = _get(client, f"/runs/{response.json()['run']['id']}")
        assert run["state"] == "failed" and run["error"].startswith("source_changed:")
        assert "no results committed" in run["error"]
        assert run["counts"]["alerts"] == 0 and run["counts"]["eligible"] == 20
        assert _get(client, "/alerts", {"run_id": run["id"]})["total"] == 0
        assert _get(client, "/summary", {"run_id": run["id"]})["alert_count"] == 0
        failed_ids.append(run["id"])
    assert len(set(failed_ids)) == 2
    analyze.assert_not_called()
    assert _sqlite_counts(client)["alerts"] == _sqlite_counts(client)["alert_events"] == 0
    reimported = _import(client, changed_content, "changed-source.csv")
    assert reimported["id"] != dataset["id"] and reimported["fingerprint"] != dataset["fingerprint"]
    successful = _analyze(client, reimported["id"])
    assert successful["counts"]["eligible"] == 21 and successful["counts"]["alerts"] == 1
    assert analyze.call_count == 1
    assert all(_get(client, f"/runs/{identifier}")["state"] == "failed" for identifier in failed_ids)
    assert original_content != private_copy.read_bytes()


@pytest.mark.parametrize("text,available", [
    ("LLM Error: Cannot connect to Ollama", False),
    ("Controlled explanation of the already retained rule evidence.", True),
])
def test_explanation_is_optional_and_only_invoked_by_explicit_post(client, monkeypatch, text, available):
    dataset = _import(client, _auth_burst(), "explain.log")
    run = _analyze(client, dataset["id"])
    alert = _get(client, f"/alerts/{_items(client, '/alerts')[0]['id']}")
    explain = Mock(return_value=text)
    monkeypatch.setattr(main, "explain", explain)
    snapshot = _sqlite_snapshot(client)
    _get(client, f"/runs/{run['id']}")
    _get(client, "/alerts", {"run_id": run["id"]})
    _get(client, "/summary", {"run_id": run["id"]})
    _get(client, f"/alerts/{alert['id']}/events", {"limit": 1})
    assert client.get("/explain").status_code == 405
    assert _analyze(client, dataset["id"], reused=True)["id"] == run["id"]
    explain.assert_not_called()
    response = client.post("/explain", json={"alert_id": alert["id"]})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["available"] is available
    assert body["explanation"] == (text if available else None)
    if available:
        assert "not detection evidence" in body["warning"]
    else:
        assert body["warning"] == text
    assert explain.call_count == 1 and explain.call_args.kwargs == {"timeout": 15}
    context = explain.call_args.args[0]
    assert context["activity_type"] == alert["activity_type"] and context["time_basis"] == "source_relative"
    assert context["evidence"]["rules"] == alert["evidence"]["rules"]
    assert context["evidence"]["raw_examples"] == alert["evidence"]["raw_examples"]
    assert "raw_events" not in context and "file_path" not in json.dumps(context)
    assert _sqlite_snapshot(client) == snapshot


@pytest.mark.parametrize("payload", [{}, {"alert_id": "invalid"}, {"alert_id": 1},
                                        {"alert_id": UNKNOWN_ID, "prompt": "untrusted arbitrary instructions"}])
def test_explanation_only_accepts_a_typed_persisted_alert_identifier(client, payload):
    _error(client.post("/explain", json=payload), 422, "validation_error")
