"""Opt-in acceptance on the supplied full CSV preset and retained OpenSSH sample."""

import json
import os
import time

import pytest
from fastapi.testclient import TestClient

import main
from ingestion import NETWORK_FILES, ROOT, file_hash
from sources import OPENSSH_PATH


@pytest.mark.skipif(os.getenv("SOC_REAL_PRESET_TESTS") != "1", reason="Set SOC_REAL_PRESET_TESTS=1 after explicit model training to exercise full immutable sources.")
def test_real_presets_persistence_evidence_and_read_only_refresh(monkeypatch):
    originals = (*NETWORK_FILES, OPENSSH_PATH, ROOT / "data" / "logs.csv", ROOT / "models" / "model.pkl", ROOT / "models" / "network_model.pkl")
    before = {str(path.relative_to(ROOT)): file_hash(path) for path in originals}

    def no_ollama(*args, **kwargs):
        raise AssertionError("Detection and refresh must work without calling Ollama")

    monkeypatch.setattr(main, "explain", no_ollama)
    report, persisted = {"original_source_hashes": before, "datasets": {}, "no_ollama": True}, []
    application = main.create_app()
    with TestClient(application) as client:
        health = client.get("/health").json()
        assert health["model"]["available"], "Run python backend/train.py explicitly first"
        assert client.get("/analyze").status_code == 405
        for preset_id, expected_raw, expected_eligible in (("openssh", 2000, 519), ("ait_network", 377704, 377702)):
            started = time.perf_counter()
            print(f"Importing real preset {preset_id}", flush=True)
            imported = client.post("/datasets/preset", json={"preset_id": preset_id})
            assert imported.status_code in (200, 201), imported.text
            dataset = imported.json()["dataset"]
            assert dataset["raw_count"] == expected_raw and dataset["eligible_count"] == expected_eligible
            assert all("file_path" not in source for source in dataset["sources"])
            print(f"Explicit analysis {preset_id}; source hashes retained", flush=True)
            submitted = client.post("/analyze", json={"dataset_id": dataset["id"]})
            assert submitted.status_code in (200, 202), submitted.text
            run_id = submitted.json()["run"]["id"]
            run = client.get("/runs/" + run_id).json()
            assert run["state"] == "completed", run
            assert run["counts"]["raw"] == expected_raw and run["counts"]["eligible"] == expected_eligible
            assert run["counts"]["alerts"] > 0 and run["counts"]["alerts"] != expected_eligible
            page = client.get("/alerts", params={"run_id": run_id, "limit": 1}).json()
            next_page = client.get("/alerts", params={"run_id": run_id, "limit": 1, "offset": 1}).json()
            assert page["total"] == run["counts"]["alerts"] and len(page["items"]) == 1
            assert page["items"][0]["id"] != next_page["items"][0]["id"]
            summary = client.get("/summary", params={"run_id": run_id}).json()
            assert summary["alert_count"] == page["total"] == sum(summary["severity_counts"].values())
            assert summary["alert_count"] == sum(summary["method_counts"].values())
            assert summary["event_counts"]["eligible"] == expected_eligible
            if preset_id == "openssh":
                assert not run["model_available"] and run["counts"]["ml_evaluated"] == 0
                assert dataset["profile"]["outcome_counts"] == {"failed": 518, "accepted": 1}
                assert summary["activity_counts"].get("suspicious_login", 0) == 0
                assert any("source-relative" in warning for warning in run["warnings"])
                selected_id = page["items"][0]["id"]
            else:
                assert run["model_available"] and run["counts"]["ml_evaluated"] == 377702
                assert run["counts"]["ml_anomalies"] > 0 and dataset["duplicate_count"] == 2
                # The frozen held-out report identifies an actual complementary
                # example. Resolve its retained physical line against persisted
                # normalized evidence, then inspect it through the public API.
                evaluation = json.loads((ROOT / "evaluation" / "network_evaluation.json").read_text(encoding="utf-8"))
                example = evaluation["complementary_ml_examples"][0]["raw_evidence"]
                with application.state.storage.connection() as connection:
                    row = connection.execute(
                        "SELECT a.id FROM alerts a JOIN alert_events e ON e.alert_id=a.id WHERE a.run_id=? AND a.method='ml' AND json_extract(e.event_json,'$.source_id')=? AND json_extract(e.event_json,'$.source_line')=? LIMIT 1",
                        (run_id, example["source_id"], example["source_line"]),
                    ).fetchone()
                assert row is not None, "Complementary held-out evidence must also be reviewable in the real preset run"
                selected_id = row["id"]
                report["complementary_example"] = evaluation["complementary_ml_examples"][0]
                report["held_out_metrics"] = evaluation["per_flow_ml"]
            detail = client.get("/alerts/" + selected_id).json()
            assert detail["evidence"]["source_references"] and detail["evidence"]["raw_examples"]
            raw = client.get(detail["evidence"]["raw_events_url"], params={"limit": 1}).json()
            assert raw["total"] == detail["occurrence_count"] == detail["evidence"]["raw_event_count"]
            assert raw["items"][0]["source_line"] > 1
            if preset_id == "ait_network":
                assert detail["methods"] == ["ml"] and detail["activity_type"] == "network_anomaly"
                assert detail["evidence"]["ml"]["max_margin"] > 0
                assert detail["evidence"]["ml"]["model_version"] == health["model"]["version"]
                assert "client_bytes" in raw["items"][0] and "duration_ms" in raw["items"][0]
            assert client.patch("/alerts/" + selected_id, json={"status": "investigating"}).status_code == 200
            incidents = client.get("/incidents", params={"run_id": run_id}).json()["items"]
            incident = next((item for item in incidents if item["title"] == "Demo: " + preset_id + " evidence review"), None)
            if incident is None:
                response = client.post("/incidents", json={
                    "run_id": run_id, "title": "Demo: " + preset_id + " evidence review",
                    "notes": "Functional demonstration of manual analyst grouping; suspected activity, not confirmed compromise.",
                    "alert_ids": [selected_id],
                })
                assert response.status_code == 201, response.text
                incident = response.json()
            assert client.patch("/incidents/" + incident["id"], json={"status": "investigating"}).status_code == 200
            repeat = client.post("/analyze", json={"dataset_id": dataset["id"]})
            assert repeat.status_code == 200 and repeat.json()["reused"] and repeat.json()["run"]["id"] == run_id
            assert client.get("/alerts/" + selected_id).json()["status"] == "investigating"
            assert client.get("/summary", params={"run_id": run_id}).json()["alert_count"] == page["total"]
            report["datasets"][preset_id] = {"dataset_id": dataset["id"], "run_id": run_id, "counts": run["counts"], "warnings": run["warnings"], "processing_seconds": time.perf_counter() - started}
            persisted.append((run_id, selected_id, incident["id"]))
            print(json.dumps(report["datasets"][preset_id], allow_nan=False), flush=True)
        for route in ("/data/logs.csv", "/data/OpenSSH_2k.log", "/models/model.pkl", "/models/network_model.pkl", "/frontend/app.py"):
            assert client.get(route).status_code == 404

    with TestClient(main.create_app()) as restarted:
        for run_id, alert_id, incident_id in persisted:
            assert restarted.get("/runs/" + run_id).json()["state"] == "completed"
            assert restarted.get("/alerts/" + alert_id).json()["status"] == "investigating"
            assert restarted.get("/incidents/" + incident_id).json()["status"] == "investigating"
            assert alert_id in restarted.get("/incidents/" + incident_id).json()["alert_ids"]
    after = {str(path.relative_to(ROOT)): file_hash(path) for path in originals}
    assert after == before, "Original data, generated logs.csv, legacy model and trusted inference artifact must not be overwritten"
    report.update(restart_persistence=True, read_only_refresh=True, originals_unchanged=True)
    output = ROOT / "evaluation" / "preset_acceptance.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, allow_nan=False), encoding="utf-8")
