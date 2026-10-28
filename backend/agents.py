"""Independent detectors composed into evidence-backed suspected-activity alerts."""

import hashlib
import json
import time
from collections import namedtuple

import numpy as np

from detection import MODEL_PATH, load_model, predict
from ingestion import compact_references
from preprocessing import FEATURE_VERSION, MAGNITUDES
from rules import DetectionConfig, detect_rules
from severity import compute_severity

_AUTO_MODEL = object()
TITLES = {
    "brute_force": "Suspected authentication brute-force burst",
    "port_scan": "Suspected destination port scan",
    "suspicious_login": "Accepted login after an observed failure burst",
    "network_anomaly": "Unusual network-flow behavior",
}


def analyze_logs(df, config=None, artifact=_AUTO_MODEL, model_path=MODEL_PATH):
    config = config or DetectionConfig()
    events = df.sort_values(["clock_id", "event_time", "source_id", "source_line"], kind="stable").reset_index(drop=True)
    started = time.perf_counter()
    detections = detect_rules(events, config)
    rule_seconds = time.perf_counter() - started
    groups, event_to_rule, rule_supported = [], {}, set()
    for detection in detections:
        group_index = len(groups)
        groups.append({"activity": detection.activity_type, "indices": set(detection.indices), "rules": [detection], "anomalies": set()})
        rule_supported.update(detection.indices)
        for index in detection.indices:
            if events.at[index, "kind"] == "network":
                event_to_rule[index] = group_index

    warnings, margin_by_index = [], {}
    network = events.loc[events["kind"] == "network"]
    ml_evaluated, anomaly_indices = 0, set()
    ml_seconds, ml_available = 0.0, False
    if not network.empty:
        started = time.perf_counter()
        try:
            if artifact is _AUTO_MODEL:
                artifact = load_model(model_path)
            if artifact is None:
                raise RuntimeError("Network ML unavailable for this snapshot; rule detection remains operational.")
            predictions, margins = predict(network, artifact=artifact)
            ml_evaluated, ml_available = len(network), True
            anomaly_indices = set(int(index) for index in network.index[predictions == -1])
            margin_by_index = {int(index): float(margin) for index, margin in zip(network.index, margins) if int(index) in anomaly_indices}
        except Exception as exc:
            artifact = None
            warnings.append(f"ML-unavailable: {str(exc)[:1000]} No normal predictions have been fabricated; rules ran independently.")
        ml_seconds = time.perf_counter() - started

    if anomaly_indices:
        anomalous = events.loc[sorted(anomaly_indices), ["dataset_id", "source_ip", "destination_ip", "protocol", "event_time"]].copy()
        anomalous["bucket"] = np.floor(anomalous["event_time"] / config.ml_bucket_seconds).astype(np.int64)
        for _, flows in anomalous.groupby(["dataset_id", "source_ip", "destination_ip", "protocol", "bucket"], sort=False):
            uncovered = set()
            for index in flows.index:
                index = int(index)
                if index in event_to_rule:
                    group = groups[event_to_rule[index]]
                    group["anomalies"].add(index)
                else:
                    uncovered.add(index)
            if uncovered:
                groups.append({"activity": "network_anomaly", "indices": uncovered, "rules": [], "anomalies": uncovered})

    started = time.perf_counter()
    supported = sorted(set().union(*(group["indices"] for group in groups))) if groups else []
    common_fields = (
        "source_id", "source_name", "source_line", "source_end_line", "event_time", "event_time_display",
        "recorded_time", "source_ip", "source_port", "destination_ip", "destination_port", "protocol",
        "connection_state", "time_basis", "hostname", "account", "outcome",
    )
    raw_fields = list(common_fields) + [field for field in (*MAGNITUDES, "raw_message", "authentication_method") if field in events]
    raw_lookup = {}
    for values in events.loc[supported, raw_fields].itertuples(index=True, name=None):
        raw = dict(zip(raw_fields, values[1:]))
        raw_lookup[int(values[0])] = {key: (None if isinstance(value, float) and not np.isfinite(value) else value) for key, value in raw.items()}
    Reference = namedtuple("Reference", "source_id source_line source_end_line source_name duplicate_refs")
    reference_lookup = {
        int(row.Index): Reference(row.source_id, row.source_line, row.source_end_line, row.source_name, row.duplicate_refs)
        for row in events.loc[supported, ["source_id", "source_line", "source_end_line", "source_name", "duplicate_refs"]].itertuples()
    }
    alerts = []
    for group in groups:
        indices = sorted(group["indices"])
        first, last = raw_lookup[indices[0]], raw_lookup[indices[-1]]
        methods = (["rule"] if group["rules"] else []) + (["ml"] if group["anomalies"] else [])
        severity, severity_info = compute_severity(group["activity"], methods)
        raw_events = [raw_lookup[index] for index in indices]
        sample_indices = [indices[0], indices[-1]]
        if group["anomalies"]:
            sample_indices.extend((max(group["anomalies"], key=margin_by_index.get), min(group["anomalies"], key=margin_by_index.get)))
        evidence = {
            "rules": [], "ml": None, "raw_event_count": len(raw_events),
            "raw_examples": [raw_lookup[index] for index in dict.fromkeys(sample_indices)],
            "source_references": compact_references(reference_lookup[index] for index in indices),
            "investigation_note": "Suspected activity for analyst review, not confirmed compromise. Severity is priority; optional LLM prose is not detection evidence.",
        }
        for rule in group["rules"]:
            rule_indices = sorted(rule.indices)
            evidence["rules"].append({
                "id": rule.rule_id, "thresholds": rule.thresholds,
                "occurrence_count": len(rule.indices), "peak_window_count": rule.peak_window_count,
                "unique_ports": sorted(rule.unique_ports),
                "first_event_time": raw_lookup[rule_indices[0]]["event_time"],
                "last_event_time": raw_lookup[rule_indices[-1]]["event_time"],
                "trigger_time": rule.trigger_time, "last_trigger_time": rule.last_trigger_time,
                "failed_authentication_count": sum(raw_lookup[index]["outcome"] == "failed" for index in rule_indices),
                "accepted_authentication_count": sum(raw_lookup[index]["outcome"] == "accepted" for index in rule_indices),
                "source_references": compact_references(reference_lookup[index] for index in rule_indices),
            })
        if group["anomalies"] and artifact is not None:
            margins = [margin_by_index[index] for index in group["anomalies"]]
            evidence["ml"] = {
                "model_version": artifact.version, "feature_version": FEATURE_VERSION,
                "threshold": float(artifact.metadata["threshold"]),
                "anomaly_flow_count": len(group["anomalies"]), "min_margin": min(margins), "max_margin": max(margins),
                "score_meaning": "margin = calibrated threshold - Isolation Forest score_samples; positive means unusual, not an attack probability",
                "aggregation_window_seconds": config.ml_bucket_seconds,
            }
        if first["protocol"] in ("TCP", "UDP"):
            evidence["raw_feature_summary"] = {
                field: {"minimum": min(raw[field] for raw in raw_events), "maximum": max(raw[field] for raw in raw_events)}
                for field in MAGNITUDES
            }
        identity = [group["activity"], first["source_ip"], first["destination_ip"], first["protocol"], first["account"], first["hostname"], first["event_time"], first["source_id"], first["source_line"]]
        alerts.append({
            "dedup_key": hashlib.sha256(json.dumps(identity).encode("utf-8")).hexdigest(),
            "activity_type": group["activity"], "title": TITLES[group["activity"]], "severity": severity,
            "severity_reason": severity_info["reason"],
            **{key: first[key] for key in ("source_ip", "destination_ip", "account", "hostname", "protocol", "time_basis")},
            "first_event_time": first["event_time"], "last_event_time": last["event_time"],
            "first_recorded_time": first["event_time_display"], "last_recorded_time": last["event_time_display"],
            "occurrence_count": len(indices), "methods": methods, "evidence": evidence, "raw_events": raw_events,
        })
    return {
        "alerts": alerts, "warnings": warnings,
        "counts": {
            "eligible": len(events), "network": len(network), "authentication": len(events) - len(network),
            "ml_evaluated": ml_evaluated, "ml_anomalies": len(anomaly_indices),
            "rule_supported_events": len(rule_supported), "alerts": len(alerts),
        },
        "metrics": {
            "ml_available": ml_available, "ml_applicable": not network.empty,
            "ml_inlier_flow_count": ml_evaluated - len(anomaly_indices) if ml_available else None,
            "rule_detection_count": len(detections),
            "processing_seconds": {"rules": rule_seconds, "ml": ml_seconds, "composition": time.perf_counter() - started},
            "unit_note": "Event/prediction counts are per normalized record; alert counts are grouped notifications. This run is not the independent held-out model evaluation.",
        },
    }
