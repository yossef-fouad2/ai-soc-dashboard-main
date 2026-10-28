"""Offline supervised TCP experiment; never replaces the dashboard's Isolation Forest."""

import argparse
import hashlib
import json
import pickle
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier

from detection import MODEL_PATH, load_model, predict
from evaluation import LABEL_MAPPING_VERSION, binary_metrics, publisher_targets
from ingestion import ROOT, file_hash, load_network
from preprocessing import FEATURE_NAMES as BASE_FEATURE_NAMES, preprocess


FEATURE_VERSION = "supervised-completed-flow-context-v1"
PROTOCOL_SCOPE = "TCP"
WINDOW_SECONDS = 60.0
TCP_COUNTERS = (
    "client_syn", "server_syn", "client_fin", "server_fin", "client_reset", "server_reset",
)
FEATURE_NAMES = BASE_FEATURE_NAMES + (
    "log1p_client_bytes_per_packet", "log1p_server_bytes_per_packet",
    "log1p_client_bytes_per_second", "log1p_server_bytes_per_second",
    "log_byte_direction_ratio", "log_packet_direction_ratio", "tcp_incomplete",
) + tuple("log1p_" + name for name in TCP_COUNTERS) + (
    "log1p_prior_source_flows_60s", "log1p_prior_service_flows_60s",
    "prior_service_mean_log_bytes_60s", "prior_service_no_response_fraction_60s",
)
SCORE_NOTE = "Uncalibrated classifier score, not a verified real-world attack probability."
MODEL_PARAMETERS = {
    "n_estimators": 160, "max_depth": 18, "min_samples_leaf": 3,
    "max_features": "sqrt", "class_weight": "balanced", "n_jobs": 2,
}


def features(events):
    """Finalized-flow evidence plus history in [end_time - 60, end_time).

    End time is an availability proxy, not an exporter-arrival timestamp. Equal-end
    neighbors are excluded so arbitrary row order never supplies future evidence.
    Supply complete capture history, including unknown labels, before label filtering.
    """
    required = {
        "dataset_id", "clock_id", "source_ip", "destination_ip", "destination_port",
        "event_time", "end_time", "connection_state",
    }
    missing = required - set(events.columns)
    if missing:
        raise ValueError(f"Supervised context fields missing: {', '.join(sorted(missing))}")
    if not events.index.is_unique:
        raise ValueError("Supervised features require a unique event index.")
    result = preprocess(events).copy()
    if events.empty:
        return pd.DataFrame(index=events.index, columns=FEATURE_NAMES, dtype=float)
    times = events[["event_time", "end_time", "destination_port"]].apply(pd.to_numeric, errors="coerce")
    if (not np.isfinite(times.to_numpy()).all() or (times < 0).any().any()
            or (times["end_time"] < times["event_time"]).any()
            or (times["destination_port"] > 65535).any()
            or (times["destination_port"] % 1 != 0).any()):
        raise ValueError("Supervised context requires valid intervals and destination ports.")
    identity = events[["dataset_id", "clock_id", "source_ip", "destination_ip"]]
    if identity.isna().any().any() or identity.eq("").any().any():
        raise ValueError("Supervised history requires explicit capture/clock/endpoint identities.")
    tcp = events["protocol"].eq("TCP").to_numpy()
    state = events["connection_state"]
    if not (state.isin(["complete", "incomplete"]) & tcp | state.eq("datagram") & ~tcp).all():
        raise ValueError("Connection state does not match the validated transport.")
    raw = events[["client_bytes", "server_bytes", "client_packets", "server_packets", "duration_ms"]].to_numpy(dtype=float)
    cb, sb, cp, sp, duration = raw.T
    result["log1p_client_bytes_per_packet"] = np.log1p(cb / np.maximum(cp, 1))
    result["log1p_server_bytes_per_packet"] = np.log1p(sb / np.maximum(sp, 1))
    seconds = np.maximum(duration / 1000.0, 0.001)
    result["log1p_client_bytes_per_second"] = np.log1p(cb / seconds)
    result["log1p_server_bytes_per_second"] = np.log1p(sb / seconds)
    result["log_byte_direction_ratio"] = np.log1p(sb) - np.log1p(cb)
    result["log_packet_direction_ratio"] = np.log1p(sp) - np.log1p(cp)
    result["tcp_incomplete"] = state.eq("incomplete").astype(float)
    counters = events.reindex(columns=TCP_COUNTERS).apply(pd.to_numeric, errors="coerce").to_numpy(dtype=float)
    if not np.isfinite(counters[tcp]).all() or (counters[tcp] < 0).any():
        raise ValueError("TCP rows require finite, nonnegative TCP counters.")
    counters[~tcp] = 0.0
    for position, name in enumerate(TCP_COUNTERS):
        result["log1p_" + name] = np.log1p(counters[:, position])

    context = events.reset_index(drop=True)
    end_times = times["end_time"].to_numpy(dtype=float)
    byte_logs = np.log1p(cb + sb)
    no_response = (sp == 0).astype(float)
    source_keys = ["dataset_id", "clock_id", "source_ip", "protocol"]
    for scope, keys in (
        ("source", source_keys),
        ("service", source_keys + ["destination_ip", "destination_port"]),
    ):
        counts, mean_bytes, empty_responses = np.zeros((3, len(events)), dtype=float)
        for positions in context.groupby(keys, sort=False, dropna=False).indices.values():
            order = positions[np.argsort(end_times[positions], kind="stable")]
            timestamps = end_times[order]
            left = np.searchsorted(timestamps, timestamps - WINDOW_SECONDS, side="left")
            right = np.searchsorted(timestamps, timestamps, side="left")
            count = right - left
            counts[order] = count
            if scope == "service":
                for values, destination in ((byte_logs, mean_bytes), (no_response, empty_responses)):
                    prefix = np.concatenate(([0.0], np.cumsum(values[order])))
                    destination[order] = (prefix[right] - prefix[left]) / np.maximum(count, 1)
        result[f"log1p_prior_{scope}_flows_60s"] = np.log1p(counts)
        if scope == "service":
            result["prior_service_mean_log_bytes_60s"] = mean_bytes
            result["prior_service_no_response_fraction_60s"] = empty_responses
    result = result.loc[:, list(FEATURE_NAMES)]
    if not np.isfinite(result.to_numpy()).all():
        raise ValueError("Supervised features must be finite.")
    return result


def metrics(targets, flagged):
    targets, flagged = np.asarray(targets), np.asarray(flagged, dtype=bool)
    if targets.ndim != 1 or flagged.shape != targets.shape:
        raise ValueError("Targets and predictions must be aligned one-dimensional arrays.")
    if not np.isin(targets, [-1, 0, 1]).all():
        raise ValueError("Targets must be benign (0), attack (1), or unknown (-1).")
    known = targets >= 0
    report = binary_metrics(targets[known] == 1, flagged[known])
    tp, fp, fn, tn = (report[key] for key in ("true_positive", "false_positive", "false_negative", "true_negative"))
    report["unknown_excluded"] = int((~known).sum())
    report["accuracy"] = (tp + tn) / report["units"] if report["units"] else None
    report["balanced_accuracy"] = ((tp / (tp + fn) + tn / (tn + fp)) / 2) if tp + fn and tn + fp else None
    return report


def select_threshold(targets, scores, false_alert_budget=0.01, minimum_precision=0.5):
    """Maximize validation F1 subject to both constraints, without splitting ties."""
    targets, scores = np.asarray(targets), np.asarray(scores, dtype=float)
    if targets.ndim != 1 or scores.shape != targets.shape:
        raise ValueError("Validation targets and scores must be aligned.")
    if not np.isin(targets, [-1, 0, 1]).all():
        raise ValueError("Targets must be benign (0), attack (1), or unknown (-1).")
    if not 0 <= false_alert_budget < 1 or not 0 <= minimum_precision <= 1:
        raise ValueError("Invalid validation precision or false-alert constraint.")
    if not np.isfinite(scores).all() or ((scores < 0) | (scores > 1)).any():
        raise ValueError("Classifier scores must be finite and within [0, 1].")
    known = targets >= 0
    truth, values = targets[known] == 1, scores[known]
    positives, negatives = int(truth.sum()), int((~truth).sum())
    if not positives or not negatives:
        raise ValueError("Threshold selection requires both labeled benign and attack validation examples.")
    order = np.argsort(-values, kind="stable")
    values, truth = values[order], truth[order]
    ends = np.r_[np.flatnonzero(values[:-1] != values[1:]), len(values) - 1]
    tp = np.cumsum(truth)[ends]
    fp = ends + 1 - tp
    precision = tp / (tp + fp)
    f1 = 2 * tp / (positives + tp + fp)
    feasible = np.flatnonzero((tp > 0) & (fp / negatives <= false_alert_budget) & (precision >= minimum_precision))
    threshold = float(np.nextafter(1.0, np.inf))
    if len(feasible):
        best = max(feasible, key=lambda i: (f1[i], precision[i], values[ends[i]]))
        threshold = float(values[ends[best]])
    return {
        "threshold": threshold,
        "status": "selected" if len(feasible) else "no_feasible_threshold",
        "objective": "maximum validation F1; tie-break precision then stricter threshold",
        "comparison": "score >= threshold",
        "false_alert_budget": false_alert_budget, "minimum_precision": minimum_precision,
        "thresholds_considered": len(ends), "feasible_thresholds": len(feasible),
        "validation_metrics": metrics(targets, scores >= threshold),
    }


def assert_disjoint(datasets):
    """Reject reused inputs/observations rather than silently leaking across roles."""
    items = list(datasets.items())
    for position, (name, dataset) in enumerate(items):
        files = {source["sha256"] for source in dataset.profile["sources"]}
        observations = set(dataset.events["observation_hash"])
        for other_name, other in items[:position]:
            if files & {source["sha256"] for source in other.profile["sources"]}:
                raise ValueError(f"Shared source file across {other_name} and {name}; capture split is invalid.")
            if observations.intersection(other.events["observation_hash"]):
                raise ValueError(f"Duplicate exporter observations across {other_name} and {name}; capture split is invalid.")


def population(dataset):
    events = dataset.events
    targets = publisher_targets(events["evaluation_label"])
    return {
        "fingerprint": dataset.fingerprint,
        "raw_count": dataset.profile["raw_count"], "eligible_count": len(events),
        "duplicate_count": dataset.profile["duplicate_count"],
        "rejected_count": dataset.profile["rejected_count"],
        "benign": int((targets == 0).sum()), "attack_related": int((targets == 1).sum()),
        "unknown": int((targets < 0).sum()), "warnings": dataset.warnings,
        "sources": [{key: source[key] for key in ("name", "sha256", "bytes", "schema")} for source in dataset.profile["sources"]],
        "counts_by_label": {str(label): int(count) for label, count in events["evaluation_label"].value_counts().items()},
        "counts_by_date": {str(date): int(count) for date, count in events["event_time_display"].str[:10].value_counts().sort_index().items()},
    }


def compare(events, scores, threshold, baseline):
    targets = publisher_targets(events["evaluation_label"])
    candidate, original = scores >= threshold, predict(events, artifact=baseline)[0] == -1
    result = {"supervised": metrics(targets, candidate), "isolation_forest": metrics(targets, original)}
    for column, key in (("protocol", "by_protocol"), ("connection_state", "by_schema_state"), ("evaluation_label", "by_label")):
        result[key] = {}
        for value, positions in events.reset_index(drop=True).groupby(column, sort=True).indices.items():
            result[key][str(value)] = {
                "flows": len(positions),
                "supervised_flagged": int(candidate[positions].sum()),
                "baseline_flagged": int(original[positions].sum()),
                "supervised": metrics(targets[positions], candidate[positions]),
                "isolation_forest": metrics(targets[positions], original[positions]),
            }
    tcp = events["protocol"].eq("TCP").to_numpy()
    result["tcp_only_sensitivity"] = {
        "note": "Excludes UDP, including the publisher's residual exfiltration assignment.",
        "supervised": metrics(targets[tcp], candidate[tcp]),
        "isolation_forest": metrics(targets[tcp], original[tcp]),
    }
    result["examples"] = {}
    for name, mask in (
        ("true_positive", (targets == 1) & candidate), ("false_positive", (targets == 0) & candidate),
        ("false_negative", (targets == 1) & ~candidate), ("true_negative", (targets == 0) & ~candidate),
    ):
        indices = np.flatnonzero(mask)[:5]
        result["examples"][name] = [
            {"source": str(events.iloc[i]["source_name"]), "line": int(events.iloc[i]["source_line"]),
             "publisher_label": str(events.iloc[i]["evaluation_label"]), "score": float(scores[i])}
            for i in indices
        ]
    return result


def candidate_scores(events, payload):
    """Score a full capture using a trusted, separately stored experiment artifact."""
    if not isinstance(payload, dict) or payload.get("artifact_type") != "supervised-experiment-v1":
        raise ValueError("Not a supervised experiment artifact.")
    model, metadata = payload.get("estimator"), payload.get("metadata", {})
    if (not isinstance(model, RandomForestClassifier)
            or not isinstance(metadata, dict)
            or metadata.get("feature_version") != FEATURE_VERSION
            or metadata.get("feature_names") != list(FEATURE_NAMES)
            or metadata.get("sklearn_version") != sklearn.__version__
            or metadata.get("protocol_scope") != PROTOCOL_SCOPE
            or not isinstance(metadata.get("selection"), dict)
            or not isinstance(metadata.get("model_version"), str)
            or list(getattr(model, "feature_names_in_", [])) != list(FEATURE_NAMES)
            or list(getattr(model, "classes_", [])) != [0, 1]):
        raise ValueError("Supervised model, classes, feature order or library version is incompatible.")
    if not events["protocol"].eq(PROTOCOL_SCOPE).all():
        raise ValueError("This candidate supports TCP only; do not fabricate UDP predictions.")
    threshold = metadata.get("selection", {}).get("threshold")
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)) or not 0 <= threshold <= np.nextafter(1.0, np.inf):
        raise ValueError("Supervised artifact has no valid validation-selected threshold.")
    return model.predict_proba(features(events))[:, 1]


def write_json(path, value):
    with Path(path).open("x", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, allow_nan=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--validation", nargs="+", type=Path, help="Fit on Russellmitchell and select threshold on this separate development capture.")
    mode.add_argument("--score-only", nargs="+", type=Path, help="Score a complete recorded capture using the saved candidate, without fitting or selecting thresholds.")
    parser.add_argument("--candidate", type=Path, default=ROOT / "evaluation" / "supervised_v1" / "candidate.pkl", help="Trusted local candidate artifact, for score-only mode. Never use an untrusted pickle.")
    parser.add_argument("--output-dir", type=Path, help="Must not already exist; defaults to evaluation/supervised_v1 or evaluation/supervised_scores.")
    parser.add_argument("--test-santos", action="store_true", help="After freezing the candidate, fetch and evaluate the pinned, preselected Santos capture (26 MB archive).")
    parser.add_argument("--false-alert-budget", type=float, default=0.01)
    parser.add_argument("--minimum-precision", type=float, default=0.5)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)
    if args.score_only and (args.test_santos or args.false_alert_budget != 0.01 or args.minimum_precision != 0.5 or args.seed != 42):
        parser.error("Score-only mode uses the saved model/threshold; training options cannot be changed.")
    args.output_dir = args.output_dir or ROOT / "evaluation" / ("supervised_scores" if args.score_only else "supervised_v1")
    if not 0 <= args.false_alert_budget < 0.1 or not 0 <= args.minimum_precision <= 1:
        parser.error("Require 0 <= false-alert-budget < 0.1 and 0 <= minimum-precision <= 1.")
    if args.output_dir.exists():
        parser.error("Output directory already exists; previous experiments will not be overwritten.")
    baseline = load_model()
    baseline_hash = baseline.artifact_sha256
    args.output_dir.mkdir(parents=True, exist_ok=False)
    if args.score_only:
        artifact_hash = file_hash(args.candidate)
        # Explicit local CLI only; this is not an artifact-upload API.
        with args.candidate.open("rb") as handle:
            payload = pickle.load(handle)
        dataset = load_network(args.score_only)
        events = dataset.events.loc[dataset.events["protocol"] == PROTOCOL_SCOPE].reset_index(drop=True)
        if events.empty:
            raise ValueError("No eligible TCP flows; this candidate does not score UDP or authentication logs.")
        scores = candidate_scores(events, payload)
        threshold = payload["metadata"]["selection"]["threshold"]
        report = {
            "model_version": payload["metadata"]["model_version"], "artifact_sha256": artifact_hash,
            "role": "Scoring supplied records, not automatically an independent test. No fitting or threshold selection occurred.",
            "protocol_scope": PROTOCOL_SCOPE, "score_meaning": SCORE_NOTE,
            "threshold": threshold, "population": population(dataset),
            "unsupported_non_tcp_count": int((dataset.events["protocol"] != PROTOCOL_SCOPE).sum()),
            "comparison": compare(events, scores, threshold, baseline),
            "baseline_preserved": file_hash(MODEL_PATH) == baseline_hash,
            "candidate_preserved": file_hash(args.candidate) == artifact_hash,
            "dashboard_model_changed": False,
        }
        if not report["baseline_preserved"] or not report["candidate_preserved"]:
            raise RuntimeError("An artifact changed during scoring; discard this comparison.")
        records = events[["source_id", "source_line", "event_time_display"]].copy()
        records["publisher_target"] = publisher_targets(events["evaluation_label"])
        records["supervised_score"] = scores
        records["supervised_flagged"] = scores >= threshold
        records.to_csv(args.output_dir / "predictions.csv", index=False, mode="x")
        write_json(args.output_dir / "scoring.json", report)
        print(json.dumps({"supervised": report["comparison"]["supervised"], "isolation_forest": report["comparison"]["isolation_forest"], "report": str(args.output_dir / "scoring.json")}, indent=2), flush=True)
        return
    contract = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "train": "TCP from the whole Russellmitchell capture, including the former January 24 IF test period.",
        "protocol_scope": PROTOCOL_SCOPE,
        "validation_files": [str(path.resolve()) for path in args.validation],
        "test": "Santos; selected before fitting and unavailable to feature/threshold selection in this run." if args.test_santos else None,
        "feature_version": FEATURE_VERSION,
        "false_alert_budget": args.false_alert_budget, "minimum_precision": args.minimum_precision,
        "baseline_sha256": baseline_hash,
        "limitations": [
            "Jan24 and Fox previously informed development; their candidate results are NOT a fresh final test.",
            "Candidate has additional attack-labeled training data; this is not an algorithm-only comparison.",
            "Publisher heuristic annotations from simulated testbeds are not independently verified attacks.",
            "A subsequent model change after viewing Santos requires a different untouched final test.",
            "Capture identity and previous human inspection cannot be established by file disjointness alone.",
            "End-time histories approximate completed-record availability, not proven real-time detection.",
            "Candidate scope is TCP only; UDP remains outside this experiment and on the existing detector.",
        ],
    }
    write_json(args.output_dir / "experiment_plan.json", contract)
    started = time.perf_counter()
    print("Loading Russellmitchell training and separate validation capture...", flush=True)
    training, validation = load_network(), load_network(args.validation)
    assert_disjoint({"training": training, "validation": validation})
    training_events = training.events.loc[training.events["protocol"] == PROTOCOL_SCOPE].reset_index(drop=True)
    validation_events = validation.events.loc[validation.events["protocol"] == PROTOCOL_SCOPE].reset_index(drop=True)
    targets = publisher_targets(training_events["evaluation_label"])
    validation_targets = publisher_targets(validation_events["evaluation_label"])
    if set(targets[targets >= 0]) != {0, 1} or set(validation_targets[validation_targets >= 0]) != {0, 1}:
        raise ValueError("Training and validation captures must each contain known benign and attack examples.")
    populations = {"training": population(training), "validation": population(validation)}
    write_json(args.output_dir / "development_populations.json", populations)
    print(f"Training on {int((targets >= 0).sum())} labeled TCP flows; validation has {len(validation_events)} TCP flows.", flush=True)
    parameters = {**MODEL_PARAMETERS, "random_state": args.seed}
    model = RandomForestClassifier(**parameters)
    training_features = features(training_events)
    model.fit(training_features.loc[targets >= 0], targets[targets >= 0])
    del training_features
    validation_scores = model.predict_proba(features(validation_events))[:, 1]
    selection = select_threshold(validation_targets, validation_scores, args.false_alert_budget, args.minimum_precision)
    metadata = {
        "feature_version": FEATURE_VERSION, "feature_names": list(FEATURE_NAMES),
        "sklearn_version": sklearn.__version__, "model_parameters": parameters,
        "protocol_scope": PROTOCOL_SCOPE,
        "training_labeled_tcp_count": int((targets >= 0).sum()),
        "validation_labeled_tcp_count": int((validation_targets >= 0).sum()),
        "selection": selection, "label_mapping_version": LABEL_MAPPING_VERSION,
        "training": populations["training"], "validation": populations["validation"],
        "history": "Same capture/clock; strict prior completed flows in [end-60, end), built before label filtering.",
        "score_meaning": SCORE_NOTE, "baseline_sha256": baseline_hash,
    }
    identity = hashlib.sha256(json.dumps(metadata, sort_keys=True, allow_nan=False).encode("utf-8")).hexdigest()
    metadata["model_version"] = "network-supervised-" + identity[:16]
    metadata["frozen_at"] = datetime.now(timezone.utc).isoformat()
    payload = {"artifact_type": "supervised-experiment-v1", "estimator": model, "metadata": metadata}
    model_path = args.output_dir / "candidate.pkl"
    with model_path.open("xb") as handle:
        pickle.dump(payload, handle, protocol=pickle.HIGHEST_PROTOCOL)
    write_json(args.output_dir / "model_metadata.json", metadata)
    artifact_hash = file_hash(model_path)
    report = {
        "model_version": metadata["model_version"], "artifact_sha256": artifact_hash,
        "plan": contract, "selection": selection, "populations": populations,
        "validation": compare(validation_events, validation_scores, selection["threshold"], baseline),
        "test": None, "dashboard_model_changed": False,
    }
    write_json(args.output_dir / "validation_comparison.json", report["validation"])
    print(json.dumps({"selection": selection, "validation_baseline": report["validation"]["isolation_forest"]}, indent=2), flush=True)
    candidate_metrics, baseline_metrics = report["validation"]["supervised"], report["validation"]["isolation_forest"]
    report["validation_goal_met"] = (
        selection["status"] == "selected"
        and (candidate_metrics["precision"] or 0) > (baseline_metrics["precision"] or 0)
        and (candidate_metrics["f1"] or 0) > (baseline_metrics["f1"] or 0)
    )
    if args.test_santos and report["validation_goal_met"]:
        from sources import ensure_santos

        print("Candidate and threshold frozen. Loading preselected Santos test capture...", flush=True)
        test = load_network(ensure_santos())
        assert_disjoint({"training": training, "validation": validation, "test": test})
        report["populations"]["test"] = population(test)
        test_events = test.events.loc[test.events["protocol"] == PROTOCOL_SCOPE].reset_index(drop=True)
        report["test"] = compare(test_events, candidate_scores(test_events, payload), selection["threshold"], baseline)
        report["test"]["role"] = "Capture held out of fitting and threshold selection; not a tuning target."
        print(json.dumps({"test_candidate": report["test"]["supervised"], "test_baseline": report["test"]["isolation_forest"]}, indent=2), flush=True)
    elif args.test_santos:
        report["test_skip_reason"] = "Validation did not improve both precision and F1 under the constraints; final test remains unused."
        print(report["test_skip_reason"], flush=True)
    report["processing_seconds"] = time.perf_counter() - started
    report["baseline_preserved"] = file_hash(MODEL_PATH) == baseline_hash
    report["candidate_preserved_after_test"] = file_hash(model_path) == artifact_hash
    if not report["baseline_preserved"] or not report["candidate_preserved_after_test"]:
        raise RuntimeError("A model artifact changed during evaluation; results are not a frozen comparison.")
    write_json(args.output_dir / "comparison.json", report)
    print(f"Saved {args.output_dir / 'comparison.json'}. Existing dashboard model remains unchanged.", flush=True)


if __name__ == "__main__":
    main()
