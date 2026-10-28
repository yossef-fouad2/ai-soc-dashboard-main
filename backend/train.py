"""Explicit normal-only fitting/calibration and one held-out publisher-label experiment."""

import argparse
import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest

from detection import MODEL_PATH, save_model
from evaluation import ATTACK_LABELS, BENIGN_LABELS, LABEL_MAPPING_VERSION, evaluate_network, partition_events
from ingestion import ROOT, load_network
from preprocessing import FEATURE_NAMES, FEATURE_VERSION, preprocess
from rules import DetectionConfig, RULE_VERSION, detect_rules


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--false-alert-budget", type=float, default=0.01)
    parser.add_argument("--model-output", type=Path, default=MODEL_PATH)
    parser.add_argument("--evaluation-dir", type=Path, default=ROOT / "evaluation")
    args = parser.parse_args()
    if not 0 < args.false_alert_budget < 0.1:
        parser.error("False-alert budget must be greater than zero and less than 0.1.")
    if args.model_output.resolve() == (ROOT / "models" / "model.pkl").resolve():
        parser.error("The legacy model.pkl must remain untouched.")
    timings = {}
    started = time.perf_counter()
    dataset = load_network()
    timings["ingestion_seconds"] = time.perf_counter() - started
    print(f"Profiled {dataset.profile['raw_count']} raw records; {len(dataset.events)} eligible unique observations.", flush=True)
    started = time.perf_counter()
    parts, targets, partition_report = partition_events(dataset.events)
    timings["partition_checks_seconds"] = time.perf_counter() - started
    training = dataset.events.loc[(parts == "train") & (targets == 0)]
    validation = dataset.events.loc[(parts == "validation") & (targets == 0)]
    test = dataset.events.loc[parts == "test"].reset_index(drop=True)
    if training.empty or validation.empty or test.empty:
        raise RuntimeError("Required normal training, normal validation, or mixed held-out test period has no eligible records. Inspect coverage; no date-only fallback is permitted.")
    print(f"Normal training: {len(training)}; normal validation: {len(validation)}; held-out mixed test: {len(test)}.", flush=True)
    parameters = {
        "n_estimators": 300, "max_samples": min(2048, len(training)),
        "contamination": "auto", "max_features": 1.0, "random_state": args.seed,
        "n_jobs": 1, "bootstrap": False,
    }
    estimator = IsolationForest(**parameters)
    started = time.perf_counter()
    estimator.fit(preprocess(training))
    timings["fit_seconds"] = time.perf_counter() - started
    started = time.perf_counter()
    validation_scores = estimator.score_samples(preprocess(validation))
    # Strict '< threshold' with a lower empirical quantile does not exceed the
    # specified validation budget when score ties are present.
    threshold = float(np.quantile(validation_scores, args.false_alert_budget, method="lower"))
    validation_fpr = float((validation_scores < threshold).mean())
    timings["validation_scoring_seconds"] = time.perf_counter() - started
    metadata = {
        "feature_version": FEATURE_VERSION, "feature_names": list(FEATURE_NAMES),
        "transform": "log1p of five nonnegative magnitudes; validated TCP=0, UDP=1; duration in milliseconds",
        "threshold": threshold, "threshold_policy": "lower normal-validation quantile; positive threshold-score_samples margin is anomalous",
        "target_validation_false_alert_budget": args.false_alert_budget,
        "validation_false_positive_rate": validation_fpr,
        "normal_training_count": len(training), "normal_validation_count": len(validation),
        "model_parameters": parameters, "seed": args.seed, "sklearn_version": sklearn.__version__,
        "source_hashes": {source["name"]: source["sha256"] for source in dataset.profile["sources"]},
        "dataset_fingerprint": dataset.fingerprint, "ingestion_version": dataset.profile["ingestion_version"],
        "partitions": partition_report, "label_mapping_version": LABEL_MAPPING_VERSION,
        "publisher_benign_labels": sorted(BENIGN_LABELS), "publisher_attack_related_labels": sorted(ATTACK_LABELS),
    }
    version_hash = hashlib.sha256(json.dumps(metadata, sort_keys=True, allow_nan=False).encode("utf-8")).hexdigest()
    metadata["model_version"] = f"network-iforest-{version_hash[:16]}"
    metadata["trained_at"] = datetime.now(timezone.utc).isoformat()
    artifact = save_model(estimator, metadata, args.model_output)
    print(f"Saved {artifact.version}; validation FPR {validation_fpr:.4%}; threshold {threshold:.6f}.", flush=True)
    started = time.perf_counter()
    test_scores = estimator.score_samples(preprocess(test))
    margins = threshold - test_scores
    predictions = np.where(margins > 0, -1, 1)
    timings["test_scoring_seconds"] = time.perf_counter() - started
    started = time.perf_counter()
    detections = detect_rules(test, DetectionConfig())
    timings["test_rules_seconds"] = time.perf_counter() - started
    started = time.perf_counter()
    report = evaluate_network(test, predictions, margins, detections)
    timings["evaluation_seconds"] = time.perf_counter() - started
    report.update({
        "model_version": artifact.version, "artifact_sha256": artifact.artifact_sha256,
        "metadata": metadata, "partition_report": partition_report, "processing_time": timings,
        "rule_version": RULE_VERSION, "rule_config": DetectionConfig().model_dump(),
        "test_used_for_calibration_or_feature_selection": False,
    })
    args.evaluation_dir.mkdir(parents=True, exist_ok=True)
    for name, content in (
        ("network_evaluation.json", report), ("model_metadata.json", metadata),
        ("data_profile.json", {"network": dataset.profile, "network_warnings": dataset.warnings}),
    ):
        (args.evaluation_dir / name).write_text(json.dumps(content, indent=2, allow_nan=False), encoding="utf-8")
    print(json.dumps({
        "held_out_per_flow_ml": report["per_flow_ml"],
        "fixed_unit_comparison": report["fixed_unit_comparison"],
        "complementary_behavior_demonstrated": report["complementary_behavior_demonstrated"],
        "processing_time": timings, "evaluation_report": str(args.evaluation_dir / "network_evaluation.json"),
    }, indent=2, allow_nan=False), flush=True)
    if not report["complementary_behavior_demonstrated"]:
        print("LIMITATION: no evidence-backed ML-only attack-related group demonstrated. Do not declare complementary detection complete or tune on this held-out test set.", flush=True)


if __name__ == "__main__":
    main()
