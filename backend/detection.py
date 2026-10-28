import pickle
import threading
import warnings
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.exceptions import InconsistentVersionWarning

from ingestion import file_hash
from preprocessing import FEATURE_NAMES, FEATURE_VERSION, preprocess

MODEL_PATH = Path(__file__).resolve().parents[1] / "models" / "network_model.pkl"
ARTIFACT_VERSION = 1
_cache = {}
_cache_lock = threading.Lock()


class ModelUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class NetworkModel:
    estimator: IsolationForest
    metadata: dict
    artifact_sha256: str

    @property
    def version(self):
        return self.metadata["model_version"]


def validate_artifact(payload):
    if not isinstance(payload, dict) or payload.get("artifact_version") != ARTIFACT_VERSION:
        raise ModelUnavailable("Incompatible artifact: train the new network model; legacy model.pkl is not supported.")
    model, metadata = payload.get("estimator"), payload.get("metadata")
    if not isinstance(model, IsolationForest) or not isinstance(metadata, dict):
        raise ModelUnavailable("Network model artifact is invalid.")
    if metadata.get("feature_version") != FEATURE_VERSION or metadata.get("feature_names") != list(FEATURE_NAMES):
        raise ModelUnavailable("Network model feature/transform version is incompatible.")
    if metadata.get("sklearn_version") != sklearn.__version__:
        raise ModelUnavailable("Network model scikit-learn version is incompatible; explicitly retrain in this environment.")
    threshold = metadata.get("threshold")
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)) or not np.isfinite(threshold) or not -1 <= threshold <= 0:
        raise ModelUnavailable("Network model has no valid calibrated score threshold.")
    if not isinstance(metadata.get("model_version"), str) or not metadata["model_version"]:
        raise ModelUnavailable("Network model version is missing.")
    if getattr(model, "n_features_in_", None) != len(FEATURE_NAMES) or not hasattr(model, "estimators_"):
        raise ModelUnavailable("Network model is not fitted for the six required features.")
    if list(getattr(model, "feature_names_in_", [])) != list(FEATURE_NAMES):
        raise ModelUnavailable("Network model feature order is incompatible.")
    return model, metadata


def save_model(estimator, metadata, path=MODEL_PATH):
    path = Path(path)
    payload = {"artifact_version": ARTIFACT_VERSION, "estimator": estimator, "metadata": metadata}
    validate_artifact(payload)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".pkl.tmp")
    try:
        with temporary.open("wb") as handle:
            pickle.dump(payload, handle, protocol=pickle.HIGHEST_PROTOCOL)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    return load_model(path)


def load_model(path=MODEL_PATH):
    # Only a trusted code-configured local path can reach pickle loading. No API
    # accepts an artifact upload or a user-selected model path.
    path = Path(path).resolve()
    with _cache_lock:
        try:
            stat = path.stat()
        except OSError as exc:
            raise ModelUnavailable("Network ML is unavailable. Run python backend/train.py explicitly; rules remain operational.") from exc
        identity = (stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size)
        cached = _cache.get(path)
        if cached is not None and cached[0] == identity:
            return cached[1]
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", InconsistentVersionWarning)
                with path.open("rb") as handle:
                    estimator, metadata = validate_artifact(pickle.load(handle))
            artifact = NetworkModel(estimator, metadata, file_hash(path))
        except ModelUnavailable:
            _cache.pop(path, None)
            raise
        except Exception as exc:
            _cache.pop(path, None)
            raise ModelUnavailable("Network model could not be loaded or is incompatible; rules remain operational.") from exc
        _cache[path] = (identity, artifact)
        return artifact


def model_health(path=MODEL_PATH):
    try:
        artifact = load_model(path)
    except ModelUnavailable as exc:
        return {"available": False, "version": None, "message": str(exc)}
    metadata = artifact.metadata
    return {
        "available": True, "version": artifact.version,
        "feature_version": metadata["feature_version"], "threshold": metadata["threshold"],
        "trained_at": metadata.get("trained_at"), "artifact_sha256": artifact.artifact_sha256,
        "validation_false_positive_rate": metadata.get("validation_false_positive_rate"),
        "message": "Positive centered margin indicates anomaly; it is not an attack probability.",
    }


def predict(df, artifact=None, path=MODEL_PATH):
    artifact = artifact or load_model(path)
    scores = artifact.estimator.score_samples(preprocess(df))
    margins = artifact.metadata["threshold"] - scores
    predictions = np.where(margins > 0, -1, 1).astype(np.int8)
    return predictions, margins
