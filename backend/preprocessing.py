"""Deterministic per-flow features; no batch statistics or annotation leakage."""

import numpy as np
import pandas as pd

FEATURE_VERSION = "network-log1p-six-v1"
MAGNITUDES = ("client_bytes", "server_bytes", "client_packets", "server_packets", "duration_ms")
FEATURE_NAMES = tuple(f"log1p_{name}" for name in MAGNITUDES) + ("protocol_code",)
PROTOCOL_MAP = {"TCP": 0, "UDP": 1}


def preprocess(df):
    missing = set(MAGNITUDES + ("protocol",)) - set(df.columns)
    if missing:
        raise ValueError(f"Normalized network features are missing: {', '.join(sorted(missing))}")
    raw = df.loc[:, list(MAGNITUDES)].apply(pd.to_numeric, errors="coerce").to_numpy(dtype=np.float64)
    protocol = df["protocol"].map(PROTOCOL_MAP).to_numpy(dtype=np.float64)
    if not np.isfinite(raw).all() or (raw < 0).any() or not np.isfinite(protocol).all():
        raise ValueError("Network model requires finite, nonnegative magnitudes and validated TCP/UDP transport.")
    transformed = np.column_stack((np.log1p(raw), protocol))
    return pd.DataFrame(transformed, columns=FEATURE_NAMES, index=df.index)
