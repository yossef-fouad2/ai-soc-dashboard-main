"""Immutable-source ingestion shared by training and explicit analysis runs."""

import argparse
import csv
import hashlib
import ipaddress
import json
import re
import time
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
NETWORK_FILES = tuple(DATA_DIR / name for name in (
    "tcp_complete.csv", "tcp_nocomplete.csv", "udp_complete.csv"
))
INGESTION_VERSION = "security-events-v1"
csv.field_size_limit(1024 * 1024)

TCP_COLUMNS = {
    "source_ip": "#15#c_ip:1", "source_port": "c_port:2",
    "destination_ip": "s_ip:15", "destination_port": "s_port:16",
    "client_bytes": "c_bytes_all:9", "server_bytes": "s_bytes_all:23",
    "client_packets": "c_pkts_all:3", "server_packets": "s_pkts_all:17",
    "start_ms": "first:29", "end_ms": "last:30", "duration_ms": "durat:31",
    "client_syn": "c_syn_cnt:13", "server_syn": "s_syn_cnt:27",
    "client_fin": "c_fin_cnt:14", "server_fin": "s_fin_cnt:28",
    "client_reset": "c_rst_cnt:4", "server_reset": "s_rst_cnt:18",
}
UDP_COLUMNS = {
    "source_ip": "#c_ip:1", "source_port": "c_port:2",
    "destination_ip": "s_ip:10", "destination_port": "s_port:11",
    "client_bytes": "c_bytes_all:5", "server_bytes": "s_bytes_all:14",
    "client_packets": "c_pkts_all:6", "server_packets": "s_pkts_all:15",
    "client_start_ms": "c_first_abs:3", "client_duration_ms": "c_durat:4",
    "server_start_ms": "s_first_abs:12", "server_duration_ms": "s_durat:13",
}
ANNOTATION_COLUMNS = {
    "label", "role_cli", "role_serv", "ipv4_address_cli", "ipv4_address_serv",
    "network_cli", "network_serv", "timestamp", "rounded_timestamp",
}
MONTHS = {name: i for i, name in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
)}
MONTH_LENGTHS = (31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
PREFIX = re.compile(
    r"^(?P<time>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<message>.*)$"
)
ATTEMPT = re.compile(
    r"^(?P<outcome>Failed|Accepted) (?P<method>password|publickey) for "
    r"(?:invalid user )?(?P<account>.+?) from (?P<ip>\S+) port (?P<port>\d+)"
    r"(?:\s|$)"
)


class IngestionError(ValueError):
    def __init__(self, code, message, details=None):
        super().__init__(message)
        self.code = code
        self.details = details or {}


@dataclass
class IngestedDataset:
    events: pd.DataFrame
    profile: dict
    warnings: list[str]

    @property
    def fingerprint(self):
        return self.profile["fingerprint"]


def file_hash(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@lru_cache(maxsize=65536)
def valid_ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def dataset_fingerprint(kind, source_hashes):
    identity = [INGESTION_VERSION, kind, sorted(set(source_hashes))]
    return hashlib.sha256(json.dumps(identity).encode("utf-8")).hexdigest()


def _epoch_times(values, index):
    values = np.asarray(values, dtype=np.float64)
    upper = pd.Timestamp.max.value / 1_000_000
    safe = np.where(np.isfinite(values) & (values >= 0) & (values < upper), values, np.nan)
    return pd.Series(pd.to_datetime(safe, unit="ms", errors="coerce", utc=True), index=index)


def recognize_schema(header):
    if len(header) != len(set(header)):
        raise IngestionError("invalid_schema", "CSV contains duplicate column names.")
    columns = set(header)
    tcp = set(TCP_COLUMNS.values()).issubset(columns)
    udp = set(UDP_COLUMNS.values()).issubset(columns)
    if tcp == udp or "timestamp" not in columns:
        raise IngestionError(
            "unsupported_schema",
            "Expected a supplied AIT TCP or UDP schema, including its # header and timestamp column."
        )
    if udp:
        return "udp_complete", UDP_COLUMNS
    # Transport and observation state come from the exporter schema, never the filename.
    if "c_rtt_avg:45" in columns and "s_rtt_avg:52" in columns:
        return "tcp_complete", TCP_COLUMNS
    if "con_t:42" in columns and "http_t:44" in columns:
        return "tcp_incomplete", TCP_COLUMNS
    raise IngestionError("unsupported_schema", "Unrecognized TCP exporter schema.")


def _network_file(path, max_rows=None, max_bytes=None):
    path = Path(path)
    if not path.is_file():
        raise IngestionError("source_missing", f"Source is missing: {path.name}")
    size = path.stat().st_size
    if max_bytes is not None and size > max_bytes:
        raise IngestionError("size_limit", "Source exceeds the import byte limit.")
    source_id = file_hash(path)
    rows, lines, end_lines, record_hashes, observation_hashes = [], [], [], [], []
    structural_rejections, rejected_examples = 0, []
    raw_count, ignored_count = 0, 0
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.reader(handle, strict=True)
            header = next(reader, None)
            if not header:
                raise IngestionError("empty_input", "CSV is empty or has no header.")
            schema, mapping = recognize_schema(header)
            selected = list(mapping.values()) + [
                col for col in ("timestamp", "label", "role_cli", "role_serv") if col in header
            ]
            indices = [header.index(col) for col in selected]
            observation_indices = [
                header.index(col) for col in sorted(set(header) - ANNOTATION_COLUMNS)
            ]
            previous_line = reader.line_num
            for row in reader:
                start_line, previous_line = previous_line + 1, reader.line_num
                raw_count += 1
                if max_rows is not None and raw_count > max_rows:
                    raise IngestionError("row_limit", "Source exceeds the import row limit.")
                if not row:
                    ignored_count += 1
                    continue
                if len(row) != len(header) or any("\0" in value for value in row):
                    structural_rejections += 1
                    if len(rejected_examples) < 20:
                        rejected_examples.append({"source_line": start_line, "reason": "invalid_column_count_or_nul"})
                    continue
                # Keep only detector/evaluation columns in memory, but hash the complete
                # exporter observation so deduplication does not collapse different flows.
                record_hashes.append(hashlib.sha256("\0".join(row).encode("utf-8")).hexdigest())
                observation_hashes.append(hashlib.sha256(
                    (schema + "\0" + "\0".join(row[i] for i in observation_indices)).encode("utf-8")
                ).hexdigest())
                rows.append([row[i] for i in indices])
                lines.append(start_line)
                end_lines.append(reader.line_num)
    except (UnicodeError, csv.Error) as exc:
        raise IngestionError("invalid_text", f"Cannot parse UTF-8 CSV: {exc}") from exc
    frame = pd.DataFrame(rows, columns=selected).rename(columns={v: k for k, v in mapping.items()})
    profile = {
        "source_id": source_id, "name": path.name, "sha256": source_id, "bytes": size,
        "schema": schema, "columns": header, "loaded_columns": selected,
        "raw_count": raw_count, "ignored_count": ignored_count,
        "missing_values": {col: int((frame[col] == "").sum()) for col in frame.columns},
        "label_counts": dict(Counter(frame.get("label", pd.Series(dtype=str)))),
        "exact_record_duplicates": len(record_hashes) - len(set(record_hashes)),
        "rejected_examples": rejected_examples,
    }
    frame["source_id"] = source_id
    frame["source_name"] = path.name
    frame["source_line"] = lines
    frame["source_end_line"] = end_lines
    frame["observation_hash"] = observation_hashes
    frame["kind"] = "network"
    frame["protocol"] = "UDP" if schema == "udp_complete" else "TCP"
    frame["connection_state"] = schema.removeprefix("tcp_") if schema.startswith("tcp_") else "datagram"
    frame["time_basis"] = "utc"
    frame["recorded_time"] = frame.get("timestamp", "")
    frame["evaluation_label"] = frame.get("label", "")
    frame["evaluation_role_client"] = frame.get("role_cli", "")
    frame["evaluation_role_server"] = frame.get("role_serv", "")
    invalid_reasons = {}
    valid = pd.Series(True, index=frame.index)

    def reject(reason, mask):
        nonlocal valid
        mask = pd.Series(mask, index=frame.index).fillna(True)
        invalid_reasons[reason] = int(mask.sum())
        valid &= ~mask

    for col in ("source_ip", "destination_ip"):
        values = frame[col].map(valid_ip)
        reject(f"invalid_{col}", values.isna())
        frame[col] = values
    numeric_columns = [col for col in mapping if col not in ("source_ip", "destination_ip")]
    for col in numeric_columns:
        frame[col] = pd.to_numeric(frame[col], errors="coerce")
        # An absent UDP direction may have an empty duration, but its populated
        # counterpart must have a finite duration. Epoch zero itself is not an event.
        if schema == "udp_complete" and col.endswith("duration_ms"):
            prefix = col.split("_")[0]
            absent = pd.to_numeric(frame[f"{prefix}_start_ms"], errors="coerce") == 0
            frame.loc[absent & frame[col].isna(), col] = 0.0
        reject(f"invalid_{col}", ~np.isfinite(frame[col]) | (frame[col] < 0))
        if col.endswith("port"):
            reject(f"noninteger_or_out_of_range_{col}", (frame[col] % 1 != 0) | (frame[col] > 65535))
        elif col in ("client_bytes", "server_bytes", "client_packets", "server_packets") or col.endswith(("syn", "fin", "reset")):
            reject(f"noninteger_or_unsafe_{col}", (frame[col] % 1 != 0) | (frame[col] > 2**53 - 1))
    if schema == "udp_complete":
        client_present = frame["client_start_ms"] > 0
        server_present = frame["server_start_ms"] > 0
        profile["absent_direction_counts"] = {"client": int((~client_present).sum()), "server": int((~server_present).sum())}
        reject("both_udp_directions_absent", ~client_present & ~server_present)
        for prefix, present in (("client", client_present), ("server", server_present)):
            reject(f"{prefix}_traffic_without_time", ~present & ((frame[f"{prefix}_bytes"] > 0) | (frame[f"{prefix}_packets"] > 0)))
        client_start = np.where(client_present, frame["client_start_ms"], np.inf)
        server_start = np.where(server_present, frame["server_start_ms"], np.inf)
        start_ms = np.minimum(client_start, server_start)
        end_ms = np.maximum(
            np.where(client_present, frame["client_start_ms"] + frame["client_duration_ms"], -np.inf),
            np.where(server_present, frame["server_start_ms"] + frame["server_duration_ms"], -np.inf),
        )
        span = np.full(len(frame), np.nan, dtype=np.float64)
        np.subtract(end_ms, start_ms, out=span, where=np.isfinite(start_ms) & np.isfinite(end_ms))
        frame["duration_ms"] = span
        timestamp_ms = np.where(client_present, frame["client_start_ms"], frame["server_start_ms"])
    else:
        start_ms, end_ms = frame["start_ms"], frame["end_ms"]
        timestamp_ms = start_ms
        reject("invalid_tcp_interval", (start_ms <= 0) | (end_ms < start_ms))
        profile["duration_mismatch_count"] = int(((end_ms - start_ms - frame["duration_ms"]).abs() > 1).sum())
    epoch_time = _epoch_times(start_ms, frame.index)
    reject("invalid_epoch_time", epoch_time.isna())
    reject("invalid_end_epoch_time", _epoch_times(end_ms, frame.index).isna())
    formatted_time = pd.to_datetime(frame["recorded_time"], errors="coerce", format="mixed", utc=True)
    exported_time = _epoch_times(timestamp_ms, frame.index)
    mismatch = formatted_time.isna() | ((formatted_time - exported_time).abs() > pd.Timedelta(milliseconds=1))
    profile["timestamp_mismatch_count"] = int(mismatch.sum())
    frame["timestamp_mismatch"] = mismatch
    frame["event_time"] = np.asarray(start_ms) / 1000.0
    frame["end_time"] = np.asarray(end_ms) / 1000.0
    frame["event_time_display"] = epoch_time.dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    frame["hostname"] = ""
    frame["account"] = ""
    frame["outcome"] = ""
    profile["invalid_values"] = invalid_reasons
    rejected_indices = frame.index[~valid]
    for idx in rejected_indices[:max(0, 20 - len(rejected_examples))]:
        rejected_examples.append({"source_line": int(frame.at[idx, "source_line"]), "reason": "invalid_required_value"})
    frame = frame.loc[valid].copy()
    profile["zero_values"] = {col: int((frame[col] == 0).sum()) for col in (
        "client_bytes", "server_bytes", "client_packets", "server_packets", "duration_ms"
    )}
    for col in ("source_port", "destination_port", "client_bytes", "server_bytes", "client_packets", "server_packets"):
        frame[col] = frame[col].astype("int64")
    profile["rejected_count"] = structural_rejections + len(rejected_indices)
    profile["valid_before_dedup_count"] = len(frame)
    profile["time_start"] = frame["event_time_display"].min() if len(frame) else None
    profile["time_end"] = frame["event_time_display"].max() if len(frame) else None
    profile["date_counts"] = {str(k): int(v) for k, v in frame["event_time_display"].str[:10].value_counts().sort_index().items()}
    return frame, profile


def load_network(paths=NETWORK_FILES, max_rows=None, max_bytes=None):
    frames, sources = [], []
    for path in paths:
        frame, profile = _network_file(path, max_rows=max_rows, max_bytes=max_bytes)
        frames.append(frame)
        sources.append(profile)
    if not sources:
        raise IngestionError("empty_input", "No network sources supplied.")
    events = pd.concat(frames, ignore_index=True)
    if events.empty:
        raise IngestionError("all_invalid", "No eligible network events remain after validation.", {"sources": sources})
    duplicate_mask = events.duplicated("observation_hash", keep="first")
    duplicate_count = int(duplicate_mask.sum())
    duplicate_refs, conflicting = {}, set()
    if duplicate_count:
        duplicate_hashes = set(events.loc[duplicate_mask, "observation_hash"])
        for observation, group in events.loc[events["observation_hash"].isin(duplicate_hashes)].groupby("observation_hash", sort=False):
            duplicate_refs[observation] = tuple(
                (row.source_id, int(row.source_line), int(row.source_end_line), row.source_name)
                for row in group.iloc[1:].itertuples(index=False)
            )
            if group["evaluation_label"].nunique(dropna=False) > 1:
                conflicting.add(observation)
    events = events.loc[~duplicate_mask].copy()
    events["duplicate_refs"] = events["observation_hash"].map(lambda value: duplicate_refs.get(value, ()))
    events.loc[events["observation_hash"].isin(conflicting), "evaluation_label"] = "__conflicting_annotations__"
    fingerprint = dataset_fingerprint("network", [source["sha256"] for source in sources])
    events["dataset_id"] = fingerprint
    events["clock_id"] = fingerprint
    events = events.sort_values(["event_time", "source_id", "source_line"], kind="stable").reset_index(drop=True)
    warnings = []
    for source in sources:
        if source["rejected_count"]:
            warnings.append(f"{source['name']}: rejected {source['rejected_count']} invalid records; original line references retained.")
        if source["timestamp_mismatch_count"]:
            warnings.append(f"{source['name']}: {source['timestamp_mismatch_count']} missing/mismatched formatted timestamps; valid epoch times used.")
    if duplicate_count:
        warnings.append(f"Removed {duplicate_count} exact exporter-observation duplicates, retaining all source references.")
    if conflicting:
        warnings.append(f"{len(conflicting)} duplicate observations have conflicting annotations and are evaluation-unknown.")
    profile = {
        "ingestion_version": INGESTION_VERSION, "fingerprint": fingerprint,
        "kind": "network", "time_basis": "utc", "sources": sources,
        "raw_count": sum(source["raw_count"] for source in sources),
        "eligible_count": len(events), "duplicate_count": duplicate_count,
        "rejected_count": sum(source["rejected_count"] for source in sources),
        "ignored_count": sum(source["ignored_count"] for source in sources),
        "time_start": events["event_time_display"].min(), "time_end": events["event_time_display"].max(),
        "label_counts": {str(k): int(v) for k, v in events["evaluation_label"].value_counts().items()},
        "protocol_counts": {str(k): int(v) for k, v in events["protocol"].value_counts().items()},
    }
    profile["skipped_count"] = profile["raw_count"] - profile["eligible_count"]
    return IngestedDataset(events, profile, warnings)


def _source_clock(recorded_time):
    month_name, day, clock = recorded_time.split()
    month = MONTHS[month_name]
    day = int(day)
    hour, minute, second = map(int, clock.split(":"))
    if not (1 <= day <= MONTH_LENGTHS[month] and 0 <= hour < 24 and 0 <= minute < 60 and 0 <= second < 60):
        raise ValueError("Invalid source-relative timestamp")
    # A month/day coordinate, not a claimed Gregorian capture year or timezone.
    return (sum(MONTH_LENGTHS[:month]) + day - 1) * 86400 + hour * 3600 + minute * 60 + second, month


def load_authentication(path, max_rows=None, max_bytes=None):
    path = Path(path)
    if not path.is_file():
        raise IngestionError("source_missing", f"Source is missing: {path.name}")
    size = path.stat().st_size
    if max_bytes is not None and size > max_bytes:
        raise IngestionError("size_limit", "Source exceeds the import byte limit.")
    source_id = file_hash(path)
    rows, raw_lines, rejected_examples = [], [], []
    rejected_count, ignored_count, raw_count, rollover = 0, 0, 0, 0
    compressed_summaries = []
    previous_month = None
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            for line_number, line in enumerate(handle, 1):
                raw_count += 1
                if max_rows is not None and raw_count > max_rows:
                    raise IngestionError("row_limit", "Source exceeds the import row limit.")
                if len(line) > 1024 * 1024 or "\0" in line:
                    raise IngestionError("invalid_text", "Authentication lines must be bounded UTF-8 text without NULs.")
                text = line.rstrip("\r\n")
                raw_lines.append(text)
                prefix = PREFIX.match(text)
                summary = re.search(r"message repeated (\d+) times", text)
                if summary:
                    ignored_count += 1
                    compressed_summaries.append({
                        "source_line": line_number, "represented_repetitions": int(summary[1]),
                        "recorded_time": prefix["time"] if prefix else None, "text": text,
                    })
                    continue
                attempt = ATTEMPT.match(prefix["message"]) if prefix else None
                explicit_attempt = bool(re.search(r"(?:Failed password|Accepted (?:password|publickey)) for ", text))
                if not attempt:
                    if explicit_attempt:
                        rejected_count += 1
                        if len(rejected_examples) < 20:
                            rejected_examples.append({"source_line": line_number, "reason": "malformed_explicit_attempt"})
                    else:
                        ignored_count += 1
                    continue
                # Failed publickey/PAM/invalid-user notices and repetition summaries
                # are not additional password attempts.
                if attempt["outcome"] == "Failed" and attempt["method"] != "password":
                    ignored_count += 1
                    continue
                try:
                    coordinate, month = _source_clock(prefix["time"])
                    if previous_month is not None and previous_month - month > 6:
                        rollover += 366 * 86400
                    previous_month = month
                    ip = valid_ip(attempt["ip"])
                    port = int(attempt["port"])
                    if ip is None or not 0 <= port <= 65535:
                        raise ValueError("Invalid address or port")
                except (ValueError, KeyError):
                    rejected_count += 1
                    if len(rejected_examples) < 20:
                        rejected_examples.append({"source_line": line_number, "reason": "invalid_attempt_value"})
                    continue
                rows.append({
                    "source_id": source_id, "source_name": path.name,
                    "source_line": line_number, "source_end_line": line_number,
                    "kind": "authentication", "time_basis": "source_relative", "clock_id": source_id,
                    "event_time": float(coordinate + rollover), "end_time": float(coordinate + rollover),
                    "recorded_time": prefix["time"], "event_time_display": prefix["time"],
                    "hostname": prefix["host"], "account": attempt["account"],
                    "source_ip": ip, "source_port": port, "destination_ip": "", "destination_port": None,
                    "protocol": "SSH", "connection_state": "authentication_attempt",
                    "outcome": "failed" if attempt["outcome"] == "Failed" else "accepted",
                    "authentication_method": attempt["method"], "raw_message": prefix["message"],
                    "evaluation_label": "", "duplicate_refs": (),
                })
    except UnicodeError as exc:
        raise IngestionError("invalid_text", "Authentication source must be UTF-8 text.") from exc
    if not raw_count:
        raise IngestionError("empty_input", "Authentication source is empty.")
    if not rows:
        raise IngestionError("all_invalid", "No explicit failed/accepted authentication attempts found.", {
            "raw_count": raw_count, "rejected_count": rejected_count, "ignored_count": ignored_count,
        })
    events = pd.DataFrame(rows).sort_values(["event_time", "source_line"], kind="stable").reset_index(drop=True)
    origin = float(events["event_time"].min())
    events["event_time"] -= origin
    events["end_time"] -= origin
    fingerprint = dataset_fingerprint("authentication", [source_id])
    events["dataset_id"] = fingerprint
    sources = [{
        "source_id": source_id, "name": path.name, "sha256": source_id, "bytes": size,
        "schema": "openssh_syslog", "raw_count": raw_count,
        "valid_before_dedup_count": len(events), "rejected_count": rejected_count,
        "ignored_count": ignored_count, "exact_record_duplicates": len(raw_lines) - len(set(raw_lines)),
        "rejected_examples": rejected_examples,
        "compressed_retry_summaries": compressed_summaries,
        "time_start": events.iloc[0]["recorded_time"], "time_end": events.iloc[-1]["recorded_time"],
    }]
    warnings = [
        "Authentication capture year/timezone are unknown. Window times are source-relative; recorded timestamps are preserved and must not be correlated with AIT UTC.",
        "OpenSSH messages have no independent attack labels; rule evidence is not measured authentication accuracy.",
        f"Ignored {ignored_count} non-attempt lines, including PAM, invalid-user notices and compressed retry summaries; distinct explicit attempts are never deduplicated.",
    ]
    if rejected_count:
        warnings.append(f"Rejected {rejected_count} malformed explicit authentication records.")
    profile = {
        "ingestion_version": INGESTION_VERSION, "fingerprint": fingerprint,
        "kind": "authentication", "time_basis": "source_relative", "sources": sources,
        "raw_count": raw_count, "eligible_count": len(events), "duplicate_count": 0,
        "rejected_count": rejected_count, "ignored_count": ignored_count,
        "skipped_count": raw_count - len(events),
        "time_start": events.iloc[0]["recorded_time"], "time_end": events.iloc[-1]["recorded_time"],
        "outcome_counts": {str(k): int(v) for k, v in events["outcome"].value_counts().items()},
    }
    return IngestedDataset(events, profile, warnings)


def load_source(path, **limits):
    suffix = Path(path).suffix.lower()
    if suffix == ".csv":
        return load_network([path], **limits)
    if suffix in (".txt", ".log"):
        return load_authentication(path, **limits)
    raise IngestionError("unsupported_format", "Only recognized CSV, .log or .txt security sources are accepted.")


def source_references(events, indices):
    """Lossless compact physical-line ranges, including deduplicated observations."""
    columns = events.loc[list(indices), ["source_id", "source_line", "source_end_line", "source_name", "duplicate_refs"]]
    return compact_references(columns.itertuples(index=False))


def compact_references(records):
    by_source = {}
    for row in records:
        refs = ((row.source_id, int(row.source_line), int(row.source_end_line), row.source_name),) + row.duplicate_refs
        for source_id, start, end, name in refs:
            entry = by_source.setdefault(source_id, {"source_id": source_id, "name": name, "ranges": set()})
            entry["ranges"].add((start, end))
    result = []
    for source_id, entry in sorted(by_source.items()):
        ranges = []
        for start, end in sorted(entry["ranges"]):
            if ranges and start <= ranges[-1][1] + 1:
                ranges[-1][1] = max(ranges[-1][1], end)
            else:
                ranges.append([start, end])
        result.append({"source_id": source_id, "name": entry["name"], "line_ranges": ranges})
    return result


def main():
    parser = argparse.ArgumentParser(description="Profile the immutable supplied network/authentication sources.")
    parser.add_argument("--output", type=Path, default=ROOT / "evaluation" / "data_profile.json")
    args = parser.parse_args()
    started = time.perf_counter()
    network = load_network()
    report = {"network": network.profile, "network_warnings": network.warnings, "network_processing_seconds": time.perf_counter() - started}
    auth_path = DATA_DIR / "OpenSSH_2k.log"
    if auth_path.is_file():
        auth = load_authentication(auth_path)
        report.update(authentication=auth.profile, authentication_warnings=auth.warnings)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, allow_nan=False), encoding="utf-8")
    print(json.dumps({
        "report": str(args.output), "network_counts": {key: network.profile[key] for key in (
            "raw_count", "eligible_count", "duplicate_count", "rejected_count", "ignored_count"
        )}, "sources": [{key: source[key] for key in (
            "name", "bytes", "schema", "sha256", "date_counts", "timestamp_mismatch_count"
        )} for source in network.profile["sources"]],
        "authentication_counts": report.get("authentication", {}).get("outcome_counts"),
    }, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
