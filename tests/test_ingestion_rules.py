"""Controlled acceptance evidence for ingestion and event-time suspicion rules."""

import csv
import hashlib
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import pytest

from ingestion import (
    IngestionError,
    load_authentication,
    load_network,
    load_source,
    source_references,
)
from rules import DetectionConfig, detect_rules


DATA = Path(__file__).resolve().parents[1] / "data"
BASE_MS = 1_642_723_200_000
SCHEMAS = ("tcp_complete", "tcp_incomplete", "udp_complete")
SOURCE_FILES = dict(zip(SCHEMAS, ("tcp_complete.csv", "tcp_nocomplete.csv", "udp_complete.csv")))
TCP_FIELDS = {
    "source_ip": "#15#c_ip:1", "source_port": "c_port:2",
    "destination_ip": "s_ip:15", "destination_port": "s_port:16",
    "client_bytes": "c_bytes_all:9", "server_bytes": "s_bytes_all:23",
    "client_packets": "c_pkts_all:3", "server_packets": "s_pkts_all:17",
    "start_ms": "first:29", "end_ms": "last:30", "duration_ms": "durat:31",
    "client_syn": "c_syn_cnt:13", "server_syn": "s_syn_cnt:27",
    "client_fin": "c_fin_cnt:14", "server_fin": "s_fin_cnt:28",
    "client_reset": "c_rst_cnt:4", "server_reset": "s_rst_cnt:18",
}
UDP_FIELDS = {
    "source_ip": "#c_ip:1", "source_port": "c_port:2",
    "destination_ip": "s_ip:10", "destination_port": "s_port:11",
    "client_bytes": "c_bytes_all:5", "server_bytes": "s_bytes_all:14",
    "client_packets": "c_pkts_all:6", "server_packets": "s_pkts_all:15",
    "client_start_ms": "c_first_abs:3", "client_duration_ms": "c_durat:4",
    "server_start_ms": "s_first_abs:12", "server_duration_ms": "s_durat:13",
}


def _fields(schema):
    return UDP_FIELDS if schema == "udp_complete" else TCP_FIELDS


def _formatted(milliseconds):
    return pd.Timestamp(milliseconds, unit="ms", tz="UTC").isoformat()


def _flow(schema="tcp_complete", offset_ms=0, duration_ms=0, **raw_values):
    start = BASE_MS + offset_ms
    values = {
        "source_ip": "192.0.2.10", "source_port": 40000,
        "destination_ip": "198.51.100.20", "destination_port": 443,
        "client_bytes": 0, "server_bytes": 0,
        "client_packets": 0, "server_packets": 0,
    }
    if schema == "udp_complete":
        values.update(client_start_ms=start, client_duration_ms=duration_ms,
                      server_start_ms=0, server_duration_ms="")
    else:
        values.update(start_ms=start, end_ms=start + duration_ms, duration_ms=duration_ms,
                      client_syn=0, server_syn=0, client_fin=0, server_fin=0,
                      client_reset=0, server_reset=0)
    row = {_fields(schema)[key]: value for key, value in values.items()}
    row.update(timestamp=_formatted(start), label="fixture annotation",
               role_cli="fixture client", role_serv="fixture server")
    row.update(raw_values)
    return row


@pytest.fixture(scope="session")
def exporter_headers():
    headers = {}
    for schema, name in SOURCE_FILES.items():
        with (DATA / name).open(encoding="utf-8-sig", newline="") as handle:
            headers[schema] = next(csv.reader(handle))
    return headers


@pytest.fixture
def network_source(tmp_path, exporter_headers):
    def create(schema="tcp_complete", rows=None, name="flows.csv", header=None):
        columns = exporter_headers[schema] if header is None else header
        path = tmp_path / name
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(columns)
            for row in [_flow(schema)] if rows is None else rows:
                if row is None:
                    writer.writerow([])
                elif isinstance(row, dict):
                    writer.writerow([row.get(column, "0") for column in columns])
                else:
                    writer.writerow(row)
        return path
    return create


def _auth_line(seconds=0, outcome="Failed", method="password", account="alice",
               host="lab-host", ip="192.0.2.10", port=40000, invalid_user=False):
    recorded = (datetime(2000, 12, 10) + timedelta(seconds=seconds)).strftime("%b %d %H:%M:%S")
    user = f"invalid user {account}" if invalid_user else account
    return f"{recorded} {host} sshd[123]: {outcome} {method} for {user} from {ip} port {port} ssh2"


@pytest.fixture
def auth_source(tmp_path):
    def create(lines, name="auth.log"):
        path = tmp_path / name
        path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        return path
    return create


def _rule_events(kind, times, **changes):
    rows = []
    for index, timestamp in enumerate(times):
        row = {
            "kind": kind, "dataset_id": "dataset-a", "clock_id": "clock-a",
            "source_id": "source-a", "source_name": "controlled.log",
            "source_line": index + 2, "source_end_line": index + 2, "duplicate_refs": (),
            "event_time": float(timestamp), "end_time": float(timestamp),
            "hostname": "lab-host", "source_ip": "192.0.2.10", "account": "alice",
            "destination_ip": "198.51.100.20", "destination_port": 10000 + index,
            "source_port": 40000, "protocol": "SSH" if kind == "authentication" else "TCP",
            "outcome": "failed" if kind == "authentication" else "",
            "client_bytes": 0, "server_bytes": 0, "client_packets": 0,
            "server_packets": 0, "duration_ms": 0,
        }
        row.update(changes)
        rows.append(row)
    return pd.DataFrame(rows)


def _ranges(references):
    return {reference["source_id"]: reference["line_ranges"] for reference in references}


@pytest.mark.parametrize("schema,name,protocol,state", [
    ("tcp_complete", "udp_complete.csv", "TCP", "complete"),
    ("tcp_incomplete", "udp_tcp_complete.csv", "TCP", "incomplete"),
    ("udp_complete", "tcp_nocomplete.csv", "UDP", "datagram"),
])
def test_exporter_schema_not_filename_preserves_hash_header_and_zero_values(
    network_source, exporter_headers, schema, name, protocol, state,
):
    path = network_source(schema, name=name)
    dataset = load_source(path)
    event = dataset.events.iloc[0]
    source = dataset.profile["sources"][0]
    assert source["schema"] == schema
    assert source["columns"] == exporter_headers[schema]
    assert source["columns"][0].startswith("#")
    assert _fields(schema)["source_ip"] in source["loaded_columns"]
    assert event["protocol"] == protocol
    assert event["connection_state"] == state
    assert event["source_ip"] == "192.0.2.10"
    assert event["destination_ip"] == "198.51.100.20"
    for field in ("client_bytes", "server_bytes", "client_packets", "server_packets", "duration_ms"):
        assert event[field] == 0
        assert source["zero_values"][field] == 1
    assert event["event_time"] == BASE_MS / 1000
    assert event["end_time"] == event["event_time"]
    assert event["event_time_display"].startswith("2022-01-21T00:00:00")
    assert event["event_time_display"].endswith("Z")
    assert event["time_basis"] == "utc"
    assert event["source_line"] == event["source_end_line"] == 2
    assert event["source_id"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert event["dataset_id"] == dataset.fingerprint == event["clock_id"]
    assert dataset.profile["eligible_count"] == 1
    assert dataset.profile["rejected_count"] == dataset.profile["skipped_count"] == 0
    assert dataset.warnings == []


@pytest.mark.parametrize("schema", SCHEMAS)
@pytest.mark.parametrize("source_port,destination_port", [(0, 65535), (65535, 0)])
def test_network_port_boundaries_and_ipv6_normalization(network_source, schema, source_port, destination_port):
    fields = _fields(schema)
    path = network_source(schema, [_flow(schema, **{
        fields["source_port"]: source_port, fields["destination_port"]: destination_port,
        fields["source_ip"]: "2001:0db8:0000:0000:0000:0000:0000:0001",
        fields["destination_ip"]: "2001:db8::2",
    })])
    event = load_network([path]).events.iloc[0]
    assert (event["source_port"], event["destination_port"]) == (source_port, destination_port)
    assert (event["source_ip"], event["destination_ip"]) == ("2001:db8::1", "2001:db8::2")


INVALID_NETWORK_VALUES = [
    ("source_ip", "", "invalid_source_ip"),
    ("source_ip", "not-an-ip", "invalid_source_ip"),
    ("destination_ip", "256.1.1.1", "invalid_destination_ip"),
    ("source_port", "", "invalid_source_port"),
    ("source_port", "-1", "invalid_source_port"),
    ("source_port", "inf", "invalid_source_port"),
    ("source_port", "65536", "noninteger_or_out_of_range_source_port"),
    ("source_port", "12.5", "noninteger_or_out_of_range_source_port"),
    ("destination_port", "-1", "invalid_destination_port"),
    ("destination_port", "65536", "noninteger_or_out_of_range_destination_port"),
    ("destination_port", "1.25", "noninteger_or_out_of_range_destination_port"),
    ("client_bytes", "", "invalid_client_bytes"),
    ("client_bytes", "garbage", "invalid_client_bytes"),
    ("client_bytes", "-1", "invalid_client_bytes"),
    ("client_bytes", "nan", "invalid_client_bytes"),
    ("client_bytes", "inf", "invalid_client_bytes"),
    ("client_bytes", "-inf", "invalid_client_bytes"),
    ("client_bytes", "0.5", "noninteger_or_unsafe_client_bytes"),
    ("client_bytes", str(2**53), "noninteger_or_unsafe_client_bytes"),
    ("server_bytes", "-1", "invalid_server_bytes"),
    ("server_bytes", "NaN", "invalid_server_bytes"),
    ("client_packets", "-1", "invalid_client_packets"),
    ("client_packets", "inf", "invalid_client_packets"),
    ("client_packets", "0.5", "noninteger_or_unsafe_client_packets"),
    ("server_packets", "", "invalid_server_packets"),
]


@pytest.mark.parametrize("schema", SCHEMAS)
@pytest.mark.parametrize("field,value,reason", INVALID_NETWORK_VALUES,
                         ids=[f"{field}-{value or 'missing'}" for field, value, _ in INVALID_NETWORK_VALUES])
def test_invalid_network_values_are_reported_without_losing_valid_rows(network_source, schema, field, value, reason):
    bad = _flow(schema, offset_ms=1000, **{_fields(schema)[field]: value})
    dataset = load_network([network_source(schema, [_flow(schema), bad])])
    source = dataset.profile["sources"][0]
    assert dataset.profile["raw_count"] == 2
    assert dataset.profile["eligible_count"] == 1
    assert dataset.profile["rejected_count"] == dataset.profile["skipped_count"] == 1
    assert source["invalid_values"][reason] == 1
    assert source["rejected_examples"] == [{"source_line": 3, "reason": "invalid_required_value"}]
    if value == "":
        assert source["missing_values"][field] == 1
    assert list(dataset.events.index) == [0]
    assert list(dataset.events["source_line"]) == [2]
    assert any("rejected 1 invalid records" in warning for warning in dataset.warnings)


@pytest.mark.parametrize("schema", SCHEMAS)
@pytest.mark.parametrize("corruption", ["short", "extra", "nul"])
def test_malformed_csv_rows_report_original_physical_lines(network_source, exporter_headers, schema, corruption):
    columns = exporter_headers[schema]
    bad = [_flow(schema).get(column, "0") for column in columns]
    if corruption == "short":
        bad.pop()
    elif corruption == "extra":
        bad.append("extra column")
    else:
        bad[columns.index("label")] = "bad\0annotation"
    dataset = load_network([network_source(schema, [None, bad, _flow(schema)])])
    assert dataset.profile["raw_count"] == 3
    assert dataset.profile["ignored_count"] == dataset.profile["rejected_count"] == 1
    assert dataset.profile["eligible_count"] == 1
    assert dataset.profile["sources"][0]["rejected_examples"] == [
        {"source_line": 3, "reason": "invalid_column_count_or_nul"},
    ]
    assert list(dataset.events["source_line"]) == [4]


@pytest.mark.parametrize("absent", ["client", "server"])
@pytest.mark.parametrize("duration", [0, 125])
def test_udp_absent_direction_epoch_zero_and_empty_duration_do_not_widen_span(network_source, absent, duration):
    present = "server" if absent == "client" else "client"
    row = _flow("udp_complete", **{
        UDP_FIELDS[f"{absent}_start_ms"]: 0,
        UDP_FIELDS[f"{absent}_duration_ms"]: "",
        UDP_FIELDS[f"{present}_start_ms"]: BASE_MS + 1000,
        UDP_FIELDS[f"{present}_duration_ms"]: duration,
        "timestamp": _formatted(BASE_MS + 1000),
    })
    dataset = load_network([network_source("udp_complete", [row])])
    event = dataset.events.iloc[0]
    assert event["event_time"] == (BASE_MS + 1000) / 1000
    assert event["end_time"] == (BASE_MS + 1000 + duration) / 1000
    assert event["duration_ms"] == duration
    assert dataset.profile["sources"][0]["absent_direction_counts"] == {absent: 1, present: 0}
    assert not event["timestamp_mismatch"]
    assert dataset.warnings == []


@pytest.mark.parametrize("client_start,client_duration,server_start,server_duration,span", [
    (2000, 100, 0, 500, 2100),
    (0, 200, 1500, 400, 1900),
    (2000, 0, 1000, 0, 1000),
])
def test_udp_span_uses_earliest_start_and_latest_end_of_both_directions(
    network_source, client_start, client_duration, server_start, server_duration, span,
):
    row = _flow("udp_complete", **{
        "c_first_abs:3": BASE_MS + client_start, "c_durat:4": client_duration,
        "s_first_abs:12": BASE_MS + server_start, "s_durat:13": server_duration,
        "timestamp": _formatted(BASE_MS + client_start),
    })
    dataset = load_network([network_source("udp_complete", [row])])
    event = dataset.events.iloc[0]
    assert event["event_time"] == (BASE_MS + min(client_start, server_start)) / 1000
    assert event["end_time"] == (BASE_MS + max(client_start + client_duration, server_start + server_duration)) / 1000
    assert event["duration_ms"] == span
    assert not event["timestamp_mismatch"]
    assert dataset.profile["sources"][0]["timestamp_mismatch_count"] == 0


@pytest.mark.parametrize("changes,reason", [
    ({"c_first_abs:3": 0}, "both_udp_directions_absent"),
    ({"c_durat:4": ""}, "invalid_client_duration_ms"),
    ({"c_durat:4": -1}, "invalid_client_duration_ms"),
    ({"c_durat:4": "inf"}, "invalid_client_duration_ms"),
    ({"s_bytes_all:14": 1}, "server_traffic_without_time"),
    ({"s_pkts_all:15": 1}, "server_traffic_without_time"),
    ({"c_first_abs:3": 0, "c_bytes_all:5": 1, "s_first_abs:12": BASE_MS}, "client_traffic_without_time"),
    ({"c_first_abs:3": 0, "c_pkts_all:6": 1, "s_first_abs:12": BASE_MS}, "client_traffic_without_time"),
    ({"c_first_abs:3": ""}, "invalid_client_start_ms"),
    ({"c_first_abs:3": "nan"}, "invalid_client_start_ms"),
    ({"c_first_abs:3": "inf"}, "invalid_client_start_ms"),
    ({"s_first_abs:12": "inf"}, "invalid_server_start_ms"),
    ({"c_durat:4": "-inf"}, "invalid_client_duration_ms"),
    ({"c_durat:4": "nan"}, "invalid_client_duration_ms"),
    ({"s_first_abs:12": BASE_MS, "s_durat:13": "inf"}, "invalid_server_duration_ms"),
    ({"s_first_abs:12": BASE_MS, "s_durat:13": ""}, "invalid_server_duration_ms"),
])
def test_udp_missing_or_invalid_direction_values_are_rejected(network_source, changes, reason):
    dataset = load_network([network_source("udp_complete", [_flow("udp_complete"), _flow("udp_complete", **changes)])])
    assert dataset.profile["eligible_count"] == dataset.profile["rejected_count"] == 1
    assert dataset.profile["sources"][0]["invalid_values"][reason] == 1
    assert list(dataset.events["source_line"]) == [2]


@pytest.mark.parametrize("schema", ["tcp_complete", "tcp_incomplete"])
@pytest.mark.parametrize("column,value,reason", [
    ("durat:31", "", "invalid_duration_ms"),
    ("durat:31", -1, "invalid_duration_ms"),
    ("durat:31", "nan", "invalid_duration_ms"),
    ("durat:31", "inf", "invalid_duration_ms"),
    ("first:29", 0, "invalid_tcp_interval"),
    ("first:29", -1, "invalid_start_ms"),
    ("first:29", "nan", "invalid_start_ms"),
    ("first:29", "inf", "invalid_start_ms"),
    ("first:29", "-inf", "invalid_start_ms"),
    ("last:30", BASE_MS - 1, "invalid_tcp_interval"),
    ("last:30", "inf", "invalid_end_ms"),
    ("last:30", "-inf", "invalid_end_ms"),
    ("last:30", "nan", "invalid_end_ms"),
    ("c_syn_cnt:13", -1, "invalid_client_syn"),
])
def test_tcp_invalid_times_and_connection_counts_are_reported(network_source, schema, column, value, reason):
    dataset = load_network([network_source(schema, [_flow(schema), _flow(schema, **{column: value})])])
    assert dataset.profile["eligible_count"] == dataset.profile["rejected_count"] == 1
    assert dataset.profile["sources"][0]["invalid_values"][reason] == 1


@pytest.mark.parametrize("schema", SCHEMAS)
@pytest.mark.parametrize("recorded,mismatch", [
    (_formatted(BASE_MS + 1), False),
    (_formatted(BASE_MS + 2), True),
    ("", True),
    ("not a timestamp", True),
])
def test_formatted_epoch_disagreement_warns_but_uses_valid_epoch(network_source, schema, recorded, mismatch):
    dataset = load_network([network_source(schema, [_flow(schema, timestamp=recorded)])])
    event = dataset.events.iloc[0]
    assert event["recorded_time"] == recorded
    assert event["event_time"] == BASE_MS / 1000
    assert bool(event["timestamp_mismatch"]) is mismatch
    assert dataset.profile["sources"][0]["timestamp_mismatch_count"] == int(mismatch)
    assert any("formatted timestamps; valid epoch times used" in warning for warning in dataset.warnings) is mismatch
    assert dataset.profile["rejected_count"] == 0


@pytest.mark.parametrize("problem,code", [
    ("hash_header_removed", "unsupported_schema"),
    ("timestamp_missing", "unsupported_schema"),
    ("discriminators_missing", "unsupported_schema"),
    ("duplicate_columns", "invalid_schema"),
    ("ambiguous_transports", "unsupported_schema"),
])
def test_unvalidated_exporter_schemas_fail_explicitly(network_source, exporter_headers, problem, code):
    header = list(exporter_headers["tcp_complete"])
    if problem == "hash_header_removed":
        header[0] = header[0].lstrip("#")
    elif problem == "timestamp_missing":
        header.remove("timestamp")
    elif problem == "discriminators_missing":
        header = [column for column in header if column not in {"con_t:42", "http_t:44", "c_rtt_avg:45", "s_rtt_avg:52"}]
    elif problem == "duplicate_columns":
        header.append(header[0])
    else:
        header.extend(column for column in exporter_headers["udp_complete"] if column not in header)
    with pytest.raises(IngestionError) as error:
        load_network([network_source(header=header)])
    assert error.value.code == code


@pytest.mark.parametrize("mode,code", [("no_sources", "empty_input"), ("empty_file", "empty_input"), ("header_only", "all_invalid")])
def test_empty_network_inputs_fail_explicitly(network_source, tmp_path, mode, code):
    if mode == "no_sources":
        paths = []
    elif mode == "empty_file":
        path = tmp_path / "empty.csv"
        path.write_text("", encoding="utf-8")
        paths = [path]
    else:
        paths = [network_source(rows=[])]
    with pytest.raises(IngestionError) as error:
        load_network(paths)
    assert error.value.code == code


@pytest.mark.parametrize("schema", SCHEMAS)
def test_all_invalid_network_input_returns_rejection_evidence(network_source, schema):
    path = network_source(schema, [_flow(schema, **{_fields(schema)["source_ip"]: "bad"})])
    with pytest.raises(IngestionError) as error:
        load_network([path])
    assert error.value.code == "all_invalid"
    source = error.value.details["sources"][0]
    assert source["raw_count"] == source["rejected_count"] == 1
    assert source["valid_before_dedup_count"] == 0
    assert source["rejected_examples"][0]["source_line"] == 2


@pytest.mark.parametrize("changes,reason", [
    ({"c_first_abs:3": 0}, "both_udp_directions_absent"),
    ({"c_durat:4": "inf"}, "invalid_client_duration_ms"),
])
def test_all_invalid_udp_direction_input_fails_with_typed_rejection_evidence(network_source, changes, reason):
    path = network_source("udp_complete", [_flow("udp_complete", **changes)])
    with pytest.raises(IngestionError) as error:
        load_network([path])
    assert error.value.code == "all_invalid"
    source = error.value.details["sources"][0]
    assert source["raw_count"] == source["rejected_count"] == 1
    assert source["invalid_values"][reason] == 1
    assert source["rejected_examples"] == [{"source_line": 2, "reason": "invalid_required_value"}]


def test_unterminated_csv_quoting_fails_with_typed_parse_error(tmp_path, exporter_headers):
    path = tmp_path / "broken.csv"
    path.write_text(",".join(exporter_headers["tcp_complete"]) + '\n"unterminated record\n', encoding="utf-8")
    with pytest.raises(IngestionError) as error:
        load_network([path])
    assert error.value.code == "invalid_text"


def test_exact_observation_dedup_keeps_every_physical_reference_and_distinct_exporter_detail(network_source):
    early = _flow(label="fixture\nannotation")
    late = _flow(offset_ms=60000)
    changed_detail = dict(early, **{"c_ack_cnt:5": 1})
    first = network_source(rows=[late, early, None, early], name="first.csv")
    second = network_source(rows=[early, changed_detail], name="second.csv")
    dataset = load_network([first, second])
    first_id = hashlib.sha256(first.read_bytes()).hexdigest()
    second_id = hashlib.sha256(second.read_bytes()).hexdigest()
    duplicate = dataset.events.loc[dataset.events["duplicate_refs"].map(bool)].iloc[0]
    assert dataset.profile["raw_count"] == 6
    assert dataset.profile["eligible_count"] == 3
    assert dataset.profile["duplicate_count"] == 2
    assert dataset.profile["ignored_count"] == 1
    assert dataset.profile["rejected_count"] == 0
    assert dataset.profile["skipped_count"] == 3
    assert dataset.profile["sources"][0]["exact_record_duplicates"] == 1
    assert "c_ack_cnt:5" not in dataset.profile["sources"][0]["loaded_columns"]
    assert duplicate["source_id"] == first_id
    assert duplicate["source_line"] == 3
    assert duplicate["source_end_line"] == 4
    assert duplicate["duplicate_refs"] == ((first_id, 6, 7, "first.csv"), (second_id, 2, 3, "second.csv"))
    assert _ranges(source_references(dataset.events, [duplicate.name])) == {
        first_id: [[3, 4], [6, 7]], second_id: [[2, 3]],
    }
    assert _ranges(source_references(dataset.events, dataset.events.index)) == {
        first_id: [[2, 4], [6, 7]], second_id: [[2, 5]],
    }
    assert len(dataset.events.loc[dataset.events["event_time"] == BASE_MS / 1000]) == 2
    assert dataset.events["event_time"].is_monotonic_increasing
    assert list(dataset.events.index) == [0, 1, 2]
    assert any("Removed 2 exact exporter-observation duplicates" in warning for warning in dataset.warnings)
    reordered = load_network([second, first])
    assert reordered.fingerprint == dataset.fingerprint
    assert set(reordered.events["observation_hash"]) == set(dataset.events["observation_hash"])


def test_annotation_changes_do_not_create_new_observations_or_hide_conflicting_labels(network_source):
    first = network_source(rows=[_flow(label="browsing/update")], name="first.csv")
    second = network_source(rows=[_flow(label="data exfiltration", role_cli="different role",
                                       timestamp=_formatted(BASE_MS + 2000))], name="second.csv")
    dataset = load_network([first, second])
    assert dataset.profile["eligible_count"] == dataset.profile["duplicate_count"] == 1
    assert dataset.events.iloc[0]["evaluation_label"] == "__conflicting_annotations__"
    assert len(source_references(dataset.events, [0])) == 2
    assert any("conflicting annotations" in warning for warning in dataset.warnings)


def test_reimporting_identical_source_is_deduplicated_with_stable_identity(network_source):
    path = network_source(rows=[_flow(offset_ms=index * 1000, **{"s_port:16": 10000 + index}) for index in range(20)])
    original = load_network([path])
    repeated = load_network([path, path])
    assert repeated.fingerprint == original.fingerprint
    assert repeated.profile["raw_count"] == 40
    assert repeated.profile["eligible_count"] == repeated.profile["duplicate_count"] == 20
    assert list(repeated.events["source_line"]) == list(original.events["source_line"]) == list(range(2, 22))
    for event in repeated.events.itertuples():
        assert event.duplicate_refs == ((event.source_id, event.source_line, event.source_end_line, path.name),)
    original_detection, = detect_rules(original.events)
    repeated_detection, = detect_rules(repeated.events)
    assert repeated_detection.rule_id == original_detection.rule_id == "network.port_scan"
    assert repeated_detection.indices == original_detection.indices == set(range(20))
    assert repeated_detection.peak_window_count == original_detection.peak_window_count == 20
    assert repeated_detection.unique_ports == original_detection.unique_ports == set(range(10000, 10020))
    assert repeated_detection.last_seen == original_detection.last_seen == (BASE_MS + 19000) / 1000
    assert source_references(repeated.events, repeated_detection.indices) == source_references(original.events, original_detection.indices)
    assert source_references(repeated.events, repeated_detection.indices)[0]["line_ranges"] == [[2, 21]]


def test_network_sort_and_reset_keep_original_lines_after_rejections(network_source):
    rows = [_flow(offset_ms=3000), _flow(offset_ms=0), _flow(offset_ms=1000, **{"c_port:2": -1}), _flow(offset_ms=2000)]
    dataset = load_network([network_source(rows=rows)])
    assert list(dataset.events.index) == [0, 1, 2]
    assert list(dataset.events["source_line"]) == [3, 5, 2]
    assert list(dataset.events["event_time"]) == [(BASE_MS + offset) / 1000 for offset in (0, 2000, 3000)]


def test_authentication_counts_only_explicit_password_failures_and_password_publickey_successes(auth_source):
    notice = "Dec 10 00:00:00 lab-host sshd[123]: "
    repeated = _auth_line(invalid_user=True)
    lines = [
        notice + "pam_unix(sshd:auth): authentication failure; rhost=192.0.2.10 user=alice",
        notice + "Invalid user alice from 192.0.2.10",
        notice + "input_userauth_request: invalid user alice [preauth]",
        _auth_line(method="publickey"),
        _auth_line(method="none"),
        notice + "message repeated 5 times: [ Failed password for alice from 192.0.2.10 port 40000 ssh2 ]",
        repeated,
        repeated,
        _auth_line(1, outcome="Accepted", account="bob"),
        _auth_line(2, outcome="Accepted", method="publickey", account="carol"),
        _auth_line(3, outcome="Accepted", method="keyboard-interactive"),
    ]
    dataset = load_authentication(auth_source(lines))
    assert dataset.profile["raw_count"] == 11
    assert dataset.profile["eligible_count"] == 4
    assert dataset.profile["outcome_counts"] == {"failed": 2, "accepted": 2}
    assert dataset.profile["ignored_count"] == dataset.profile["skipped_count"] == 7
    assert dataset.profile["rejected_count"] == dataset.profile["duplicate_count"] == 0
    assert list(dataset.events["source_line"]) == [7, 8, 9, 10]
    assert list(dataset.events["account"]) == ["alice", "alice", "bob", "carol"]
    assert list(dataset.events["authentication_method"]) == ["password", "password", "password", "publickey"]
    assert all(reference == () for reference in dataset.events["duplicate_refs"])
    source = dataset.profile["sources"][0]
    assert source["exact_record_duplicates"] == 1
    assert source["compressed_retry_summaries"][0]["source_line"] == 6
    assert source["compressed_retry_summaries"][0]["represented_repetitions"] == 5


def test_authentication_unsorted_source_relative_clock_preserves_recorded_time_and_lines(auth_source):
    early = _auth_line(0).replace("Dec 10", "Dec  9")
    late = _auth_line(120).replace("Dec 10", "Dec  9")
    path = auth_source([late, "unrecognized notice", early, early])
    dataset = load_authentication(path)
    assert list(dataset.events.index) == [0, 1, 2]
    assert list(dataset.events["source_line"]) == [3, 4, 1]
    assert list(dataset.events["source_end_line"]) == [3, 4, 1]
    assert list(dataset.events["event_time"]) == list(dataset.events["end_time"]) == [0.0, 0.0, 120.0]
    assert list(dataset.events["recorded_time"]) == list(dataset.events["event_time_display"]) == [
        "Dec  9 00:00:00", "Dec  9 00:00:00", "Dec  9 00:02:00",
    ]
    assert set(dataset.events["time_basis"]) == {"source_relative"}
    assert set(dataset.events["clock_id"]) == {hashlib.sha256(path.read_bytes()).hexdigest()}
    assert set(dataset.events["dataset_id"]) == {dataset.fingerprint}
    assert any("year/timezone are unknown" in warning for warning in dataset.warnings)
    assert any("must not be correlated with AIT UTC" in warning for warning in dataset.warnings)
    assert _ranges(source_references(dataset.events, [0, 1])) == {dataset.events.iloc[0]["source_id"]: [[3, 4]]}


def test_authentication_year_rollover_is_relative_without_fabricated_capture_year(auth_source):
    december = _auth_line().replace("Dec 10 00:00:00", "Dec 31 23:59:59")
    january = _auth_line().replace("Dec 10 00:00:00", "Jan  1 00:00:00")
    dataset = load_authentication(auth_source([december, january]))
    assert list(dataset.events["event_time"]) == [0.0, 1.0]
    assert list(dataset.events["event_time_display"]) == ["Dec 31 23:59:59", "Jan  1 00:00:00"]
    assert dataset.profile["time_basis"] == "source_relative"


@pytest.mark.parametrize("bad,reason", [
    (_auth_line(ip="999.1.1.1"), "invalid_attempt_value"),
    (_auth_line(ip="host.example"), "invalid_attempt_value"),
    (_auth_line(outcome="Accepted", method="publickey", ip="invalid"), "invalid_attempt_value"),
    (_auth_line(port=65536), "invalid_attempt_value"),
    (_auth_line(port=-1), "malformed_explicit_attempt"),
    (_auth_line().replace(" port 40000", ""), "malformed_explicit_attempt"),
    (_auth_line().replace(" from 192.0.2.10", ""), "malformed_explicit_attempt"),
    (_auth_line().replace("Dec 10", "Dec 32"), "invalid_attempt_value"),
    (_auth_line().replace("00:00:00", "24:00:00"), "invalid_attempt_value"),
    (_auth_line().replace("Dec 10 00:00:00", "2022-12-10T00:00:00Z"), "malformed_explicit_attempt"),
    (_auth_line().replace("sshd[123]", "unknown[123]"), "malformed_explicit_attempt"),
])
def test_invalid_explicit_authentication_rows_report_physical_lines(auth_source, bad, reason):
    dataset = load_authentication(auth_source(["ignored", bad, _auth_line()]))
    assert dataset.profile["raw_count"] == 3
    assert dataset.profile["eligible_count"] == dataset.profile["ignored_count"] == dataset.profile["rejected_count"] == 1
    assert dataset.profile["sources"][0]["rejected_examples"] == [{"source_line": 2, "reason": reason}]
    assert list(dataset.events["source_line"]) == [3]
    assert any("Rejected 1 malformed explicit" in warning for warning in dataset.warnings)


@pytest.mark.parametrize("lines,code,rejected,ignored", [
    ([], "empty_input", 0, 0),
    (["unknown format", "Dec 10 00:00:00 lab-host sshd[123]: Invalid user alice"], "all_invalid", 0, 2),
    ([_auth_line(ip="invalid")], "all_invalid", 1, 0),
])
def test_empty_unknown_and_all_invalid_authentication_fail_explicitly(auth_source, lines, code, rejected, ignored):
    with pytest.raises(IngestionError) as error:
        load_authentication(auth_source(lines))
    assert error.value.code == code
    if lines:
        assert error.value.details == {"raw_count": len(lines), "rejected_count": rejected, "ignored_count": ignored}


@pytest.mark.parametrize("suffix", [".log", ".txt", ".LOG"])
def test_recognized_authentication_file_formats_use_explicit_parser(auth_source, suffix):
    dataset = load_source(auth_source([_auth_line()], name="source" + suffix))
    assert dataset.profile["kind"] == "authentication"
    assert dataset.profile["eligible_count"] == 1


def test_unknown_file_format_is_rejected_without_guessing_from_contents(auth_source):
    with pytest.raises(IngestionError) as error:
        load_source(auth_source([_auth_line()], name="auth.json"))
    assert error.value.code == "unsupported_format"


@pytest.mark.parametrize("kind,count,expected", [
    ("authentication", 4, False), ("authentication", 5, True),
    ("network", 19, False), ("network", 20, True),
])
def test_default_rule_thresholds_exact_and_just_below(kind, count, expected):
    config = DetectionConfig()
    assert (config.failure_threshold, config.failure_window_seconds) == (5, 300)
    assert (config.scan_port_threshold, config.scan_window_seconds) == (20, 60)
    assert config.success_window_seconds == 300
    events = _rule_events(kind, range(count))
    detections = detect_rules(events)
    if not expected:
        assert detections == []
        return
    detection, = detections
    assert detection.rule_id == ("authentication.failure_burst" if kind == "authentication" else "network.port_scan")
    assert detection.indices == set(events.index)
    assert detection.peak_window_count == count
    assert detection.trigger_time == detection.last_trigger_time == detection.last_seen == count - 1
    assert detection.thresholds["window_seconds"] == (300 if kind == "authentication" else 60)
    assert "inclusive" in detection.thresholds["bounds"]
    if kind == "network":
        assert detection.unique_ports == set(events["destination_port"])


@pytest.mark.parametrize("kind", ["authentication", "network"])
@pytest.mark.parametrize("delta,expected", [(-0.001, True), (0, True), (0.001, False)])
def test_rule_windows_include_exact_lower_bound_but_exclude_just_outside(kind, delta, expected):
    times = [0, 75, 150, 225, 300 + delta] if kind == "authentication" else [0, *range(3, 55, 3), 60 + delta]
    detections = detect_rules(_rule_events(kind, times))
    assert bool(detections) is expected
    if expected:
        detection, = detections
        assert detection.indices == set(range(len(times)))
        assert detection.peak_window_count == len(times)


@pytest.mark.parametrize("kind", ["authentication", "network"])
def test_rule_thresholds_and_windows_are_configurable(kind):
    config = DetectionConfig(failure_threshold=3, failure_window_seconds=10,
                             scan_port_threshold=3, scan_window_seconds=10)
    events = _rule_events(kind, [0, 5, 10])
    detection, = detect_rules(events, config)
    assert detection.indices == {0, 1, 2}
    assert detection.peak_window_count == 3
    assert detection.thresholds["window_seconds"] == 10
    assert detection.thresholds["failure_threshold" if kind == "authentication" else "distinct_port_threshold"] == 3
    events.loc[2, "event_time"] = 10.001
    assert detect_rules(events, config) == []


IDENTITY_FIELDS = [
    ("authentication", "dataset_id", "dataset-b"),
    ("authentication", "clock_id", "clock-b"),
    ("authentication", "hostname", "other-host"),
    ("authentication", "account", "bob"),
    ("authentication", "source_ip", "192.0.2.11"),
    ("network", "dataset_id", "dataset-b"),
    ("network", "source_ip", "192.0.2.11"),
    ("network", "destination_ip", "198.51.100.21"),
    ("network", "protocol", "UDP"),
]


@pytest.mark.parametrize("kind,field,other", IDENTITY_FIELDS)
def test_rule_groups_do_not_combine_subthreshold_identities(kind, field, other):
    count = 5 if kind == "authentication" else 20
    events = _rule_events(kind, range(count))
    events.loc[count // 2:, field] = other
    assert detect_rules(events) == []


@pytest.mark.parametrize("kind,field,other", IDENTITY_FIELDS)
def test_each_independent_identity_can_generate_its_own_alert(kind, field, other):
    count = 5 if kind == "authentication" else 20
    first = _rule_events(kind, range(count))
    second = _rule_events(kind, range(count), **{field: other})
    events = pd.concat([first, second], ignore_index=True)
    detections = detect_rules(events)
    assert len(detections) == 2
    assert {frozenset(detection.indices) for detection in detections} == {
        frozenset(range(count)), frozenset(range(count, count * 2)),
    }
    for detection in detections:
        assert events.loc[list(detection.indices), field].nunique() == 1
        assert detection.peak_window_count == count


@pytest.mark.parametrize("window,delay,expected", [
    (300, 0, True), (300, 299.999, True), (300, 300, True), (300, 300.001, False),
    (7, 7, True), (7, 7.001, False), (600, 600, True), (600, 600.001, False),
])
def test_accepted_login_requires_known_burst_within_configured_inclusive_success_window(window, delay, expected):
    events = _rule_events("authentication", [0, 1, 2, 3, 4, 4 + delay])
    events.loc[5, "outcome"] = "accepted"
    detections = detect_rules(events, DetectionConfig(success_window_seconds=window))
    assert [detection.rule_id for detection in detections] == ["authentication.failure_burst"] + (
        ["authentication.success_after_burst"] if expected else []
    )
    if expected:
        success = detections[1]
        assert success.activity_type == "suspicious_login"
        assert success.indices == set(events.index)
        assert success.peak_window_count == 5
        assert success.trigger_time == success.last_seen == 4 + delay
        assert success.thresholds["success_after_burst_seconds"] == window


@pytest.mark.parametrize("field,other", [(field, other) for kind, field, other in IDENTITY_FIELDS if kind == "authentication"])
def test_success_cannot_borrow_failure_burst_from_different_identity(field, other):
    events = _rule_events("authentication", [0, 1, 2, 3, 4, 5])
    events.loc[5, "outcome"] = "accepted"
    events.loc[5, field] = other
    assert [detection.rule_id for detection in detect_rules(events)] == ["authentication.failure_burst"]


@pytest.mark.parametrize("failures", [0, 1, 2, 4])
def test_benign_mistakes_followed_by_success_are_not_suspicious(failures):
    events = _rule_events("authentication", range(failures + 1))
    events.loc[failures, "outcome"] = "accepted"
    assert detect_rules(events) == []


@pytest.mark.parametrize("accepted_first", [True, False])
def test_same_timestamp_success_requires_preceding_explicit_burst(accepted_first):
    events = _rule_events("authentication", [0] * 6)
    events.loc[0 if accepted_first else 5, "outcome"] = "accepted"
    detections = detect_rules(events)
    assert [detection.rule_id for detection in detections] == ["authentication.failure_burst"] + (
        [] if accepted_first else ["authentication.success_after_burst"]
    )


def test_isolated_late_failure_does_not_refresh_known_burst_success_window():
    events = _rule_events("authentication", [0, 1, 2, 3, 4, 305, 306])
    events.loc[6, "outcome"] = "accepted"
    detections = detect_rules(events, DetectionConfig(auth_cooldown_seconds=600))
    detection, = detections
    assert detection.rule_id == "authentication.failure_burst"
    assert detection.last_trigger_time == 4
    assert detection.last_seen == 305
    assert detection.indices == set(range(6))


def test_pam_notices_and_retry_summaries_do_not_turn_benign_mistakes_into_burst(auth_source):
    lines = [_auth_line(seconds) for seconds in range(4)]
    lines.extend([
        "Dec 10 00:00:04 lab-host sshd[123]: pam_unix(sshd:auth): authentication failure; user=alice rhost=192.0.2.10",
        "Dec 10 00:00:04 lab-host sshd[123]: Invalid user alice from 192.0.2.10",
        "Dec 10 00:00:04 lab-host sshd[123]: message repeated 20 times: [ Failed password for alice from 192.0.2.10 port 40000 ssh2 ]",
        _auth_line(5, outcome="Accepted"),
    ])
    dataset = load_authentication(auth_source(lines))
    assert dataset.profile["outcome_counts"] == {"failed": 4, "accepted": 1}
    assert detect_rules(dataset.events) == []


def test_repeated_explicit_authentication_lines_remain_distinct_rule_support(auth_source):
    dataset = load_authentication(auth_source([_auth_line()] * 5))
    detection, = detect_rules(dataset.events)
    assert dataset.profile["duplicate_count"] == 0
    assert detection.indices == {0, 1, 2, 3, 4}
    assert detection.peak_window_count == 5
    assert source_references(dataset.events, detection.indices)[0]["line_ranges"] == [[1, 5]]


@pytest.mark.parametrize("schema", SCHEMAS)
@pytest.mark.parametrize("payload", [0, 1])
def test_scans_with_tiny_or_zero_payloads_trigger_from_distinct_ports(network_source, schema, payload):
    fields = _fields(schema)
    rows = [_flow(schema, offset_ms=index * 1000, **{
        fields["destination_port"]: 10000 + index,
        fields["client_bytes"]: payload, fields["client_packets"]: payload,
    }) for index in range(20)]
    dataset = load_network([network_source(schema, rows)])
    detection, = detect_rules(dataset.events)
    assert detection.rule_id == "network.port_scan"
    assert detection.indices == set(range(20))
    assert detection.unique_ports == set(range(10000, 10020))
    assert detection.peak_window_count == 20
    assert source_references(dataset.events, detection.indices)[0]["line_ranges"] == [[2, 21]]


def test_repeated_contact_to_one_port_is_not_a_twenty_port_scan():
    events = _rule_events("network", range(40), destination_port=443)
    assert detect_rules(events) == []


def test_large_udp_flow_is_not_classified_as_flooding(network_source):
    dataset = load_network([network_source("udp_complete", [_flow("udp_complete", **{
        "c_bytes_all:5": 1_000_000_000, "c_pkts_all:6": 1_000_000,
    })])])
    assert detect_rules(dataset.events) == []


def test_incomplete_tcp_connections_are_not_failed_authentication(network_source):
    dataset = load_network([network_source("tcp_incomplete", [_flow("tcp_incomplete", offset_ms=index * 1000) for index in range(5)])])
    assert set(dataset.events["connection_state"]) == {"incomplete"}
    assert set(dataset.events["outcome"]) == {""}
    assert detect_rules(dataset.events) == []


@pytest.mark.parametrize("kind", ["authentication", "network"])
def test_rules_sort_unsorted_events_without_replacing_support_indices(kind):
    count = 5 if kind == "authentication" else 20
    events = _rule_events(kind, range(count))
    events.index = [100 + index * 3 for index in range(count)]
    events = events.iloc[::-1]
    detection, = detect_rules(events)
    assert detection.indices == set(events.index)
    assert detection.trigger_time == detection.last_trigger_time == detection.last_seen == count - 1
    assert source_references(events, detection.indices)[0]["line_ranges"] == [[2, count + 1]]


@pytest.mark.parametrize("kind", ["authentication", "network"])
def test_cooldown_retains_nontriggering_continuations_and_splits_only_after_boundary(kind):
    events = _rule_events(kind, [0, 1, 2, 12, 32, 52.001, 53, 54])
    events["destination_port"] = [10, 11, 12, 10, 11, 10, 11, 12]
    events.index = [10, 20, 30, 40, 50, 60, 70, 80]
    config = DetectionConfig(failure_threshold=3, failure_window_seconds=10, auth_cooldown_seconds=20,
                             scan_port_threshold=3, scan_window_seconds=10, scan_cooldown_seconds=20)
    first, second = detect_rules(events, config)
    assert first.indices == {10, 20, 30, 40, 50}
    assert first.trigger_time == first.last_trigger_time == 2
    assert first.last_seen == 32
    assert first.peak_window_count == 3
    assert first.thresholds["effective_cooldown_seconds"] == 20
    assert second.indices == {60, 70, 80}
    assert second.trigger_time == second.last_trigger_time == second.last_seen == 54
    assert len(first.indices) + len(second.indices) == len(events)
    assert source_references(events, first.indices)[0]["line_ranges"] == [[2, 6]]
    assert source_references(events, second.indices)[0]["line_ranges"] == [[7, 9]]
    if kind == "network":
        assert first.unique_ports == second.unique_ports == {10, 11, 12}


@pytest.mark.parametrize("kind,step", [("authentication", 10), ("network", 2)])
def test_continuing_bursts_aggregate_all_occurrences_not_only_peak_window_count(kind, step):
    events = _rule_events(kind, [index * step for index in range(100)])
    detection, = detect_rules(events)
    assert detection.indices == set(range(100))
    assert len(detection.indices) == 100
    assert detection.peak_window_count == 31
    assert detection.last_trigger_time == detection.last_seen == 99 * step
    assert min(events.loc[list(detection.indices), "event_time"]) == 0
    assert source_references(events, detection.indices)[0]["line_ranges"] == [[2, 101]]
    if kind == "network":
        assert detection.unique_ports == set(range(10000, 10100))


def test_suspicious_login_cooldown_aggregates_all_failure_and_success_support():
    events = _rule_events("authentication", [0, 1, 2, 3, 5, 6, 8])
    events.loc[[3, 4, 6], "outcome"] = "accepted"
    config = DetectionConfig(failure_threshold=3, failure_window_seconds=10,
                             success_window_seconds=7, auth_cooldown_seconds=20)
    burst, success = detect_rules(events, config)
    assert burst.rule_id == "authentication.failure_burst"
    assert burst.indices == {0, 1, 2, 5}
    assert burst.peak_window_count == 4
    assert burst.last_trigger_time == burst.last_seen == 6
    assert success.rule_id == "authentication.success_after_burst"
    assert success.indices == set(range(7))
    assert success.peak_window_count == 4
    assert success.trigger_time == 3
    assert success.last_trigger_time == success.last_seen == 8
    support = events.loc[list(success.indices)]
    assert support["outcome"].value_counts().to_dict() == {"failed": 4, "accepted": 3}
    assert source_references(events, success.indices)[0]["line_ranges"] == [[2, 8]]


@pytest.fixture(scope="module")
def openssh_sample():
    return load_authentication(DATA / "OpenSSH_2k.log")


def test_retained_openssh_sample_has_518_explicit_failures_and_one_accepted_login(openssh_sample):
    dataset = openssh_sample
    assert dataset.profile["sources"][0]["sha256"] == "1e4912727fa88245113d41b16a0cd25ceadba7f931e1c406542885b91254264f"
    assert dataset.profile["raw_count"] == 2000
    assert dataset.profile["eligible_count"] == 519
    assert dataset.profile["outcome_counts"] == {"failed": 518, "accepted": 1}
    assert dataset.profile["ignored_count"] == dataset.profile["skipped_count"] == 1481
    assert dataset.profile["rejected_count"] == dataset.profile["duplicate_count"] == 0
    accepted = dataset.events.loc[dataset.events["outcome"] == "accepted"].iloc[0]
    assert (accepted["hostname"], accepted["account"], accepted["source_ip"], accepted["source_port"]) == (
        "LabSZ", "fztu", "119.137.62.142", 49116,
    )
    assert accepted["source_line"] == accepted["source_end_line"] == 956
    assert accepted["event_time_display"] == accepted["recorded_time"] == "Dec 10 09:32:20"
    assert accepted["authentication_method"] == "password"
    assert accepted["time_basis"] == "source_relative"
    assert dataset.events["event_time"].is_monotonic_increasing
    assert list(dataset.events.index) == list(range(519))


def test_retained_openssh_success_is_not_suspicious_without_same_identity_failure_burst(openssh_sample):
    events = openssh_sample.events
    config = DetectionConfig()
    accepted_events = events.loc[events["outcome"] == "accepted"]
    accepted = accepted_events.iloc[0]
    matching = events.loc[events["outcome"] == "failed"]
    for field in ("dataset_id", "clock_id", "hostname", "source_ip", "account"):
        matching = matching.loc[matching[field] == accepted[field]]
    assert matching.empty
    assert detect_rules(accepted_events) == []
    detections = detect_rules(events, config)
    assert detections
    assert all(detection.rule_id == "authentication.failure_burst" for detection in detections)
    for detection in detections:
        support = events.loc[list(detection.indices)]
        assert set(support["outcome"]) == {"failed"}
        assert accepted.name not in detection.indices
        assert detection.peak_window_count >= config.failure_threshold
        for field in ("dataset_id", "clock_id", "hostname", "source_ip", "account"):
            assert support[field].nunique() == 1
        last_window = support.loc[support["event_time"].between(
            detection.last_trigger_time - config.failure_window_seconds, detection.last_trigger_time,
        )]
        assert len(last_window) >= config.failure_threshold
        reference, = source_references(events, detection.indices)
        retained_lines = {line for start, end in reference["line_ranges"] for line in range(start, end + 1)}
        assert retained_lines == set(support["source_line"])
