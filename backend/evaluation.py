"""Publisher-label experiment, separate from detector inputs and alert confidence."""

import numpy as np
import pandas as pd

from ingestion import source_references

LABEL_MAPPING_VERSION = "ait-notebook-exact-labels-v1"
LABEL_NOTEBOOK_URL = "https://zenodo.org/api/records/6610489/files/2_label_logs.ipynb/content"
BENIGN_LABELS = frozenset((
    "browsing/update", "benign_share", "mail", "monitoring", "HTTP(S) intra", "HTTP(S) DMZ",
    "SSH", "proxy", "HTTPS", "HTTP", "DNS", "update/command on unassigned port",
    "broken flow - benign", "NTP", "bootp", "OpenVPN", "STUN VoIP", "NetBIOS", "QUIC",
    "mDNS", "mDNSv6", "GoogleDNS", "systemd-resolver (local)", "benign DNS",
    "benign DNS - attacker requesting updates",
))
ATTACK_LABELS = frozenset((
    "data exfiltration", "dirb_scan", "dns_brute_force_start", "host_discover_dmz",
    "host_discover_local", "online_cracking", "service_scan", "upload_rce_shell", "wpscan",
    "check_cpuinfo", "check_date", "check_df", "check_id", "check_last", "check_meminfo",
    "check_netstat_l", "check_netstat_nat", "check_netstat_t", "check_network_config",
    "check_ps_a", "check_release", "check_uname_a", "check_uname_r", "check_uptime",
    "check_user_id", "check_who", "check_whoami", "check_wp_config", "clear", "dump_wp_users",
    "list_home", "list_web_dir", "list_www", "read_group", "read_passwd", "read_profile",
    "read_resolv", "vpn_connect", "traceroute", "run_cracking",
))
LABEL_MAP = {**{label: 0 for label in BENIGN_LABELS}, **{label: 1 for label in ATTACK_LABELS}}
PARTITIONS = {
    "train": ("2022-01-21T00:00:00Z", "2022-01-23T00:00:00Z"),
    "validation": ("2022-01-23T00:00:00Z", "2022-01-24T00:00:00Z"),
    "test": ("2022-01-24T00:00:00Z", "2022-01-25T00:00:00Z"),
}


def publisher_targets(labels):
    """0 benign, 1 attack-related, -1 unknown. Never infer labels from roles."""
    return pd.Series(labels).map(LABEL_MAP).fillna(-1).to_numpy(dtype=np.int8)


def partition_events(events):
    parts = pd.Series("outside", index=events.index, dtype=object)
    boundaries = set()
    for name, (start, end) in PARTITIONS.items():
        lower, upper = pd.Timestamp(start).timestamp(), pd.Timestamp(end).timestamp()
        parts.loc[(events["event_time"] >= lower) & (events["event_time"] < upper)] = name
        boundaries.update((lower, upper))
    spanning = pd.Series(False, index=events.index)
    for boundary in boundaries:
        spanning |= (events["event_time"] < boundary) & (events["end_time"] >= boundary)

    overlaps = set()
    keys = ["dataset_id", "source_ip", "destination_ip", "source_port", "destination_port", "protocol"]
    for _, group in events.groupby(keys, sort=False, dropna=False):
        if parts.loc[group.index].nunique() < 2:
            continue
        component, component_end, component_parts = [], -np.inf, set()
        for row in group.sort_values("event_time", kind="stable")[["event_time", "end_time"]].itertuples():
            if row.event_time > component_end:
                if len(component_parts) > 1:
                    overlaps.update(component)
                component, component_parts = [], set()
                component_end = -np.inf
            component.append(int(row.Index))
            component_parts.add(parts.at[row.Index])
            component_end = max(component_end, row.end_time)
        if len(component_parts) > 1:
            overlaps.update(component)
    overlap_mask = events.index.isin(overlaps)
    excluded = spanning | overlap_mask
    initial_counts = parts.value_counts().to_dict()
    parts.loc[excluded] = "excluded_overlap"
    targets = publisher_targets(events["evaluation_label"])
    report = {
        "date_partitions_utc": {key: list(value) for key, value in PARTITIONS.items()},
        "initial_partition_counts": {str(k): int(v) for k, v in initial_counts.items()},
        "boundary_spanning_flow_count": int(spanning.sum()),
        "cross_partition_overlapping_connection_count": int(overlap_mask.sum()),
        "excluded_overlap_flow_count": int(excluded.sum()),
        "partition_counts": {},
        "unknown_label_count": int((targets == -1).sum()),
        "label_mapping_version": LABEL_MAPPING_VERSION, "label_notebook_url": LABEL_NOTEBOOK_URL,
        "overlap_policy": "Deduplicate exact exporter observations first; exclude boundary-spanning flows and all overlapping same-5-tuple components spanning partitions. Nonoverlapping tuple reuse is not automatically a duplicate.",
    }
    for name in ("train", "validation", "test", "outside", "excluded_overlap"):
        selected = parts == name
        report["partition_counts"][name] = {
            "total": int(selected.sum()), "publisher_benign": int((selected & (targets == 0)).sum()),
            "publisher_attack_related": int((selected & (targets == 1)).sum()),
            "unknown": int((selected & (targets == -1)).sum()),
        }
    return parts, targets, report


def binary_metrics(truth, detected):
    truth, detected = np.asarray(truth, dtype=bool), np.asarray(detected, dtype=bool)
    tp, fp = int((truth & detected).sum()), int((~truth & detected).sum())
    fn, tn = int((truth & ~detected).sum()), int((~truth & ~detected).sum())
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None
    return {
        "units": len(truth), "true_positive": tp, "false_positive": fp,
        "false_negative": fn, "true_negative": tn,
        "precision": precision, "recall": recall, "f1": f1,
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
    }


def raw_network_example(row):
    fields = (
        "source_id", "source_name", "source_line", "source_end_line", "event_time_display",
        "recorded_time", "source_ip", "source_port", "destination_ip", "destination_port",
        "protocol", "connection_state", "client_bytes", "server_bytes", "client_packets",
        "server_packets", "duration_ms",
    )
    result = {}
    for key in fields:
        value = row.get(key)
        if isinstance(value, np.generic):
            value = value.item()
        if isinstance(value, float) and not np.isfinite(value):
            value = None
        result[key] = value
    return result


def evaluate_network(events, predictions, margins, detections, unit_seconds=60):
    events = events.reset_index(drop=True)
    targets = publisher_targets(events["evaluation_label"])
    anomaly = np.asarray(predictions) == -1
    known = targets >= 0
    rule_mask = np.zeros(len(events), dtype=bool)
    for detection in detections:
        rule_mask[list(detection.indices)] = True
    report = {
        "ground_truth": "publisher annotations, not independently adjudicated attacks",
        "unknown_flows_excluded": int((~known).sum()),
        "per_flow_ml": binary_metrics(targets[known] == 1, anomaly[known]),
        "ml_anomaly_flow_count": int(anomaly.sum()),
        "rule_supported_flow_count": int(rule_mask.sum()),
        "counts_by_label": {}, "counts_by_protocol": {},
    }
    for field, output in (("evaluation_label", "counts_by_label"), ("protocol", "counts_by_protocol")):
        for value, group in events.groupby(field, sort=True):
            indices = group.index.to_numpy()
            eligible = indices[known[indices]]
            report[output][str(value)] = {
                "flows": len(indices), "known_flows": len(eligible),
                "ml_flagged": int(anomaly[indices].sum()),
                "ml_only_flagged": int((anomaly[indices] & ~rule_mask[indices]).sum()),
                "attack_related_missed_by_ml": int(((targets[indices] == 1) & ~anomaly[indices]).sum()),
                "metrics": binary_metrics(targets[eligible] == 1, anomaly[eligible]),
            }
    units = events[["dataset_id", "source_ip", "destination_ip", "protocol"]].copy()
    units["bucket"] = np.floor(events["event_time"] / unit_seconds).astype(np.int64)
    units["truth"] = targets
    units["unknown"] = ~known
    units["rule"] = rule_mask
    units["ml"] = anomaly
    unit_keys = ["dataset_id", "source_ip", "destination_ip", "protocol", "bucket"]
    grouped = units.groupby(unit_keys, sort=False).agg(
        truth=("truth", "max"), unknown=("unknown", "any"), rule=("rule", "any"), ml=("ml", "any"),
        flow_count=("truth", "size"),
    )
    eligible_units = grouped.loc[~grouped["unknown"]]
    truth = eligible_units["truth"].to_numpy() == 1
    report["fixed_unit_comparison"] = {
        "unit": f"{unit_seconds}-second UTC source/destination/transport groups",
        "truth_policy": "attack-related if any flow has a known attack label; groups containing unknown labels excluded",
        "total_groups": len(grouped), "unknown_groups_excluded": int(grouped["unknown"].sum()),
        "rules_only": binary_metrics(truth, eligible_units["rule"]),
        "ml_only": binary_metrics(truth, eligible_units["ml"]),
        "combined": binary_metrics(truth, eligible_units["rule"] | eligible_units["ml"]),
        "ml_only_attack_related_groups": int(((eligible_units["truth"] == 1) & eligible_units["ml"] & ~eligible_units["rule"]).sum()),
    }
    group_rule = units.groupby(unit_keys)["rule"].transform("any").to_numpy()
    group_unknown = units.groupby(unit_keys)["unknown"].transform("any").to_numpy()
    candidates = np.flatnonzero((targets == 1) & anomaly & ~group_rule & ~group_unknown)
    candidates = sorted(candidates, key=lambda index: float(margins[index]), reverse=True)[:10]
    report["complementary_ml_examples"] = [
        {
            "raw_evidence": raw_network_example(events.iloc[index]),
            "publisher_annotation": events.iloc[index]["evaluation_label"],
            "centered_margin": float(margins[index]),
            "source_references": source_references(events, [index]),
            "implemented_rule_covered_flow_or_group": False,
            "interpretation": "Network anomaly outside the implemented port-scan rule; publisher annotation is evaluation context, not a model-predicted attack name.",
        } for index in candidates
    ]
    report["complementary_behavior_demonstrated"] = bool(candidates)
    report["limitations"] = [
        "AIT is a recorded simulated testbed; scores are not probabilities and do not establish production accuracy.",
        "Publisher TCP labels use role/time-window heuristics; UDP data exfiltration is a residual label even on January 21-23.",
        "Authentication detection is evaluated with controlled rule cases and sample evidence, not these network labels.",
        "The six features and 1% normal-validation budget were specified before examining the held-out results; do not tune on this final test period.",
    ]
    return report
