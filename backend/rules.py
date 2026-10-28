"""Known-pattern suspicion rules. Network states are not authentication outcomes."""

from collections import Counter, deque
from dataclasses import dataclass, field

from pydantic import BaseModel, ConfigDict, Field

RULE_VERSION = "event-windows-v1"


class DetectionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    failure_threshold: int = Field(default=5, ge=2, le=1000)
    failure_window_seconds: int = Field(default=300, ge=1, le=86400)
    scan_port_threshold: int = Field(default=20, ge=2, le=65536)
    scan_window_seconds: int = Field(default=60, ge=1, le=3600)
    success_window_seconds: int = Field(default=300, ge=1, le=86400)
    auth_cooldown_seconds: int = Field(default=300, ge=0, le=86400)
    scan_cooldown_seconds: int = Field(default=60, ge=0, le=86400)
    ml_bucket_seconds: int = Field(default=60, ge=1, le=3600)


@dataclass
class RuleDetection:
    rule_id: str
    activity_type: str
    indices: set[int]
    thresholds: dict
    trigger_time: float
    last_trigger_time: float
    last_seen: float
    peak_window_count: int = 0
    unique_ports: set[int] = field(default_factory=set)


def detect_rules(events, config=None):
    config = config or DetectionConfig()
    detections = []
    if events.empty:
        return detections
    network = events.loc[events["kind"] == "network"]
    network_keys = ["dataset_id", "source_ip", "destination_ip", "protocol"]
    for _, group in network.groupby(network_keys, sort=False, dropna=False):
        window, ports, active = deque(), Counter(), None
        cooldown = max(config.scan_cooldown_seconds, config.scan_window_seconds)
        ordered = group.sort_values(["event_time", "source_line"], kind="stable")
        for row in ordered[["event_time", "destination_port"]].itertuples():
            index, timestamp, port = int(row.Index), float(row.event_time), int(row.destination_port)
            lower = timestamp - config.scan_window_seconds
            while window and window[0][0] < lower:
                _, _, expired_port = window.popleft()
                ports[expired_port] -= 1
                if not ports[expired_port]:
                    del ports[expired_port]
            window.append((timestamp, index, port))
            ports[port] += 1
            if active is not None and timestamp - active.last_seen > cooldown:
                active = None
            if len(ports) >= config.scan_port_threshold:
                if active is None:
                    active = RuleDetection(
                        "network.port_scan", "port_scan", set(), {
                            "distinct_port_threshold": config.scan_port_threshold,
                            "window_seconds": config.scan_window_seconds,
                            "effective_cooldown_seconds": cooldown,
                            "bounds": "inclusive [current-window, current]",
                        }, timestamp, timestamp, timestamp,
                    )
                    detections.append(active)
                active.indices.update(item[1] for item in window)
                active.unique_ports.update(item[2] for item in window)
                active.peak_window_count = max(active.peak_window_count, len(ports))
                active.last_trigger_time = timestamp
            if active is not None:
                active.indices.add(index)
                active.unique_ports.add(port)
                active.last_seen = timestamp

    auth = events.loc[events["kind"] == "authentication"]
    auth_keys = ["dataset_id", "clock_id", "hostname", "source_ip", "account"]
    for _, group in auth.groupby(auth_keys, sort=False, dropna=False):
        failures, active, suspicious = deque(), None, None
        cooldown = max(config.auth_cooldown_seconds, config.failure_window_seconds)
        ordered = group.sort_values(["event_time", "source_line"], kind="stable")
        for row in ordered[["event_time", "outcome"]].itertuples():
            index, timestamp = int(row.Index), float(row.event_time)
            while failures and failures[0][0] < timestamp - config.failure_window_seconds:
                failures.popleft()
            if row.outcome == "failed":
                failures.append((timestamp, index))
                if active is not None and timestamp - active.last_seen > cooldown:
                    active, suspicious = None, None
                if len(failures) >= config.failure_threshold:
                    if active is None:
                        active = RuleDetection(
                            "authentication.failure_burst", "brute_force", set(), {
                                "failure_threshold": config.failure_threshold,
                                "window_seconds": config.failure_window_seconds,
                                "effective_cooldown_seconds": cooldown,
                                "bounds": "inclusive [current-window, current]",
                            }, timestamp, timestamp, timestamp,
                        )
                        detections.append(active)
                    active.indices.update(item[1] for item in failures)
                    active.peak_window_count = max(active.peak_window_count, len(failures))
                    active.last_trigger_time = timestamp
                if active is not None:
                    active.indices.add(index)
                    active.last_seen = timestamp
            elif row.outcome == "accepted" and active is not None:
                if 0 <= timestamp - active.last_trigger_time <= config.success_window_seconds:
                    if suspicious is None or timestamp - suspicious.last_seen > cooldown:
                        suspicious = RuleDetection(
                            "authentication.success_after_burst", "suspicious_login", set(), {
                                "failure_threshold": config.failure_threshold,
                                "failure_window_seconds": config.failure_window_seconds,
                                "success_after_burst_seconds": config.success_window_seconds,
                                "bounds": "inclusive; accepted event follows a detected failure burst",
                            }, timestamp, timestamp, timestamp,
                        )
                        detections.append(suspicious)
                    suspicious.indices.update(active.indices)
                    suspicious.indices.add(index)
                    suspicious.peak_window_count = max(suspicious.peak_window_count, active.peak_window_count)
                    suspicious.last_trigger_time = timestamp
                    suspicious.last_seen = timestamp
    return detections
