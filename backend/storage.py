"""Task-local SQLite connections and atomic, idempotent investigation snapshots."""

import hashlib
import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from ingestion import INGESTION_VERSION, ROOT
from rules import RULE_VERSION

DATABASE_PATH = ROOT / "state" / "soc.sqlite3"
STORAGE_VERSION = 1
COMPOSITION_VERSION = "explainable-alerts-v1"
ALERT_STATUSES = ("new", "investigating", "resolved", "false_positive")
INCIDENT_STATUSES = ("open", "investigating", "closed")
SEVERITIES = ("Low", "Medium", "High", "Critical")
ACTIVITIES = ("port_scan", "brute_force", "suspicious_login", "network_anomaly")


class StorageError(ValueError):
    def __init__(self, code, message, status_code=400, details=None):
        super().__init__(message)
        self.code, self.status_code, self.details = code, status_code, details or {}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


SCHEMA = """
CREATE TABLE IF NOT EXISTS datasets (
    id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('network','authentication')),
    time_basis TEXT NOT NULL CHECK(time_basis IN ('utc','source_relative')),
    profile_json TEXT NOT NULL, warnings_json TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS imports (
    id TEXT PRIMARY KEY, dataset_id TEXT NOT NULL REFERENCES datasets(id),
    source_id TEXT NOT NULL, display_name TEXT NOT NULL, file_path TEXT NOT NULL,
    sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL, source_json TEXT NOT NULL,
    UNIQUE(dataset_id, source_id)
);
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY, dataset_id TEXT NOT NULL REFERENCES datasets(id),
    snapshot_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('pending','running','completed','failed')),
    config_json TEXT NOT NULL, model_version TEXT, model_sha256 TEXT,
    model_available INTEGER NOT NULL, counts_json TEXT NOT NULL,
    warnings_json TEXT NOT NULL, metrics_json TEXT NOT NULL, error TEXT,
    created_at TEXT NOT NULL, started_at TEXT, completed_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS one_active_run ON runs ((1))
    WHERE state IN ('pending','running');
CREATE UNIQUE INDEX IF NOT EXISTS completed_snapshot ON runs(snapshot_id)
    WHERE state = 'completed';
CREATE INDEX IF NOT EXISTS run_dataset_time ON runs(dataset_id, created_at DESC);
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id),
    activity_type TEXT NOT NULL, title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('Low','Medium','High','Critical')),
    severity_reason TEXT NOT NULL,
    source_ip TEXT NOT NULL, destination_ip TEXT NOT NULL, account TEXT NOT NULL,
    hostname TEXT NOT NULL, protocol TEXT NOT NULL,
    first_event_time REAL NOT NULL, last_event_time REAL NOT NULL,
    first_recorded_time TEXT NOT NULL, last_recorded_time TEXT NOT NULL,
    time_basis TEXT NOT NULL CHECK(time_basis IN ('utc','source_relative')),
    occurrence_count INTEGER NOT NULL CHECK(occurrence_count > 0),
    methods_json TEXT NOT NULL, method TEXT NOT NULL CHECK(method IN ('rule','ml','both')),
    evidence_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('new','investigating','resolved','false_positive')),
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS alert_run_filter ON alerts(run_id, severity, activity_type, status);
CREATE INDEX IF NOT EXISTS alert_run_time ON alerts(run_id, last_event_time DESC);
CREATE INDEX IF NOT EXISTS alert_summary_cover ON alerts(run_id, severity, activity_type, status, method);
CREATE INDEX IF NOT EXISTS alert_queue_order ON alerts(
    run_id, CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END,
    last_event_time DESC, id
);
CREATE TABLE IF NOT EXISTS alert_events (
    alert_id TEXT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL, event_json TEXT NOT NULL,
    PRIMARY KEY(alert_id, ordinal)
);
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id),
    title TEXT NOT NULL, notes TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('open','investigating','closed')),
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incident_alerts (
    incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    alert_id TEXT NOT NULL REFERENCES alerts(id), PRIMARY KEY(incident_id, alert_id)
);
CREATE TRIGGER IF NOT EXISTS coherent_incident BEFORE INSERT ON incident_alerts
WHEN (SELECT run_id FROM incidents WHERE id = NEW.incident_id)
  <> (SELECT run_id FROM alerts WHERE id = NEW.alert_id)
BEGIN SELECT RAISE(ABORT, 'Incident members must belong to the same run'); END;
"""


class Storage:
    def __init__(self, path=DATABASE_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, STORAGE_VERSION):
                raise StorageError("database_version", "Incompatible database schema; existing investigation state has not been changed.", 500)
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(SCHEMA)
            connection.execute(f"PRAGMA user_version={STORAGE_VERSION}")

    @contextmanager
    def connection(self, write=False):
        connection = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=15000")
        try:
            if write:
                connection.execute("BEGIN IMMEDIATE")
            yield connection
            if write:
                connection.commit()
        except Exception:
            if write:
                connection.rollback()
            raise
        finally:
            connection.close()

    def register_dataset(self, dataset, name, paths, provenance=None):
        identifier = str(uuid.uuid5(uuid.NAMESPACE_URL, "soc-dataset:" + dataset.fingerprint))
        sources = dataset.profile["sources"]
        if len(paths) != len(sources):
            raise StorageError("invalid_import", "Source path/provenance count does not match the imported dataset.")
        with self.connection(write=True) as connection:
            existing = connection.execute("SELECT id FROM datasets WHERE fingerprint=?", (dataset.fingerprint,)).fetchone()
            if existing:
                return self._dataset(connection, existing["id"]), True
            connection.execute(
                "INSERT INTO datasets VALUES (?,?,?,?,?,?,?,?)",
                (identifier, dataset.fingerprint, name, dataset.profile["kind"], dataset.profile["time_basis"],
                 encode(dataset.profile), encode(dataset.warnings), utc_now()),
            )
            for path, source in zip(paths, sources):
                source_record = {**source, **(provenance or {})}
                import_id = str(uuid.uuid5(uuid.NAMESPACE_URL, identifier + ":" + source["source_id"]))
                connection.execute(
                    "INSERT OR IGNORE INTO imports VALUES (?,?,?,?,?,?,?,?)",
                    (import_id, identifier, source["source_id"], source["name"], str(Path(path).resolve()),
                     source["sha256"], source["bytes"], encode(source_record)),
                )
            return self._dataset(connection, identifier), False

    def _dataset(self, connection, identifier):
        row = connection.execute("SELECT * FROM datasets WHERE id=?", (identifier,)).fetchone()
        if row is None:
            raise StorageError("dataset_not_found", "Dataset not found.", 404)
        profile = json.loads(row["profile_json"])
        return {
            "id": row["id"], "name": row["name"], "kind": row["kind"], "time_basis": row["time_basis"],
            "fingerprint": row["fingerprint"], "created_at": row["created_at"],
            **{key: profile[key] for key in (
                "raw_count", "eligible_count", "skipped_count", "duplicate_count", "rejected_count", "ignored_count"
            )},
            "profile": profile, "warnings": json.loads(row["warnings_json"]),
            "sources": [json.loads(source["source_json"]) for source in connection.execute(
                "SELECT source_json FROM imports WHERE dataset_id=? ORDER BY display_name", (identifier,)
            )],
        }

    def get_dataset(self, identifier):
        with self.connection() as connection:
            return self._dataset(connection, identifier)

    def dataset_sources(self, identifier):
        with self.connection() as connection:
            self._dataset(connection, identifier)
            return [dict(row) for row in connection.execute(
                "SELECT * FROM imports WHERE dataset_id=? ORDER BY display_name", (identifier,)
            )]

    def list_datasets(self, limit=50, offset=0):
        with self.connection() as connection:
            total = connection.execute("SELECT COUNT(*) FROM datasets").fetchone()[0]
            identifiers = connection.execute("SELECT id FROM datasets ORDER BY created_at DESC, id LIMIT ? OFFSET ?", (limit, offset))
            return {"items": [self._dataset(connection, row["id"]) for row in identifiers], "total": total, "limit": limit, "offset": offset}

    def reserve_run(self, dataset_id, config, model=None, ml_warning=None):
        with self.connection(write=True) as connection:
            dataset = self._dataset(connection, dataset_id)
            identity = {
                "dataset_fingerprint": dataset["fingerprint"], "ingestion_version": INGESTION_VERSION,
                "rule_version": RULE_VERSION, "composition_version": COMPOSITION_VERSION,
                "config": config, "model_version": model.version if model else None,
                "model_sha256": model.artifact_sha256 if model else None,
                "model_state": "available" if model else ("not_applicable" if dataset["kind"] == "authentication" else "unavailable"),
            }
            snapshot = hashlib.sha256(encode(identity).encode("utf-8")).hexdigest()
            completed = connection.execute("SELECT id FROM runs WHERE snapshot_id=? AND state='completed'", (snapshot,)).fetchone()
            if completed:
                return self._run(connection, completed["id"]), True
            active = connection.execute("SELECT id,state FROM runs WHERE state IN ('pending','running')").fetchone()
            if active:
                raise StorageError("active_run", "Only one analysis may run at a time.", 409, {"run_id": active["id"], "state": active["state"]})
            run_id = str(uuid.uuid4())
            counts = {
                "raw": dataset["raw_count"], "eligible": dataset["eligible_count"], "skipped": dataset["skipped_count"],
                "duplicate": dataset["duplicate_count"], "rejected": dataset["rejected_count"], "ignored": dataset["ignored_count"],
                "network": dataset["eligible_count"] if dataset["kind"] == "network" else 0,
                "authentication": dataset["eligible_count"] if dataset["kind"] == "authentication" else 0,
                "ml_evaluated": 0, "ml_anomalies": 0, "rule_supported_events": 0, "alerts": 0,
            }
            warnings = list(dataset["warnings"])
            if ml_warning:
                warnings.append(ml_warning)
            connection.execute(
                "INSERT INTO runs VALUES (?,?,?,'pending',?,?,?,?,?,?,?,NULL,?,NULL,NULL)",
                (run_id, dataset_id, snapshot, encode(config), model.version if model else None,
                 model.artifact_sha256 if model else None, int(model is not None), encode(counts),
                 encode(warnings), encode({}), utc_now()),
            )
            return self._run(connection, run_id), False

    def _run(self, connection, identifier):
        row = connection.execute(
            "SELECT r.*, d.name AS dataset_name FROM runs r JOIN datasets d ON d.id=r.dataset_id WHERE r.id=?", (identifier,)
        ).fetchone()
        if row is None:
            raise StorageError("run_not_found", "Analysis run not found.", 404)
        result = dict(row)
        for field in ("config", "counts", "warnings", "metrics"):
            result[field] = json.loads(result.pop(field + "_json"))
        result["model_available"] = bool(result["model_available"])
        return result

    def get_run(self, identifier):
        with self.connection() as connection:
            return self._run(connection, identifier)

    def list_runs(self, dataset_id=None, limit=50, offset=0):
        where, parameters = (" WHERE dataset_id=?", [dataset_id]) if dataset_id else ("", [])
        with self.connection() as connection:
            total = connection.execute("SELECT COUNT(*) FROM runs" + where, parameters).fetchone()[0]
            rows = connection.execute("SELECT id FROM runs" + where + " ORDER BY created_at DESC,id LIMIT ? OFFSET ?", parameters + [limit, offset])
            return {"items": [self._run(connection, row["id"]) for row in rows], "total": total, "limit": limit, "offset": offset}

    def active_run(self):
        with self.connection() as connection:
            row = connection.execute("SELECT id,state FROM runs WHERE state IN ('pending','running')").fetchone()
            return dict(row) if row else None

    def start_run(self, identifier):
        with self.connection(write=True) as connection:
            changed = connection.execute("UPDATE runs SET state='running',started_at=? WHERE id=? AND state='pending'", (utc_now(), identifier)).rowcount
            if not changed:
                raise StorageError("run_state", "Run is no longer pending.", 409)

    def complete_run(self, identifier, alerts, counts, warnings, metrics):
        columns = (
            "activity_type", "title", "severity", "severity_reason", "source_ip", "destination_ip", "account",
            "hostname", "protocol", "first_event_time", "last_event_time", "first_recorded_time",
            "last_recorded_time", "time_basis", "occurrence_count",
        )
        with self.connection(write=True) as connection:
            run = self._run(connection, identifier)
            if run["state"] != "running":
                raise StorageError("run_state", "Run is no longer running; no partial results committed.", 409)
            now = utc_now()
            for alert in alerts:
                alert_id = str(uuid.uuid5(uuid.NAMESPACE_URL, identifier + ":" + alert["dedup_key"]))
                methods = sorted(set(alert["methods"]))
                method = "both" if len(methods) == 2 else methods[0]
                values = (alert_id, identifier) + tuple(alert[key] for key in columns) + (
                    encode(methods), method, encode(alert["evidence"]), "new", now, now,
                )
                connection.execute("INSERT INTO alerts VALUES (" + ",".join("?" for _ in values) + ")", values)
                connection.executemany("INSERT INTO alert_events VALUES (?,?,?)", (
                    (alert_id, ordinal, encode(event)) for ordinal, event in enumerate(alert.get("raw_events", ()))
                ))
            counts = {**counts, "alerts": len(alerts)}
            connection.execute(
                "UPDATE runs SET state='completed',counts_json=?,warnings_json=?,metrics_json=?,model_available=?,completed_at=? WHERE id=?",
                (encode(counts), encode(warnings), encode(metrics), int(metrics.get("ml_available", run["model_available"])), now, identifier),
            )

    def fail_run(self, identifier, message):
        with self.connection(write=True) as connection:
            connection.execute(
                "UPDATE runs SET state='failed',error=?,completed_at=? WHERE id=? AND state IN ('pending','running')",
                (message[:2000], utc_now(), identifier),
            )

    def recover_orphans(self):
        with self.connection(write=True) as connection:
            return connection.execute(
                "UPDATE runs SET state='failed',error=?,completed_at=? WHERE state IN ('pending','running')",
                ("Interrupted by application restart before atomic completion. Explicitly analyze again to retry.", utc_now()),
            ).rowcount

    def _alert_where(self, filters):
        clauses, parameters = [], []
        for field in ("run_id", "severity", "activity_type", "status"):
            if filters.get(field):
                clauses.append(f"{field}=?")
                parameters.append(filters[field])
        method = filters.get("method")
        if method:
            clauses.append("method IN (?, 'both')" if method in ("rule", "ml") else "method=?")
            parameters.append(method)
        if filters.get("search"):
            search = filters["search"].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            fields = ("source_ip", "destination_ip", "account", "hostname", "title")
            clauses.append("(" + " OR ".join(field + " LIKE ? ESCAPE '\\'" for field in fields) + ")")
            parameters.extend(["%" + search + "%"] * len(fields))
        return (" WHERE " + " AND ".join(clauses) if clauses else ""), parameters

    def _alert(self, row, detail=False):
        result = dict(row)
        result["methods"] = json.loads(result.pop("methods_json"))
        result.pop("method", None)
        evidence = result.pop("evidence_json", None)
        if detail:
            result["evidence"] = json.loads(evidence)
            result["evidence"]["raw_events_url"] = "/alerts/" + result["id"] + "/events"
        return result

    def list_alerts(self, filters=None, limit=25, offset=0):
        where, parameters = self._alert_where(filters or {})
        projection = ("id,run_id,activity_type,title,severity,severity_reason,source_ip,destination_ip,account,hostname,protocol,"
                      "first_event_time,last_event_time,first_recorded_time,last_recorded_time,time_basis,occurrence_count,"
                      "methods_json,status,created_at,updated_at")
        with self.connection() as connection:
            total = connection.execute("SELECT COUNT(*) FROM alerts" + where, parameters).fetchone()[0]
            rows = connection.execute(
                "SELECT " + projection + " FROM alerts" + where + " ORDER BY CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END,last_event_time DESC,id LIMIT ? OFFSET ?",
                parameters + [limit, offset],
            )
            return {"items": [self._alert(row) for row in rows], "total": total, "limit": limit, "offset": offset}

    def get_alert(self, identifier):
        with self.connection() as connection:
            row = connection.execute("SELECT * FROM alerts WHERE id=?", (identifier,)).fetchone()
            if row is None:
                raise StorageError("alert_not_found", "Alert not found.", 404)
            return self._alert(row, detail=True)

    def alert_events(self, identifier, limit=25, offset=0):
        with self.connection() as connection:
            if not connection.execute("SELECT 1 FROM alerts WHERE id=?", (identifier,)).fetchone():
                raise StorageError("alert_not_found", "Alert not found.", 404)
            total = connection.execute("SELECT COUNT(*) FROM alert_events WHERE alert_id=?", (identifier,)).fetchone()[0]
            rows = connection.execute("SELECT event_json FROM alert_events WHERE alert_id=? ORDER BY ordinal LIMIT ? OFFSET ?", (identifier, limit, offset))
            return {"items": [json.loads(row[0]) for row in rows], "total": total, "limit": limit, "offset": offset}

    def summary(self, filters=None):
        filters = filters or {}
        where, parameters = self._alert_where(filters)
        result = {"severity_counts": {level: 0 for level in SEVERITIES}, "activity_counts": {}, "method_counts": {}, "status_counts": {}}
        with self.connection() as connection:
            result["alert_count"] = 0
            # One covering-index aggregation, independent of page size and the
            # large evidence payloads stored alongside each alert.
            rows = connection.execute(
                "SELECT severity,activity_type,status,method,COUNT(*) AS count FROM alerts" + where +
                " GROUP BY severity,activity_type,status,method", parameters,
            )
            for row in rows:
                result["alert_count"] += row["count"]
                for column, output in (("severity", "severity_counts"), ("activity_type", "activity_counts"), ("method", "method_counts"), ("status", "status_counts")):
                    result[output][row[column]] = result[output].get(row[column], 0) + row["count"]
            result["event_counts"] = self._run(connection, filters["run_id"])["counts"] if filters.get("run_id") else {}
        return result

    def update_alert_status(self, identifier, status):
        if status not in ALERT_STATUSES:
            raise StorageError("invalid_status", "Invalid alert status.", 422)
        with self.connection(write=True) as connection:
            if not connection.execute("UPDATE alerts SET status=?,updated_at=? WHERE id=?", (status, utc_now(), identifier)).rowcount:
                raise StorageError("alert_not_found", "Alert not found.", 404)
        return self.get_alert(identifier)

    def _incident(self, connection, identifier):
        row = connection.execute("SELECT * FROM incidents WHERE id=?", (identifier,)).fetchone()
        if row is None:
            raise StorageError("incident_not_found", "Incident not found.", 404)
        result = dict(row)
        result["alert_ids"] = [row[0] for row in connection.execute("SELECT alert_id FROM incident_alerts WHERE incident_id=? ORDER BY alert_id", (identifier,))]
        return result

    def get_incident(self, identifier):
        with self.connection() as connection:
            return self._incident(connection, identifier)

    def list_incidents(self, run_id=None, limit=50, offset=0):
        where, parameters = (" WHERE run_id=?", [run_id]) if run_id else ("", [])
        with self.connection() as connection:
            total = connection.execute("SELECT COUNT(*) FROM incidents" + where, parameters).fetchone()[0]
            rows = connection.execute("SELECT id FROM incidents" + where + " ORDER BY updated_at DESC,id LIMIT ? OFFSET ?", parameters + [limit, offset])
            return {"items": [self._incident(connection, row["id"]) for row in rows], "total": total, "limit": limit, "offset": offset}

    def _membership(self, connection, incident_id, run_id, alert_ids):
        alert_ids = list(dict.fromkeys(alert_ids))
        if not alert_ids:
            raise StorageError("empty_incident", "An incident must group at least one alert.", 422)
        for alert_id in alert_ids:
            row = connection.execute("SELECT run_id FROM alerts WHERE id=?", (alert_id,)).fetchone()
            if row is None or row["run_id"] != run_id:
                raise StorageError("incoherent_incident", "Incident members must belong to the same coherent source/run.", 422)
        connection.execute("DELETE FROM incident_alerts WHERE incident_id=?", (incident_id,))
        connection.executemany("INSERT INTO incident_alerts VALUES (?,?)", ((incident_id, alert_id) for alert_id in alert_ids))

    def create_incident(self, run_id, title, notes, alert_ids):
        with self.connection(write=True) as connection:
            run = self._run(connection, run_id)
            if run["state"] != "completed":
                raise StorageError("run_incomplete", "Incident creation requires a completed analysis run.", 409)
            incident_id, now = str(uuid.uuid4()), utc_now()
            connection.execute("INSERT INTO incidents VALUES (?,?,?,?,'open',?,?)", (incident_id, run_id, title, notes, now, now))
            self._membership(connection, incident_id, run_id, alert_ids)
            return self._incident(connection, incident_id)

    def update_incident(self, identifier, changes):
        if changes.get("status") is not None and changes["status"] not in INCIDENT_STATUSES:
            raise StorageError("invalid_status", "Invalid incident status.", 422)
        with self.connection(write=True) as connection:
            incident = self._incident(connection, identifier)
            for field in ("title", "notes", "status"):
                if changes.get(field) is not None:
                    incident[field] = changes[field]
            connection.execute("UPDATE incidents SET title=?,notes=?,status=?,updated_at=? WHERE id=?", (incident["title"], incident["notes"], incident["status"], utc_now(), identifier))
            if changes.get("alert_ids") is not None:
                self._membership(connection, identifier, incident["run_id"], changes["alert_ids"])
            return self._incident(connection, identifier)
