"""Local, single-analyst imports and explicit persisted analysis runs."""

import logging
import threading
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit

from fastapi import BackgroundTasks, Depends, FastAPI, File, HTTPException, Query, Request, Response, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.concurrency import run_in_threadpool

from agents import analyze_logs
from detection import MODEL_PATH, ModelUnavailable, load_model, model_health
from ingestion import INGESTION_VERSION, NETWORK_FILES, ROOT, IngestionError, load_authentication, load_network, load_source
from llm import explain
from rules import DetectionConfig
from sources import OPENSSH_PATH, OPENSSH_PINNED_URL, OPENSSH_URL, ensure_openssh
from storage import DATABASE_PATH, Storage, StorageError

FRONTEND_DIR = ROOT / "frontend"
IMPORT_DIR = ROOT / "data" / "imports"
# Measured preset: largest file 82,014,921 bytes / 154,877 maximum source rows;
# full preset 377,704 rows. These are per-upload/per-source, not truncation limits.
MAX_UPLOAD_BYTES = 128 * 1024 * 1024
MAX_ROWS = 500_000
AIT_URL = "https://zenodo.org/records/6610489"
Identifier = Annotated[str, Field(pattern=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
AlertStatus = Literal["new", "investigating", "resolved", "false_positive"]
IncidentStatus = Literal["open", "investigating", "closed"]


class StrictInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class PresetInput(StrictInput):
    preset_id: Literal["ait_network", "openssh"]


class AnalysisInput(StrictInput):
    dataset_id: Identifier
    config: DetectionConfig = Field(default_factory=DetectionConfig)


class AlertUpdate(StrictInput):
    status: AlertStatus


class IncidentInput(StrictInput):
    run_id: Identifier
    title: str = Field(min_length=1, max_length=160)
    notes: str = Field(default="", max_length=10000)
    alert_ids: list[Identifier] = Field(min_length=1, max_length=1000)

    @field_validator("title")
    @classmethod
    def nonblank_title(cls, value):
        if not value.strip():
            raise ValueError("Incident title cannot be blank")
        return value.strip()


class IncidentUpdate(StrictInput):
    title: str | None = Field(default=None, min_length=1, max_length=160)
    notes: str | None = Field(default=None, max_length=10000)
    status: IncidentStatus | None = None
    alert_ids: list[Identifier] | None = Field(default=None, min_length=1, max_length=1000)

    @field_validator("title")
    @classmethod
    def nonblank_title(cls, value):
        if value is not None and not value.strip():
            raise ValueError("Incident title cannot be blank")
        return value.strip() if value is not None else None


class ExplanationInput(StrictInput):
    alert_id: Identifier


def alert_filters(
    run_id: uuid.UUID | None = None,
    severity: Literal["Low", "Medium", "High", "Critical"] | None = None,
    activity_type: Literal["port_scan", "brute_force", "suspicious_login", "network_anomaly"] | None = None,
    method: Literal["rule", "ml", "both"] | None = None,
    status: AlertStatus | None = None,
    search: str | None = Query(default=None, max_length=200),
):
    return {"run_id": str(run_id) if run_id else None, "severity": severity,
            "activity_type": activity_type, "method": method, "status": status, "search": search}


class BodyLimitMiddleware:
    """Bound multipart/JSON streams before parsing, including chunked requests."""
    def __init__(self, app, upload_limit):
        self.app, self.upload_limit = app, upload_limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] not in ("POST", "PATCH", "PUT"):
            return await self.app(scope, receive, send)
        limit = self.upload_limit + 1024 * 1024 if scope["path"] == "/datasets/import" else 256 * 1024
        headers = dict(scope.get("headers", ()))
        try:
            declared = int(headers.get(b"content-length", b"0"))
        except ValueError:
            return await JSONResponse(status_code=400, content={"detail": {"code": "invalid_length", "message": "Invalid Content-Length."}})(scope, receive, send)
        if declared < 0 or declared > limit:
            return await JSONResponse(status_code=413, content={"detail": {"code": "size_limit", "message": "Request exceeds the bounded import/JSON limit."}})(scope, receive, send)
        consumed = 0

        async def bounded_receive():
            nonlocal consumed
            message = await receive()
            consumed += len(message.get("body", b""))
            if consumed > limit:
                raise HTTPException(status_code=413, detail={"code": "size_limit", "message": "Request stream exceeds the bounded import/JSON limit."})
            return message

        await self.app(scope, bounded_receive, send)


class BrowserSafetyMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        request = Request(scope)
        security_headers = {
            b"x-content-type-options": b"nosniff",
            b"referrer-policy": b"no-referrer",
            b"cross-origin-resource-policy": b"same-origin",
            b"content-security-policy": b"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
            b"cache-control": b"no-store",
        }

        async def safe_send(message):
            if message["type"] == "http.response.start":
                headers = [(key, value) for key, value in message.get("headers", ()) if key.lower() not in security_headers]
                message = {**message, "headers": headers + list(security_headers.items())}
            await send(message)

        origin = request.headers.get("origin")
        if origin and request.method in ("POST", "PATCH", "PUT", "DELETE"):
            try:
                parsed = urlsplit(origin)
                allowed = (parsed.scheme == request.url.scheme and parsed.netloc == request.url.netloc
                           and not parsed.path and not parsed.query and not parsed.fragment)
            except ValueError:
                allowed = False
            if not allowed:
                return await JSONResponse(status_code=403, content={"detail": {"code": "cross_origin", "message": "Mutation requests must originate from this local dashboard."}})(scope, receive, safe_send)
        # Pure ASGI avoids BaseHTTPMiddleware's response-disconnect listener,
        # which can drain an already rejected buffered request past its limit.
        await self.app(scope, receive, safe_send)


def create_app(
    database_path=DATABASE_PATH, import_dir=IMPORT_DIR, model_path=MODEL_PATH,
    network_files=NETWORK_FILES, auth_path=OPENSSH_PATH,
    max_upload_bytes=MAX_UPLOAD_BYTES, max_rows=MAX_ROWS,
):
    storage = Storage(database_path)
    import_dir, model_path, auth_path = Path(import_dir), Path(model_path), Path(auth_path)
    import_gate = threading.Lock()

    @asynccontextmanager
    async def lifespan(application):
        application.state.recovered_runs = storage.recover_orphans()
        yield

    application = FastAPI(title="Local Hybrid SOC Investigation API", version="2.0", lifespan=lifespan, docs_url=None, redoc_url=None)
    application.state.storage = storage
    application.add_middleware(BodyLimitMiddleware, upload_limit=max_upload_bytes)
    application.add_middleware(BrowserSafetyMiddleware)

    @application.exception_handler(IngestionError)
    async def ingestion_failure(request, exc):
        statuses = {"size_limit": 413, "row_limit": 413, "source_missing": 404,
                    "source_unavailable": 503, "source_changed": 409, "checksum_mismatch": 409,
                    "unsupported_format": 415, "notice_missing": 500}
        return JSONResponse(status_code=statuses.get(exc.code, 422), content={"detail": {"code": exc.code, "message": str(exc), "details": exc.details}})

    @application.exception_handler(StorageError)
    async def storage_failure(request, exc):
        return JSONResponse(status_code=exc.status_code, content={"detail": {"code": exc.code, "message": str(exc), "details": exc.details}})

    @application.exception_handler(RequestValidationError)
    async def validation_failure(request, exc):
        errors = [{"location": list(error["loc"]), "message": error["msg"], "type": error["type"]} for error in exc.errors()]
        return JSONResponse(status_code=422, content={"detail": {"code": "validation_error", "message": "Request parameters are invalid.", "details": errors}})

    def frontend_file(name, media_type):
        path = FRONTEND_DIR / name
        if not path.is_file():
            raise HTTPException(503, {"code": "dashboard_unavailable", "message": "Browser dashboard assets are not installed."})
        return FileResponse(path, media_type=media_type)

    @application.get("/")
    def dashboard():
        return frontend_file("index.html", "text/html")

    @application.get("/styles.css")
    def styles():
        return frontend_file("styles.css", "text/css")

    @application.get("/dashboard.js")
    def script():
        return frontend_file("dashboard.js", "application/javascript")

    @application.get("/health")
    def health():
        return {"status": "ok", "model": model_health(model_path), "active_run": storage.active_run(),
                "limits": {"max_upload_bytes": max_upload_bytes, "max_rows": max_rows},
                "rules_defaults": DetectionConfig().model_dump()}

    @application.get("/presets")
    def presets():
        return {"items": [
            {"id": "ait_network", "name": "AIT Russellmitchell network flows", "kind": "network",
             "description": "Three immutable TCP/UDP sources. Publisher simulated-testbed annotations are evaluation context, not detector features.",
             "available": all(Path(path).is_file() for path in network_files), "source_url": AIT_URL},
            {"id": "openssh", "name": "Loghub OpenSSH authentication sample", "kind": "authentication",
             "description": "2,000 recorded syslog lines; explicit authentication attempts only. Unknown capture year/timezone, no independent attack labels.",
             "available": auth_path.is_file(), "source_url": OPENSSH_URL},
        ], "notice": "Import previews data; only an explicit Analyze action starts detection. Raw sources are not modified."}

    @application.post("/datasets/preset")
    def import_preset(data: PresetInput, response: Response):
        if not import_gate.acquire(blocking=False):
            raise HTTPException(409, {"code": "import_busy", "message": "Another import is being validated."})
        try:
            if data.preset_id == "ait_network":
                paths = list(network_files)
                dataset = load_network(paths, max_rows=max_rows, max_bytes=max_upload_bytes)
                name = "AIT Russellmitchell network flows"
                provenance = {"source_url": AIT_URL, "license": "CC BY 4.0", "provenance_type": "publisher simulated-testbed netflows"}
            else:
                paths = [ensure_openssh(auth_path)]
                dataset = load_authentication(paths[0], max_rows=max_rows, max_bytes=max_upload_bytes)
                name = "Loghub OpenSSH authentication sample"
                provenance = {"source_url": OPENSSH_URL, "pinned_source_url": OPENSSH_PINNED_URL,
                              "license": "Loghub research/academic notice; retained in data/Loghub-LICENSE.txt",
                              "provenance_type": "public lab-server sample, unlabeled authentication outcomes"}
            registered, reused = storage.register_dataset(dataset, name, paths, provenance)
            response.status_code = 200 if reused else 201
            return {"dataset": registered, "reused": reused}
        finally:
            import_gate.release()

    @application.post("/datasets/import")
    async def import_file(response: Response, file: UploadFile = File(...)):
        filename = file.filename or ""
        if not filename or "/" in filename or "\\" in filename or any(ord(char) < 32 for char in filename) or len(filename) > 160:
            await file.close()
            raise IngestionError("invalid_filename", "Use a plain filename without paths or control characters.")
        suffix = Path(filename).suffix.lower()
        if suffix not in (".csv", ".log", ".txt"):
            await file.close()
            raise IngestionError("unsupported_format", "Only recognized .csv, .log and .txt sources are importable; model artifacts are never uploads.")
        if not import_gate.acquire(blocking=False):
            await file.close()
            raise HTTPException(409, {"code": "import_busy", "message": "Another import is being validated."})
        path = import_dir / (uuid.uuid4().hex + suffix)
        keep = False
        try:
            import_dir.mkdir(parents=True, exist_ok=True)
            total = 0
            with path.open("xb") as handle:
                while chunk := await file.read(1024 * 1024):
                    total += len(chunk)
                    if total > max_upload_bytes:
                        raise IngestionError("size_limit", "Uploaded file exceeds the measured byte limit.")
                    handle.write(chunk)
            if not total:
                raise IngestionError("empty_input", "Uploaded file is empty.")
            dataset = await run_in_threadpool(load_source, path, max_rows=max_rows, max_bytes=max_upload_bytes)
            private_name = path.name
            dataset.events["source_name"] = filename
            dataset.profile["sources"][0]["name"] = filename
            dataset.warnings = [warning.replace(private_name, filename) for warning in dataset.warnings]
            registered, reused = await run_in_threadpool(storage.register_dataset, dataset, filename, [path], {"provenance_type": "analyst file import; source hash and original line references retained"})
            keep = not reused
            response.status_code = 200 if reused else 201
            return {"dataset": registered, "reused": reused}
        finally:
            try:
                await file.close()
                if not keep:
                    path.unlink(missing_ok=True)
            finally:
                import_gate.release()

    @application.get("/datasets")
    def datasets(limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
        return storage.list_datasets(limit, offset)

    @application.get("/datasets/{dataset_id}")
    def dataset_detail(dataset_id: uuid.UUID):
        return storage.get_dataset(str(dataset_id))

    def execute_run(run_id, artifact):
        try:
            storage.start_run(run_id)
            run = storage.get_run(run_id)
            dataset = storage.get_dataset(run["dataset_id"])
            if dataset["profile"]["ingestion_version"] != INGESTION_VERSION:
                raise IngestionError("source_changed", "Parser version changed since import; explicitly reimport before analysis.")
            sources = storage.dataset_sources(run["dataset_id"])
            paths = [source["file_path"] for source in sources]
            started = time.perf_counter()
            if dataset["kind"] == "network":
                ingested = load_network(paths, max_rows=max_rows, max_bytes=max_upload_bytes)
            else:
                ingested = load_authentication(paths[0], max_rows=max_rows, max_bytes=max_upload_bytes)
            ingestion_seconds = time.perf_counter() - started
            if ingested.fingerprint != dataset["fingerprint"]:
                raise IngestionError("source_changed", "Source contents changed since import; no results committed. Reimport to create a new snapshot.")
            for source in sources:
                ingested.events.loc[ingested.events["source_id"] == source["source_id"], "source_name"] = source["display_name"]
            result = analyze_logs(ingested.events, DetectionConfig(**run["config"]), artifact=artifact)
            warnings = list(dict.fromkeys(run["warnings"] + result["warnings"]))
            result["metrics"]["processing_seconds"]["ingestion"] = ingestion_seconds
            storage.complete_run(run_id, result["alerts"], {**run["counts"], **result["counts"]}, warnings, result["metrics"])
        except (IngestionError, StorageError) as exc:
            storage.fail_run(run_id, f"{exc.code}: {exc}")
        except Exception:
            logging.exception("Analysis %s failed before atomic completion", run_id)
            storage.fail_run(run_id, "analysis_failure: Analysis failed unexpectedly; no partial results committed.")

    @application.post("/analyze")
    def submit_analysis(data: AnalysisInput, background_tasks: BackgroundTasks, response: Response):
        dataset = storage.get_dataset(data.dataset_id)
        artifact, warning = None, None
        if dataset["kind"] == "network":
            try:
                artifact = load_model(model_path)
            except ModelUnavailable as exc:
                warning = "ML-unavailable: " + str(exc)
        run, reused = storage.reserve_run(data.dataset_id, data.config.model_dump(), artifact, warning)
        if not reused:
            background_tasks.add_task(execute_run, run["id"], artifact)
        response.status_code = 200 if reused else 202
        return {"run": run, "reused": reused}

    @application.get("/runs")
    def runs(dataset_id: uuid.UUID | None = None, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
        if dataset_id:
            storage.get_dataset(str(dataset_id))
        return storage.list_runs(str(dataset_id) if dataset_id else None, limit, offset)

    @application.get("/runs/{run_id}")
    def run_detail(run_id: uuid.UUID):
        return storage.get_run(str(run_id))

    @application.get("/alerts")
    def alerts(filters: dict = Depends(alert_filters), limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0)):
        if filters.get("run_id"):
            storage.get_run(filters["run_id"])
        return storage.list_alerts(filters, limit, offset)

    @application.get("/summary")
    def summary(filters: dict = Depends(alert_filters)):
        return storage.summary(filters)

    @application.get("/alerts/{alert_id}")
    def alert_detail(alert_id: uuid.UUID):
        return storage.get_alert(str(alert_id))

    @application.get("/alerts/{alert_id}/events")
    def evidence_events(alert_id: uuid.UUID, limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0)):
        return storage.alert_events(str(alert_id), limit, offset)

    @application.patch("/alerts/{alert_id}")
    def update_alert(alert_id: uuid.UUID, data: AlertUpdate):
        return storage.update_alert_status(str(alert_id), data.status)

    @application.get("/incidents")
    def incidents(run_id: uuid.UUID | None = None, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
        if run_id:
            storage.get_run(str(run_id))
        return storage.list_incidents(str(run_id) if run_id else None, limit, offset)

    @application.get("/incidents/{incident_id}")
    def incident_detail(incident_id: uuid.UUID):
        return storage.get_incident(str(incident_id))

    @application.post("/incidents", status_code=201)
    def create_incident(data: IncidentInput):
        return storage.create_incident(data.run_id, data.title, data.notes, data.alert_ids)

    @application.patch("/incidents/{incident_id}")
    def update_incident(incident_id: uuid.UUID, data: IncidentUpdate):
        return storage.update_incident(str(incident_id), data.model_dump(exclude_unset=True))

    @application.post("/explain")
    def explain_alert(data: ExplanationInput):
        alert = storage.get_alert(data.alert_id)
        context = {key: alert[key] for key in (
            "title", "activity_type", "severity_reason", "source_ip", "destination_ip", "account",
            "hostname", "first_recorded_time", "last_recorded_time", "time_basis", "methods",
        )}
        context["evidence"] = {key: alert["evidence"].get(key) for key in ("rules", "ml", "raw_examples")}
        text = explain(context, timeout=15)
        if text.startswith("LLM Error:"):
            return {"available": False, "explanation": None, "warning": text}
        return {"available": True, "explanation": text, "warning": "Optional LLM prose is not detection evidence or confirmation of an attack."}

    return application


app = create_app()
