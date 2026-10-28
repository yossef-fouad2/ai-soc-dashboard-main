(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const DEFAULTS = Object.freeze({
    failure_threshold: 5,
    failure_window_seconds: 300,
    scan_port_threshold: 20,
    scan_window_seconds: 60,
    success_window_seconds: 300,
    auth_cooldown_seconds: 300,
    scan_cooldown_seconds: 60,
    ml_bucket_seconds: 60
  });
  const ACTIVITIES = {
    port_scan: "Port Scan",
    brute_force: "Brute Force",
    suspicious_login: "Suspicious Login",
    network_anomaly: "Network Anomaly"
  };
  const ALERT_STATUSES = ["new", "investigating", "resolved", "false_positive"];
  const COUNT_FORMAT = new Intl.NumberFormat("en-US");
  const state = {
    health: null,
    healthError: null,
    presets: [],
    datasets: [],
    runs: [],
    datasetId: "",
    runId: "",
    run: null,
    activeRun: null,
    loaded: { presets: false, datasets: false, runs: false, alerts: false, incidents: false },
    busy: { refresh: false, preset: false, file: false, analyze: false, alerts: false, incidents: false, incidentSave: false, dataset: false, run: false },
    filters: { severity: "", activity_type: "", method: "", status: "", search: "" },
    pageSize: 25,
    page: 0,
    alerts: [],
    alertTotal: null,
    alertOffset: 0,
    alertFilterKey: null,
    summary: null,
    summaryFilterKey: null,
    summaryError: false,
    selected: new Map(),
    alertCache: new Map(),
    incidents: [],
    incidentTotal: null,
    incidentError: null,
    incidentOffset: 0,
    incidentPageSize: 50,
    draft: null,
    configDirty: false,
    runRequest: 0,
    datasetRequest: 0,
    resultRequest: 0,
    incidentRequest: 0,
    evidenceRequest: 0,
    evidenceAlert: null,
    evidenceReturnFocus: null,
    savingAlerts: new Set(),
    eventView: null,
    eventRequest: 0,
    explaining: new Set(),
    explanations: new Map(),
    searchTimer: null,
    pollTimer: null,
    pollId: "",
    pollGeneration: 0,
    pollInFlight: false,
    pollFailures: 0
  };

  function node(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = text;
    if (tag === "pre") element.tabIndex = 0;
    return element;
  }

  function json(value) {
    try { return JSON.stringify(value, null, 2) ?? "Not recorded"; }
    catch { return "This value could not be displayed as JSON."; }
  }

  function hasValue(value) {
    return value !== null && value !== undefined && value !== "";
  }

  function display(value, fallback = "Not recorded") {
    if (!hasValue(value)) return fallback;
    return typeof value === "object" ? json(value) : String(value);
  }

  function count(value) {
    return typeof value === "number" && Number.isFinite(value) ? COUNT_FORMAT.format(value) : "--";
  }

  function humanize(value) {
    const text = String(value ?? "").replace(/[_-]+/g, " ");
    return text.replace(/\b\w/g, (character) => character.toUpperCase());
  }

  function auditTime(value) {
    if (!hasValue(value)) return "Not recorded";
    const text = String(value);
    if (/^\d{4}-\d{2}-\d{2}T/.test(text) && /(Z|[+-]\d{2}:?\d{2})$/i.test(text)) {
      const parsed = new Date(text);
      if (Number.isFinite(parsed.getTime())) return parsed.toISOString().slice(0, 19).replace("T", " ") + " UTC";
    }
    return text;
  }

  function isActive(run) {
    return run && (run.state === "pending" || run.state === "running");
  }

  function selectedDataset() {
    return state.datasets.find((item) => item.id === state.datasetId) || null;
  }

  function activeRun() {
    if (isActive(state.activeRun)) return state.activeRun;
    if (isActive(state.health?.active_run)) return state.health.active_run;
    return isActive(state.run) ? state.run : null;
  }

  function url(path, parameters = {}) {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(parameters)) {
      if (value !== "" && value !== null && value !== undefined) query.set(key, String(value));
    }
    return path + (query.size ? "?" + query.toString() : "");
  }

  class ApiError extends Error {
    constructor(message, status = 0, code = "", details = null) {
      super(message);
      this.name = "ApiError";
      this.status = status;
      this.code = code;
      this.details = details;
    }
  }

  function apiError(payload, status) {
    const detail = payload?.detail ?? payload;
    if (Array.isArray(detail)) {
      const messages = detail.map((item) => {
        if (!item || typeof item !== "object") return display(item);
        const location = Array.isArray(item.loc) ? item.loc.join(".") : "";
        return (location ? location + ": " : "") + display(item.msg ?? item.message, "Validation failed");
      });
      return new ApiError(messages.join("; ") || "Request validation failed.", status, "validation_error", detail);
    }
    if (detail && typeof detail === "object") {
      const code = typeof detail.code === "string" ? detail.code : "";
      const message = display(detail.message ?? detail.msg, "The request was rejected (HTTP " + status + ").");
      return new ApiError((code ? code + ": " : "") + message, status, code, detail.details ?? null);
    }
    return new ApiError(display(detail, "The request failed (HTTP " + status + ")."), status);
  }

  async function api(path, { method = "GET", body, timeout = 30000 } = {}) {
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), timeout);
    const multipart = body instanceof FormData;
    const headers = { Accept: "application/json" };
    if (body !== undefined && !multipart) headers["Content-Type"] = "application/json";
    try {
      const response = await fetch(path, {
        method,
        headers,
        body: body === undefined ? undefined : multipart ? body : JSON.stringify(body),
        signal: controller.signal,
        credentials: "same-origin",
        cache: "no-store"
      });
      const text = await response.text();
      let payload;
      try { payload = text ? JSON.parse(text) : null; }
      catch { throw new ApiError("The API returned a non-JSON response (HTTP " + response.status + ").", response.status); }
      if (!response.ok) throw apiError(payload, response.status);
      if (payload === null) throw new ApiError("The API returned an empty response.", response.status);
      return payload;
    } catch (error) {
      if (error instanceof ApiError) throw error;
      if (error.name === "AbortError") throw new ApiError(method === "GET" ? "The API request timed out. Stored results have not been discarded." : "The request timed out and may have completed on the server. Read stored state before retrying a write.");
      throw new ApiError("The API could not be reached. " + display(error.message, "Check the local service."));
    } finally {
      window.clearTimeout(timer);
    }
  }

  function validatePage(page, scopeRunId = null) {
    if (!page || !Array.isArray(page.items) || !Number.isInteger(page.total) || page.total < 0 || page.items.some((item) => !item || typeof item !== "object")) {
      throw new ApiError("The API returned an invalid paginated response.");
    }
    if (scopeRunId && page.items.some((item) => item.run_id !== scopeRunId)) {
      throw new ApiError("The API returned a record from another run. It was not applied to this investigation.", 0, "run_scope_mismatch");
    }
    return page;
  }

  async function listAll(path, parameters = {}) {
    const items = [];
    let offset = 0;
    let total = Infinity;
    while (offset < total) {
      const page = validatePage(await api(url(path, { ...parameters, limit: 50, offset })));
      items.push(...page.items);
      total = page.total;
      if (!page.items.length) break;
      offset += page.items.length;
    }
    return items;
  }

  function setMessage(id, text, tone = "info", details = null) {
    const element = $(id);
    if (!element) return;
    element.replaceChildren();
    element.hidden = !text;
    element.className = "message is-" + tone;
    element.setAttribute("role", tone === "error" ? "alert" : "status");
    element.setAttribute("aria-live", tone === "error" ? "assertive" : "polite");
    if (text) element.append(node("p", "", text));
    if (details !== null && details !== undefined) element.append(jsonDetails("Request Details", details));
  }

  function showError(id, context, error) {
    setMessage(id, context + ": " + display(error?.message, "An unexpected error occurred."), "error", error?.details);
  }

  function jsonDetails(label, value, open = false) {
    const details = node("details", "json-details");
    details.open = open;
    details.append(node("summary", "", label), node("pre", "", json(value)));
    return details;
  }

  function addFact(list, label, value) {
    const row = node("div");
    const description = node("dd");
    if (value !== null && typeof value === "object") description.append(node("pre", "", json(value)));
    else description.textContent = display(value);
    row.append(node("dt", "", label), description);
    list.append(row);
  }

  function objectFacts(value, className = "evidence-facts") {
    const list = node("dl", className);
    if (value && typeof value === "object" && !Array.isArray(value)) {
      for (const [key, item] of Object.entries(value)) addFact(list, humanize(key), item);
    } else addFact(list, "Recorded Value", value);
    return list;
  }

  function renderWarnings(container, warnings, label = "Recorded Warnings") {
    container.replaceChildren();
    if (!Array.isArray(warnings) || !warnings.length) return;
    const details = node("details");
    const list = node("ul");
    for (const warning of warnings) list.append(node("li", "", display(warning)));
    details.append(node("summary", "", count(warnings.length) + " " + label), list);
    container.append(details);
  }

  function sourceLink(value, label) {
    try {
      const target = new URL(String(value));
      if (target.protocol !== "https:" && target.protocol !== "http:") return node("span", "", display(value));
      const link = node("a", "", label);
      link.href = target.href;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      return link;
    } catch { return node("span", "", display(value)); }
  }

  function buttonState(id, loading, normalText, loadingText) {
    const button = $(id);
    button.classList.toggle("is-loading", loading);
    button.textContent = loading ? loadingText : normalText;
  }

  function updateControls() {
    const importing = state.busy.preset || state.busy.file;
    const locked = state.busy.refresh || importing || state.busy.analyze || state.busy.incidentSave;
    const readingSelection = state.busy.dataset || state.busy.run;
    const preset = state.presets.find((item) => item.id === $("preset-select").value);
    $("preset-select").disabled = !state.loaded.presets || !state.presets.length || importing || state.busy.refresh;
    $("import-preset").disabled = !preset?.available || locked;
    $("upload-file").disabled = importing || state.busy.refresh;
    $("import-file").disabled = !$("upload-file").files.length || locked;
    $("dataset-select").disabled = !state.datasets.length || locked;
    $("run-select").disabled = (!state.runId && !state.runs.some((run) => run.dataset_id === state.datasetId)) || locked || state.busy.dataset;
    $("analyze-button").disabled = !state.datasetId || Boolean(activeRun()) || locked || readingSelection;
    $("refresh-button").disabled = locked || readingSelection;
    $("config-fields").disabled = state.busy.analyze;
    $("reset-config").disabled = state.busy.analyze;
    $("clear-selection").disabled = !state.selected.size || state.busy.incidentSave;
    $("new-incident").disabled = !state.selected.size || !state.runId || state.busy.incidentSave;
    $("add-checked").disabled = !state.draft || !state.selected.size || state.busy.incidentSave;
    $("remove-checked").disabled = !state.draft || !state.selected.size || state.busy.incidentSave;
    $("save-incident").disabled = !state.draft || state.busy.incidentSave;
    $("cancel-incident").disabled = state.busy.incidentSave;
    $("incident-title").disabled = state.busy.incidentSave;
    $("incident-notes").disabled = state.busy.incidentSave;
    $("incident-status").disabled = !state.draft?.id || state.busy.incidentSave;
    buttonState("refresh-button", state.busy.refresh, "Refresh Stored State", "Reading Stored State");
    buttonState("import-preset", state.busy.preset, "Import Preset", "Importing...");
    buttonState("import-file", state.busy.file, "Import File", "Importing...");
    buttonState("analyze-button", state.busy.analyze, "Run Analysis", "Requesting Run...");
    buttonState("save-incident", state.busy.incidentSave, state.draft?.id ? "Save Incident" : "Create Incident", "Saving...");
    renderSelection();
    renderPagination();
  }

  function describePreset() {
    const preset = state.presets.find((item) => item.id === $("preset-select").value);
    const description = $("preset-description");
    description.replaceChildren();
    if (!preset) {
      description.textContent = state.loaded.presets ? "No reference presets are available." : "Preset information has not been read.";
      return;
    }
    description.append(node("span", "", display(preset.description)));
    if (preset.source_url) description.append(sourceLink(preset.source_url, "Recorded Source"));
    if (!preset.available) description.append(node("span", "", " This preset is currently unavailable."));
  }

  function renderPresets() {
    if (!state.loaded.presets) return;
    const select = $("preset-select");
    const previous = select.value;
    select.replaceChildren();
    if (!state.presets.length) select.append(node("option", "", "No Reference Presets"));
    for (const preset of state.presets) {
      const option = node("option", "", display(preset.name, preset.id) + (preset.available ? "" : " / Unavailable"));
      option.value = preset.id;
      option.disabled = !preset.available;
      select.append(option);
    }
    select.value = state.presets.some((preset) => preset.id === previous && preset.available) ? previous : state.presets.find((preset) => preset.available)?.id || "";
    describePreset();
  }

  function sortRecent(items) {
    return [...items].sort((left, right) => String(right.created_at ?? "").localeCompare(String(left.created_at ?? "")));
  }

  function upsert(items, item) {
    return sortRecent([item, ...items.filter((existing) => existing.id !== item.id)]);
  }

  function renderDatasetSelect() {
    const select = $("dataset-select");
    select.replaceChildren();
    const placeholder = node("option", "", state.loaded.datasets ? state.datasets.length ? "Select Imported Dataset" : "No Imported Datasets" : "Datasets Not Read");
    placeholder.value = "";
    select.append(placeholder);
    for (const dataset of state.datasets) {
      const option = node("option", "", display(dataset.name, dataset.id) + (dataset.kind ? " / " + humanize(dataset.kind) : ""));
      option.value = dataset.id;
      select.append(option);
    }
    if (state.datasetId && !state.datasets.some((dataset) => dataset.id === state.datasetId)) {
      const option = node("option", "", display(state.run?.dataset_name, state.datasetId) + " / Run Reference");
      option.value = state.datasetId;
      select.append(option);
    }
    select.value = state.datasetId;
  }

  function renderRunSelect() {
    const select = $("run-select");
    const runs = sortRecent(state.runs.filter((run) => run.dataset_id === state.datasetId));
    select.replaceChildren();
    const placeholder = node("option", "", runs.length ? "Select Stored Run" : state.loaded.runs ? "No Stored Runs for Dataset" : "Runs Not Read");
    placeholder.value = "";
    select.append(placeholder);
    for (const run of runs) {
      const option = node("option", "", humanize(run.state) + " / " + auditTime(run.created_at) + " / " + String(run.id).slice(0, 8));
      option.value = run.id;
      option.title = run.id;
      select.append(option);
    }
    select.value = state.runId;
  }

  function relativeClock(alert) {
    const basis = String(alert.time_basis ?? "").toLowerCase();
    return basis.includes("relative") || (["brute_force", "suspicious_login"].includes(alert.activity_type) && !/utc|epoch/.test(basis));
  }

  function clockDescription(value) {
    if (!hasValue(value)) return "Clock basis not recorded; no alignment is inferred.";
    return /relative/i.test(String(value)) ? "Source-relative clock; capture year/timezone are not established. Not an AIT UTC timeline." : display(value) + "; no cross-source clock alignment is inferred.";
  }

  function recordedRange(alert) {
    const first = hasValue(alert.first_recorded_time) ? String(alert.first_recorded_time) : "Recorded time unavailable";
    const last = hasValue(alert.last_recorded_time) ? String(alert.last_recorded_time) : "";
    return { first, last: last && last !== first ? "Last: " + last : "" };
  }

  function renderDatasetContext() {
    const container = $("dataset-context");
    container.replaceChildren();
    const dataset = selectedDataset();
    if (!dataset) {
      container.append(node("p", "empty-note", "Select an imported dataset to inspect recorded provenance and import accounting."));
      return;
    }
    const overview = node("dl", "compact-facts dataset-overview");
    for (const [label, value] of [["Dataset ID", dataset.id], ["Kind", dataset.kind], ["Raw", dataset.raw_count], ["Eligible", dataset.eligible_count], ["Skipped", dataset.skipped_count], ["Duplicate", dataset.duplicate_count], ["Rejected", dataset.rejected_count], ["Ignored", dataset.ignored_count], ["Imported", auditTime(dataset.created_at)]]) addFact(overview, label, value);
    container.append(overview, node("p", "clock-note", clockDescription(dataset.time_basis)));
    const warnings = node("div", "warning-list");
    renderWarnings(warnings, dataset.warnings, "Import Warnings");
    container.append(warnings);
    for (const source of Array.isArray(dataset.sources) ? dataset.sources : []) {
      const section = node("div", "dataset-source");
      section.append(node("p", "", display(source.name, source.source_id)), node("p", "mono muted", "Source ID: " + display(source.source_id) + " / " + count(source.bytes) + " bytes"));
      section.append(jsonDetails("Checksum, Schema + Full Source Provenance", source));
      container.append(section);
    }
    container.append(jsonDetails("Full Dataset Profile + Stored Record", dataset));
  }

  function applyDefaults() {
    const defaults = { ...DEFAULTS, ...(state.health?.rules_defaults || {}) };
    for (const input of document.querySelectorAll("[data-config]")) {
      const value = defaults[input.dataset.config];
      if (typeof value === "number" && Number.isFinite(value)) input.value = String(value);
    }
  }

  function applyHealth(health) {
    state.health = health;
    state.healthError = null;
    state.activeRun = isActive(health.active_run) ? health.active_run : null;
    if (!state.configDirty) applyDefaults();
    const limits = health.limits || {};
    const parts = ["CSV, LOG or TXT."];
    if (hasValue(limits.max_upload_bytes)) parts.push("Upload limit: " + count(limits.max_upload_bytes) + " bytes.");
    if (hasValue(limits.max_rows)) parts.push("Row limit: " + count(limits.max_rows) + ".");
    parts.push("The API validates source schemas and preserves originals.");
    $("import-limits").textContent = parts.join(" ");
  }

  function renderHealth() {
    const connection = $("connection-state");
    connection.className = "connection-state " + (state.healthError ? "is-error" : state.health ? "is-ok" : state.busy.refresh ? "is-loading" : "is-error");
    connection.textContent = state.healthError ? "API Health Read Failed" : state.health ? "API / " + display(state.health.status) : state.busy.refresh ? "Reading API State" : "API Not Read";
    const model = state.health?.model;
    $("model-details").replaceChildren();
    $("model-state").className = "badge " + (!model ? "state-none" : model.available ? "state-available" : "state-unavailable");
    $("model-state").textContent = !model ? "Not Read" : model.available ? "Available" : "Unavailable";
    $("model-message").textContent = model ? display(model.message, model.available ? "Recorded network model is available." : "Network ML is unavailable; source-appropriate rules remain usable.") : "Model health has not been read.";
    if (model) {
      for (const [label, value] of [["Version", model.version], ["Feature Version", model.feature_version], ["Threshold", model.threshold], ["Trained", auditTime(model.trained_at)]]) addFact($("model-details"), label, value);
    }
    renderRunHealth();
  }

  function renderRunHealth() {
    const run = state.run;
    const badge = $("run-state");
    badge.className = "badge state-" + (run?.state || "none");
    badge.textContent = run ? humanize(run.state) : "No Run";
    $("run-name").textContent = run ? display(run.dataset_name, run.dataset_id) : "Select a stored snapshot";
    const details = $("run-details");
    details.replaceChildren();
    if (run) {
      const authOnly = run.counts?.authentication > 0 && run.counts?.network === 0;
      const modelUse = authOnly ? "Bypassed / Authentication" : run.model_available === true ? "Available" : run.model_available === false ? "Unavailable" : "Not recorded";
      for (const [label, value] of [["Run ID", run.id], ["Model In Run", modelUse], ["Model Version", run.model_version], ["Stored Alerts", run.counts?.alerts], ["Created", auditTime(run.created_at)], ["Started", auditTime(run.started_at)], ["Completed", auditTime(run.completed_at)]]) addFact(details, label, value);
    }
    const active = activeRun();
    $("active-run-note").textContent = active ? "Active run " + display(active.id) + " / " + humanize(active.state) + ". Only status GETs are polled; no reanalysis." : "No active analysis reported. Refresh only reads stored state.";
    $("run-record-details").hidden = !run;
    $("run-record").replaceChildren();
    if (run) $("run-record").append(jsonDetails("Stored Run Configuration", run.config), jsonDetails("Stored Metrics + Full Run Record", run));
    const warnings = $("run-warnings");
    renderWarnings(warnings, run?.warnings, "Run Warnings");
    if (run?.error) warnings.append(node("p", "run-error", "Recorded run error: " + display(run.error)));
  }

  function filterParameters() {
    return { run_id: state.runId, ...state.filters };
  }

  function filterKey() {
    return url("", filterParameters());
  }

  function renderCounts() {
    const counts = state.summary?.event_counts || state.run?.counts;
    $("raw-count").textContent = count(counts?.raw);
    $("eligible-count").textContent = count(counts?.eligible);
    $("skipped-count").textContent = count(counts?.skipped);
    $("alert-count").textContent = count(state.summary?.alert_count);
    $("count-breakdown").textContent = counts ? ["Duplicate " + count(counts.duplicate), "Rejected " + count(counts.rejected), "Ignored " + count(counts.ignored), "Network " + count(counts.network), "Auth " + count(counts.authentication), "ML evaluated " + count(counts.ml_evaluated), "ML anomalies " + count(counts.ml_anomalies), "Rule-supported events " + count(counts.rule_supported_events)].join(" / ") : "Select a run to read its event accounting.";
  }

  function renderBars(id, entries, values, activity = false) {
    const container = $(id);
    container.replaceChildren();
    container.className = "bar-chart" + (activity ? " activity-bars" : "");
    const numbers = entries.map(([key]) => values?.[key]).filter((value) => typeof value === "number" && Number.isFinite(value));
    const maximum = Math.max(0, ...numbers);
    const accessible = [];
    for (const [key, label] of entries) {
      const value = values ? (values[key] ?? 0) : undefined;
      const row = node("div", "bar-row" + (!activity ? " severity-" + key.toLowerCase() : ""));
      const track = node("div", "bar-track");
      const fill = node("div", "bar-fill");
      fill.style.width = maximum > 0 && typeof value === "number" && Number.isFinite(value) ? String(Math.max(0, value) / maximum * 100) + "%" : "0%";
      track.append(fill);
      row.append(node("span", "bar-label", label), track, node("span", "bar-count", count(value)));
      container.append(row);
      accessible.push(label + ": " + (hasValue(value) ? count(value) : "not loaded"));
    }
    container.setAttribute("aria-label", (activity ? "Suspected activity counts. " : "Investigation priority counts, not confidence. ") + accessible.join("; ") + ". Bar lengths are relative to the largest category.");
  }

  function renderProfile() {
    const summary = state.summary;
    renderBars("severity-chart", [["Critical", "Critical"], ["High", "High"], ["Medium", "Medium"], ["Low", "Low"]], summary?.severity_counts);
    renderBars("activity-chart", Object.entries(ACTIVITIES), summary?.activity_counts, true);
    $("method-counts").textContent = summary ? "Rule only " + count(summary.method_counts?.rule ?? 0) + " / ML only " + count(summary.method_counts?.ml ?? 0) + " / Both " + count(summary.method_counts?.both ?? 0) : "Method counts have not been loaded.";
    const stale = summary && (state.summaryFilterKey !== filterKey() || state.summaryError);
    $("alert-count").closest(".stat-card").classList.toggle("is-stale", Boolean(stale));
    $("severity-chart").closest(".profile-panel").classList.toggle("is-stale", Boolean(stale));
    $("summary-source").textContent = stale ? "Last successful summary is retained. A fresh summary for the current filters has not been read successfully." : summary ? summary.alert_count === 0 ? "No matching stored alerts. Counts reflect the selected run and all current filters, not this page." : "Persisted filtered summary / all matching alerts, not just the visible page." : "Summary is read for completed runs only. No values are synthesized from table rows.";
    const record = $("summary-record");
    if (record) {
      record.replaceChildren();
      if (summary) record.append(jsonDetails("Inspect Full Persisted Filtered Summary", summary));
    }
  }

  function renderSelection() {
    $("selection-count").textContent = count(state.selected.size) + " Checked";
    const selectPage = $("select-page");
    const checkedOnPage = state.alerts.filter((alert) => state.selected.has(alert.id)).length;
    selectPage.checked = state.alerts.length > 0 && checkedOnPage === state.alerts.length;
    selectPage.indeterminate = checkedOnPage > 0 && checkedOnPage < state.alerts.length;
    selectPage.disabled = !state.loaded.alerts || !state.alerts.length || state.busy.alerts || state.busy.incidentSave;
    selectPage.tabIndex = window.matchMedia("(max-width: 640px)").matches ? -1 : 0;
    $("check-page").disabled = selectPage.disabled;
    $("check-page").textContent = selectPage.checked ? "Uncheck Page" : "Check Page";
    for (const checkbox of $("alert-table-body").querySelectorAll("input[data-alert-id]")) {
      checkbox.checked = state.selected.has(checkbox.dataset.alertId);
      checkbox.disabled = state.busy.incidentSave;
      checkbox.closest("tr").classList.toggle("is-selected", checkbox.checked);
    }
  }

  function resultMatches() {
    return state.loaded.alerts && state.alertFilterKey === filterKey() && state.alertOffset === state.page * state.pageSize;
  }

  function renderPagination() {
    const matches = resultMatches();
    $("prev-page").disabled = state.busy.alerts || !matches || state.page === 0;
    $("next-page").disabled = state.busy.alerts || !matches || state.alertTotal === null || (state.page + 1) * state.pageSize >= state.alertTotal;
    $("page-position").textContent = !state.loaded.alerts ? "No Results Loaded" : state.alertTotal === 0 ? "0 Matching Alerts" : count(state.alertOffset + 1) + "-" + count(state.alertOffset + state.alerts.length) + " of " + count(state.alertTotal);
    $("queue-total").textContent = state.loaded.alerts ? count(state.alertTotal) + " Matching Alerts" : state.run ? humanize(state.run.state) + " Run" : "No Run Selected";
    const result = $("result-state");
    result.classList.toggle("is-loading", state.busy.alerts);
    result.classList.toggle("is-stale", state.loaded.alerts && !matches && !state.busy.alerts);
    result.textContent = state.busy.alerts ? "Reading stored alerts and matching summary. Last successful results remain visible." : state.loaded.alerts && !matches ? "Last successful rows are retained; the requested filters/page have not been applied to this table." : state.loaded.alerts ? "Stored results / same run and current filters. Open any priority level for evidence." : state.run && isActive(state.run) ? "Analysis is in progress. Status polling does not reanalyze; final results are published when complete." : state.run?.state === "failed" ? "This run failed. Its recorded error is in the run ledger; retry requires the Run Analysis button." : "Select a completed run to read stored results.";
  }

  function appendCell(row, className, label, children) {
    const cell = node("td", className);
    cell.dataset.label = label;
    for (const child of children) if (child) cell.append(child);
    row.append(cell);
    return cell;
  }

  function renderAlerts() {
    const body = $("alert-table-body");
    const fragment = document.createDocumentFragment();
    if (!state.loaded.alerts || !state.alerts.length) {
      const row = node("tr", "empty-row");
      const text = state.loaded.alerts ? "No stored alerts match these filters. Clear filters to broaden the queue; no new analysis is needed." : state.run && isActive(state.run) ? "Analysis is pending or running. Only stored run status is polled." : state.run?.state === "failed" ? "No completed results for this failed run. Inspect the run error above." : state.run ? "Reading stored results for this run..." : "Select a completed run to inspect stored alerts. Importing and refreshing do not start analysis.";
      const cell = node("td", "", text);
      cell.colSpan = 8;
      row.append(cell);
      fragment.append(row);
    } else {
      for (const alert of state.alerts) {
        const row = node("tr", state.selected.has(alert.id) ? "is-selected" : "");
        const checkbox = node("input");
        checkbox.type = "checkbox";
        checkbox.dataset.alertId = alert.id;
        checkbox.checked = state.selected.has(alert.id);
        checkbox.setAttribute("aria-label", "Check alert " + display(alert.title, alert.id) + " for manual incident membership");
        checkbox.addEventListener("change", () => {
          if (checkbox.checked) state.selected.set(alert.id, alert);
          else state.selected.delete(alert.id);
          updateControls();
        });
        const checkLabel = node("label", "alert-check");
        checkLabel.append(checkbox);
        appendCell(row, "col-select", "Select", [checkLabel]);
        appendCell(row, "col-priority", "Priority", [node("span", "badge severity-" + String(alert.severity).toLowerCase(), display(alert.severity))]);
        const open = node("button", "evidence-link", display(alert.title, "Suspected " + display(ACTIVITIES[alert.activity_type], alert.activity_type)));
        open.type = "button";
        open.dataset.evidenceAlertId = alert.id;
        open.setAttribute("aria-label", "Inspect full evidence for " + display(alert.title, alert.id));
        open.addEventListener("click", () => openEvidence(alert.id, open));
        appendCell(row, "col-activity", "Suspected Activity", [open, node("span", "cell-secondary", display(ACTIVITIES[alert.activity_type], humanize(alert.activity_type)) + " / " + count(alert.occurrence_count) + " occurrences")]);
        appendCell(row, "col-endpoints", "Endpoints", [node("span", "cell-primary", "Src " + display(alert.source_ip, "Not applicable")), node("span", "cell-secondary mono", "Dst " + display(alert.destination_ip, "Not applicable") + (alert.protocol ? " / " + display(alert.protocol) : ""))]);
        appendCell(row, "col-identity", "Identity / Host", [node("span", "cell-primary", display(alert.account, "Not applicable")), node("span", "cell-secondary", display(alert.hostname, "Host not recorded"))]);
        const times = recordedRange(alert);
        appendCell(row, "col-time", "Recorded Event Time", [node("span", "cell-primary", times.first), times.last ? node("span", "cell-secondary", times.last) : null, node("span", "cell-secondary", relativeClock(alert) ? "Source-relative clock / no capture year" : "Clock: " + display(alert.time_basis, "Not recorded"))]);
        const methods = Array.isArray(alert.methods) ? alert.methods.map((method) => method === "ml" ? "ML" : method === "rule" ? "Rule" : display(method)).join(" + ") : "Not recorded";
        appendCell(row, "col-methods", "Detection Method", [node("span", "method-label", methods)]);
        appendCell(row, "col-status", "Alert Status", [node("span", "badge status-" + String(alert.status), humanize(alert.status))]);
        fragment.append(row);
      }
    }
    body.replaceChildren(fragment);
    renderSelection();
    renderPagination();
  }

  async function loadAlertsAndSummary() {
    if (!state.runId || state.run?.state !== "completed") return;
    const request = ++state.resultRequest;
    const runId = state.runId;
    const key = filterKey();
    const parameters = filterParameters();
    const offset = state.page * state.pageSize;
    state.busy.alerts = true;
    $("alert-table-region").setAttribute("aria-busy", "true");
    $("alert-table-region").classList.add("is-loading");
    updateControls();
    const results = await Promise.allSettled([
      api(url("/alerts", { ...parameters, limit: state.pageSize, offset })).then((page) => validatePage(page, runId)),
      api(url("/summary", parameters)).then((summary) => {
        if (typeof summary.alert_count !== "number" || !Number.isFinite(summary.alert_count)) throw new ApiError("The API returned an invalid filtered summary.");
        return summary;
      })
    ]);
    if (request !== state.resultRequest || runId !== state.runId) return;
    state.busy.alerts = false;
    $("alert-table-region").setAttribute("aria-busy", "false");
    $("alert-table-region").classList.remove("is-loading");
    const errors = [];
    if (results[0].status === "fulfilled") {
      const page = results[0].value;
      if (offset > 0 && offset >= page.total) {
        state.page = Math.max(0, Math.ceil(page.total / state.pageSize) - 1);
        return loadAlertsAndSummary();
      }
      state.alerts = page.items;
      state.alertTotal = page.total;
      state.alertOffset = typeof page.offset === "number" ? page.offset : offset;
      state.alertFilterKey = key;
      state.loaded.alerts = true;
      for (const alert of page.items) {
        const cached = state.alertCache.get(alert.id);
        state.alertCache.set(alert.id, { ...cached, ...alert });
        if (state.selected.has(alert.id)) state.selected.set(alert.id, alert);
      }
    } else errors.push({ section: "Alert table", error: results[0].reason });
    if (results[1].status === "fulfilled") {
      state.summary = results[1].value;
      state.summaryFilterKey = key;
      state.summaryError = false;
    } else {
      state.summaryError = true;
      errors.push({ section: "Filtered summary", error: results[1].reason });
    }
    setMessage("alert-message", errors.length ? "Some stored results could not be read. Last successful results are retained. " + errors.map((item) => item.section + ": " + item.error.message).join(" ") : "", "error", errors.length ? errors.map((item) => ({ section: item.section, message: item.error.message, details: item.error.details })) : null);
    renderCounts();
    renderProfile();
    renderAlerts();
    updateControls();
  }

  function clearRunView() {
    state.resultRequest += 1;
    state.incidentRequest += 1;
    state.busy.alerts = false;
    state.busy.incidents = false;
    state.busy.run = false;
    state.alerts = [];
    state.alertTotal = null;
    state.alertOffset = 0;
    state.alertFilterKey = null;
    state.summary = null;
    state.summaryFilterKey = null;
    state.summaryError = false;
    state.page = 0;
    state.incidents = [];
    state.incidentTotal = null;
    state.incidentError = null;
    state.incidentOffset = 0;
    state.loaded.alerts = false;
    state.loaded.incidents = false;
    state.selected.clear();
    state.alertCache.clear();
    closeIncidentEditor();
    closeEvidence(false);
    $("alert-table-region").setAttribute("aria-busy", "false");
    $("alert-table-region").classList.remove("is-loading");
    $("incident-list").setAttribute("aria-busy", "false");
    setMessage("alert-message", "");
    setMessage("incident-message", "");
    renderCounts();
    renderProfile();
    renderAlerts();
    renderIncidents();
  }

  async function readSelectedRun() {
    if (!state.runId) return;
    const request = ++state.runRequest;
    const runId = state.runId;
    let failure = null;
    state.busy.run = true;
    updateControls();
    try {
      const run = await api("/runs/" + encodeURIComponent(runId));
      if (request !== state.runRequest || runId !== state.runId) return;
      if (run.id !== runId || run.dataset_id !== state.datasetId) throw new ApiError("The returned run does not match the selected dataset.", 0, "run_scope_mismatch");
      state.run = run;
      state.runs = upsert(state.runs, run);
      renderRunSelect();
      renderRunHealth();
      renderCounts();
      renderPagination();
      if (run.state === "completed") await Promise.all([loadAlertsAndSummary(), loadIncidents()]);
      else if (!state.loaded.alerts) {
        renderAlerts();
        renderIncidents();
      }
      ensurePolling();
    } catch (error) {
      if (request === state.runRequest && runId === state.runId) {
        failure = error;
        showError("global-message", "Stored run could not be read; last successful results are retained", error);
      }
    } finally {
      if (request === state.runRequest) state.busy.run = false;
      updateControls();
    }
    return failure;
  }

  async function selectRun(runId) {
    if (state.runId !== runId) {
      state.runRequest += 1;
      state.runId = runId;
      state.run = state.runs.find((run) => run.id === runId && run.dataset_id === state.datasetId) || null;
      clearRunView();
      renderRunSelect();
      renderRunHealth();
      updateControls();
    }
    if (runId) return readSelectedRun();
    else ensurePolling();
  }

  async function selectDataset(datasetId, preferredRunId = null) {
    const request = ++state.datasetRequest;
    state.busy.dataset = Boolean(datasetId);
    state.runRequest += 1;
    state.datasetId = datasetId;
    state.runId = "";
    state.run = null;
    clearRunView();
    renderDatasetSelect();
    renderDatasetContext();
    renderRunSelect();
    renderRunHealth();
    updateControls();
    if (!datasetId) return;
    try {
      const runs = sortRecent(await listAll("/runs", { dataset_id: datasetId }));
      if (request !== state.datasetRequest || datasetId !== state.datasetId) return;
      if (runs.some((run) => run.dataset_id !== datasetId)) throw new ApiError("The API returned a run from another dataset.", 0, "run_scope_mismatch");
      state.runs = sortRecent([...state.runs.filter((run) => run.dataset_id !== datasetId), ...runs]);
      state.loaded.runs = true;
      renderRunSelect();
      const preferred = runs.find((run) => run.id === preferredRunId) || runs.find((run) => run.state === "completed") || runs[0];
      if (preferred) await selectRun(preferred.id);
    } catch (error) {
      if (request === state.datasetRequest) showError("global-message", "Stored dataset runs could not be read", error);
    } finally {
      if (request === state.datasetRequest) state.busy.dataset = false;
      updateControls();
    }
    ensurePolling();
  }

  async function refreshWorkspace(initial = false) {
    if (state.busy.refresh) return;
    state.busy.refresh = true;
    updateControls();
    renderHealth();
    setMessage("global-message", "Reading persisted datasets, runs, source presets and model health. No analysis is started.", "loading");
    try {
      const results = await Promise.allSettled([api("/health"), api("/presets"), listAll("/datasets"), listAll("/runs")]);
      const errors = [];
      if (results[0].status === "fulfilled") applyHealth(results[0].value);
      else {
        state.healthError = results[0].reason;
        errors.push({ section: "Health", error: results[0].reason });
      }
      if (results[1].status === "fulfilled" && Array.isArray(results[1].value.items)) {
        state.presets = results[1].value.items;
        state.loaded.presets = true;
        $("preset-notice").textContent = display(results[1].value.notice, "No additional source notice was returned by the API.");
      } else errors.push({ section: "Presets", error: results[1].status === "rejected" ? results[1].reason : new ApiError("Invalid preset listing.") });
      if (results[2].status === "fulfilled") {
        state.datasets = sortRecent(results[2].value);
        state.loaded.datasets = true;
      } else errors.push({ section: "Datasets", error: results[2].reason });
      if (results[3].status === "fulfilled") {
        state.runs = sortRecent(results[3].value);
        state.loaded.runs = true;
      } else errors.push({ section: "Runs", error: results[3].reason });
      renderPresets();
      let runError = null;
      if (!state.runId) {
        const candidates = state.datasetId ? state.runs.filter((run) => run.dataset_id === state.datasetId) : state.runs;
        const latest = candidates.find((run) => run.state === "completed") || candidates[0];
        if (latest) {
          state.datasetId = latest.dataset_id;
          renderDatasetSelect();
          renderDatasetContext();
          runError = await selectRun(latest.id);
        } else {
          if (!state.datasetId && state.datasets.length) state.datasetId = state.datasets[0].id;
          renderDatasetSelect();
          renderDatasetContext();
          renderRunSelect();
          renderCounts();
          renderProfile();
          renderAlerts();
          renderIncidents();
        }
      } else {
        renderDatasetSelect();
        renderDatasetContext();
        renderRunSelect();
        runError = await readSelectedRun();
      }
      if (runError) errors.push({ section: "Selected run", error: runError });
      if (errors.length) setMessage("global-message", "Some API reads failed. Last successful state remains visible. " + errors.map((item) => item.section + ": " + item.error.message).join(" "), "error", errors.map((item) => ({ section: item.section, message: item.error.message, details: item.error.details })));
      else setMessage("global-message", "Workspace ledger read. No import, analysis, training or explanation was requested. Result-read errors, if any, appear in their panels.", "success");
    } catch (error) {
      showError("global-message", "Stored-state refresh failed; last successful results are retained", error);
    } finally {
      state.busy.refresh = false;
      renderHealth();
      updateControls();
      ensurePolling();
    }
  }

  async function importDataset(kind) {
    if (state.busy.preset || state.busy.file) return;
    let body;
    let path;
    if (kind === "preset") {
      const preset = state.presets.find((item) => item.id === $("preset-select").value);
      if (!preset?.available) return;
      body = { preset_id: preset.id };
      path = "/datasets/preset";
    } else {
      const file = $("upload-file").files[0];
      if (!file) return;
      if (!/\.(csv|log|txt)$/i.test(file.name)) {
        setMessage("control-message", "Import rejected locally: select a .csv, .log or .txt file. The API also validates the source schema.", "error");
        return;
      }
      const limit = state.health?.limits?.max_upload_bytes;
      if (typeof limit === "number" && file.size > limit) {
        setMessage("control-message", "This file is " + count(file.size) + " bytes; the API upload limit is " + count(limit) + " bytes.", "error");
        return;
      }
      body = new FormData();
      body.append("file", file, file.name);
      path = "/datasets/import";
    }
    state.busy[kind] = true;
    setMessage("control-message", "Importing and validating source records. Original sources are preserved. Analysis will not start automatically.", "loading");
    updateControls();
    try {
      const result = await api(path, { method: "POST", body, timeout: 180000 });
      if (!result.dataset?.id) throw new ApiError("The import did not return a dataset record.");
      state.datasets = upsert(state.datasets, result.dataset);
      state.loaded.datasets = true;
      await selectDataset(result.dataset.id);
      setMessage("control-message", (result.reused ? "Stored dataset reused. " : "Dataset imported. ") + display(result.dataset.name, result.dataset.id) + ": " + count(result.dataset.raw_count) + " raw / " + count(result.dataset.eligible_count) + " eligible / " + count(result.dataset.skipped_count) + " skipped. No analysis was started.", "success");
    } catch (error) { showError("control-message", "Dataset import failed", error); }
    finally {
      state.busy[kind] = false;
      updateControls();
    }
  }

  async function analyze() {
    if (!state.datasetId || state.busy.analyze || state.busy.refresh || state.busy.dataset || state.busy.run || state.busy.preset || state.busy.file || activeRun()) return;
    const form = $("analysis-config");
    if (!form.checkValidity()) {
      $("config-details").open = true;
      form.reportValidity();
      return;
    }
    const config = {};
    for (const input of form.querySelectorAll("[data-config]")) {
      const value = Number(input.value);
      if (!Number.isFinite(value) || !Number.isInteger(value)) {
        $("config-details").open = true;
        input.focus();
        setMessage("control-message", "Configuration values must be finite whole numbers. No analysis was requested.", "error");
        return;
      }
      config[input.dataset.config] = value;
    }
    const datasetId = state.datasetId;
    state.busy.analyze = true;
    updateControls();
    setMessage("control-message", "Requesting a finite dataset/config/model snapshot. No retraining or language-model explanation is requested.", "loading");
    try {
      const result = await api("/analyze", { method: "POST", body: { dataset_id: datasetId, config }, timeout: 60000 });
      if (!result.run?.id || result.run.dataset_id !== datasetId) throw new ApiError("The analysis response did not match the requested dataset.", 0, "run_scope_mismatch");
      state.runs = upsert(state.runs, result.run);
      state.loaded.runs = true;
      if (isActive(result.run)) {
        state.activeRun = { id: result.run.id, state: result.run.state };
        if (state.health) state.health.active_run = state.activeRun;
      }
      await selectRun(result.run.id);
      setMessage("control-message", result.reused ? "Identical stored snapshot reused. No duplicate analysis or alerts were created." : "Analysis queued. Only run status is polled while pending/running; results are read when complete.", "success");
    } catch (error) {
      showError("control-message", error.status === 409 ? "An active-run conflict prevented a new analysis" : "Analysis request failed", error);
      if (error.status === 409) await refreshWorkspace();
    } finally {
      state.busy.analyze = false;
      updateControls();
      ensurePolling();
    }
  }

  function stopPolling() {
    if (state.pollTimer !== null) window.clearTimeout(state.pollTimer);
    state.pollTimer = null;
    state.pollId = "";
    state.pollGeneration += 1;
    state.pollInFlight = false;
    state.pollFailures = 0;
  }

  function ensurePolling() {
    const active = activeRun();
    if (!active) {
      if (state.pollId) stopPolling();
      return;
    }
    if (state.pollId === active.id && (state.pollTimer !== null || state.pollInFlight)) return;
    if (state.pollId !== active.id) {
      stopPolling();
      state.pollId = active.id;
    }
    const generation = state.pollGeneration;
    state.pollTimer = window.setTimeout(() => pollRun(active.id, generation), 2500);
  }

  async function pollRun(runId, generation) {
    if (generation !== state.pollGeneration || state.pollId !== runId) return;
    state.pollTimer = null;
    state.pollInFlight = true;
    try {
      const run = await api("/runs/" + encodeURIComponent(runId));
      if (generation !== state.pollGeneration || state.pollId !== runId) return;
      if (run.id !== runId) throw new ApiError("Run status returned a different run ID.");
      state.pollFailures = 0;
      state.runs = upsert(state.runs, run);
      state.loaded.runs = true;
      if (state.runId === runId) state.run = run;
      state.activeRun = isActive(run) ? { id: run.id, state: run.state } : null;
      if (state.health?.active_run?.id === runId) state.health.active_run = state.activeRun;
      renderRunSelect();
      renderRunHealth();
      renderCounts();
      renderPagination();
      if (isActive(run)) {
        state.pollInFlight = false;
        updateControls();
        ensurePolling();
        return;
      }
      stopPolling();
      if (state.runId === runId) {
        if (run.state === "completed") await Promise.all([loadAlertsAndSummary(), loadIncidents()]);
        else {
          renderAlerts();
          renderIncidents();
        }
      }
      setMessage("global-message", "Stored run " + runId + " " + humanize(run.state).toLowerCase() + ". " + (state.runId === runId ? "Its persisted state is shown." : "Select it in the run ledger to inspect results."), run.state === "failed" ? "warning" : "success");
      try { applyHealth(await api("/health")); }
      catch (error) { state.healthError = error; }
      renderHealth();
      updateControls();
      ensurePolling();
    } catch (error) {
      if (generation !== state.pollGeneration || state.pollId !== runId) return;
      state.pollInFlight = false;
      state.pollFailures += 1;
      if (state.pollFailures >= 3) {
        stopPolling();
        showError("global-message", "Run status polling paused after three failed reads. Refresh Stored State to retry GETs; no reanalysis occurs", error);
      } else {
        showError("global-message", "Run status could not be read. Stored results remain visible; status GET will retry", error);
        state.pollTimer = window.setTimeout(() => pollRun(runId, generation), 5000);
      }
      updateControls();
    }
  }

  async function loadIncidents(offset = state.incidentOffset) {
    if (!state.runId || state.run?.state !== "completed") return;
    const request = ++state.incidentRequest;
    const runId = state.runId;
    state.busy.incidents = true;
    $("incident-list").setAttribute("aria-busy", "true");
    renderIncidentPagination();
    try {
      const page = validatePage(await api(url("/incidents", { run_id: runId, limit: state.incidentPageSize, offset })), runId);
      if (request !== state.incidentRequest || runId !== state.runId) return;
      if (offset > 0 && offset >= page.total) {
        return loadIncidents(Math.max(0, Math.ceil(page.total / state.incidentPageSize) - 1) * state.incidentPageSize);
      }
      state.incidents = page.items;
      state.incidentTotal = page.total;
      state.incidentOffset = typeof page.offset === "number" ? page.offset : offset;
      state.loaded.incidents = true;
      state.incidentError = null;
      setMessage("incident-message", "");
      renderIncidents();
    } catch (error) {
      if (request === state.incidentRequest && runId === state.runId) {
        state.incidentError = error;
        showError("incident-message", "Incident ledger read failed; last successful entries and the editor are retained", error);
      }
    } finally {
      if (request === state.incidentRequest) {
        state.busy.incidents = false;
        $("incident-list").setAttribute("aria-busy", "false");
        renderIncidentPagination();
      }
    }
  }

  function renderIncidentPagination() {
    $("incident-pagination").hidden = !state.loaded.incidents || state.incidentTotal <= state.incidentPageSize;
    $("incident-prev").disabled = state.busy.incidents || state.incidentOffset === 0;
    $("incident-next").disabled = state.busy.incidents || state.incidentTotal === null || state.incidentOffset + state.incidentPageSize >= state.incidentTotal;
    $("incident-page-position").textContent = state.incidentTotal ? count(state.incidentOffset + 1) + "-" + count(state.incidentOffset + state.incidents.length) + " of " + count(state.incidentTotal) : "0 Incidents";
  }

  function renderIncidents() {
    const container = $("incident-list");
    container.replaceChildren();
    $("incident-total").textContent = count(state.incidentTotal);
    if (!state.loaded.incidents || !state.incidents.length) {
      container.append(node("p", "empty-note", state.loaded.incidents ? "No manual incidents in this run. Check alerts to create an analyst-led investigation." : "Select a completed run to read its incident ledger. No cross-run grouping is performed."));
    } else {
      for (const incident of state.incidents) {
        const button = node("button", "incident-card" + (state.draft?.id === incident.id ? " is-selected" : ""));
        button.type = "button";
        button.disabled = state.busy.incidentSave;
        button.setAttribute("aria-label", "Inspect and edit incident " + display(incident.title, incident.id));
        const heading = node("span", "incident-card-heading");
        heading.append(node("span", "badge status-" + String(incident.status), humanize(incident.status)), node("span", "mono", count(Array.isArray(incident.alert_ids) ? incident.alert_ids.length : null) + " alerts"));
        button.append(heading, node("strong", "", display(incident.title, incident.id)), node("p", "", display(incident.notes, "No notes recorded.")), node("span", "mono", "Updated " + auditTime(incident.updated_at)));
        button.addEventListener("click", () => openIncidentEditor(incident));
        container.append(button);
      }
    }
    renderIncidentPagination();
  }

  function closeIncidentEditor() {
    state.draft = null;
    $("incident-form").hidden = true;
    $("incident-editor-placeholder").hidden = false;
  }

  function openIncidentEditor(incident = null) {
    if (state.busy.incidentSave || !state.runId || incident && incident.run_id !== state.runId) return;
    if (!incident && !state.selected.size) return;
    state.draft = {
      id: incident?.id || null,
      runId: state.runId,
      alertIds: new Set(incident ? incident.alert_ids || [] : state.selected.keys())
    };
    $("incident-editor-title").textContent = incident ? "Edit Incident" : "New Incident Draft";
    $("incident-editor-id").textContent = incident ? String(incident.id).slice(0, 12) : "Unsaved / Same Run";
    $("incident-title").value = incident?.title || "";
    $("incident-notes").value = incident?.notes || "";
    $("incident-status").value = incident?.status || "open";
    $("incident-status-help").textContent = incident ? "Title, notes, status and membership change only when saved." : "New incidents start open. No grouping is inferred automatically.";
    $("incident-form").hidden = false;
    $("incident-editor-placeholder").hidden = true;
    setMessage("incident-message", "");
    renderMembers();
    renderIncidents();
    updateControls();
    $("incident-title").focus({ preventScroll: true });
    $("incident-form").scrollIntoView({ block: "nearest", behavior: "auto" });
  }

  function renderMembers() {
    const list = $("incident-members");
    list.replaceChildren();
    $("incident-member-count").textContent = count(state.draft?.alertIds.size ?? 0);
    if (!state.draft) return;
    if (!state.draft.alertIds.size) {
      list.append(node("li", "empty-note", "No members in this draft. Add checked alerts from the selected run."));
      return;
    }
    for (const id of state.draft.alertIds) {
      const alert = state.alertCache.get(id) || state.selected.get(id);
      const item = node("li");
      const inspect = node("button", "evidence-link", alert ? display(alert.title, id) : "Inspect Alert " + id);
      inspect.type = "button";
      inspect.dataset.memberAlertId = id;
      inspect.setAttribute("aria-label", "Inspect incident member " + id);
      inspect.addEventListener("click", () => openEvidence(id, inspect));
      const remove = node("button", "member-remove", "Remove");
      remove.type = "button";
      remove.disabled = state.busy.incidentSave;
      remove.setAttribute("aria-label", "Remove alert " + id + " from the incident draft");
      remove.addEventListener("click", () => {
        state.draft.alertIds.delete(id);
        renderMembers();
      });
      item.append(inspect, remove);
      list.append(item);
    }
  }

  function changeMembers(add) {
    if (!state.draft || state.draft.runId !== state.runId || state.busy.incidentSave) return;
    for (const [id, alert] of state.selected) {
      if (alert.run_id !== state.runId) continue;
      if (add) state.draft.alertIds.add(id);
      else state.draft.alertIds.delete(id);
    }
    renderMembers();
  }

  async function saveIncident(event) {
    event.preventDefault();
    const draft = state.draft;
    if (!draft || draft.runId !== state.runId || state.busy.incidentSave) return;
    const title = $("incident-title").value.trim();
    if (!title) {
      $("incident-title").focus();
      setMessage("incident-message", "Enter a title for this manual investigation.", "error");
      return;
    }
    if (!draft.id && !draft.alertIds.size) {
      setMessage("incident-message", "A new incident requires checked alerts from this run. Add members before creating it.", "error");
      return;
    }
    const fields = { title, notes: $("incident-notes").value, alert_ids: [...draft.alertIds] };
    if (draft.id) fields.status = $("incident-status").value;
    else fields.run_id = draft.runId;
    state.busy.incidentSave = true;
    setMessage("incident-message", "Saving this manual investigation. The previous saved record remains unchanged until the request completes.", "loading");
    updateControls();
    renderMembers();
    let savedIncident = null;
    try {
      const incident = await api(draft.id ? "/incidents/" + encodeURIComponent(draft.id) : "/incidents", { method: draft.id ? "PATCH" : "POST", body: fields });
      if (incident.run_id !== draft.runId || !incident.id) throw new ApiError("The saved incident does not match the selected run.", 0, "run_scope_mismatch");
      if (state.runId !== draft.runId || state.draft !== draft) return;
      savedIncident = incident;
      state.incidents = state.incidents.map((item) => item.id === incident.id ? incident : item);
      await loadIncidents(0);
    } catch (error) { showError("incident-message", "Incident save failed; your draft is retained", error); }
    finally {
      state.busy.incidentSave = false;
      if (savedIncident && state.runId === draft.runId && state.draft === draft) {
        const ledgerError = state.incidentError;
        openIncidentEditor(savedIncident);
        if (ledgerError) showError("incident-message", "Incident saved, but its ledger refresh failed; the saved record is in the editor", ledgerError);
        else setMessage("incident-message", "Incident saved. This is a manual grouping within the selected run, not evidence of correlation or compromise.", "success");
      } else {
        updateControls();
        renderMembers();
        renderIncidents();
      }
    }
  }

  function closeEvidence(restoreFocus = true) {
    if ($("evidence-panel").hidden) return;
    state.evidenceRequest += 1;
    state.evidenceAlert = null;
    state.eventRequest += 1;
    state.eventView = null;
    $("evidence-panel").hidden = true;
    $("evidence-panel").setAttribute("aria-busy", "false");
    $("drawer-backdrop").hidden = true;
    $("workspace-shell").inert = false;
    document.body.classList.remove("drawer-open");
    const previous = state.evidenceReturnFocus;
    state.evidenceReturnFocus = null;
    if (!restoreFocus) return;
    let target = previous?.isConnected ? previous : null;
    if (!target && previous?.dataset.memberAlertId) target = [...$("incident-members").querySelectorAll("button[data-member-alert-id]")].find((button) => button.dataset.memberAlertId === previous.dataset.memberAlertId);
    if (!target && previous?.dataset.evidenceAlertId) target = [...$("alert-table-body").querySelectorAll("button[data-evidence-alert-id]")].find((button) => button.dataset.evidenceAlertId === previous.dataset.evidenceAlertId);
    (target || $("alert-table-region")).focus({ preventScroll: true });
  }

  async function openEvidence(alertId, returnFocus) {
    if (!state.runId) return;
    const request = ++state.evidenceRequest;
    const runId = state.runId;
    state.evidenceReturnFocus = returnFocus || document.activeElement;
    state.evidenceAlert = state.alertCache.get(alertId)?.evidence ? state.alertCache.get(alertId) : null;
    $("evidence-panel").hidden = false;
    $("evidence-panel").setAttribute("aria-busy", "true");
    $("drawer-backdrop").hidden = false;
    $("workspace-shell").inert = true;
    document.body.classList.add("drawer-open");
    $("evidence-title").textContent = "Alert Evidence";
    $("evidence-alert-id").textContent = alertId;
    if (state.evidenceAlert) renderEvidence(state.evidenceAlert);
    else $("evidence-content").replaceChildren(node("p", "empty-note", "Reading the full stored alert, rule evidence, model margins and source records..."));
    setMessage("evidence-message", "Reading stored evidence. No explanation or analysis is requested.", "loading");
    $("close-evidence").focus({ preventScroll: true });
    try {
      const alert = await api("/alerts/" + encodeURIComponent(alertId));
      if (request !== state.evidenceRequest || state.runId !== runId) return;
      if (alert.id !== alertId || alert.run_id !== runId) throw new ApiError("This alert is not part of the selected run. It cannot be inspected or grouped here.", 0, "run_scope_mismatch");
      state.evidenceAlert = alert;
      state.alertCache.set(alert.id, alert);
      if (state.selected.has(alert.id)) state.selected.set(alert.id, alert);
      renderEvidence(alert);
      renderMembers();
      setMessage("evidence-message", "");
    } catch (error) {
      if (request === state.evidenceRequest) showError("evidence-message", "Evidence read failed; any last successful evidence is retained", error);
    } finally {
      if (request === state.evidenceRequest) $("evidence-panel").setAttribute("aria-busy", "false");
    }
  }

  function evidenceSection(title, help = "") {
    const section = node("section", "evidence-section");
    section.append(node("h3", "", title));
    if (help) section.append(node("p", "section-help", help));
    return section;
  }

  function rawRecordDetails(record, position, label) {
    const details = node("details", "evidence-item");
    const recorded = hasValue(record.recorded_time) ? record.recorded_time : record.event_time_display;
    details.append(node("summary", "", label + " " + position + " / Source " + display(record.source_id) + " / Line " + display(record.source_line) + " / " + display(recorded, "Recorded time not provided")));
    const item = node("div", "evidence-item-content");
    item.append(objectFacts(record), jsonDetails("Full Recorded Raw Values", record));
    details.append(item);
    return details;
  }

  function supportingEventsSection(alert) {
    if (!state.eventView || state.eventView.alertId !== alert.id || state.eventView.runId !== alert.run_id) {
      state.eventRequest += 1;
      state.eventView = { alertId: alert.id, runId: alert.run_id, open: false, page: null, loading: false, error: null, requestedOffset: 0 };
    }
    const view = state.eventView;
    const section = evidenceSection("All Supporting Events", "Every supporting normalized raw event is stored. Read 25 at a time, including raw magnitudes and recorded source times. These GETs do not analyze or request generated commentary.");
    const browser = node("details", "evidence-item events-browser");
    browser.id = "supporting-events";
    browser.open = view.open;
    browser.append(node("summary", "", "Browse " + count(alert.evidence?.raw_event_count) + " Stored Supporting Events / 25 per Page"));
    const content = node("div", "evidence-item-content");
    const toolbar = node("div", "events-toolbar");
    const position = node("p");
    position.id = "events-position";
    position.setAttribute("aria-live", "polite");
    const read = node("button", "button button-small button-quiet", "Read Supporting Events");
    read.id = "events-read";
    read.type = "button";
    read.addEventListener("click", () => loadSupportingEvents(view.error ? view.requestedOffset : view.page?.offset || 0));
    toolbar.append(position, read);
    const message = node("div", "message");
    message.id = "events-message";
    message.hidden = true;
    message.setAttribute("role", "status");
    message.setAttribute("aria-live", "polite");
    const list = node("div", "events-list");
    list.id = "events-list";
    list.setAttribute("role", "region");
    list.setAttribute("aria-label", "Paginated supporting raw event records");
    list.tabIndex = 0;
    const pager = node("div", "pagination events-pagination");
    const previous = node("button", "button button-small button-quiet", "Previous Events");
    previous.id = "events-prev";
    previous.type = "button";
    previous.addEventListener("click", () => loadSupportingEvents(Math.max(0, (view.page?.offset || 0) - 25)));
    const next = node("button", "button button-small button-quiet", "Next Events");
    next.id = "events-next";
    next.type = "button";
    next.addEventListener("click", () => loadSupportingEvents((view.page?.offset || 0) + 25));
    pager.append(previous, next);
    content.append(toolbar, message, list, pager);
    browser.append(content);
    browser.addEventListener("toggle", () => {
      if (state.eventView !== view) return;
      view.open = browser.open;
      if (browser.open && !view.page && !view.loading) loadSupportingEvents(0);
    });
    section.append(browser);
    return section;
  }

  function renderSupportingEvents() {
    const view = state.eventView;
    if (!view || !$("supporting-events") || state.evidenceAlert?.id !== view.alertId) return;
    const page = view.page;
    const browser = $("supporting-events");
    browser.classList.toggle("is-loading", view.loading);
    browser.classList.toggle("is-stale", Boolean(view.error && page));
    browser.classList.toggle("is-empty", Boolean(page && page.total === 0));
    const list = $("events-list");
    list.setAttribute("aria-busy", String(view.loading));
    list.replaceChildren();
    if (page?.items.length) page.items.forEach((record, index) => list.append(rawRecordDetails(record, page.offset + index + 1, "Supporting Event")));
    else list.append(node("p", "empty-note", page ? "No supporting events were returned for this stored alert." : view.loading ? "Reading the first stored raw-event page..." : "Expand this viewer or press Read Supporting Events. No raw-event query has been issued yet."));
    $("events-position").textContent = !page ? "Supporting Events Not Read" : page.total === 0 ? "0 Supporting Events" : count(page.offset + 1) + "-" + count(page.offset + page.items.length) + " of " + count(page.total) + (view.error ? " / Last Successful Page" : "");
    $("events-prev").disabled = view.loading || !page || page.offset === 0;
    $("events-next").disabled = view.loading || !page || page.offset + page.limit >= page.total;
    $("events-read").disabled = view.loading;
    buttonState("events-read", view.loading, view.error ? "Retry Event Read" : page ? "Refresh This Page" : "Read Supporting Events", "Reading Events...");
    if (view.error) showError("events-message", "Supporting-event read failed; any last successful page is retained", view.error);
    else setMessage("events-message", "");
  }

  async function loadSupportingEvents(offset = 0) {
    const view = state.eventView;
    if (!view || view.loading || view.runId !== state.runId || state.evidenceAlert?.id !== view.alertId) return;
    const request = ++state.eventRequest;
    view.loading = true;
    view.requestedOffset = offset;
    view.error = null;
    renderSupportingEvents();
    try {
      // Construct the known same-origin endpoint; never follow a log-supplied URL.
      const page = validatePage(await api(url("/alerts/" + encodeURIComponent(view.alertId) + "/events", { limit: 25, offset })));
      if (request !== state.eventRequest || state.eventView !== view || state.runId !== view.runId) return;
      if (page.items.some((record) => record.run_id && record.run_id !== view.runId)) throw new ApiError("Supporting evidence belongs to a different run.", 0, "run_scope_mismatch");
      view.page = { ...page, limit: page.limit || 25, offset: typeof page.offset === "number" ? page.offset : offset };
    } catch (error) {
      if (request === state.eventRequest && state.eventView === view) view.error = error;
    } finally {
      if (request === state.eventRequest && state.eventView === view) {
        view.loading = false;
        renderSupportingEvents();
      }
    }
  }

  function renderEvidence(alert) {
    $("evidence-title").textContent = display(alert.title, "Alert Evidence");
    $("evidence-alert-id").textContent = "Alert " + alert.id + " / Run " + alert.run_id;
    const content = $("evidence-content");
    content.replaceChildren();
    const overview = evidenceSection("Investigation Record");
    const basis = relativeClock(alert) ? "Source-relative clock (not UTC or an absolute capture date): " + display(alert.first_event_time) + " through " + display(alert.last_event_time) + ". Recorded authentication times below are preserved verbatim; no year or timezone is invented." : "Clock basis: " + display(alert.time_basis) + ". Event clock values and recorded times are displayed as stored, without cross-source alignment.";
    overview.append(node("p", "clock-note", basis));
    const facts = node("dl", "evidence-facts");
    for (const [label, value] of [["Suspected Activity", ACTIVITIES[alert.activity_type] || alert.activity_type], ["Priority / Severity", alert.severity], ["Severity Reason", alert.severity_reason], ["Source IP", alert.source_ip], ["Destination IP", alert.destination_ip], ["Account", alert.account], ["Hostname", alert.hostname], ["Protocol", alert.protocol], ["Occurrences", alert.occurrence_count], ["Detection Methods", alert.methods], ["First Recorded Time", alert.first_recorded_time], ["Last Recorded Time", alert.last_recorded_time], ["First Event Clock", alert.first_event_time], ["Last Event Clock", alert.last_event_time], ["Time Basis", alert.time_basis], ["Status", alert.status], ["Created", auditTime(alert.created_at)], ["Updated", auditTime(alert.updated_at)]]) addFact(facts, label, value);
    overview.append(facts);
    const statusForm = node("form", "alert-status-form");
    const field = node("div", "field");
    const label = node("label", "", "Alert Disposition");
    label.htmlFor = "evidence-status";
    const select = node("select");
    select.id = "evidence-status";
    for (const status of ALERT_STATUSES) {
      const option = node("option", "", humanize(status));
      option.value = status;
      select.append(option);
    }
    select.value = alert.status;
    const saving = state.savingAlerts.has(alert.id);
    select.disabled = saving;
    field.append(label, select);
    const save = node("button", "button" + (saving ? " is-loading" : ""), saving ? "Saving..." : "Save Alert Status");
    save.id = "save-alert-status";
    save.type = "submit";
    save.disabled = saving;
    statusForm.append(field, save);
    statusForm.addEventListener("submit", (event) => {
      event.preventDefault();
      saveAlertStatus(alert.id, select.value);
    });
    overview.append(statusForm);
    content.append(overview);

    const evidence = alert.evidence || {};
    const note = evidenceSection("Recorded Investigation Note");
    note.append(node("p", "investigation-note", display(evidence.investigation_note, "No investigation note was recorded.")));
    content.append(note);

    const rules = evidenceSection("Rule Evidence", "Thresholds, event-time windows, counts and supporting ports are recorded detector evidence, not proof of compromise.");
    const ruleItems = Array.isArray(evidence.rules) ? evidence.rules : [];
    if (!ruleItems.length) rules.append(node("p", "empty-note", "No rule evidence recorded for this alert."));
    for (const rule of ruleItems) {
      const details = node("details", "evidence-item");
      details.open = ruleItems.length === 1;
      details.append(node("summary", "", display(rule.id, "Recorded Rule") + " / " + count(rule.occurrence_count) + " occurrences / peak window " + count(rule.peak_window_count)));
      const item = node("div", "evidence-item-content");
      item.append(objectFacts(rule), jsonDetails("Full Recorded Rule Evidence", rule));
      details.append(item);
      rules.append(details);
    }
    content.append(rules);

    const ml = evidenceSection("Network ML Evidence", "Isolation Forest margins describe deviation from a recorded model threshold. They are not attack probabilities or attack-name predictions.");
    if (evidence.ml) ml.append(objectFacts(evidence.ml), jsonDetails("Full Recorded ML Evidence", evidence.ml));
    else ml.append(node("p", "empty-note", relativeClock(alert) ? "No network ML evidence. Authentication detections bypass the network model." : "No ML evidence recorded for this alert; inspect its independent rule evidence."));
    content.append(ml);

    const examples = Array.isArray(evidence.raw_examples) ? evidence.raw_examples : [];
    const raw = evidenceSection("Raw Source Examples / " + count(examples.length), "Inspectable at every priority level. Original recorded fields are shown as text; source-relative times are not assigned an invented year.");
    if (!examples.length) raw.append(node("p", "empty-note", "No raw examples were returned for this alert."));
    examples.forEach((example, index) => raw.append(rawRecordDetails(example, index + 1, "Example")));
    content.append(raw);
    content.append(supportingEventsSection(alert));
    renderSupportingEvents();

    const references = Array.isArray(evidence.source_references) ? evidence.source_references : [];
    const sources = evidenceSection("Source References / " + count(references.length), "Large line ranges stay compact until expanded. References preserve provenance; they do not establish correlation between unrelated sources.");
    if (!references.length) sources.append(node("p", "empty-note", "No source references were returned."));
    for (const reference of references) {
      sources.append(jsonDetails(display(reference.name, reference.source_id) + " / " + count(Array.isArray(reference.line_ranges) ? reference.line_ranges.length : null) + " line ranges", reference));
    }
    content.append(sources);

    const generated = evidenceSection("Optional Generated Commentary");
    generated.classList.add("explanation-section");
    generated.append(node("p", "explanation-warning", "NOT DETECTION EVIDENCE. Generated text can be inaccurate and must be checked against the records above. It does not alter detections, status, priority or incident membership. The optional language service is contacted only when this button is pressed."));
    const explain = node("button", "button button-quiet" + (state.explaining.has(alert.id) ? " is-loading" : ""), state.explaining.has(alert.id) ? "Requesting Commentary..." : "Request Optional Explanation");
    explain.type = "button";
    explain.id = "explain-button";
    explain.disabled = state.explaining.has(alert.id);
    explain.addEventListener("click", () => requestExplanation(alert.id));
    const message = node("div", "message");
    message.id = "explanation-message";
    message.hidden = true;
    message.setAttribute("role", "status");
    message.setAttribute("aria-live", "polite");
    const result = node("div");
    result.id = "explanation-result";
    generated.append(explain, message, result);
    content.append(generated);
    if (state.explanations.has(alert.id)) renderExplanation(state.explanations.get(alert.id));
    const complete = evidenceSection("Complete Stored Record");
    complete.append(jsonDetails("Expand Full Alert + Evidence JSON", alert));
    content.append(complete);
  }

  async function saveAlertStatus(alertId, status) {
    if (state.savingAlerts.has(alertId) || state.evidenceAlert?.id !== alertId || !ALERT_STATUSES.includes(status)) return;
    const request = state.evidenceRequest;
    const runId = state.runId;
    state.savingAlerts.add(alertId);
    setMessage("evidence-message", "Saving alert disposition. Detection evidence is not changed by this update.", "loading");
    const button = $("save-alert-status");
    button.disabled = true;
    button.classList.add("is-loading");
    button.textContent = "Saving...";
    $("evidence-status").disabled = true;
    try {
      const alert = await api("/alerts/" + encodeURIComponent(alertId), { method: "PATCH", body: { status } });
      if (alert.id !== alertId || alert.run_id !== runId) throw new ApiError("The updated alert did not match this run.", 0, "run_scope_mismatch");
      if (state.runId !== runId) return;
      state.alertCache.set(alertId, alert);
      if (state.selected.has(alertId)) state.selected.set(alertId, alert);
      state.savingAlerts.delete(alertId);
      state.summaryError = true;
      renderProfile();
      if (request === state.evidenceRequest && state.evidenceAlert?.id === alertId) {
        state.evidenceAlert = alert;
        renderEvidence(alert);
        setMessage("evidence-message", "Alert status saved. Filtered stored counts and the queue are being read again, without reanalysis.", "success");
        $("save-alert-status").focus({ preventScroll: true });
      }
      await loadAlertsAndSummary();
    } catch (error) {
      if (request === state.evidenceRequest) showError("evidence-message", "Alert status save failed; recorded evidence is retained", error);
    } finally {
      state.savingAlerts.delete(alertId);
      if (state.evidenceAlert?.id === alertId && $("save-alert-status")) {
        $("save-alert-status").disabled = false;
        $("save-alert-status").classList.remove("is-loading");
        $("save-alert-status").textContent = "Save Alert Status";
        $("evidence-status").disabled = false;
      }
    }
  }

  function renderExplanation(result) {
    const container = $("explanation-result");
    if (!container) return;
    container.replaceChildren();
    if (result.warning) container.append(node("p", "explanation-warning", display(result.warning)));
    if (result.explanation) container.append(node("p", "generated-text", display(result.explanation)));
    else container.append(node("p", "field-help", result.available ? "No explanation text was returned." : "Optional explanation is unavailable. Recorded detection evidence remains usable."));
  }

  async function requestExplanation(alertId) {
    if (state.evidenceAlert?.id !== alertId || state.explaining.has(alertId)) return;
    const request = state.evidenceRequest;
    state.explaining.add(alertId);
    buttonState("explain-button", true, "Request Optional Explanation", "Requesting Commentary...");
    $("explain-button").disabled = true;
    setMessage("explanation-message", "Contacting the optional language service on your request. This output is not detection evidence.", "loading");
    try {
      const result = await api("/explain", { method: "POST", body: { alert_id: alertId }, timeout: 120000 });
      state.explanations.set(alertId, result);
      if (request === state.evidenceRequest && state.evidenceAlert?.id === alertId) {
        renderExplanation(result);
        setMessage("explanation-message", "");
      }
    } catch (error) {
      if (request === state.evidenceRequest && state.evidenceAlert?.id === alertId) showError("explanation-message", "Optional commentary request failed; detection evidence is unchanged", error);
    } finally {
      state.explaining.delete(alertId);
      if (state.evidenceAlert?.id === alertId && $("explain-button")) {
        buttonState("explain-button", false, "Request Optional Explanation", "Requesting Commentary...");
        $("explain-button").disabled = false;
      }
    }
  }

  function readFilters() {
    state.filters = {
      severity: $("severity-filter").value,
      activity_type: $("activity-filter").value,
      method: $("method-filter").value,
      status: $("status-filter").value,
      search: $("alert-search").value.trim()
    };
    state.page = 0;
    renderProfile();
    renderPagination();
  }

  function applyFilters() {
    window.clearTimeout(state.searchTimer);
    readFilters();
    loadAlertsAndSummary();
  }

  function bindEvents() {
    $("refresh-button").addEventListener("click", () => refreshWorkspace());
    $("preset-select").addEventListener("change", () => { describePreset(); updateControls(); });
    $("upload-file").addEventListener("change", updateControls);
    $("import-preset").addEventListener("click", () => importDataset("preset"));
    $("import-file").addEventListener("click", () => importDataset("file"));
    $("dataset-select").addEventListener("change", () => selectDataset($("dataset-select").value));
    $("run-select").addEventListener("change", () => selectRun($("run-select").value));
    $("analyze-button").addEventListener("click", analyze);
    $("analysis-config").addEventListener("input", () => { state.configDirty = true; });
    $("analysis-config").addEventListener("submit", (event) => event.preventDefault());
    $("reset-config").addEventListener("click", () => { state.configDirty = false; applyDefaults(); });
    $("alert-filters").addEventListener("submit", (event) => { event.preventDefault(); applyFilters(); });
    for (const id of ["severity-filter", "activity-filter", "method-filter", "status-filter"]) $(id).addEventListener("change", applyFilters);
    $("alert-search").addEventListener("input", () => {
      window.clearTimeout(state.searchTimer);
      readFilters();
      state.resultRequest += 1;
      state.busy.alerts = false;
      $("alert-table-region").setAttribute("aria-busy", "false");
      $("alert-table-region").classList.remove("is-loading");
      updateControls();
      state.searchTimer = window.setTimeout(() => loadAlertsAndSummary(), 300);
    });
    $("clear-filters").addEventListener("click", () => {
      for (const id of ["severity-filter", "activity-filter", "method-filter", "status-filter", "alert-search"]) $(id).value = "";
      applyFilters();
    });
    $("prev-page").addEventListener("click", () => {
      if (state.page > 0) { state.page -= 1; loadAlertsAndSummary(); }
    });
    $("next-page").addEventListener("click", () => {
      if ((state.page + 1) * state.pageSize < state.alertTotal) { state.page += 1; loadAlertsAndSummary(); }
    });
    $("select-page").addEventListener("change", () => {
      for (const alert of state.alerts) {
        if ($("select-page").checked) state.selected.set(alert.id, alert);
        else state.selected.delete(alert.id);
      }
      updateControls();
    });
    $("check-page").addEventListener("click", () => {
      const uncheck = state.alerts.every((alert) => state.selected.has(alert.id));
      for (const alert of state.alerts) {
        if (uncheck) state.selected.delete(alert.id);
        else state.selected.set(alert.id, alert);
      }
      updateControls();
    });
    window.matchMedia("(max-width: 640px)").addEventListener("change", renderSelection);
    $("clear-selection").addEventListener("click", () => { state.selected.clear(); updateControls(); });
    $("new-incident").addEventListener("click", () => openIncidentEditor());
    $("cancel-incident").addEventListener("click", () => { closeIncidentEditor(); renderIncidents(); updateControls(); });
    $("add-checked").addEventListener("click", () => changeMembers(true));
    $("remove-checked").addEventListener("click", () => changeMembers(false));
    $("incident-form").addEventListener("submit", saveIncident);
    $("incident-prev").addEventListener("click", () => loadIncidents(Math.max(0, state.incidentOffset - state.incidentPageSize)));
    $("incident-next").addEventListener("click", () => loadIncidents(state.incidentOffset + state.incidentPageSize));
    $("close-evidence").addEventListener("click", closeEvidence);
    $("drawer-backdrop").addEventListener("click", closeEvidence);
    document.addEventListener("keydown", (event) => {
      if ($("evidence-panel").hidden) return;
      if (event.key === "Escape") { event.preventDefault(); closeEvidence(); }
      if (event.key !== "Tab") return;
      const focusable = [...$("evidence-panel").querySelectorAll("button:not(:disabled), select:not(:disabled), input:not(:disabled), textarea:not(:disabled), summary, a[href], [tabindex='0']")].filter((element) => element.getClientRects().length);
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (!first) { event.preventDefault(); $("evidence-panel").focus(); }
      else if (event.shiftKey && (document.activeElement === first || document.activeElement === $("evidence-panel"))) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    });
    window.addEventListener("pagehide", () => {
      stopPolling();
      window.clearTimeout(state.searchTimer);
    });
    window.addEventListener("pageshow", (event) => { if (event.persisted) ensurePolling(); });
  }

  bindEvents();
  renderCounts();
  renderProfile();
  updateControls();
  refreshWorkspace(true).catch((error) => {
    state.busy.refresh = false;
    showError("global-message", "Workbench initialization failed; no analysis was requested", error);
    updateControls();
  });
})();
