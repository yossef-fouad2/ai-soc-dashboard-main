"""Served Chromium acceptance, including real presets and isolated controlled cases."""

import argparse
import json
import os
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "evaluation" / "browser"
ACCOUNT = "<img/src=x/onerror=window.__soc_xss=1>"
HOST = "lab-<svg/onload=window.__soc_xss=2>"
INCIDENT_TITLE = "Browser validation: <b>hostile text</b>"


def ready(page):
    expect(page.locator("#refresh-button")).to_be_enabled(timeout=30000)
    expect(page.locator("#connection-state")).to_contain_text("API / ok")


def select_dataset(page, identifier, raw):
    ready(page)
    page.select_option("#dataset-select", identifier)
    expect(page.locator("#raw-count")).to_have_text(f"{raw:,}", timeout=30000)
    ready(page)


def safe_dom(page):
    assert page.evaluate("window.__soc_xss === undefined")
    assert page.locator("img[src='x'], svg[onload], #incident-list script, #incident-list b").count() == 0


def no_overflow(page):
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"), "Unexpected horizontal page overflow"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8001")
    args = parser.parse_args()
    cache = Path(tempfile.gettempdir()) / "kilo" / "playwright-browsers"
    if cache.is_dir():
        os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", str(cache))
    OUTPUT.mkdir(parents=True, exist_ok=True)
    report, requests, page_errors, console_errors = {}, [], [], []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(base_url=args.base_url, viewport={"width": 1440, "height": 1050}, reduced_motion="reduce")
        api = context.request

        def get(path, params=None):
            response = api.get(path, params=params)
            assert response.ok, response.text()
            return response.json()

        datasets = get("/datasets", {"limit": 100})["items"]
        network = next(item for item in datasets if item["name"] == "AIT Russellmitchell network flows")
        auth = next(item for item in datasets if item["name"] == "Loghub OpenSSH authentication sample")
        page = context.new_page()
        page.on("request", lambda request: requests.append((request.method, urlsplit(request.url).path)))
        page.on("pageerror", lambda error: page_errors.append(str(error)))
        page.on("console", lambda message: console_errors.append(message.text) if message.type == "error" else None)
        page.goto(args.base_url, wait_until="networkidle")
        select_dataset(page, network["id"], 377704)
        run_id = page.locator("#run-select").input_value()
        summary = get("/summary", {"run_id": run_id})
        expect(page.locator("#alert-count")).to_have_text(f"{summary['alert_count']:,}")
        expect(page.locator("#eligible-count")).to_have_text("377,702")
        expect(page.locator("#skipped-count")).to_have_text("2")
        assert page.locator("#alert-table-body tr").count() == 25
        first_ids = page.locator("#alert-table-body button[data-evidence-alert-id]").evaluate_all("els => els.map(e => e.dataset.evidenceAlertId)")
        page.click("#next-page")
        expect(page.locator("#page-position")).to_contain_text("26-50", timeout=10000)
        next_ids = page.locator("#alert-table-body button[data-evidence-alert-id]").evaluate_all("els => els.map(e => e.dataset.evidenceAlertId)")
        assert not set(first_ids) & set(next_ids)
        page.select_option("#severity-filter", "Medium")
        medium = get("/summary", {"run_id": run_id, "severity": "Medium"})
        expect(page.locator("#alert-count")).to_have_text(f"{medium['alert_count']:,}")
        expect(page.locator("#severity-chart .severity-high .bar-count")).to_have_text("0")
        expect(page.locator("#activity-chart .bar-row").filter(has_text="Brute Force").locator(".bar-count")).to_have_text("0")
        page.click("#clear-filters")
        expect(page.locator("#alert-count")).to_have_text(f"{summary['alert_count']:,}")
        ready(page)
        no_overflow(page)
        page.screenshot(path=str(OUTPUT / "desktop.png"), full_page=True)

        # The real-preset acceptance saved a manual incident linked to an actual
        # held-out ML-only example, so it can be opened without guessing a row.
        page.locator(".incident-card").filter(has_text="Demo: ait_network evidence review").click()
        example_id = page.locator("#incident-members button[data-member-alert-id]").first.get_attribute("data-member-alert-id")
        page.locator("#incident-members button[data-member-alert-id]").first.click()
        expect(page.locator("#evidence-content")).to_contain_text("Network ML Evidence")
        detail = get("/alerts/" + example_id)
        assert detail["methods"] == ["ml"] and detail["evidence"]["ml"]["max_margin"] > 0
        expect(page.locator("#evidence-content")).to_contain_text(str(detail["evidence"]["ml"]["threshold"]))
        page.screenshot(path=str(OUTPUT / "ml-evidence.png"))
        page.click("#close-evidence")
        page.select_option("#severity-filter", "High")
        high = get("/summary", {"run_id": run_id, "severity": "High"})
        try:
            expect(page.locator("#alert-count")).to_have_text(f"{high['alert_count']:,}", timeout=30000)
        except Exception:
            print(json.dumps({"page_errors": page_errors, "console_errors": console_errors, "requests": requests,
                              "alert_message": page.locator("#alert-message").inner_text(),
                              "result_state": page.locator("#result-state").inner_text()}, indent=2), flush=True)
            page.screenshot(path=str(OUTPUT / "failed-queue.png"))
            raise
        heavy = next(alert for alert in get("/alerts", {"run_id": run_id, "severity": "High", "limit": 100})["items"] if alert["occurrence_count"] > 25)
        page.locator("button[data-evidence-alert-id='" + heavy["id"] + "']").click()
        page.locator("#supporting-events > summary").click()
        expect(page.locator("#events-position")).to_contain_text("1-25", timeout=10000)
        page.click("#events-next")
        expect(page.locator("#events-position")).to_contain_text("26-50")
        assert page.locator("#events-list > details").count() == 25
        page.click("#close-evidence")
        ready(page)
        baseline_requests, baseline_runs = len(requests), get("/runs")["total"]
        page.click("#refresh-button")
        ready(page)
        page.reload(wait_until="networkidle")
        ready(page)
        assert get("/runs")["total"] == baseline_runs
        assert all(method == "GET" for method, path in requests[baseline_requests:])
        assert not any(path == "/explain" or (path == "/analyze" and method == "GET") for method, path in requests)
        assert not page_errors and not console_errors, (page_errors, console_errors)
        report["desktop"] = {"viewport": [1440, 1050], "real_network_alerts": summary["alert_count"], "page_rows": 25, "pagination": True, "filtered_charts": True, "raw_event_pagination": True, "ml_only_evidence": True, "read_only_refresh": True}
        print("Desktop real-preset, filtered summary, evidence and read-only refresh checks passed.", flush=True)

        # Controlled cases exercise suspicious-success rules and hostile text,
        # not an accuracy claim or a replacement for the supplied raw corpus.
        fixture = OUTPUT / "controlled-browser-auth.log"
        lines = [f"Dec 10 12:00:{second:02d} {HOST} sshd[44]: Failed password for {ACCOUNT} from 192.0.2.55 port 4444 ssh2" for second in range(6)]
        lines.append(f"Dec 10 12:00:06 {HOST} sshd[44]: Accepted publickey for {ACCOUNT} from 192.0.2.55 port 4444 ssh2")
        fixture.write_text("\n".join(lines) + "\n", encoding="utf-8")
        page.click("#clear-filters")
        ready(page)
        before_import = get("/runs")["total"]
        page.locator("#upload-file").set_input_files(str(fixture))
        page.click("#import-file")
        expect(page.locator("#control-message")).to_contain_text("No analysis was started.", timeout=30000)
        assert get("/runs")["total"] == before_import
        ready(page)
        page.click("#analyze-button")
        expect(page.locator("#run-state")).to_have_text("Completed", timeout=30000)
        expect(page.locator("#alert-count")).to_have_text("2")
        expect(page.locator("#raw-count")).to_have_text("7")
        expect(page.locator("#run-details")).to_contain_text("Bypassed / Authentication")
        expect(page.locator("#alert-table-body")).to_contain_text(ACCOUNT)
        expect(page.locator("#alert-table-body")).to_contain_text(HOST)
        expect(page.locator("#alert-table-body")).to_contain_text("Source-relative clock")
        safe_dom(page)
        controlled_run = page.locator("#run-select").input_value()
        critical = get("/alerts", {"run_id": controlled_run, "severity": "Critical"})["items"][0]
        page.locator("button[data-evidence-alert-id='" + critical["id"] + "']").click()
        expect(page.locator("#evidence-content")).to_contain_text(ACCOUNT)
        expect(page.locator("#evidence-content")).to_contain_text("no year or timezone is invented")
        safe_dom(page)
        page.select_option("#evidence-status", "false_positive")
        page.click("#save-alert-status")
        expect(page.locator("#evidence-message")).to_contain_text("Alert status saved")
        assert get("/alerts/" + critical["id"])["status"] == "false_positive"
        assert not any(path == "/explain" for method, path in requests)
        with page.expect_response(lambda response: urlsplit(response.url).path == "/explain") as explanation_response:
            page.click("#explain-button")
        explanation = explanation_response.value.json()
        expect(page.locator("#explain-button")).to_be_enabled(timeout=30000)
        assert get("/summary", {"run_id": controlled_run})["alert_count"] == 2
        assert get("/alerts/" + critical["id"])["evidence"]["ml"] is None
        report["optional_explanation_available"] = explanation["available"]
        page.click("#close-evidence")
        page.locator("#alert-table-body input[type=checkbox]").first.check()
        page.locator("#alert-table-body input[type=checkbox]").nth(1).check()
        existing = next((incident for incident in get("/incidents", {"run_id": controlled_run})["items"] if incident["title"] == INCIDENT_TITLE), None)
        if existing:
            page.locator(".incident-card").filter(has_text=INCIDENT_TITLE).click()
            page.click("#add-checked")
        else:
            page.click("#new-incident")
        page.fill("#incident-title", INCIDENT_TITLE)
        page.fill("#incident-notes", "<script>window.__soc_xss=3</script> Controlled functional check only; not a confirmed attack.")
        page.click("#save-incident")
        expect(page.locator("#incident-message")).to_contain_text("Incident saved", timeout=10000)
        page.select_option("#incident-status", "closed")
        page.locator("#incident-members .member-remove").first.click()
        page.click("#save-incident")
        expect(page.locator("#incident-message")).to_contain_text("Incident saved")
        ready(page)
        saved = next(incident for incident in get("/incidents", {"run_id": controlled_run})["items"] if incident["title"] == INCIDENT_TITLE)
        assert saved["status"] == "closed" and len(saved["alert_ids"]) == 1
        safe_dom(page)
        page.reload(wait_until="networkidle")
        ready(page)
        assert get("/incidents/" + saved["id"])["notes"].startswith("<script>")
        assert get("/alerts/" + critical["id"])["status"] == "false_positive"
        page.fill("#alert-search", "unmatched-browser-filter")
        expect(page.locator("#alert-count")).to_have_text("0")
        expect(page.locator("#alert-table-body")).to_contain_text("No stored alerts match")
        page.click("#clear-filters")
        expect(page.locator("#alert-count")).to_have_text("2")
        page.route("**/summary?*", lambda route: route.fulfill(status=503, content_type="application/json", body=json.dumps({"detail": {"code": "controlled_unavailable", "message": ACCOUNT + " controlled summary failure"}})))
        page.fill("#alert-search", "unmatched-browser-filter")
        expect(page.locator("#alert-message")).to_contain_text("controlled summary failure")
        expect(page.locator("#alert-count")).to_have_text("2")
        expect(page.locator("#summary-source")).to_contain_text("Last successful summary is retained")
        safe_dom(page)
        page.unroute("**/summary?*")
        page.click("#clear-filters")
        expect(page.locator("#alert-count")).to_have_text("2")
        report["controlled_cases"] = {"raw_auth_events": 7, "rule_alerts": 2, "hostile_text_escaped": True, "source_relative_clock": True, "status_persisted": True, "manual_incident_membership_persisted": True, "empty_and_stale_error_states": True, "no_automatic_ollama": True}

        mobile = browser.new_context(base_url=args.base_url, viewport={"width": 390, "height": 844}, is_mobile=True, has_touch=True, reduced_motion="reduce")
        phone = mobile.new_page()
        phone.on("pageerror", lambda error: page_errors.append(str(error)))
        phone.goto(args.base_url, wait_until="networkidle")
        select_dataset(phone, network["id"], 377704)
        no_overflow(phone)
        phone.screenshot(path=str(OUTPUT / "mobile-network.png"), full_page=True)
        select_dataset(phone, auth["id"], 2000)
        expect(phone.locator("#eligible-count")).to_have_text("519")
        expect(phone.locator("#skipped-count")).to_have_text("1,481")
        expect(phone.locator("#alert-table-body")).to_contain_text("Source-relative clock / no capture year")
        expect(phone.locator("#check-page")).to_be_visible()
        no_overflow(phone)
        phone.screenshot(path=str(OUTPUT / "mobile-auth.png"), full_page=True)
        phone.locator("#alert-table-body .evidence-link").first.click()
        expect(phone.locator("#evidence-content")).to_contain_text("Authentication detections bypass the network model")
        no_overflow(phone)
        phone.screenshot(path=str(OUTPUT / "mobile-evidence.png"))
        phone.keyboard.press("Escape")
        expect(phone.locator("#evidence-panel")).to_be_hidden()
        assert not page_errors, page_errors
        report.update(mobile={"viewport": [390, 844], "real_network_and_auth": True, "horizontal_overflow": False, "evidence_drawer": True}, page_errors=page_errors, browser_version=browser.version)
        mobile.close()
        context.close()
        browser.close()
    output = OUTPUT / "browser_acceptance.json"
    output.write_text(json.dumps(report, indent=2, allow_nan=False), encoding="utf-8")
    print(json.dumps(report, indent=2, allow_nan=False), flush=True)
    print("Browser acceptance report: " + str(output), flush=True)


if __name__ == "__main__":
    main()
