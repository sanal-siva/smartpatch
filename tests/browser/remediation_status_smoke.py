"""Synthetic-only CVE lifecycle, container maintenance and archive evidence checks.

No port is bound and no request reaches a switch or service. All API requests
are intercepted and must be GET, including automatic progress refreshes.
"""
import argparse
import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from playwright.sync_api import expect, sync_playwright

from workspace_smoke import ATTACK_TEXT, NOW, TEST_TOKEN, fixtures, mock_routes, ready


def run(output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    errors, requests, status_reads = [], [], []
    device, _ = fixtures()
    device.update(maintenance={"maintenance_mode": True,
                               "capabilities": {"container_package_update": 1},
                               "reported_at": NOW},
                  container_maintenance_eligible=True,
                  maintenance_reason="Fresh collector maintenance mode and capability report.")
    archive = {"package": "socat", "version": "1.0", "architecture": "amd64",
               "sha256": "a" * 64, "source": {"type": "debian_snapshot",
               "snapshot": "20260901T000000Z", "archive": "debian", "suite": "trixie",
               "verification": "apt_signed_repository",
               "url": "https://snapshot.debian.org/archive/debian/20260901T000000Z/"}}
    common = dict(device_id=device["id"], hostname=device["hostname"], package_name="socat",
                  scope="container:pmon", from_version="1.0", target_version="1.1",
                  observed_version="1.1", updated_at=NOW, applicability="affected",
                  current_matching_finding=True,
                  central_resolution={"status": "pending", "reason": "Waiting for an accepted central scan."})
    rows = [dict(common, id="cli-row", cve_id="CVE-TEST-0001", origin="cli",
                 local_plan_id="local-plan", state="downloading", collector_state="downloading",
                 progress={"phase": "downloading", "events": [{"phase": "planned", "timestamp": NOW}]},
                 staging_result={"value": {"details": {"maintenance_checks_enabled": False,
                     "rollback_available": True, "rollback_sources": [archive],
                     "checks_skipped": ["disk_space"]}}}),
            dict(common, id="service-row", cve_id="CVE-TEST-0002", origin="service",
                 plan_id="plan-staged-test", state="staged", collector_state="staged"),
            dict(common, id="resolved-row", cve_id="CVE-TEST-0003", origin="cli",
                 local_plan_id="older-plan", state="resolved", collector_state="pending_reassessment",
                 current_matching_finding=False,
                 central_resolution={"status": "completed", "reason": "Selected CVE absent from the accepted scoped scan.", "scan_completed_at": NOW}),
            dict(common, id="fixed-row", cve_id="CVE-TEST-0004", origin="inventory",
                 state="no_plan", collector_state=None, applicability="fixed", scope="host",
                 package_name=ATTACK_TEXT, current_matching_finding=True,
                 central_resolution={"status": "not_assessed", "reason": "No remediation attempt has been centrally verified."})]
    control = {}
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, args=["--no-sandbox"])
        context = browser.new_context(viewport={"width": 1550, "height": 1060})
        base = mock_routes(context, requests)
        base["maintenance_plan"].update(scope="container:pmon", container_maintenance=True,
                                         maintenance_required=False, status="staged", approved=True,
                                         execution_eligible=True)

        def status_handler(route):
            request = route.request
            assert request.method == "GET", "Status refresh must never mutate operations"
            assert request.headers.get("authorization") == "Bearer " + TEST_TOKEN
            query = parse_qs(urlparse(request.url).query)
            status_reads.append(query)
            if control.get("error"):
                route.fulfill(status=503, json={"detail": "Synthetic status outage"})
                return
            selected = rows
            if query.get("record_id"):
                selected = [row for row in selected if row["id"] == query["record_id"][0]]
            for key in ("device_id", "cve_id", "scope"):
                if query.get(key):
                    selected = [row for row in selected if row[key] == query[key][0]]
            if query.get("status"):
                selected = [row for row in selected if row["state"] == query["status"][0]]
            offset, limit = int(query.get("offset", ["0"])[0]), int(query.get("limit", ["50"])[0])
            route.fulfill(json={"items": selected[offset:offset+limit], "total": len(selected),
                                "offset": offset, "limit": limit, "counts": {}})

        def device_handler(route):
            assert route.request.method == "GET"
            route.fulfill(json={"devices": [device]} if urlparse(route.request.url).path.endswith("/devices") else device)

        context.route("**/api/v1/remediation-status**", status_handler)
        context.route("**/api/v1/devices**", device_handler)
        context.route("**/api/v1/devices/**", device_handler)
        context.add_init_script("sessionStorage.setItem('smart_patch_admin_token', '" + TEST_TOKEN + "')")
        page = context.new_page()
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto("https://smart-patch.test/ui/remediation-status")
        ready(page)
        expect(page.get_by_role("heading", name="Remediation status", exact=True)).to_be_visible()
        expect(page.get_by_text("CVE-TEST-0003", exact=True)).to_be_visible()
        assert page.locator("img[src=x]").count() == 0
        assert page.evaluate("window.smartPatchXss || null") is None
        rows[3].update(package_name="example-library", target_version=None, observed_version=None)
        page.get_by_role("button", name="Refresh status", exact=True).click()
        expect(page.get_by_text("example-library", exact=True)).to_be_visible()
        page.screenshot(path=str(output / "remediation-status-history.png"), full_page=True)
        page.set_viewport_size({"width": 390, "height": 844})
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), "Remediation status overflows the mobile viewport"
        page.screenshot(path=str(output / "remediation-status-mobile.png"), full_page=True)
        page.set_viewport_size({"width": 1550, "height": 1060})

        # Local plans cannot be centrally approved or executed from this history.
        page.get_by_label("Remediation state", exact=True).select_option("downloading")
        expect(page.locator("#page-content tbody tr")).to_have_count(1)
        page.locator("tr").filter(has_text="CVE-TEST-0001").get_by_role("button", name="Inspect status").click()
        dialog = page.locator("#detail-dialog")
        expect(dialog.get_by_text("Switch CLI", exact=True)).to_be_visible()
        expect(dialog.get_by_role("button", name="Review service plan")).to_have_count(0)
        expect(dialog.get_by_role("button", name="Approve", exact=False)).to_have_count(0)
        expect(dialog.get_by_text("Debian snapshot (collector reported)", exact=True)).to_be_visible()
        expect(dialog.get_by_text("APT signed repository (collector reported)", exact=True)).to_be_visible()
        expect(dialog.get_by_text("Maintenance checks disabled for this request.", exact=False)).to_be_visible()
        assert dialog.get_by_role("link", name="Open recorded archive").get_attribute("href").startswith("https://snapshot.debian.org/")

        # Collector-supplied archive claims are text, never executable markup;
        # a claimed Debian source must not disguise another hostname.
        stage_details = rows[0]["staging_result"]["value"]["details"]
        stage_details["rollback_sources"] = [archive, None] + [
            {"package": ATTACK_TEXT, "source": {"type": "debian_snapshot", "verification": ATTACK_TEXT, "url": url}}
            for url in ("javascript:window.smartPatchXss=1", "data:text/html,<script>window.smartPatchXss=1</script>",
                        "https://snapshot.debian.org.attacker.invalid/archive/")]
        stage_details["rollback_missing"] = [None, {"package": ATTACK_TEXT, "reason": ATTACK_TEXT}]
        rows[0]["progress"] = {"phase": "downloading", "events": [None, {"phase": ATTACK_TEXT}]}
        dialog.get_by_role("button", name="Refresh this record", exact=True).click()
        expect(dialog.get_by_text("Snapshot source not established", exact=True)).to_have_count(3)
        assert not dialog.locator('a[href^="javascript:"],a[href^="data:"],img[src=x]').count()
        assert page.evaluate("window.smartPatchXss || null") is None
        archive_links = dialog.get_by_role("link", name="Open recorded archive")
        assert archive_links.count() == 2
        for archive_link in archive_links.all():
            assert urlparse(archive_link.get_attribute("href")).scheme in ("http", "https")
            assert "noopener" in archive_link.get_attribute("rel")
        stage_details["rollback_sources"] = [archive]
        stage_details.pop("rollback_missing")

        # Installation and restart outcomes do not inherit an inconsistent
        # completed/resolved label from an older scan payload.
        for phase in ("installed", "restarting"):
            rows[0].update(state=phase, collector_state=phase, progress={"phase": phase},
                           central_resolution={"status": "completed", "reason": "Earlier scan result"})
            dialog.get_by_role("button", name="Refresh this record", exact=True).click()
            expect(dialog.locator('.detail-badges .badge').first).to_have_text(phase.title())
            expect(dialog.get_by_text("Resolved", exact=True)).to_have_count(0)
            expect(dialog.get_by_text("Pending Reassessment", exact=True)).to_be_visible()
        rows[0]["central_resolution"] = {"status": "pending", "reason": "Waiting for an accepted central scan."}

        # The detail remains current when a new phase no longer matches the
        # original table filter, without issuing any package action.
        rows[0].update(state="pending_reassessment", collector_state="installed",
                       progress={"phase": "installed"}, execution_result={"value": {"details": {
                           "container_restart": {"status": "complete", "container_id": "container-test", "started_at": NOW, "completed_at": NOW},
                           "writable_layer_warning": "Container recreation can discard this package change.",
                           "rollback_available": False, "rollback_missing": ["Previous dependency unavailable"]}}})
        page.wait_for_timeout(5300)
        expect(dialog.get_by_text("Pending Reassessment", exact=True)).to_be_visible()
        expect(dialog.get_by_role("heading", name="Target container restart", exact=True)).to_be_visible()
        expect(dialog.get_by_text("The collector reported that the target container restart completed.", exact=False)).to_be_visible()
        expect(dialog.get_by_text("Automatic rollback unavailable.", exact=False)).to_be_visible()
        page.screenshot(path=str(output / "cli-container-reassessment.png"), full_page=True)
        dialog.get_by_role("button", name="Close details").click()

        # Resolution history remains filterable; fixed applicability isn't a resolved attempt.
        page.get_by_label("Remediation state", exact=True).select_option("resolved")
        expect(page.locator("#page-content tbody tr")).to_have_count(1)
        expect(page.get_by_text("CVE-TEST-0003", exact=True)).to_be_visible()
        reads = len(status_reads)
        page.wait_for_timeout(5300)
        assert len(status_reads) == reads, "Terminal history must not keep polling"
        page.get_by_label("Remediation state", exact=True).select_option("no_plan")
        expect(page.get_by_text("CVE-TEST-0004", exact=True)).to_be_visible()
        expect(page.locator("#page-content .badge").filter(has_text="Resolved")).to_have_count(0)
        page.get_by_label("Remediation state", exact=True).select_option("")
        page.get_by_label("Remediation scope", exact=True).fill("container:pmon")
        expect(page.locator("#page-content tbody tr")).to_have_count(3)
        page.get_by_label("Remediation CVE", exact=True).fill("CVE-TEST-0002")
        expect(page.locator("#page-content tbody tr")).to_have_count(1)
        page.get_by_role("button", name="Inspect status", exact=True).click()
        dialog.get_by_role("button", name="Review service plan", exact=True).click()
        expect(dialog.get_by_text("Container maintenance is enabled for this plan.", exact=False)).to_be_visible()
        expect(dialog.get_by_text("sudo config security smart-patch maintenance-mode enable", exact=True)).to_be_visible()
        expect(dialog.get_by_role("button", name="4 · Review execution", exact=True)).to_be_enabled()
        dialog.get_by_role("button", name="4 · Review execution", exact=True).click()
        expect(dialog.get_by_text("This also authorizes an automatic restart of container:pmon.", exact=False)).to_be_visible()
        dialog.get_by_role("button", name="Back to review", exact=True).click()
        dialog.get_by_role("button", name="Inspect switch maintenance mode").click()
        expect(dialog.get_by_text("Enabled on switch", exact=True), f"Device detail JS errors: {errors}").to_be_visible()
        expect(dialog.get_by_text("Enter maintenance mode after arranging any required traffic drain.", exact=False)).to_be_visible()
        page.screenshot(path=str(output / "switch-container-maintenance.png"), full_page=True)
        dialog.get_by_role("button", name="Close details").click()

        # Read errors leave the latest data visible and stop automatic retries.
        control["error"] = True
        page.get_by_role("button", name="Refresh status", exact=True).click()
        expect(page.get_by_text("Status could not be loaded: Synthetic status outage", exact=False)).to_be_visible()
        expect(page.get_by_text("CVE-TEST-0002", exact=True)).to_be_visible()
        reads = len(status_reads)
        page.wait_for_timeout(5300)
        assert len(status_reads) == reads
        control.clear()
        page.get_by_role("button", name="Refresh status", exact=True).click()
        expect(page.get_by_text("Active records refresh every 5 seconds", exact=False)).to_be_visible()
        page.locator('a[data-nav="fleet"]').click()
        ready(page)
        reads = len(status_reads)
        page.wait_for_timeout(5300)
        assert len(status_reads) == reads, "Leaving status view must stop its polling"
        assert all(request["method"] == "GET" for request in requests), requests

        # File metadata boundaries are sufficient for client-side validation;
        # server integration tests send the full byte-sized documents separately.
        uploads = []
        upload_control = {}
        context.route("**/api/v1/upload-limits", lambda route: route.fulfill(json={"sbom_bytes": 50 * 1024 * 1024, "request_bytes": 16 * 1024 * 1024}))

        def upload_handler(route):
            assert route.request.method == "POST"
            assert route.request.headers.get("content-type", "").startswith("multipart/form-data;")
            uploads.append(route.request.url)
            if upload_control.get("error"):
                route.fulfill(status=413, json={"detail": "SBOM upload exceeds 50 MiB limit"})
            else:
                route.fulfill(json={"message": "Synthetic SBOM accepted"})

        context.route("**/api/v1/sbom-upload", upload_handler)
        page.locator('a[data-nav="releases"]').click()
        ready(page)
        expect(page.get_by_text("Maximum 50 MiB (52,428,800 bytes).", exact=False)).to_be_visible()

        def upload_metadata(size):
            page.get_by_placeholder("Match the registered build identity").fill("synthetic-build")
            file_input = page.get_by_label("SBOM document", exact=True)
            file_input.set_input_files({"name": "synthetic.json", "mimeType": "application/json", "buffer": b"{}"})
            file_input.evaluate("(input, size) => { Object.defineProperty(input.files[0], 'size', {value: size}); input.files[0].text = () => {throw Error('Client must not parse the entire SBOM')}; }", size)
            page.get_by_role("button", name="Upload SBOM", exact=True).click()

        upload_metadata(49 * 1024 * 1024)
        expect(page.get_by_text("Synthetic SBOM accepted", exact=True)).to_be_visible()
        ready(page)
        assert len(uploads) == 1, "49 MiB metadata must pass client validation"
        upload_metadata(50 * 1024 * 1024)
        ready(page)
        assert len(uploads) == 2, "The exact 50 MiB boundary is allowed"
        upload_metadata(50 * 1024 * 1024 + 1)
        expect(page.get_by_text("SBOM upload exceeds 50 MiB limit. Select a smaller file.", exact=True)).to_be_visible()
        assert len(uploads) == 2, "Oversized files must be stopped before upload"
        upload_control["error"] = True
        upload_metadata(49 * 1024 * 1024)
        expect(page.get_by_text("SBOM upload exceeds 50 MiB limit", exact=True)).to_be_visible()
        expect(page.get_by_role("button", name="Upload SBOM", exact=True)).to_be_enabled()
        assert len(uploads) == 3
        assert not errors, errors
        browser.close()
    result = {"mode": "synthetic only", "status_reads": len(status_reads), "javascript_errors": errors,
              "screenshots": [path.name for path in output.glob("*.png")]}
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="/tmp/smart-patch-remediation-ui")
    run(parser.parse_args().output)
