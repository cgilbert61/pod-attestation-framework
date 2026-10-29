"""Host-side live verification script against the running Docker Compose `demo` stack."""

from __future__ import annotations

import json
import time

import httpx


def main() -> int:
    registry_url = "http://localhost:18080"
    snapshot_url = "http://localhost:18081"
    prevalidator_url = "http://localhost:18082"
    engine_url = "http://localhost:18083"
    gateway_url = "http://localhost:14000"
    admin_headers = {"X-POD-Admin-Key": "pod-dev-admin-key"}

    with httpx.Client(timeout=10.0) as client:
        # Wait up to 20s for engine bootstrap to populate Registry and reload Prevalidator
        for _ in range(20):
            try:
                r_prev = client.get(f"{prevalidator_url}/healthz")
                if r_prev.status_code == 200 and r_prev.json().get("status") == "ok":
                    break
            except Exception:
                pass
            time.sleep(1.0)

        reg_records = client.get(f"{registry_url}/v1/records", headers=admin_headers).json()["records"]
        reg_reviews = client.get(f"{registry_url}/v1/reviews", headers=admin_headers).json()["reviews"]
        snap_latest = client.get(f"{snapshot_url}/v1/snapshot/latest").json()
        prev_health = client.get(f"{prevalidator_url}/healthz").json()
        eng_health = client.get(f"{engine_url}/healthz").json()
        gw_health = client.get(f"{gateway_url}/healthz").json()

        # 1. OpenAI `/v1/chat/completions` ALLOW on Public attested document
        r_allow = client.post(
            f"{prevalidator_url}/v1/chat/completions",
            headers={"X-POD-Caller-Key": "pod-key-public"},
            json={
                "model": "gpt-4o",
                "messages": [
                    {
                        "role": "user",
                        "content": (
                            "Summarize: "
                            '<pod:object locator="file://estate/fileshare/product_overview_public.md">'
                            "Open Source AI Architecture Overview"
                            "</pod:object>"
                        ),
                    }
                ],
            },
        )

        # 2. Anthropic `/v1/messages` STRIP on Confidential Excel spreadsheet
        r_strip = client.post(
            f"{prevalidator_url}/v1/messages",
            headers={"X-POD-Caller-Key": "pod-key-confidential"},
            json={
                "model": "local-model",
                "messages": [
                    {
                        "role": "user",
                        "content": (
                            "Answer HR policy question. "
                            '<pod:object locator="file://estate/fileshare/dept_compensation_confidential.xlsx">'
                            "diana.prince@example.org | salary: $145,000"
                            "</pod:object>"
                        ),
                    }
                ],
            },
        )

        # 3. OpenAI `/v1/chat/completions` REFUSE (403) on Restricted clinical record
        r_deny_restricted = client.post(
            f"{prevalidator_url}/v1/chat/completions",
            headers={"X-POD-Caller-Key": "pod-key-restricted"},
            json={
                "model": "gpt-4o",
                "messages": [
                    {
                        "role": "user",
                        "content": (
                            '<pod:object locator="file://estate/fileshare/clinical_intake_restricted.txt">'
                            "Patient SSN: 412-58-9021"
                            "</pod:object>"
                        ),
                    }
                ],
            },
        )

        # 4. OpenAI `/v1/chat/completions` REFUSE (403) on Unattested object
        r_deny_unattested = client.post(
            f"{prevalidator_url}/v1/chat/completions",
            headers={"X-POD-Caller-Key": "pod-key-public"},
            json={
                "model": "gpt-4o",
                "messages": [
                    {
                        "role": "user",
                        "content": '<pod:object locator="file://estate/fileshare/unknown_secret.txt">Secret</pod:object>',
                    }
                ],
            },
        )

        audit_log = client.get(f"{prevalidator_url}/v1/admin/audit-log", headers=admin_headers).json()["entries"]

        # 5. Test PC Directory Attestation + Prevalidator Directory Scan + Unattested File Drop workflow
        r_att_dir = client.post(
            f"{prevalidator_url}/v1/admin/attest-directory",
            headers=admin_headers,
            json={"directory_path": "D:\\attestation\\pc_demo_folder"},
        )
        assert r_att_dir.status_code == 200, r_att_dir.text
        att_dir_data = r_att_dir.json()

        r_pv_before = client.post(
            f"{prevalidator_url}/v1/prevalidate-directory",
            json={
                "directory_path": "D:\\attestation\\pc_demo_folder",
                "caller_key": "pod-key-confidential",
                "model": "local-model",
            },
        )
        assert r_pv_before.status_code == 200, r_pv_before.text
        pv_before = r_pv_before.json()

        # Drop an unattested file into D:\attestation\pc_demo_folder and re-run Prevalidator Directory Scan
        r_drop = client.post(
            f"{prevalidator_url}/v1/admin/add-unattested-file",
            headers=admin_headers,
            json={
                "directory_path": "D:\\attestation\\pc_demo_folder",
                "filename": "07_rogue_unattested_note.txt",
            },
        )
        assert r_drop.status_code == 200, r_drop.text

        r_pv_after = client.post(
            f"{prevalidator_url}/v1/prevalidate-directory",
            json={
                "directory_path": "D:\\attestation\\pc_demo_folder",
                "caller_key": "pod-key-confidential",
                "model": "local-model",
            },
        )
        assert r_pv_after.status_code == 200, r_pv_after.text
        pv_after = r_pv_after.json()

    summary = {
        "services": {
            "engine": {"url": engine_url, "health": eng_health},
            "registry": {"url": registry_url, "active_records": len(reg_records), "pending_reviews": len(reg_reviews)},
            "snapshot_publisher": {"url": snapshot_url, "signatures": snap_latest.get("signatures")},
            "prevalidator": {"url": prevalidator_url, "health": prev_health},
            "ai_gateway": {"url": gateway_url, "health": gw_health},
        },
        "pc_directory_workflow": {
            "directory": "D:\\attestation\\pc_demo_folder",
            "attested_files": att_dir_data["attested_active_count"],
            "scan_before_unattested_drop": {
                "total": pv_before["total_files"],
                "passed": pv_before["passed_count"],
                "failed": pv_before["failed_count"],
                "unattested": pv_before["unattested_count"],
            },
            "scan_after_unattested_drop": {
                "total": pv_after["total_files"],
                "passed": pv_after["passed_count"],
                "failed": pv_after["failed_count"],
                "unattested": pv_after["unattested_count"],
            },
        },
        "live_requests": {
            "openai_allow": {
                "status_code": r_allow.status_code,
                "gateway_reply": r_allow.json()["choices"][0]["message"]["content"],
            },
            "anthropic_strip": {
                "status_code": r_strip.status_code,
                "gateway_reply": r_strip.json()["content"][0]["text"],
            },
            "restricted_refusal": {
                "status_code": r_deny_restricted.status_code,
                "body": r_deny_restricted.json(),
            },
            "unattested_refusal": {
                "status_code": r_deny_unattested.status_code,
                "body": r_deny_unattested.json(),
            },
        },
        "audit_log_count": len(audit_log),
    }
    print(json.dumps(summary, indent=2))
    assert r_allow.status_code == 200
    assert r_strip.status_code == 200
    assert "[POD:STRIPPED]" in r_strip.json()["content"][0]["text"]
    assert r_deny_restricted.status_code == 403
    assert r_deny_unattested.status_code == 403
    assert r_deny_restricted.json() == r_deny_unattested.json()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
