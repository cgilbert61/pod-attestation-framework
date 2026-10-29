"""Reproducible End-to-End Demo exercising Phases 0, 1, 2, and 3 over the Synthetic Sample Estate."""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from engine.pipeline import AttestationEngine
from examples.phase0_worked_example import run_phase0_worked_example
from examples.synthetic_estate import build_synthetic_estate
from prevalidator.enforcer import InMemorySnapshotStore, PrevalidatorEnforcer
from prevalidator.proxy import create_prevalidator_app
from registry.store import RegistryService
from snapshot.publisher import SnapshotPublisher


def run_end_to_end_demo(work_dir: Path | None = None) -> dict[str, Any]:
    base_dir = work_dir or Path(tempfile.mkdtemp(prefix="pod_e2e_demo_"))
    base_dir.mkdir(parents=True, exist_ok=True)

    # --- PHASE 0: Worked Single-File Example & Tamper Verification ---
    phase0_summary = run_phase0_worked_example(base_dir / "phase0")

    # --- PHASE 1: Synthetic Estate Crawl (File Share + Database) & Full Lifecycle ---
    estate = build_synthetic_estate(base_dir / "estate")
    db_file = base_dir / "pod_registry.db"
    if db_file.exists():
        db_file.unlink()
    registry_db_url = f"sqlite:///{db_file.as_posix()}"
    key_dir = base_dir / "keys"
    registry = RegistryService(db_url=registry_db_url, key_dir=key_dir)
    engine = AttestationEngine(registry=registry)

    file_results = engine.crawl_file_share(
        root_dir=estate["fileshare_dir"],
        owner="fileshare-steward@example.org",
        locator_base="file://estate/fileshare",
        environment="synthetic",
    )
    db_results = engine.crawl_database(
        db_url=estate["db_url"],
        owner="data-platform@example.org",
        locator_override_base="postgres://estate-db:5432/estate",
        environment="synthetic",
    )

    # Verify low-confidence file was queued in PENDING_REVIEW with no active record
    pending_reviews = registry.list_review_queue(status="PENDING_REVIEW")
    low_conf_reviews = [r for r in pending_reviews if r["reason"] == "low_confidence"]
    assert len(low_conf_reviews) == 1

    # Exercise lifecycle transitions:
    # 1) Raise tier of public catalog table to Internal (free and immediate)
    raised = registry.raise_tier("postgres://estate-db:5432/estate/public/public_catalog", "Internal")
    assert raised["tier"] == "Internal"

    # 2) Lower tier back to Public with dual approval (2 distinct reviewers)
    lowered = registry.lower_tier(
        "postgres://estate-db:5432/estate/public/public_catalog",
        "Public",
        approvals=[
            {"approver_id": "alice-sec@example.org", "rationale": "Verified SKU catalog contains only public SKUs."},
            {"approver_id": "bob-dpo@example.org", "rationale": "Confirmed public release approval."},
        ],
    )
    assert lowered["tier"] == "Public"
    assert lowered["status"] == "tier_lowered"

    # 3) Renew public document record with matching SHA-256
    pub_rec = registry.lookup_by_locator("file://estate/fileshare/product_overview_public.md")
    assert pub_rec is not None
    renewed = registry.renew_record(
        locator="file://estate/fileshare/product_overview_public.md",
        observed_content_sha256=pub_rec["content_sha256"],
    )
    assert renewed["status"] == "renewed"

    # --- PHASE 2: Publish Signed Snapshot ---
    snap_path = base_dir / "pod_snapshot.dsse.json"
    publisher = SnapshotPublisher(registry=registry, ttl_seconds=600, snapshot_output_path=snap_path)
    snapshot_envelope = publisher.publish_snapshot()

    # --- PHASE 3: Prevalidator Proxy (OpenAI & Anthropic, Observe & Enforce, Latency Benchmark) ---
    snap_store = InMemorySnapshotStore(registry.keyring)
    snap_store.load_from_envelope(snapshot_envelope)
    enforcer = PrevalidatorEnforcer(snapshot_store=snap_store, mode="enforce")
    app = create_prevalidator_app(enforcer=enforcer, upstream_gateway_url="mock://local")
    client = TestClient(app)

    # Warm up TestClient and measure pure in-memory snapshot-lookup enforcement latency
    client.get("/healthz")
    sample_req = {
        "model": "gpt-4o",
        "messages": [
            {
                "role": "user",
                "content": (
                    "Summarize this document: "
                    f'<pod:object locator="file://estate/fileshare/product_overview_public.md" sha256="{pub_rec["content_sha256"]}">'
                    "Open Source AI Architecture Overview"
                    "</pod:object>"
                ),
            }
        ],
    }
    t0 = time.perf_counter()
    enforcer.evaluate_request(sample_req, headers={"X-POD-Caller-Key": "pod-key-public"})
    allow_latency_ms = (time.perf_counter() - t0) * 1000.0

    # Case A: Allowed Public file reference on OpenAI `/v1/chat/completions`
    resp_allow = client.post(
        "/v1/chat/completions",
        headers={"X-POD-Caller-Key": "pod-key-public"},
        json=sample_req,
    )
    assert resp_allow.status_code == 200

    # Case B: Stripped Confidential spreadsheet reference on Anthropic `/v1/messages` (local model + Confidential clearance)
    resp_strip = client.post(
        "/v1/messages",
        headers={"X-POD-Caller-Key": "pod-key-confidential"},
        json={
            "model": "local-model",
            "messages": [
                {
                    "role": "user",
                    "content": (
                        "Provide general HR policy guidance. "
                        '<pod:object locator="file://estate/fileshare/dept_compensation_confidential.xlsx">'
                        "diana.prince@example.org | salary: $145,000"
                        "</pod:object>"
                    ),
                }
            ],
        },
    )
    assert resp_strip.status_code == 200
    strip_text = resp_strip.json()["content"][0]["text"]
    assert "diana.prince@example.org" not in strip_text
    assert "[POD:STRIPPED]" in strip_text

    # Case C: Refused Restricted clinical record on OpenAI `/v1/chat/completions`
    resp_refuse_restricted = client.post(
        "/v1/chat/completions",
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
    assert resp_refuse_restricted.status_code == 403

    # Case D: Refused Unattested / Low-confidence held file
    resp_refuse_unattested = client.post(
        "/v1/chat/completions",
        headers={"X-POD-Caller-Key": "pod-key-public"},
        json={
            "model": "gpt-4o",
            "messages": [
                {
                    "role": "user",
                    "content": (
                        '<pod:object locator="file://estate/fileshare/unverified_notes_ambiguous.txt">'
                        "AMBIGUOUS_REF_9042"
                        "</pod:object>"
                    ),
                }
            ],
        },
    )
    assert resp_refuse_unattested.status_code == 403
    # Verify uniform denial response across different refusal reasons
    assert resp_refuse_restricted.json() == resp_refuse_unattested.json()

    registry.close()

    return {
        "phase0": phase0_summary,
        "phase1": {
            "files_processed": len(file_results),
            "tables_processed": len(db_results),
            "pending_reviews_count": len(pending_reviews),
            "lifecycle_exercised": ["attest", "raise_tier", "lower_tier_dual_approval", "renew"],
        },
        "phase2": {
            "snapshot_path": str(snap_path),
            "snapshot_signatures": snapshot_envelope["signatures"],
        },
        "phase3": {
            "openai_allow_status": resp_allow.status_code,
            "anthropic_strip_status": resp_strip.status_code,
            "restricted_refusal_status": resp_refuse_restricted.status_code,
            "unattested_refusal_status": resp_refuse_unattested.status_code,
            "uniform_denial_body": resp_refuse_restricted.json(),
            "in_memory_enforcement_latency_ms": round(allow_latency_ms, 3),
        },
    }


if __name__ == "__main__":
    summary = run_end_to_end_demo(Path("./examples/out_demo"))
    print(json.dumps(summary, indent=2))
