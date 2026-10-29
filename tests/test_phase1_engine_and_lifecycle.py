"""Phase 1 Tests: Golden corpus classification regression, Registry lifecycle, dual approval, OpenLineage, and CLI."""

from __future__ import annotations

from pathlib import Path

import pytest

from engine.pipeline import AttestationEngine
from examples.synthetic_estate import build_synthetic_estate
from registry.cli import main as cli_main
from registry.signing import compute_file_sha256
from registry.store import (
    DualApprovalRequiredError,
    FingerprintChangedError,
    RegistryService,
)


def test_golden_corpus_classification_and_lifecycle(tmp_path: Path):
    estate = build_synthetic_estate(tmp_path / "estate")
    db_url = f"sqlite:///{(tmp_path / 'registry.db').as_posix()}"
    registry = RegistryService(db_url=db_url, key_dir=tmp_path / "keys")
    engine = AttestationEngine(registry=registry)

    engine.crawl_file_share(
        root_dir=estate["fileshare_dir"],
        owner="fileshare-owner@example.org",
        locator_base="file://estate/fileshare",
    )
    engine.crawl_database(
        db_url=estate["db_url"],
        owner="db-owner@example.org",
        locator_override_base="postgres://estate-db:5432/estate",
    )

    # Check every expected ground-truth classification tier across files, .xlsx spreadsheets, and DB tables
    for loc, expected_tier in estate["expected_tiers"].items():
        rec = registry.lookup_by_locator(loc)
        assert rec is not None, f"Missing record for {loc}"
        assert rec["tier"] == expected_tier, f"Locator {loc} expected {expected_tier}, got {rec['tier']}"

    # Low-confidence file must NOT have an active record until reviewed
    ambig_loc = "file://estate/fileshare/unverified_notes_ambiguous.txt"
    assert registry.lookup_by_locator(ambig_loc) is None
    reviews = registry.list_review_queue(status="PENDING_REVIEW")
    low_conf = [r for r in reviews if r["locator"] == ambig_loc]
    assert len(low_conf) == 1

    # Approve the low-confidence item in human review -> now issues an active record
    approved = registry.approve_pending_review(
        review_id=low_conf[0]["review_id"],
        approver_id="steward-1@example.org",
        confirmed_tier="Internal",
    )
    assert approved["record"]["tier"] == "Internal"
    assert registry.lookup_by_locator(ambig_loc) is not None

    # Asymmetric tier lowering: single approver or duplicate approver MUST fail
    rest_loc = "file://estate/fileshare/clinical_intake_restricted.txt"
    with pytest.raises(DualApprovalRequiredError):
        registry.lower_tier(
            locator=rest_loc,
            new_tier="Confidential",
            approvals=[{"approver_id": "reviewer-a@example.org", "rationale": "Single approval attempt"}],
        )
    with pytest.raises(DualApprovalRequiredError):
        registry.lower_tier(
            locator=rest_loc,
            new_tier="Confidential",
            approvals=[
                {"approver_id": "reviewer-a@example.org", "rationale": "First"},
                {"approver_id": "reviewer-a@example.org", "rationale": "Same person twice"},
            ],
        )

    # Two distinct approvers succeed
    lowered = registry.lower_tier(
        locator=rest_loc,
        new_tier="Confidential",
        approvals=[
            {"approver_id": "reviewer-a@example.org", "rationale": "De-identified cohort verified"},
            {"approver_id": "reviewer-b@example.org", "rationale": "Second independent sign-off"},
        ],
    )
    assert lowered["tier"] == "Confidential"
    assert lowered["status"] == "tier_lowered"

    # Fingerprint change blocks blind renewal (must re-classify, not re-stamp)
    pub_loc = "file://estate/fileshare/product_overview_public.md"
    with pytest.raises(FingerprintChangedError):
        registry.renew_record(locator=pub_loc, observed_content_sha256="0" * 64)

    registry.close()


def test_openlineage_derived_from_tier_inheritance(tmp_path: Path):
    db_url = f"sqlite:///{(tmp_path / 'lineage_reg.db').as_posix()}"
    registry = RegistryService(db_url=db_url, key_dir=tmp_path / "keys")
    engine = AttestationEngine(registry=registry)

    # Create upstream Restricted file and downstream summary file with no obvious PII
    up_file = tmp_path / "upstream_restricted.txt"
    up_file.write_text("Patient SSN: 443-22-1920\n", encoding="utf-8")
    down_file = tmp_path / "downstream_rollup.txt"
    down_file.write_text("Cohort aggregate summary metric: 42\n", encoding="utf-8")

    up_loc = "file://lineage/upstream_restricted.txt"
    down_loc = "file://lineage/downstream_rollup.txt"

    engine.attest_file(up_file, locator_override=up_loc)
    engine.ingest_openlineage_event(
        {
            "eventType": "COMPLETE",
            "eventTime": "2026-10-29T12:00:00Z",
            "run": {"runId": "run-001"},
            "job": {"namespace": "etl", "name": "cohort_rollup"},
            "inputs": [{"namespace": "file://lineage", "name": "upstream_restricted.txt"}],
            "outputs": [{"namespace": "file://lineage", "name": "downstream_rollup.txt"}],
        }
    )

    down_res = engine.attest_file(down_file, locator_override=down_loc)
    # Because downstream_rollup derives from a Restricted object, it inherits the Restricted floor
    assert down_res["record"]["tier"] == "Restricted"
    derived_links = down_res["record"]["statement"]["predicate"]["provenance"]["derived_from"]
    assert len(derived_links) == 1
    assert derived_links[0]["locator"] == up_loc
    registry.close()


def test_cli_lifecycle_end_to_end(tmp_path: Path):
    db_url = f"sqlite:///{(tmp_path / 'cli.db').as_posix()}"
    key_dir = str(tmp_path / "keys")
    doc_path = tmp_path / "sample.txt"
    doc_path.write_text("Public technical note.", encoding="utf-8")
    env_out = tmp_path / "sample.dsse.json"
    snap_out = tmp_path / "snap.dsse.json"
    loc = "file:///cli/sample.txt"

    assert cli_main(["--db-url", db_url, "--key-dir", key_dir, "keygen"]) == 0
    assert (
        cli_main(
            [
                "--db-url",
                db_url,
                "--key-dir",
                key_dir,
                "attest",
                str(doc_path),
                "--locator",
                loc,
                "--output",
                str(env_out),
            ]
        )
        == 0
    )
    assert cli_main(["--db-url", db_url, "--key-dir", key_dir, "lookup", loc]) == 0
    assert cli_main(["--db-url", db_url, "--key-dir", key_dir, "verify", str(env_out), "--file", str(doc_path)]) == 0
    assert cli_main(["--db-url", db_url, "--key-dir", key_dir, "raise-tier", loc, "Confidential"]) == 0
    assert (
        cli_main(
            [
                "--db-url",
                db_url,
                "--key-dir",
                key_dir,
                "lower-tier",
                loc,
                "Internal",
                "--approver",
                "alice@example.org",
                "--approver",
                "bob@example.org",
            ]
        )
        == 0
    )
    assert (
        cli_main(
            [
                "--db-url",
                db_url,
                "--key-dir",
                key_dir,
                "renew",
                loc,
                "--sha256",
                compute_file_sha256(doc_path),
            ]
        )
        == 0
    )
    assert cli_main(["--db-url", db_url, "--key-dir", key_dir, "list-expiring", "--within-days", "365"]) == 0
    assert cli_main(["--db-url", db_url, "--key-dir", key_dir, "publish-snapshot", "--output", str(snap_out)]) == 0
    assert cli_main(["--db-url", db_url, "--key-dir", key_dir, "revoke", loc, "--reason", "Test complete"]) == 0
