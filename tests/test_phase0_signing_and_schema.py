"""Phase 0 Tests: Schema invariants, 7 mandatory fields, DSSE signing, key rotation, and tamper detection."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from examples.phase0_worked_example import run_phase0_worked_example
from registry.schema_validator import SchemaValidationError, validate_attestation_predicate
from registry.signing import (
    Keyring,
    SignatureVerificationError,
    build_attestation_statement,
    compute_bytes_sha256,
    sign_statement,
    verify_dsse_envelope,
)


def test_phase0_worked_example_end_to_end(tmp_path: Path):
    summary = run_phase0_worked_example(tmp_path)
    assert summary["verified"] is True
    assert summary["tampered_file_rejected"] is True
    assert summary["tampered_envelope_rejected"] is True
    assert summary["tier"] == "Confidential"


def test_schema_rejects_signature_inside_predicate():
    now = datetime(2026, 10, 29, 12, 0, 0, tzinfo=timezone.utc)
    stmt = build_attestation_statement(
        locator="file:///test/doc.txt",
        content_sha256=compute_bytes_sha256(b"hello"),
        tier="Public",
        owner="owner@example.org",
        issued_at=now,
    )
    pred = dict(stmt["predicate"])
    pred["signature"] = "illegal-embedded-signature"
    with pytest.raises(SchemaValidationError, match="outer DSSE envelope"):
        validate_attestation_predicate(pred)


def test_schema_enforces_tier_max_ttl():
    now = datetime(2026, 10, 29, 12, 0, 0, tzinfo=timezone.utc)
    # Restricted max TTL is 30 days; attempting 45 days must fail
    with pytest.raises(SchemaValidationError, match="maximum TTL of 30 days"):
        build_attestation_statement(
            locator="file:///test/restricted.txt",
            content_sha256=compute_bytes_sha256(b"secret"),
            tier="Restricted",
            owner="sec@example.org",
            ttl_days=45,
            issued_at=now,
        )


def test_schema_rejects_raw_values_in_sensitive_categories():
    now = datetime(2026, 10, 29, 12, 0, 0, tzinfo=timezone.utc)
    with pytest.raises(SchemaValidationError):
        build_attestation_statement(
            locator="file:///test/leak.txt",
            content_sha256=compute_bytes_sha256(b"ssn"),
            tier="Restricted",
            owner="sec@example.org",
            sensitive_categories=[{"category": "US_SSN", "count": 1, "value": "123-45-6789"}],
            issued_at=now,
        )


def test_key_rotation_and_revocation_windows(tmp_path: Path):
    keyring = Keyring(tmp_path / "keys")
    k1 = keyring.generate_key(algorithm="Ed25519")
    t1 = datetime(2026, 10, 29, 10, 0, 0, tzinfo=timezone.utc)

    stmt1 = build_attestation_statement(
        locator="file:///test/k1.txt",
        content_sha256=compute_bytes_sha256(b"data-1"),
        tier="Public",
        owner="ops@example.org",
        issued_at=t1,
    )
    env1 = sign_statement(stmt1, keyring)

    # Rotate to ECDSA P-256 key
    k2 = keyring.rotate_key(algorithm="ECDSA_P256_SHA256")
    assert k2["keyid"] != k1["keyid"]

    # Record signed by k1 BEFORE rotation still verifies
    ver1 = verify_dsse_envelope(env1, keyring, now=t1 + timedelta(hours=1))
    assert ver1.verified is True
    assert ver1.keyid == k1["keyid"]

    # New record signed by active k2 verifies
    stmt2 = build_attestation_statement(
        locator="file:///test/k2.txt",
        content_sha256=compute_bytes_sha256(b"data-2"),
        tier="Public",
        owner="ops@example.org",
        issued_at=t1 + timedelta(hours=1),
    )
    env2 = sign_statement(stmt2, keyring)
    ver2 = verify_dsse_envelope(env2, keyring, now=t1 + timedelta(hours=2))
    assert ver2.verified is True
    assert ver2.keyid == k2["keyid"]

    # Revoking k1 immediately invalidates env1
    keyring.revoke_key(k1["keyid"])
    with pytest.raises(SignatureVerificationError, match="revoked"):
        verify_dsse_envelope(env1, keyring, now=t1 + timedelta(hours=2))
