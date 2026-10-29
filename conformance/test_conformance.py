"""Phase 2 Consumer Conformance Suite.

Tests that any POD enforcement consumer (Reference Simulator and Prevalidator):
1. Default-denies unattested objects.
2. Emits uniform denial responses that NEVER leak which rule fired.
3. Honors record expiry.
4. Honors record revocation.
5. Fails closed when the snapshot is stale or missing.
6. Rejects tampered snapshots and rollback (sequence_number regression) attacks.
7. Enforces minimum clearance and egress class boundaries.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from conformance.simulator import ReferenceConsumerSimulator
from registry.signing import SignatureVerificationError, compute_bytes_sha256
from registry.store import RegistryService
from snapshot.publisher import SnapshotPublisher


@pytest.fixture()
def conformance_env(tmp_path: Path):
    db_url = f"sqlite:///{(tmp_path / 'conformance.db').as_posix()}"
    key_dir = tmp_path / "keys"
    snap_path = tmp_path / "snapshot.dsse.json"

    registry = RegistryService(db_url=db_url, key_dir=key_dir)
    now = datetime(2026, 10, 29, 12, 0, 0, tzinfo=timezone.utc)

    # 1. Public active object
    pub_sha = compute_bytes_sha256(b"Public marketing datasheet v1")
    registry.issue_or_queue_finding(
        locator="file:///estate/public_doc.txt",
        content_sha256=pub_sha,
        tier="Public",
        owner="marketing@example.org",
        now=now,
    )

    # 2. Internal active object (requires Internal clearance, private_cloud egress)
    int_sha = compute_bytes_sha256(b"Internal Q4 roadmap PROJ-ALPHA")
    registry.issue_or_queue_finding(
        locator="file:///estate/internal_roadmap.txt",
        content_sha256=int_sha,
        tier="Internal",
        owner="product@example.org",
        now=now,
    )

    # 3. Confidential active object (default ai_eligibility='strip', local_only egress)
    conf_sha = compute_bytes_sha256(b"Customer email list: alice@example.com")
    registry.issue_or_queue_finding(
        locator="file:///estate/confidential_customers.csv",
        content_sha256=conf_sha,
        tier="Confidential",
        owner="sales@example.org",
        now=now,
    )

    # 4. Restricted active object (ai_eligibility='deny')
    rest_sha = compute_bytes_sha256(b"SSN: 123-45-6789")
    registry.issue_or_queue_finding(
        locator="file:///estate/restricted_ssn.txt",
        content_sha256=rest_sha,
        tier="Restricted",
        owner="hr@example.org",
        now=now,
    )

    # 5. Revoked object
    rev_sha = compute_bytes_sha256(b"Revoked dataset contents")
    registry.issue_or_queue_finding(
        locator="file:///estate/revoked_doc.txt",
        content_sha256=rev_sha,
        tier="Public",
        owner="ops@example.org",
        now=now,
    )
    registry.revoke_record("file:///estate/revoked_doc.txt", reason="Leaked credential rotation", now=now)

    # 6. Short-lived object that will expire in 1 day
    exp_sha = compute_bytes_sha256(b"Short TTL dataset")
    registry.issue_or_queue_finding(
        locator="file:///estate/expiring_doc.txt",
        content_sha256=exp_sha,
        tier="Public",
        owner="ops@example.org",
        ttl_days=1,
        now=now,
    )

    publisher = SnapshotPublisher(registry=registry, ttl_seconds=600, snapshot_output_path=snap_path)
    envelope = publisher.publish_snapshot(now=now)
    simulator = ReferenceConsumerSimulator(keyring=registry.keyring)
    simulator.load_snapshot(envelope, now=now)

    yield {
        "registry": registry,
        "publisher": publisher,
        "simulator": simulator,
        "now": now,
        "hashes": {
            "public": pub_sha,
            "internal": int_sha,
            "confidential": conf_sha,
            "restricted": rest_sha,
            "revoked": rev_sha,
            "expiring": exp_sha,
        },
    }
    registry.close()


def test_conformance_allow_valid_public_object(conformance_env):
    sim: ReferenceConsumerSimulator = conformance_env["simulator"]
    now = conformance_env["now"]
    pub_sha = conformance_env["hashes"]["public"]

    payload = {
        "model": "gpt-4o",
        "messages": [
            {
                "role": "user",
                "content": f'Summarize: <pod:object locator="file:///estate/public_doc.txt" sha256="{pub_sha}">Public marketing datasheet v1</pod:object>',
            }
        ],
    }
    decision = sim.check_request(payload, headers={"X-POD-Caller-Key": "pod-key-public"}, now=now)
    assert decision.allowed is True
    assert decision.status_code == 200
    # Verify <pod:object> tags are stripped cleanly before forwarding to the gateway
    forwarded_text = decision.transformed_payload["messages"][0]["content"]
    assert "<pod:object" not in forwarded_text
    assert "Public marketing datasheet v1" in forwarded_text


def test_conformance_default_deny_unattested_and_uniform_denial_responses(conformance_env):
    """Verify default-deny on unattested objects AND that all denial causes return a uniform denial body."""
    sim: ReferenceConsumerSimulator = conformance_env["simulator"]
    now = conformance_env["now"]

    # Case 1: UNATTESTED locator
    d_unattested = sim.check_request(
        {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": '<pod:object locator="file:///estate/unknown.txt">Secret</pod:object>'}],
        },
        now=now,
    )
    assert d_unattested.allowed is False
    assert d_unattested.internal_reason_codes == ["UNATTESTED"]

    # Case 2: REVOKED locator
    d_revoked = sim.check_request(
        {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": '<pod:object locator="file:///estate/revoked_doc.txt">Revoked</pod:object>'}],
        },
        now=now,
    )
    assert d_revoked.allowed is False
    assert d_revoked.internal_reason_codes == ["REVOKED"]

    # Case 3: EXPIRED locator (evaluated 2 days later with a fresh snapshot)
    future_now = now + timedelta(days=2)
    fresh_env = conformance_env["publisher"].publish_snapshot(now=future_now)
    sim.load_snapshot(fresh_env, now=future_now)
    d_expired = sim.check_request(
        {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": '<pod:object locator="file:///estate/expiring_doc.txt">Expired</pod:object>'}],
        },
        now=future_now,
    )
    assert d_expired.allowed is False
    assert d_expired.internal_reason_codes == ["EXPIRED"]

    # Case 4: INSUFFICIENT_CLEARANCE (Public caller accessing Internal object)
    d_clearance = sim.check_request(
        {
            "model": "local-model",
            "messages": [
                {
                    "role": "user",
                    "content": '<pod:object locator="file:///estate/internal_roadmap.txt">Internal Q4 roadmap PROJ-ALPHA</pod:object>',
                }
            ],
        },
        headers={"X-POD-Caller-Key": "pod-key-public"},
        now=future_now,
    )
    assert d_clearance.allowed is False
    assert d_clearance.internal_reason_codes == ["INSUFFICIENT_CLEARANCE"]

    # Case 5: EGRESS_DENIED (Internal caller sending Internal object to public_api gpt-4o)
    d_egress = sim.check_request(
        {
            "model": "gpt-4o",
            "messages": [
                {
                    "role": "user",
                    "content": '<pod:object locator="file:///estate/internal_roadmap.txt">Internal Q4 roadmap PROJ-ALPHA</pod:object>',
                }
            ],
        },
        headers={"X-POD-Caller-Key": "pod-key-internal"},
        now=future_now,
    )
    assert d_egress.allowed is False
    assert d_egress.internal_reason_codes == ["EGRESS_DENIED"]

    # CRITICAL CONTRACT CHECK: All 5 denial responses must be byte-for-byte identical so no rule leaks to the caller
    bodies = [
        d_unattested.response_body,
        d_revoked.response_body,
        d_expired.response_body,
        d_clearance.response_body,
        d_egress.response_body,
    ]
    for b in bodies[1:]:
        assert b == bodies[0]
    serialized = str(bodies[0]).lower()
    for forbidden_leak in ("unattested", "revoked", "expired", "clearance", "egress", "restricted"):
        assert forbidden_leak not in serialized


def test_conformance_staleness_fails_closed(conformance_env):
    sim: ReferenceConsumerSimulator = conformance_env["simulator"]
    now = conformance_env["now"]

    # Evaluate 15 minutes after the 10-minute snapshot TTL
    stale_time = now + timedelta(minutes=15)
    decision = sim.check_request(
        {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": '<pod:object locator="file:///estate/public_doc.txt">Hello</pod:object>'}],
        },
        now=stale_time,
    )
    assert decision.allowed is False
    assert decision.status_code == 403


def test_conformance_rejects_snapshot_rollback_and_tampering(conformance_env):
    sim: ReferenceConsumerSimulator = conformance_env["simulator"]
    pub: SnapshotPublisher = conformance_env["publisher"]
    now = conformance_env["now"]

    env_seq2 = pub.publish_snapshot(now=now + timedelta(seconds=10))
    env_seq3 = pub.publish_snapshot(now=now + timedelta(seconds=20))
    sim.load_snapshot(env_seq3, now=now + timedelta(seconds=20))

    # Attempting to load older sequence_number=2 after sequence_number=3 must fail
    with pytest.raises(ValueError, match="rollback rejected"):
        sim.load_snapshot(env_seq2, now=now + timedelta(seconds=25))

    # Attempting to load a tampered signature must fail
    tampered = dict(env_seq3)
    tampered["signatures"] = [{"keyid": env_seq3["signatures"][0]["keyid"], "sig": "AAAA" + env_seq3["signatures"][0]["sig"][4:]}]
    with pytest.raises(SignatureVerificationError):
        sim.load_snapshot(tampered, now=now + timedelta(seconds=25))


def test_conformance_inline_strip_rule(conformance_env):
    """Verify Confidential object (`ai_eligibility='strip'`) is stripped inline while forwarding the safe question."""
    sim: ReferenceConsumerSimulator = conformance_env["simulator"]
    now = conformance_env["now"]

    payload = {
        "model": "local-model",
        "messages": [
            {
                "role": "user",
                "content": (
                    "Answer the user greeting. "
                    '<pod:object locator="file:///estate/confidential_customers.csv">'
                    "Customer email list: alice@example.com"
                    "</pod:object>"
                ),
            }
        ],
    }
    decision = sim.check_request(
        payload,
        headers={"X-POD-Caller-Key": "pod-key-confidential"},
        now=now,
    )
    assert decision.allowed is True
    forwarded = decision.transformed_payload["messages"][0]["content"]
    assert "alice@example.com" not in forwarded
    assert "[POD:STRIPPED]" in forwarded
    assert "Answer the user greeting." in forwarded
