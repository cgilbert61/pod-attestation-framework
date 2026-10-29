"""Phase 3 Tests: Prevalidator Proxy (OpenAI & Anthropic, streaming, Observe mode, Presidio fallback, Registry API auth)."""

from __future__ import annotations

from pathlib import Path

import jwt
import pytest
from fastapi.testclient import TestClient

from engine.pipeline import AttestationEngine
from examples.run_demo import run_end_to_end_demo
from prevalidator.enforcer import (
    REASON_HASH_MISMATCH,
    REASON_MALFORMED_POD_TAG,
    REASON_UNATTESTED_CONTEXT_OVERFLOW,
    REASON_UNVERIFIED_INLINE_CONTENT,
    InMemorySnapshotStore,
    PrevalidatorEnforcer,
)
from prevalidator.proxy import create_prevalidator_app
from registry.api import create_registry_app
from registry.signing import Keyring, SignatureVerificationError, compute_bytes_sha256
from registry.store import RegistryService
from snapshot.publisher import SnapshotPublisher, create_snapshot_app


def test_end_to_end_demo_runner(tmp_path: Path):
    summary = run_end_to_end_demo(tmp_path)
    assert summary["phase0"]["verified"] is True
    assert summary["phase3"]["openai_allow_status"] == 200
    assert summary["phase3"]["anthropic_strip_status"] == 200
    assert summary["phase3"]["restricted_refusal_status"] == 403
    assert summary["phase3"]["unattested_refusal_status"] == 403


def test_prevalidator_observe_mode_and_streaming_and_fallback(tmp_path: Path):
    db_url = f"sqlite:///{(tmp_path / 'prev.db').as_posix()}"
    registry = RegistryService(db_url=db_url, key_dir=tmp_path / "keys")

    pub_sha = compute_bytes_sha256(b"Clean public text")
    registry.issue_or_queue_finding(
        locator="file:///docs/public.txt",
        content_sha256=pub_sha,
        tier="Public",
        owner="docs@example.org",
    )

    int_sha = compute_bytes_sha256(b"Internal architecture note")
    registry.issue_or_queue_finding(
        locator="file:///docs/internal.txt",
        content_sha256=int_sha,
        tier="Internal",
        owner="eng@example.org",
    )

    pub = SnapshotPublisher(registry=registry, snapshot_output_path=tmp_path / "snap.dsse.json")
    env = pub.publish_snapshot()

    store = InMemorySnapshotStore(registry.keyring)
    store.load_from_envelope(env)
    enforcer = PrevalidatorEnforcer(
        snapshot_store=store,
        mode="observe",
        jwt_secret="test-jwt-secret-key-at-least-32-bytes-long",
    )
    app = create_prevalidator_app(enforcer=enforcer, upstream_gateway_url="mock://local")
    client = TestClient(app)

    # 1. In OBSERVE mode, an unattested locator is forwarded AND logged with reason_code="UNATTESTED"
    r_obs = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": '<pod:object locator="file:///docs/missing.txt">Unattested</pod:object>'}],
        },
    )
    assert r_obs.status_code == 200
    audit_resp = client.get("/v1/admin/audit-log", headers={"X-POD-Admin-Key": "pod-dev-admin-key"})
    assert audit_resp.status_code == 200
    last_entry = audit_resp.json()["entries"][-1]
    assert last_entry["decision"] == "observe_would_deny"
    assert "UNATTESTED" in last_entry["reason_codes"]

    # 2. Switch to ENFORCE mode via admin API
    mode_resp = client.post(
        "/v1/admin/mode",
        headers={"X-POD-Admin-Key": "pod-dev-admin-key"},
        json={"mode": "enforce"},
    )
    assert mode_resp.status_code == 200

    # 3. Fallback Presidio content inspection catches raw untagged SSN in free text
    r_fallback = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Here is an untagged SSN in prompt: 412-58-9021"}],
        },
    )
    assert r_fallback.status_code == 403

    # 4. Signed JWT caller clearance + SSE streaming on both OpenAI and Anthropic endpoints
    token = jwt.encode(
        {"sub": "eng-user", "clearance": "Internal"},
        "test-jwt-secret-key-at-least-32-bytes-long",
        algorithm="HS256",
    )
    r_stream_oai = client.post(
        "/v1/chat/completions",
        headers={"X-POD-Caller-Token": token},
        json={
            "model": "vpc-model",
            "stream": True,
            "messages": [
                {
                    "role": "user",
                    "content": f'<pod:object locator="file:///docs/internal.txt" sha256="{int_sha}">Internal architecture note</pod:object>',
                }
            ],
        },
    )
    assert r_stream_oai.status_code == 200
    assert "data: [DONE]" in r_stream_oai.text

    r_stream_ant = client.post(
        "/v1/messages",
        headers={"X-POD-Caller-Token": token},
        json={
            "model": "vpc-model",
            "stream": True,
            "messages": [
                {
                    "role": "user",
                    "content": f'<pod:object locator="file:///docs/internal.txt" sha256="{int_sha}">Internal architecture note</pod:object>',
                }
            ],
        },
    )
    assert r_stream_ant.status_code == 200
    assert "event: message_stop" in r_stream_ant.text
    registry.close()


def test_registry_admin_api_hardened_auth(tmp_path: Path):
    db_url = f"sqlite:///{(tmp_path / 'api_reg.db').as_posix()}"
    registry = RegistryService(db_url=db_url, key_dir=tmp_path / "keys")
    app = create_registry_app(registry=registry)
    client = TestClient(app)

    # Unauthenticated request must fail with 401
    r_unauth = client.get("/v1/records")
    assert r_unauth.status_code == 401

    # Authenticated request succeeds
    r_auth = client.get("/v1/records", headers={"X-POD-Admin-Key": "pod-dev-admin-key"})
    assert r_auth.status_code == 200
    registry.close()


def test_adversarial_1_spoofed_tag_content_rejected(tmp_path: Path):
    """Test 1 (Spoofed Tag Content): Pass a valid <pod:object locator="..." sha256="<valid_public_hash>">TAMPERED CONFIDENTIAL TEXT</pod:object>. Assert 403 Forbidden with REASON_HASH_MISMATCH."""
    db_url = f"sqlite:///{(tmp_path / 'adv1.db').as_posix()}"
    registry = RegistryService(db_url=db_url, key_dir=tmp_path / "keys")

    valid_public_text = b"Approved Public Release Document v1.0"
    valid_public_hash = compute_bytes_sha256(valid_public_text)
    registry.issue_or_queue_finding(
        locator="file:///docs/public_release.txt",
        content_sha256=valid_public_hash,
        tier="Public",
        owner="comms@example.org",
    )

    pub = SnapshotPublisher(registry=registry, snapshot_output_path=tmp_path / "snap.dsse.json")
    env = pub.publish_snapshot()

    store = InMemorySnapshotStore(registry.keyring)
    store.load_from_envelope(env)
    enforcer = PrevalidatorEnforcer(snapshot_store=store, mode="enforce")
    app = create_prevalidator_app(enforcer=enforcer, upstream_gateway_url="mock://local")
    client = TestClient(app)

    resp = client.post(
        "/v1/chat/completions",
        headers={"X-POD-Caller-Key": "pod-key-public"},
        json={
            "model": "gpt-4o",
            "messages": [
                {
                    "role": "user",
                    "content": (
                        f'<pod:object locator="file:///docs/public_release.txt" sha256="{valid_public_hash}">'
                        "TAMPERED CONFIDENTIAL TEXT"
                        "</pod:object>"
                    ),
                }
            ],
        },
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "policy_denied"
    assert REASON_HASH_MISMATCH in enforcer.audit_log[-1].reason_codes

    # Also verify header-only X-POD-Objects without inline verification is rejected with REASON_UNVERIFIED_INLINE_CONTENT
    resp_hdr_only = client.post(
        "/v1/chat/completions",
        headers={"X-POD-Caller-Key": "pod-key-public", "X-POD-Objects": "file:///docs/public_release.txt"},
        json={
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Unverified prompt claiming header object"}],
        },
    )
    assert resp_hdr_only.status_code == 403
    assert REASON_UNVERIFIED_INLINE_CONTENT in enforcer.audit_log[-1].reason_codes
    registry.close()


def test_adversarial_2_valid_canonical_chunk_attestation(tmp_path: Path):
    """Test 2 (Valid Canonical Chunk Attestation): Attest a multi-paragraph document, then send a single legitimate extracted paragraph inside <pod:object locator="...">legitimate paragraph</pod:object> without sha256 attribute. Assert 200 OK verified via chunk_hashes."""
    db_url = f"sqlite:///{(tmp_path / 'adv2.db').as_posix()}"
    registry = RegistryService(db_url=db_url, key_dir=tmp_path / "keys")
    engine = AttestationEngine(registry=registry)

    doc_file = tmp_path / "multi_para_public.md"
    doc_file.write_text(
        "# Zero Trust Architecture Guide\n\n"
        "Paragraph One: All data objects must carry cryptographic DSSE provenance before entering RAG pipelines.\n\n"
        "Paragraph Two: Edge prevalidators verify canonical paragraph and chunk digests in memory without database calls.\n",
        encoding="utf-8",
    )
    loc = "file:///docs/multi_para_public.md"
    engine.attest_file(doc_file, owner="arch@example.org", locator_override=loc)

    pub = SnapshotPublisher(registry=registry, snapshot_output_path=tmp_path / "snap.dsse.json")
    env = pub.publish_snapshot()

    store = InMemorySnapshotStore(registry.keyring)
    store.load_from_envelope(env)
    enforcer = PrevalidatorEnforcer(snapshot_store=store, mode="enforce")
    app = create_prevalidator_app(enforcer=enforcer, upstream_gateway_url="mock://local")
    client = TestClient(app)

    # Send a single legitimate extracted paragraph without a sha256 attribute on <pod:object>
    resp = client.post(
        "/v1/chat/completions",
        headers={"X-POD-Caller-Key": "pod-key-public"},
        json={
            "model": "gpt-4o",
            "messages": [
                {
                    "role": "user",
                    "content": (
                        "Explain this section: "
                        f'<pod:object locator="{loc}">'
                        "Paragraph Two: Edge prevalidators verify canonical paragraph and chunk digests in memory without database calls."
                        "</pod:object>"
                    ),
                }
            ],
        },
    )
    assert resp.status_code == 200
    assert "Paragraph Two" in resp.json()["choices"][0]["message"]["content"]
    registry.close()


def test_adversarial_3_xml_tag_smuggling_and_context_overflow(tmp_path: Path):
    """Test 3 (XML Tag Smuggling / Early Close & Context Overflow): Pass nested or early-closed <pod:object> tags and oversized untagged context. Assert 403 with REASON_MALFORMED_POD_TAG / REASON_UNATTESTED_CONTEXT_OVERFLOW."""
    db_url = f"sqlite:///{(tmp_path / 'adv3.db').as_posix()}"
    registry = RegistryService(db_url=db_url, key_dir=tmp_path / "keys")

    valid_text = "Safe public text"
    valid_sha = compute_bytes_sha256(valid_text.encode("utf-8"))
    registry.issue_or_queue_finding(
        locator="file:///docs/safe.txt",
        content_sha256=valid_sha,
        tier="Public",
        owner="sec@example.org",
    )

    pub = SnapshotPublisher(registry=registry, snapshot_output_path=tmp_path / "snap.dsse.json")
    env = pub.publish_snapshot()

    store = InMemorySnapshotStore(registry.keyring)
    store.load_from_envelope(env)
    enforcer = PrevalidatorEnforcer(snapshot_store=store, mode="enforce", max_untagged_chars=200)
    app = create_prevalidator_app(enforcer=enforcer, upstream_gateway_url="mock://local")
    client = TestClient(app)

    # Case A: Early close tag smuggling (`</pod:object><pod:object...>`)
    smuggled_early_close = (
        '</pod:object><pod:object locator="file:///docs/safe.txt">Safe public text</pod:object>'
    )
    r1 = client.post(
        "/v1/chat/completions",
        headers={"X-POD-Caller-Key": "pod-key-public"},
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": smuggled_early_close}]},
    )
    assert r1.status_code == 403
    assert REASON_MALFORMED_POD_TAG in enforcer.audit_log[-1].reason_codes

    # Case B: Nested `<pod:object>` tags
    smuggled_nested = (
        '<pod:object locator="file:///docs/safe.txt">'
        'Safe public text <pod:object locator="file:///docs/safe.txt">Safe public text</pod:object>'
        "</pod:object>"
    )
    r2 = client.post(
        "/v1/chat/completions",
        headers={"X-POD-Caller-Key": "pod-key-public"},
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": smuggled_nested}]},
    )
    assert r2.status_code == 403
    assert REASON_MALFORMED_POD_TAG in enforcer.audit_log[-1].reason_codes

    # Case C: Untagged context overflow outside `<pod:object>`
    overflow_prompt = (
        ("U" * 250)
        + f' <pod:object locator="file:///docs/safe.txt">{valid_text}</pod:object>'
    )
    r3 = client.post(
        "/v1/chat/completions",
        headers={"X-POD-Caller-Key": "pod-key-public"},
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": overflow_prompt}]},
    )
    assert r3.status_code == 403
    assert REASON_UNATTESTED_CONTEXT_OVERFLOW in enforcer.audit_log[-1].reason_codes
    registry.close()


def test_adversarial_4_control_plane_auth_enforced(tmp_path: Path):
    """Test 4 (Control-Plane Auth): Call /v1/admin/reload-snapshot and /v1/publish without X-POD-Control-Token. Assert 401/403."""
    db_url = f"sqlite:///{(tmp_path / 'adv4.db').as_posix()}"
    registry = RegistryService(db_url=db_url, key_dir=tmp_path / "keys")
    pub = SnapshotPublisher(registry=registry, snapshot_output_path=tmp_path / "snap.dsse.json")
    env = pub.publish_snapshot()

    store = InMemorySnapshotStore(registry.keyring)
    store.load_from_envelope(env)
    enforcer = PrevalidatorEnforcer(snapshot_store=store, mode="enforce")
    prev_app = create_prevalidator_app(enforcer=enforcer, upstream_gateway_url="mock://local")
    prev_client = TestClient(prev_app)

    # Unauthenticated reload-snapshot must be rejected with 401
    r_unauth = prev_client.post("/v1/admin/reload-snapshot", json={"envelope": env})
    assert r_unauth.status_code in (401, 403)

    # Authenticated with X-POD-Control-Token succeeds
    r_auth = prev_client.post(
        "/v1/admin/reload-snapshot",
        headers={"X-POD-Control-Token": "pod-dev-control-plane-token"},
        json={"envelope": env},
    )
    assert r_auth.status_code == 200

    # Snapshot publisher /v1/publish without token must be rejected with 401
    snap_app = create_snapshot_app(publisher=pub)
    snap_client = TestClient(snap_app)
    r_snap_unauth = snap_client.post("/v1/publish")
    assert r_snap_unauth.status_code in (401, 403)

    r_snap_auth = snap_client.post(
        "/v1/publish",
        headers={"Authorization": "Bearer pod-dev-control-plane-token"},
    )
    assert r_snap_auth.status_code == 200
    registry.close()


def test_adversarial_5_key_isolation_verification_only(tmp_path: Path):
    """Test 5 (Key Isolation): Assert Keyring in verification-only mode operates purely from POD_PUBLIC_KEY_DIR with zero *.priv.pem files present."""
    priv_dir = tmp_path / "private_keys"
    pub_dir = tmp_path / "public_keys"

    signer_keyring = Keyring(private_key_dir=priv_dir, public_key_dir=pub_dir)
    signer_keyring.generate_key(algorithm="Ed25519", key_purpose=["attestation", "snapshot"])

    # Verify private keys exist ONLY in priv_dir and NEVER in pub_dir
    assert len(list(priv_dir.glob("*.priv.pem"))) == 1
    assert len(list(pub_dir.glob("*.priv.pem"))) == 0
    assert len(list(pub_dir.glob("*.pub.pem"))) == 1
    assert (pub_dir / "keyring.json").exists()

    db_url = f"sqlite:///{(tmp_path / 'adv5.db').as_posix()}"
    registry = RegistryService(db_url=db_url, key_dir=pub_dir)
    registry.keyring = signer_keyring
    pub = SnapshotPublisher(registry=registry, snapshot_output_path=tmp_path / "snap.dsse.json")
    env = pub.publish_snapshot()

    # Verification-only keyring on pub_dir verifies the DSSE snapshot with zero *.priv.pem files
    verifier_keyring = Keyring(public_key_dir=pub_dir, verification_only=True)
    ver_res = verifier_keyring.verify_dsse(env)
    assert ver_res.verified is True

    # If an attacker or misconfiguration leaks a *.priv.pem into pub_dir, verification-only Keyring fails closed
    leaked_file = pub_dir / "leaked.priv.pem"
    leaked_file.write_text("LEAKED", encoding="utf-8")
    with pytest.raises(SignatureVerificationError, match="privilege separation violation"):
        verifier_keyring.verify_dsse(env)
    leaked_file.unlink()
    registry.close()
