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


def test_adversarial_6_concurrency_ratchet_and_db_chunk_hashes(tmp_path: Path):
    """Test 6: Verify verify_inline_text=False parameter, high-watermark tier ratchet on content change, and DB table chunk_hashes."""
    from sqlalchemy import create_engine, text
    from engine.pipeline import AttestationEngine

    db_url = f"sqlite:///{(tmp_path / 'adv6.db').as_posix()}"
    registry = RegistryService(db_url=db_url, key_dir=tmp_path / "keys")

    # 1. High-watermark tier ratchet: Confidential asset modified with benign content must NOT silently downgrade to Public
    r1 = registry.issue_or_queue_finding(
        locator="file:///docs/ratchet.txt",
        content_sha256="1" * 64,
        tier="Confidential",
        owner="sec@example.org",
        confidence=0.95,
    )
    assert r1["record"]["tier"] == "Confidential"

    r2 = registry.issue_or_queue_finding(
        locator="file:///docs/ratchet.txt",
        content_sha256="2" * 64,
        tier="Public",
        owner="sec@example.org",
        confidence=0.99,
    )
    assert r2["record"]["tier"] == "Confidential"

    # 2. Database crawl populates chunk_hashes so inline <pod:object> row snippets verify under strict_inline_hash=True
    sample_db_url = f"sqlite:///{(tmp_path / 'estate_sample.db').as_posix()}"
    eng = create_engine(sample_db_url)
    with eng.begin() as conn:
        conn.execute(text("CREATE TABLE public_catalog (sku TEXT, title TEXT)"))
        conn.execute(text("INSERT INTO public_catalog (sku, title) VALUES ('SKU-100', 'Quantum Router')"))
    eng.dispose()

    pipeline = AttestationEngine(registry=registry)
    db_results = pipeline.crawl_database(
        db_url=sample_db_url,
        locator_override_base="postgres://estate-db:5432/estate",
    )
    assert len(db_results) == 1
    tbl_rec = db_results[0]["record"]
    assert tbl_rec.get("chunk_hashes")

    pub = SnapshotPublisher(registry=registry, snapshot_output_path=tmp_path / "snap.dsse.json")
    env = pub.publish_snapshot()
    store = InMemorySnapshotStore(registry.keyring)
    store.load_from_envelope(env)
    enforcer = PrevalidatorEnforcer(snapshot_store=store, mode="enforce", strict_inline_hash=True)

    # Evaluating a row snippet from postgres://estate-db:5432/estate/public/public_catalog succeeds under strict_inline_hash=True
    row_prompt = '<pod:object locator="postgres://estate-db:5432/estate/public/public_catalog">SKU-100 | Quantum Router</pod:object>'
    outcome_ok = enforcer.evaluate_request(
        payload={"model": "gpt-4o", "messages": [{"role": "user", "content": row_prompt}]},
        headers={"X-POD-Caller-Key": "pod-key-public"},
    )
    assert outcome_ok.allowed_to_forward is True

    # Calling evaluate_request(..., verify_inline_text=False) leaves enforcer.strict_inline_hash == True untouched
    sim_prompt = f'<pod:object locator="postgres://estate-db:5432/estate/public/public_catalog" sha256="{tbl_rec["content_sha256"]}">File content check</pod:object>'
    outcome_sim = enforcer.evaluate_request(
        payload={"model": "gpt-4o", "messages": [{"role": "user", "content": sim_prompt}]},
        headers={"X-POD-Caller-Key": "pod-key-public"},
        verify_inline_text=False,
    )
    assert outcome_sim.allowed_to_forward is True
    assert enforcer.strict_inline_hash is True
    registry.close()


def test_enterprise_data_stores_and_event_webhook(tmp_path: Path):
    """Test 7: Verify EnterpriseDataStoreManager across S3, Azure ADLS, GCS, Snowflake, BigQuery, custom store registration, and real-time storage event webhook."""
    from engine.pipeline import AttestationEngine
    from engine.storage_connectors import EnterpriseDataStoreManager

    db_url = f"sqlite:///{(tmp_path / 'adv7.db').as_posix()}"
    registry = RegistryService(db_url=db_url, key_dir=tmp_path / "keys")
    eng = AttestationEngine(registry=registry)
    mgr = EnterpriseDataStoreManager(registry=registry, engine=eng, estate_dir=tmp_path)

    # 1. Crawl and attest AWS S3 RAG Data Lake
    s3_uri = "s3://contoso-ai-datalake-prod/rag-corpus"
    s3_res = mgr.crawl_and_attest_store(s3_uri)
    assert s3_res["total_files_found"] == 4
    assert s3_res["attested_active_count"] == 4
    assert s3_res["etag_fast_path_hits"] == 0

    # Second crawl hits ETag fast-path for all 4 objects
    s3_res2 = mgr.crawl_and_attest_store(s3_uri)
    assert s3_res2["etag_fast_path_hits"] == 4

    # 2. Register a custom Snowflake or S3 store and crawl it
    reg_res = mgr.register_store(
        {
            "provider": "AWS S3",
            "uri": "s3://acme-custom-lake/curated",
            "name": "Acme Custom S3 Lake",
            "auth_mode": "iam_role",
            "region": "us-west-2",
        }
    )
    assert reg_res["registered"] is True
    custom_crawl = mgr.crawl_and_attest_store("s3://acme-custom-lake/curated")
    assert custom_crawl["attested_active_count"] == 3

    # 3. Fire real-time ObjectCreated:Put event -> auto-attests new S3 object
    evt_put = mgr.handle_storage_event(
        {
            "store_uri": s3_uri,
            "event_type": "ObjectCreated:Put",
            "object_key": "live_stream/public_announcement.md",
            "sample_text": "Public release note for G1 Docket v0.2.",
            "sensitivity_label": "Public",
        }
    )
    assert evt_put["action"].startswith("ATTESTED")
    assert evt_put["tier"] == "Public"

    # Publish snapshot and verify inline <pod:object> for the S3 event object passes Prevalidator
    pub = SnapshotPublisher(registry=registry, snapshot_output_path=tmp_path / "snap.dsse.json")
    env = pub.publish_snapshot()
    store = InMemorySnapshotStore(registry.keyring)
    store.load_from_envelope(env)
    enforcer = PrevalidatorEnforcer(snapshot_store=store, mode="enforce", strict_inline_hash=True)

    s3_prompt = f'<pod:object locator="{evt_put["locator"]}">Public release note for G1 Docket v0.2.</pod:object>'
    out1 = enforcer.evaluate_request(
        payload={"model": "gpt-4o", "messages": [{"role": "user", "content": s3_prompt}]},
        headers={"X-POD-Caller-Key": "pod-key-public"},
    )
    assert out1.allowed_to_forward is True

    # 4. Fire real-time ObjectRemoved:Delete event -> auto-revokes the S3 object
    evt_del = mgr.handle_storage_event(
        {
            "store_uri": s3_uri,
            "event_type": "ObjectRemoved:Delete",
            "locator": evt_put["locator"],
        }
    )
    assert evt_del["action"] == "REVOKED"
    env2 = pub.publish_snapshot()
    store.load_from_envelope(env2)

    out2 = enforcer.evaluate_request(
        payload={"model": "gpt-4o", "messages": [{"role": "user", "content": s3_prompt}]},
        headers={"X-POD-Caller-Key": "pod-key-public"},
    )
    assert out2.allowed_to_forward is False
    registry.close()


def test_continuous_delta_crawler_pass1_skip_pass2_delta_and_auto_revoke(tmp_path: Path):
    """Test 8: Verify ContinuousDeltaCrawler Pass 1 mtime/size skip, Pass 2 delta attestation, rolling micro-snapshot publishing, and auto-revocation on file deletion."""
    import asyncio
    import threading
    from engine.continuous_crawler import ContinuousDeltaCrawler
    from engine.pipeline import AttestationEngine
    from engine.storage_connectors import EnterpriseDataStoreManager

    db_url = f"sqlite:///{(tmp_path / 'adv8.db').as_posix()}"
    registry = RegistryService(db_url=db_url, key_dir=tmp_path / "keys")
    eng = AttestationEngine(registry=registry)
    mgr = EnterpriseDataStoreManager(registry=registry, engine=eng, estate_dir=tmp_path)
    pub = SnapshotPublisher(registry=registry, snapshot_output_path=tmp_path / "snap.dsse.json")

    scan_dir = tmp_path / "live_root"
    scan_dir.mkdir(parents=True, exist_ok=True)
    f1 = scan_dir / "doc_a.txt"
    f2 = scan_dir / "doc_b_conf.txt"
    f1.write_text("Public technical note", encoding="utf-8")
    f2.write_text("Contact: bruce.wayne@wayneenterprises.com | salary: $250,000", encoding="utf-8")

    crawler = ContinuousDeltaCrawler(
        registry=registry,
        engine=eng,
        store_manager=mgr,
        publish_snapshot_fn=pub.publish_snapshot,
        scan_lock=threading.Lock(),
    )
    crawler.running = True
    crawler.throttle_ms_per_file = 0.0
    crawler.micro_publish_delta_threshold = 2

    # First sweep: both files are new deltas -> Pass 2 deep scan & rolling micro-snapshot published
    asyncio.run(crawler._sweep_pc_filesystem_target(str(scan_dir)))
    tel1 = crawler.get_telemetry()
    assert tel1["files_swept"] == 2
    assert tel1["deltas_attested"] == 2
    assert tel1["unchanged_skipped"] == 0
    assert tel1["micro_snapshots_published"] >= 1
    assert len(tel1["ticker_feed"]) >= 2

    # Second sweep: neither file changed -> Pass 1 mtime_ns + size_bytes skips both in 0 bytes read!
    asyncio.run(crawler._sweep_pc_filesystem_target(str(scan_dir)))
    tel2 = crawler.get_telemetry()
    assert tel2["files_swept"] == 4
    assert tel2["deltas_attested"] == 2
    assert tel2["unchanged_skipped"] == 2

    # Delete f1 -> Third sweep auto-revokes f1 and skips unchanged f2
    f1.unlink()
    asyncio.run(crawler._sweep_pc_filesystem_target(str(scan_dir)))
    tel3 = crawler.get_telemetry()
    assert tel3["deleted_revoked"] == 1
    assert tel3["unchanged_skipped"] == 3
    registry.close()



