"""Phase 3 Tests: Prevalidator Proxy (OpenAI & Anthropic, streaming, Observe mode, Presidio fallback, Registry API auth)."""

from __future__ import annotations

from pathlib import Path

import jwt
from fastapi.testclient import TestClient

from examples.run_demo import run_end_to_end_demo
from prevalidator.enforcer import InMemorySnapshotStore, PrevalidatorEnforcer
from prevalidator.proxy import create_prevalidator_app
from registry.api import create_registry_app
from registry.signing import compute_bytes_sha256
from registry.store import RegistryService
from snapshot.publisher import SnapshotPublisher


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
