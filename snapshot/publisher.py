"""Signed Snapshot Publisher producing short-TTL DSSE snapshots for zero-DB consumer enforcement."""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import RedirectResponse

from registry.schema_validator import (
    INTOTO_STATEMENT_TYPE,
    SNAPSHOT_PREDICATE_TYPE,
    format_iso8601,
    parse_iso8601,
    validate_intoto_statement,
)
from registry.signing import Keyring, sign_statement
from registry.store import RegistryService


class SnapshotPublisher:
    """Publishes DSSE-signed snapshots containing active records plus expired and revoked tombstones."""

    def __init__(
        self,
        registry: RegistryService,
        publisher_id: str = "pod-snapshot-publisher-v0.1",
        ttl_seconds: int = 300,
        snapshot_output_path: str | Path | None = None,
    ) -> None:
        self.registry = registry
        self.publisher_id = publisher_id
        self.ttl_seconds = ttl_seconds
        self.snapshot_output_path = (
            Path(snapshot_output_path)
            if snapshot_output_path
            else Path(os.environ.get("POD_SNAPSHOT_FILE", "./pod_snapshot.dsse.json"))
        )
        self._sequence_number = self._load_existing_sequence_number()
        self._latest_envelope: dict[str, Any] | None = None

    def _load_existing_sequence_number(self) -> int:
        if self.snapshot_output_path.exists():
            try:
                env = json.loads(self.snapshot_output_path.read_text(encoding="utf-8"))
                import base64

                stmt = json.loads(base64.b64decode(env["payload"]).decode("utf-8"))
                return int(stmt.get("predicate", {}).get("sequence_number", 0))
            except Exception:
                return 0
        return 0

    def publish_snapshot(
        self,
        ttl_seconds: int | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Compile current Registry records into a signed DSSE snapshot and write it to disk."""
        now_dt = now or datetime.now(timezone.utc)
        effective_ttl = ttl_seconds if ttl_seconds is not None else self.ttl_seconds
        exp_dt = now_dt + timedelta(seconds=effective_ttl)

        records = self.registry.list_records(current_only=True)
        entries: dict[str, Any] = {}
        for rec in records:
            raw_status = rec["status"]
            if raw_status == "revoked":
                norm_status = "revoked"
            elif raw_status == "expired" or parse_iso8601(rec["expires_at"]) <= now_dt:
                norm_status = "expired"
            else:
                norm_status = "active"

            redact_cats = (
                rec["statement"]
                .get("predicate", {})
                .get("handling", {})
                .get("redaction_categories", [])
            )

            entries[rec["locator"]] = {
                "record_id": rec["record_id"],
                "locator": rec["locator"],
                "content_sha256": rec["content_sha256"],
                "tier": rec["tier"],
                "status": norm_status,
                "ai_eligibility": rec["ai_eligibility"],
                "minimum_clearance": rec["minimum_clearance"],
                "egress_class": rec["egress_class"],
                "record_expires_at": rec["expires_at"],
                "revoked_at": rec["revoked_at"],
                "redaction_categories": redact_cats,
            }

        self._sequence_number += 1
        snap_id = f"pod-snap-{uuid.uuid4().hex[:16]}"
        predicate = {
            "schema_version": "0.1.0",
            "snapshot_id": snap_id,
            "sequence_number": self._sequence_number,
            "issued_at": format_iso8601(now_dt),
            "expires_at": format_iso8601(exp_dt),
            "publisher_id": self.publisher_id,
            "entries": entries,
        }

        entries_bytes = json.dumps(entries, separators=(",", ":"), sort_keys=True).encode("utf-8")
        entries_sha256 = hashlib.sha256(entries_bytes).hexdigest()

        statement = {
            "_type": INTOTO_STATEMENT_TYPE,
            "subject": [
                {
                    "name": f"pod://snapshots/{snap_id}",
                    "digest": {"sha256": entries_sha256},
                }
            ],
            "predicateType": SNAPSHOT_PREDICATE_TYPE,
            "predicate": predicate,
        }
        validate_intoto_statement(statement, expected_predicate_type=SNAPSHOT_PREDICATE_TYPE)
        envelope = sign_statement(statement, self.registry.keyring)

        self.snapshot_output_path.parent.mkdir(parents=True, exist_ok=True)
        self.snapshot_output_path.write_text(json.dumps(envelope, indent=2, sort_keys=True), encoding="utf-8")
        self._latest_envelope = envelope
        return envelope

    def get_latest_snapshot(self) -> dict[str, Any]:
        if self._latest_envelope is None:
            return self.publish_snapshot()
        return self._latest_envelope


def create_snapshot_app(publisher: SnapshotPublisher | None = None) -> FastAPI:
    """Create the FastAPI service for the Snapshot Publisher."""
    app = FastAPI(title="POD Signed Snapshot Publisher", version="0.1.0")
    pub = publisher or SnapshotPublisher(RegistryService())

    admin_token = os.environ.get("POD_ADMIN_API_KEY", "pod-dev-admin-key")

    def require_admin(x_pod_admin_key: str | None = Header(default=None)) -> None:
        if x_pod_admin_key != admin_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing X-POD-Admin-Key")

    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        return RedirectResponse(url="/docs")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "service": "pod-snapshot-publisher"}

    @app.get("/v1/snapshot/latest")
    def get_latest() -> dict[str, Any]:
        return pub.get_latest_snapshot()

    @app.post("/v1/snapshot/publish", dependencies=[Depends(require_admin)])
    def trigger_publish() -> dict[str, Any]:
        return pub.publish_snapshot()

    @app.get("/v1/snapshot/keys")
    def get_public_keys() -> dict[str, Any]:
        keys = [
            {
                "keyid": k["keyid"],
                "algorithm": k["algorithm"],
                "status": k["status"],
                "created_at": k["created_at"],
                "rotated_at": k["rotated_at"],
                "revoked_at": k["revoked_at"],
                "public_key_pem": k["public_key_pem"],
            }
            for k in pub.registry.keyring.list_keys()
        ]
        return {"keys": keys}

    return app
