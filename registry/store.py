"""PostgreSQL / SQLAlchemy Registry Store, Review Queue, and Lifecycle State Machine."""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import Boolean, Column, Float, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from registry.schema_validator import (
    DEFAULT_HANDLING_BY_TIER,
    TIER_MAX_TTL_DAYS,
    TIER_ORDER,
    format_iso8601,
    parse_iso8601,
)
from registry.signing import (
    Keyring,
    build_attestation_statement,
    sign_statement,
    verify_dsse_envelope,
)


class RegistryLifecycleError(ValueError):
    """Raised when an invalid lifecycle transition is requested."""


class FingerprintChangedError(RegistryLifecycleError):
    """Raised when attempting to renew a record whose underlying content SHA-256 has changed."""


class DualApprovalRequiredError(RegistryLifecycleError):
    """Raised when attempting to lower a classification tier without two distinct approvals."""


class Base(DeclarativeBase):
    pass


class AttestationRecordModel(Base):
    """Database table storing current and historical signed attestation records."""

    __tablename__ = "pod_attestation_records"

    record_id = Column(String(128), primary_key=True)
    locator = Column(String(1024), index=True, nullable=False)
    object_type = Column(String(64), nullable=False)
    content_sha256 = Column(String(64), nullable=False)
    schema_sha256 = Column(String(64), nullable=True)
    tier = Column(String(32), nullable=False)
    confidence = Column(Float, nullable=False)
    status = Column(String(32), index=True, nullable=False)
    ai_eligibility = Column(String(32), nullable=False)
    minimum_clearance = Column(String(32), nullable=False)
    egress_class = Column(String(32), nullable=False)
    owner = Column(String(256), nullable=False)
    issued_at = Column(String(64), nullable=False)
    expires_at = Column(String(64), index=True, nullable=False)
    revoked_at = Column(String(64), nullable=True)
    revocation_reason = Column(String(512), nullable=True)
    is_current = Column(Boolean, default=True, index=True, nullable=False)
    statement_json = Column(Text, nullable=False)
    dsse_envelope_json = Column(Text, nullable=False)


class ReviewQueueModel(Base):
    """Human-review queue for Restricted findings, low-confidence findings, and pending tier-lower requests."""

    __tablename__ = "pod_review_queue"

    review_id = Column(String(128), primary_key=True)
    locator = Column(String(1024), index=True, nullable=False)
    record_id = Column(String(128), nullable=True)
    reason = Column(String(64), nullable=False)  # 'restricted_tier' | 'low_confidence' | 'tier_lower_request'
    current_tier = Column(String(32), nullable=True)
    proposed_tier = Column(String(32), nullable=False)
    confidence = Column(Float, nullable=False)
    status = Column(String(32), index=True, nullable=False)  # 'PENDING_REVIEW' | 'APPROVED' | 'REJECTED'
    metadata_json = Column(Text, nullable=False)
    approvals_json = Column(Text, nullable=False)
    created_at = Column(String(64), nullable=False)
    resolved_at = Column(String(64), nullable=True)


class RegistryService:
    """Authoritative Registry managing signed records, lifecycle transitions, and the human-review queue."""

    def __init__(
        self,
        db_url: str | None = None,
        key_dir: str | Path | None = None,
    ) -> None:
        raw_url = db_url or os.environ.get("POD_REGISTRY_DB_URL", "sqlite:///./pod_registry.db")
        if raw_url.startswith("postgresql://"):
            raw_url = "postgresql+psycopg2://" + raw_url[len("postgresql://") :]
        self.db_url = raw_url
        self.registry_service_url = os.environ.get("POD_REGISTRY_SERVICE_URL", "").rstrip("/") if key_dir is None else ""
        self.control_plane_token = os.environ.get("POD_CONTROL_PLANE_TOKEN", "pod-dev-control-plane-token")
        self.admin_api_key = os.environ.get("POD_ADMIN_API_KEY", "pod-dev-admin-key")
        self.key_dir = Path(key_dir or os.environ.get("POD_PUBLIC_KEY_DIR") or os.environ.get("POD_KEY_DIR", "./.pod_keys"))
        if self.registry_service_url:
            self.keyring = Keyring(public_key_dir=self.key_dir, verification_only=True)
        else:
            priv_dir = Path(key_dir) if key_dir else Path(os.environ.get("POD_PRIVATE_KEY_DIR") or self.key_dir)
            self.keyring = Keyring(key_dir=self.key_dir, private_key_dir=priv_dir, public_key_dir=self.key_dir)
            self.keyring.ensure_active_key(purpose="attestation", operator_id="pod-registry")

        self.engine = create_engine(self.db_url, future=True)
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine, expire_on_commit=False)

    def close(self) -> None:
        """Dispose underlying SQLAlchemy connection pool."""
        self.engine.dispose()

    def _get_single_current_row(self, session: Session, locator: str) -> AttestationRecordModel | None:
        """Return the latest `is_current=True` row for `locator`, automatically deduplicating any concurrent active rows."""
        rows = (
            session.execute(
                select(AttestationRecordModel)
                .where(
                    AttestationRecordModel.locator == locator,
                    AttestationRecordModel.is_current.is_(True),
                )
                .order_by(AttestationRecordModel.issued_at.desc())
            )
            .scalars()
            .all()
        )
        if not rows:
            return None
        if len(rows) > 1:
            for extra in rows[1:]:
                extra.is_current = False
        return rows[0]

    def _row_to_dict(self, row: AttestationRecordModel) -> dict[str, Any]:
        stmt = json.loads(row.statement_json)
        integrity = stmt.get("predicate", {}).get("integrity", {})
        return {
            "record_id": row.record_id,
            "locator": row.locator,
            "object_type": row.object_type,
            "content_sha256": row.content_sha256,
            "schema_sha256": row.schema_sha256,
            "extracted_text_sha256": integrity.get("extracted_text_sha256"),
            "chunk_hashes": (integrity.get("chunk_hashes") or [])[:256],
            "tier": row.tier,
            "confidence": row.confidence,
            "status": row.status,
            "ai_eligibility": row.ai_eligibility,
            "minimum_clearance": row.minimum_clearance,
            "egress_class": row.egress_class,
            "owner": row.owner,
            "issued_at": row.issued_at,
            "expires_at": row.expires_at,
            "revoked_at": row.revoked_at,
            "revocation_reason": row.revocation_reason,
            "is_current": row.is_current,
            "statement": stmt,
            "dsse_envelope": json.loads(row.dsse_envelope_json),
        }

    def _review_to_dict(self, row: ReviewQueueModel) -> dict[str, Any]:
        return {
            "review_id": row.review_id,
            "locator": row.locator,
            "record_id": row.record_id,
            "reason": row.reason,
            "current_tier": row.current_tier,
            "proposed_tier": row.proposed_tier,
            "confidence": row.confidence,
            "status": row.status,
            "metadata": json.loads(row.metadata_json),
            "approvals": json.loads(row.approvals_json),
            "created_at": row.created_at,
            "resolved_at": row.resolved_at,
        }

    def issue_or_queue_finding(
        self,
        *,
        locator: str,
        content_sha256: str,
        tier: str,
        owner: str,
        confidence: float = 0.95,
        low_confidence: bool = False,
        sensitive_categories: list[dict[str, Any]] | None = None,
        object_type: str = "file",
        display_name: str | None = None,
        environment: str = "production",
        steward: str | None = None,
        org_unit: str | None = None,
        jurisdiction: str | None = "GLOBAL",
        attested_by: str = "pod-engine-v0.1",
        source_system: str = "tika+presidio",
        scanner_version: str = "0.1.0",
        derived_from: list[dict[str, Any]] | None = None,
        schema_sha256: str | None = None,
        size_bytes: int | None = None,
        row_count: int | None = None,
        fingerprint_method: str = "raw_bytes_sha256",
        extracted_text_sha256: str | None = None,
        chunk_hashes: list[str] | None = None,
        classifier_engine: str = "presidio",
        policy: dict[str, str] | None = None,
        ttl_days: int | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Process a classification finding from the Engine into a signed record or a pending review queue item.

        - Low-confidence findings (`low_confidence=True` or `confidence < 0.70`) are placed in `PENDING_REVIEW`
          with NO active record issued (fail-closed default-deny).
        - Upstream `derived_from` lineage is checked: a derived object cannot be attested at a lower tier
          than its active upstream sources without dual approval.
        - `Restricted` findings immediately get a signed fail-closed `Restricted` record AND a review queue entry.
        """
        now_dt = now or datetime.now(timezone.utc)
        now_str = format_iso8601(now_dt)

        if self.registry_service_url and self.keyring.verification_only:
            import httpx

            payload = {
                "locator": locator,
                "content_sha256": content_sha256,
                "tier": tier,
                "owner": owner,
                "confidence": confidence,
                "low_confidence": low_confidence,
                "sensitive_categories": sensitive_categories,
                "object_type": object_type,
                "display_name": display_name,
                "environment": environment,
                "steward": steward,
                "org_unit": org_unit,
                "jurisdiction": jurisdiction,
                "attested_by": attested_by,
                "source_system": source_system,
                "scanner_version": scanner_version,
                "derived_from": derived_from,
                "schema_sha256": schema_sha256,
                "size_bytes": size_bytes,
                "row_count": row_count,
                "fingerprint_method": fingerprint_method,
                "extracted_text_sha256": extracted_text_sha256,
                "chunk_hashes": chunk_hashes,
                "classifier_engine": classifier_engine,
                "policy": policy,
                "ttl_days": ttl_days,
            }
            with httpx.Client(timeout=15.0) as client:
                resp = client.post(
                    f"{self.registry_service_url}/v1/records/issue-finding",
                    headers={
                        "X-POD-Control-Token": self.control_plane_token,
                        "X-POD-Admin-Key": self.admin_api_key,
                        "Authorization": f"Bearer {self.control_plane_token}",
                    },
                    json=payload,
                )
                resp.raise_for_status()
                return resp.json()

        # Enforce lineage tier floor: derived objects inherit at least the highest tier of their upstream inputs
        effective_tier = tier
        lineage_list = list(derived_from or [])
        with self.SessionLocal() as session:
            for item in lineage_list:
                up_loc = item.get("locator")
                if not up_loc:
                    continue
                up_row = self._get_single_current_row(session, up_loc)
                if up_row:
                    item["record_id"] = up_row.record_id
                    if TIER_ORDER[up_row.tier] > TIER_ORDER[effective_tier]:
                        effective_tier = up_row.tier

            # Check if an active record already exists for this locator
            prev_row = self._get_single_current_row(session, locator)

            # If low confidence, hold in PENDING_REVIEW without issuing an active record
            if low_confidence or confidence < 0.70:
                if prev_row and prev_row.status not in ("revoked", "expired"):
                    # Invalidate previous record if content fingerprint changed into a low-confidence state
                    prev_row.is_current = False
                existing_rev = (
                    session.execute(
                        select(ReviewQueueModel)
                        .where(
                            ReviewQueueModel.locator == locator,
                            ReviewQueueModel.reason == "low_confidence",
                            ReviewQueueModel.status == "PENDING_REVIEW",
                        )
                        .order_by(ReviewQueueModel.created_at.desc())
                    )
                    .scalars()
                    .first()
                )
                meta_payload = json.dumps(
                    {
                        "content_sha256": content_sha256,
                        "schema_sha256": schema_sha256,
                        "owner": owner,
                        "object_type": object_type,
                        "display_name": display_name,
                        "environment": environment,
                        "sensitive_categories": sensitive_categories or [],
                        "source_system": source_system,
                        "classifier_engine": classifier_engine,
                        "size_bytes": size_bytes,
                        "row_count": row_count,
                        "fingerprint_method": fingerprint_method,
                        "extracted_text_sha256": extracted_text_sha256,
                        "chunk_hashes": chunk_hashes or [],
                        "derived_from": lineage_list,
                    }
                )
                if existing_rev:
                    existing_rev.proposed_tier = effective_tier
                    existing_rev.confidence = confidence
                    existing_rev.metadata_json = meta_payload
                    existing_rev.created_at = now_str
                    rev_row = existing_rev
                else:
                    review_id = f"pod-rev-{uuid.uuid4().hex[:12]}"
                    rev_row = ReviewQueueModel(
                        review_id=review_id,
                        locator=locator,
                        record_id=None,
                        reason="low_confidence",
                        current_tier=prev_row.tier if prev_row else None,
                        proposed_tier=effective_tier,
                        confidence=confidence,
                        status="PENDING_REVIEW",
                        metadata_json=meta_payload,
                        approvals_json="[]",
                        created_at=now_str,
                        resolved_at=None,
                    )
                    session.add(rev_row)
                session.commit()
                return {
                    "action": "queued_low_confidence",
                    "record": None,
                    "review": self._review_to_dict(rev_row),
                }

            # If previous record had a HIGHER tier than the newly classified tier (even on content change),
            # never silently downgrade without dual approval — retain the higher tier or queue for dual approval.
            if (
                prev_row
                and prev_row.status not in ("revoked", "expired")
                and TIER_ORDER[prev_row.tier] > TIER_ORDER[effective_tier]
            ):
                effective_tier = prev_row.tier
            previous_record_id = prev_row.record_id if prev_row else None
            if prev_row:
                prev_row.is_current = False

            statement = build_attestation_statement(
                locator=locator,
                content_sha256=content_sha256,
                tier=effective_tier,
                owner=owner,
                attested_by=attested_by,
                object_type=object_type,
                display_name=display_name,
                environment=environment,
                steward=steward,
                org_unit=org_unit,
                jurisdiction=jurisdiction,
                source_system=source_system,
                scanner_version=scanner_version,
                derived_from=lineage_list,
                schema_sha256=schema_sha256,
                size_bytes=size_bytes,
                row_count=row_count,
                fingerprint_method=fingerprint_method,
                extracted_text_sha256=extracted_text_sha256,
                chunk_hashes=chunk_hashes,
                confidence=confidence,
                sensitive_categories=sensitive_categories,
                classifier_engine=classifier_engine,
                policy=policy,
                status="issued",
                ttl_days=ttl_days,
                issued_at=now_dt,
                previous_record_id=previous_record_id,
            )
            envelope = sign_statement(statement, self.keyring)
            pred = statement["predicate"]
            rec_id = pred["identity"]["record_id"]
            pol = pred["handling"]["policy"]

            new_row = AttestationRecordModel(
                record_id=rec_id,
                locator=locator,
                object_type=object_type,
                content_sha256=content_sha256.lower(),
                schema_sha256=schema_sha256.lower() if schema_sha256 else None,
                tier=effective_tier,
                confidence=confidence,
                status="issued",
                ai_eligibility=pol["ai_eligibility"],
                minimum_clearance=pol["minimum_clearance"],
                egress_class=pol["egress_class"],
                owner=owner,
                issued_at=pred["lifecycle"]["issued_at"],
                expires_at=pred["lifecycle"]["expires_at"],
                revoked_at=None,
                revocation_reason=None,
                is_current=True,
                statement_json=json.dumps(statement, sort_keys=True),
                dsse_envelope_json=json.dumps(envelope, sort_keys=True),
            )
            session.add(new_row)

            review_dict: dict[str, Any] | None = None
            if effective_tier == "Restricted":
                review_id = f"pod-rev-{uuid.uuid4().hex[:12]}"
                rev_row = ReviewQueueModel(
                    review_id=review_id,
                    locator=locator,
                    record_id=rec_id,
                    reason="restricted_tier",
                    current_tier="Restricted",
                    proposed_tier="Restricted",
                    confidence=confidence,
                    status="PENDING_REVIEW",
                    metadata_json=json.dumps(
                        {
                            "note": "Restricted record issued fail-closed (ai_eligibility=deny); queued for steward acknowledgment.",
                            "sensitive_categories": sensitive_categories or [],
                        }
                    ),
                    approvals_json="[]",
                    created_at=now_str,
                    resolved_at=None,
                )
                session.add(rev_row)
                review_dict = self._review_to_dict(rev_row)

            session.commit()
            return {
                "action": "issued_and_queued_restricted" if review_dict else "issued",
                "record": self._row_to_dict(new_row),
                "review": review_dict,
            }

    def lookup_by_locator(self, locator: str, include_expired_or_revoked: bool = True) -> dict[str, Any] | None:
        """Look up the current record for a canonical object locator, auto-transitioning expired records."""
        self.expire_due_records()
        with self.SessionLocal() as session:
            row = self._get_single_current_row(session, locator)
            session.commit()
            if not row:
                return None
            if not include_expired_or_revoked and row.status in ("expired", "revoked"):
                return None
            return self._row_to_dict(row)

    def list_records(self, current_only: bool = True) -> list[dict[str, Any]]:
        """List all records in the Registry (auto-updating any newly expired records first)."""
        self.expire_due_records()
        with self.SessionLocal() as session:
            stmt = select(AttestationRecordModel)
            if current_only:
                stmt = stmt.where(AttestationRecordModel.is_current.is_(True))
                rows = (
                    session.execute(stmt.order_by(AttestationRecordModel.locator, AttestationRecordModel.issued_at.desc()))
                    .scalars()
                    .all()
                )
                deduped: list[AttestationRecordModel] = []
                seen_locators: set[str] = set()
                dirty = False
                for r in rows:
                    if r.locator in seen_locators:
                        r.is_current = False
                        dirty = True
                    else:
                        seen_locators.add(r.locator)
                        deduped.append(r)
                if dirty:
                    session.commit()
                return [self._row_to_dict(r) for r in deduped]
            rows = session.execute(stmt.order_by(AttestationRecordModel.locator)).scalars().all()
            return [self._row_to_dict(r) for r in rows]

    def list_expiring(self, within_days: int = 30, now: datetime | None = None) -> list[dict[str, Any]]:
        """Return active records whose `expires_at` is within `within_days` from `now`."""
        current_time = now or datetime.now(timezone.utc)
        horizon = current_time + timedelta(days=within_days)
        self.expire_due_records(now=current_time)

        results: list[dict[str, Any]] = []
        with self.SessionLocal() as session:
            rows = (
                session.execute(
                    select(AttestationRecordModel).where(
                        AttestationRecordModel.is_current.is_(True),
                        AttestationRecordModel.status.notin_(["expired", "revoked"]),
                    )
                )
                .scalars()
                .all()
            )
            for row in rows:
                exp_dt = parse_iso8601(row.expires_at)
                if current_time < exp_dt <= horizon:
                    results.append(self._row_to_dict(row))
        return results

    def expire_due_records(self, now: datetime | None = None) -> list[str]:
        """Mark any current record whose `expires_at <= now` as `expired`."""
        current_time = now or datetime.now(timezone.utc)
        expired_locators: list[str] = []
        with self.SessionLocal() as session:
            rows = (
                session.execute(
                    select(AttestationRecordModel).where(
                        AttestationRecordModel.is_current.is_(True),
                        AttestationRecordModel.status.notin_(["expired", "revoked"]),
                    )
                )
                .scalars()
                .all()
            )
            for row in rows:
                if parse_iso8601(row.expires_at) <= current_time:
                    row.status = "expired"
                    statement = json.loads(row.statement_json)
                    statement["predicate"]["lifecycle"]["status"] = "expired"
                    row.statement_json = json.dumps(statement, sort_keys=True)
                    expired_locators.append(row.locator)
            if expired_locators:
                session.commit()
        return expired_locators

    def renew_record(
        self,
        locator: str,
        observed_content_sha256: str,
        ttl_days: int | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Renew an existing attestation record ONLY if its content fingerprint is unchanged.

        If `observed_content_sha256` differs from the attested `content_sha256`, raises
        `FingerprintChangedError` because a changed fingerprint requires re-classification, not a re-stamp.
        """
        now_dt = now or datetime.now(timezone.utc)
        with self.SessionLocal() as session:
            prev_row = self._get_single_current_row(session, locator)
            if not prev_row:
                raise RegistryLifecycleError(f"No current record found for locator '{locator}'.")
            if prev_row.status == "revoked":
                raise RegistryLifecycleError(f"Cannot renew revoked record '{prev_row.record_id}'.")

            if observed_content_sha256.lower() != prev_row.content_sha256.lower():
                raise FingerprintChangedError(
                    f"Content fingerprint changed for '{locator}' (attested={prev_row.content_sha256}, "
                    f"observed={observed_content_sha256.lower()}). Changed content requires re-classification, not a re-stamp."
                )

            old_stmt = json.loads(prev_row.statement_json)
            old_pred = old_stmt["predicate"]
            tier = prev_row.tier
            effective_ttl = ttl_days if ttl_days is not None else TIER_MAX_TTL_DAYS[tier]
            exp_dt = now_dt + timedelta(days=effective_ttl)
            new_rec_id = f"pod-rec-{uuid.uuid4().hex[:16]}"

            old_pred["identity"]["record_id"] = new_rec_id
            old_pred["lifecycle"]["status"] = "renewed"
            old_pred["lifecycle"]["issued_at"] = format_iso8601(now_dt)
            old_pred["lifecycle"]["expires_at"] = format_iso8601(exp_dt)
            old_pred["lifecycle"]["ttl_days"] = effective_ttl
            old_pred["lifecycle"]["previous_record_id"] = prev_row.record_id

            envelope = sign_statement(old_stmt, self.keyring)
            prev_row.is_current = False

            new_row = AttestationRecordModel(
                record_id=new_rec_id,
                locator=locator,
                object_type=prev_row.object_type,
                content_sha256=prev_row.content_sha256,
                schema_sha256=prev_row.schema_sha256,
                tier=tier,
                confidence=prev_row.confidence,
                status="renewed",
                ai_eligibility=prev_row.ai_eligibility,
                minimum_clearance=prev_row.minimum_clearance,
                egress_class=prev_row.egress_class,
                owner=prev_row.owner,
                issued_at=old_pred["lifecycle"]["issued_at"],
                expires_at=old_pred["lifecycle"]["expires_at"],
                revoked_at=None,
                revocation_reason=None,
                is_current=True,
                statement_json=json.dumps(old_stmt, sort_keys=True),
                dsse_envelope_json=json.dumps(envelope, sort_keys=True),
            )
            session.add(new_row)
            session.commit()
            return self._row_to_dict(new_row)

    def raise_tier(
        self,
        locator: str,
        new_tier: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Raise an object's classification tier immediately (free and immediate per the asymmetric rule)."""
        if new_tier not in TIER_ORDER:
            raise RegistryLifecycleError(f"Unknown tier: {new_tier}")

        now_dt = now or datetime.now(timezone.utc)
        with self.SessionLocal() as session:
            prev_row = self._get_single_current_row(session, locator)
            if not prev_row:
                raise RegistryLifecycleError(f"No current record found for locator '{locator}'.")
            if TIER_ORDER[new_tier] <= TIER_ORDER[prev_row.tier]:
                raise RegistryLifecycleError(
                    f"raise_tier requires a strictly higher tier than current '{prev_row.tier}' (got '{new_tier}')."
                )

            old_stmt = json.loads(prev_row.statement_json)
            old_pred = old_stmt["predicate"]
            new_rec_id = f"pod-rec-{uuid.uuid4().hex[:16]}"
            new_ttl = TIER_MAX_TTL_DAYS[new_tier]
            exp_dt = now_dt + timedelta(days=new_ttl)
            new_policy = dict(DEFAULT_HANDLING_BY_TIER[new_tier])

            old_pred["identity"]["record_id"] = new_rec_id
            old_pred["classification"]["tier"] = new_tier
            old_pred["handling"]["policy"] = new_policy
            old_pred["handling"]["allow_rag_indexing"] = new_tier in ("Public", "Internal")
            old_pred["lifecycle"]["status"] = "tier_raised"
            old_pred["lifecycle"]["issued_at"] = format_iso8601(now_dt)
            old_pred["lifecycle"]["expires_at"] = format_iso8601(exp_dt)
            old_pred["lifecycle"]["ttl_days"] = new_ttl
            old_pred["lifecycle"]["previous_record_id"] = prev_row.record_id

            envelope = sign_statement(old_stmt, self.keyring)
            prev_row.is_current = False

            new_row = AttestationRecordModel(
                record_id=new_rec_id,
                locator=locator,
                object_type=prev_row.object_type,
                content_sha256=prev_row.content_sha256,
                schema_sha256=prev_row.schema_sha256,
                tier=new_tier,
                confidence=prev_row.confidence,
                status="tier_raised",
                ai_eligibility=new_policy["ai_eligibility"],
                minimum_clearance=new_policy["minimum_clearance"],
                egress_class=new_policy["egress_class"],
                owner=prev_row.owner,
                issued_at=old_pred["lifecycle"]["issued_at"],
                expires_at=old_pred["lifecycle"]["expires_at"],
                revoked_at=None,
                revocation_reason=None,
                is_current=True,
                statement_json=json.dumps(old_stmt, sort_keys=True),
                dsse_envelope_json=json.dumps(envelope, sort_keys=True),
            )
            session.add(new_row)
            session.commit()
            return self._row_to_dict(new_row)

    def lower_tier(
        self,
        locator: str,
        new_tier: str,
        approvals: list[dict[str, str]],
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Lower an object's classification tier — requires dual approval from at least 2 distinct principals."""
        if new_tier not in TIER_ORDER:
            raise RegistryLifecycleError(f"Unknown tier: {new_tier}")

        now_dt = now or datetime.now(timezone.utc)
        now_str = format_iso8601(now_dt)

        with self.SessionLocal() as session:
            prev_row = self._get_single_current_row(session, locator)
            if not prev_row:
                raise RegistryLifecycleError(f"No current record found for locator '{locator}'.")
            if TIER_ORDER[new_tier] >= TIER_ORDER[prev_row.tier]:
                raise RegistryLifecycleError(
                    f"lower_tier requires a strictly lower tier than current '{prev_row.tier}' (got '{new_tier}')."
                )

            normalized_approvals = [
                {
                    "approver_id": a["approver_id"].strip(),
                    "approved_at": a.get("approved_at") or now_str,
                    "rationale": a.get("rationale") or "Reviewed and approved tier lowering.",
                }
                for a in approvals
                if a.get("approver_id") and a.get("approver_id").strip()
            ]
            distinct_approvers = {a["approver_id"] for a in normalized_approvals}
            if len(distinct_approvers) < 2:
                raise DualApprovalRequiredError(
                    f"Lowering tier from '{prev_row.tier}' to '{new_tier}' requires dual approval from 2 distinct principals "
                    f"(got {len(distinct_approvers)})."
                )

            old_stmt = json.loads(prev_row.statement_json)
            old_pred = old_stmt["predicate"]
            new_rec_id = f"pod-rec-{uuid.uuid4().hex[:16]}"
            new_ttl = TIER_MAX_TTL_DAYS[new_tier]
            exp_dt = now_dt + timedelta(days=new_ttl)
            new_policy = dict(DEFAULT_HANDLING_BY_TIER[new_tier])

            old_pred["identity"]["record_id"] = new_rec_id
            old_pred["classification"]["tier"] = new_tier
            old_pred["handling"]["policy"] = new_policy
            old_pred["handling"]["allow_rag_indexing"] = new_tier in ("Public", "Internal")
            old_pred["lifecycle"]["status"] = "tier_lowered"
            old_pred["lifecycle"]["issued_at"] = now_str
            old_pred["lifecycle"]["expires_at"] = format_iso8601(exp_dt)
            old_pred["lifecycle"]["ttl_days"] = new_ttl
            old_pred["lifecycle"]["previous_record_id"] = prev_row.record_id
            old_pred["lifecycle"]["tier_lower_approvals"] = normalized_approvals

            envelope = sign_statement(old_stmt, self.keyring)
            prev_row.is_current = False

            new_row = AttestationRecordModel(
                record_id=new_rec_id,
                locator=locator,
                object_type=prev_row.object_type,
                content_sha256=prev_row.content_sha256,
                schema_sha256=prev_row.schema_sha256,
                tier=new_tier,
                confidence=prev_row.confidence,
                status="tier_lowered",
                ai_eligibility=new_policy["ai_eligibility"],
                minimum_clearance=new_policy["minimum_clearance"],
                egress_class=new_policy["egress_class"],
                owner=prev_row.owner,
                issued_at=now_str,
                expires_at=old_pred["lifecycle"]["expires_at"],
                revoked_at=None,
                revocation_reason=None,
                is_current=True,
                statement_json=json.dumps(old_stmt, sort_keys=True),
                dsse_envelope_json=json.dumps(envelope, sort_keys=True),
            )
            session.add(new_row)

            # Resolve any pending review queue entries for this locator
            pending_reviews = (
                session.execute(
                    select(ReviewQueueModel).where(
                        ReviewQueueModel.locator == locator,
                        ReviewQueueModel.status == "PENDING_REVIEW",
                    )
                )
                .scalars()
                .all()
            )
            for rev in pending_reviews:
                rev.status = "APPROVED"
                rev.approvals_json = json.dumps(normalized_approvals)
                rev.resolved_at = now_str

            session.commit()
            return self._row_to_dict(new_row)

    def revoke_record(
        self,
        locator: str,
        reason: str = "Administrative revocation",
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Revoke the current attestation record for `locator` immediately."""
        now_dt = now or datetime.now(timezone.utc)
        now_str = format_iso8601(now_dt)

        with self.SessionLocal() as session:
            row = self._get_single_current_row(session, locator)
            if not row:
                raise RegistryLifecycleError(f"No current record found for locator '{locator}'.")

            stmt = json.loads(row.statement_json)
            pred = stmt["predicate"]
            pred["lifecycle"]["status"] = "revoked"
            pred["lifecycle"]["revoked_at"] = now_str
            pred["lifecycle"]["revocation_reason"] = reason
            pred["handling"]["policy"]["ai_eligibility"] = "deny"

            envelope = sign_statement(stmt, self.keyring)
            row.status = "revoked"
            row.revoked_at = now_str
            row.revocation_reason = reason
            row.ai_eligibility = "deny"
            row.statement_json = json.dumps(stmt, sort_keys=True)
            row.dsse_envelope_json = json.dumps(envelope, sort_keys=True)

            session.commit()
            return self._row_to_dict(row)

    def list_review_queue(self, status: str | None = "PENDING_REVIEW") -> list[dict[str, Any]]:
        """List human-review queue items."""
        with self.SessionLocal() as session:
            stmt = select(ReviewQueueModel)
            if status:
                stmt = stmt.where(ReviewQueueModel.status == status)
            rows = session.execute(stmt.order_by(ReviewQueueModel.created_at)).scalars().all()
            return [self._review_to_dict(r) for r in rows]

    def approve_pending_review(
        self,
        review_id: str,
        approver_id: str,
        confirmed_tier: str | None = None,
        rationale: str = "Confirmed classification in human review",
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Approve a pending review queue item (e.g. issuing a held low-confidence record or recording an approval)."""
        now_dt = now or datetime.now(timezone.utc)
        now_str = format_iso8601(now_dt)

        with self.SessionLocal() as session:
            rev = session.execute(
                select(ReviewQueueModel).where(ReviewQueueModel.review_id == review_id)
            ).scalar_one_or_none()
            if not rev:
                raise RegistryLifecycleError(f"Review item '{review_id}' not found.")
            if rev.status != "PENDING_REVIEW":
                raise RegistryLifecycleError(f"Review item '{review_id}' is already {rev.status}.")

            approvals = json.loads(rev.approvals_json)
            approvals.append({"approver_id": approver_id, "approved_at": now_str, "rationale": rationale})
            rev.approvals_json = json.dumps(approvals)

            target_tier = confirmed_tier or rev.proposed_tier
            meta = json.loads(rev.metadata_json)

            if rev.reason == "low_confidence":
                rev.status = "APPROVED"
                rev.resolved_at = now_str
                session.commit()
                # Now issue the confirmed record with high confidence (0.95)
                issued = self.issue_or_queue_finding(
                    locator=rev.locator,
                    content_sha256=meta["content_sha256"],
                    schema_sha256=meta.get("schema_sha256"),
                    tier=target_tier,
                    owner=meta["owner"],
                    confidence=0.95,
                    low_confidence=False,
                    sensitive_categories=meta.get("sensitive_categories", []),
                    object_type=meta.get("object_type", "file"),
                    display_name=meta.get("display_name"),
                    environment=meta.get("environment", "production"),
                    source_system=meta.get("source_system", "human-review"),
                    classifier_engine=meta.get("classifier_engine", "human-reviewed"),
                    size_bytes=meta.get("size_bytes"),
                    row_count=meta.get("row_count"),
                    fingerprint_method=meta.get("fingerprint_method", "raw_bytes_sha256"),
                    extracted_text_sha256=meta.get("extracted_text_sha256"),
                    chunk_hashes=meta.get("chunk_hashes", []),
                    derived_from=meta.get("derived_from", []),
                    now=now_dt,
                )
                return issued

            # For restricted_tier review: if lowering tier, require 2 distinct approvers
            if rev.current_tier and TIER_ORDER[target_tier] < TIER_ORDER[rev.current_tier]:
                distinct = {a["approver_id"] for a in approvals}
                if len(distinct) < 2:
                    rev.proposed_tier = target_tier
                    session.commit()
                    return {
                        "action": "awaiting_second_approval",
                        "record": None,
                        "review": self._review_to_dict(rev),
                    }
                session.commit()
                lowered = self.lower_tier(
                    locator=rev.locator,
                    new_tier=target_tier,
                    approvals=approvals,
                    now=now_dt,
                )
                return {"action": "tier_lowered", "record": lowered, "review": self._review_to_dict(rev)}

            rev.status = "APPROVED"
            rev.resolved_at = now_str
            session.commit()
            return {
                "action": "acknowledged",
                "record": self.lookup_by_locator(rev.locator),
                "review": self._review_to_dict(rev),
            }

    def verify_record(
        self,
        envelope: dict[str, Any],
        expected_content_sha256: str | None = None,
        check_expiry: bool = True,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Verify a DSSE attestation record envelope against the Registry's local keyring."""
        res = verify_dsse_envelope(
            envelope=envelope,
            keyring=self.keyring,
            expected_content_sha256=expected_content_sha256,
            check_expiry=check_expiry,
            now=now,
        )
        return {
            "verified": res.verified,
            "keyid": res.keyid,
            "algorithm": res.algorithm,
            "locator": res.subject_name,
            "content_sha256": res.subject_sha256,
            "tier": res.statement["predicate"]["classification"]["tier"],
            "status": res.statement["predicate"]["lifecycle"]["status"],
            "expires_at": res.statement["predicate"]["lifecycle"]["expires_at"],
        }
