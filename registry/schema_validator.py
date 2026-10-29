"""Schema validation and tier/TTL policy invariants for POD attestation records and snapshots."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import jsonschema

SCHEMAS_DIR = Path(__file__).resolve().parent.parent / "schemas"

ATTESTATION_PREDICATE_TYPE = "https://schemas.proofofdata.dev/attestation/v0.1"
SNAPSHOT_PREDICATE_TYPE = "https://schemas.proofofdata.dev/snapshot/v0.1"
INTOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"

TIER_ORDER: dict[str, int] = {
    "Public": 0,
    "Internal": 1,
    "Confidential": 2,
    "Restricted": 3,
}

CLEARANCE_ORDER: dict[str, int] = {
    "Public": 0,
    "Internal": 1,
    "Confidential": 2,
    "Restricted": 3,
}

EGRESS_ORDER: dict[str, int] = {
    "local_only": 0,
    "private_cloud": 1,
    "public_api": 2,
}

TIER_MAX_TTL_DAYS: dict[str, int] = {
    "Restricted": 30,
    "Confidential": 90,
    "Internal": 180,
    "Public": 365,
}

DEFAULT_HANDLING_BY_TIER: dict[str, dict[str, str]] = {
    "Public": {
        "ai_eligibility": "allow",
        "minimum_clearance": "Public",
        "egress_class": "public_api",
    },
    "Internal": {
        "ai_eligibility": "allow",
        "minimum_clearance": "Internal",
        "egress_class": "private_cloud",
    },
    "Confidential": {
        "ai_eligibility": "strip",
        "minimum_clearance": "Confidential",
        "egress_class": "local_only",
    },
    "Restricted": {
        "ai_eligibility": "deny",
        "minimum_clearance": "Restricted",
        "egress_class": "local_only",
    },
}


class SchemaValidationError(ValueError):
    """Raised when an attestation predicate, statement, or snapshot violates the schema contract."""


def _load_schema(filename: str) -> dict[str, Any]:
    path = SCHEMAS_DIR / filename
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


ATTESTATION_SCHEMA = _load_schema("attestation-predicate.schema.json")
SNAPSHOT_SCHEMA = _load_schema("snapshot-predicate.schema.json")
DSSE_SCHEMA = _load_schema("dsse-envelope.schema.json")


def parse_iso8601(ts: str) -> datetime:
    """Parse an ISO-8601 timestamp into a timezone-aware UTC datetime."""
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def format_iso8601(dt: datetime) -> str:
    """Format a datetime as an ISO-8601 UTC string with Z suffix."""
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def validate_attestation_predicate(predicate: dict[str, Any]) -> None:
    """Validate an attestation predicate against JSON Schema and semantic tier/TTL invariants."""
    if "signature" in predicate or "signatures" in predicate:
        raise SchemaValidationError(
            "Phase 0 invariant violation: cryptographic signature must live in the outer DSSE envelope, not inside the predicate."
        )

    try:
        jsonschema.validate(instance=predicate, schema=ATTESTATION_SCHEMA)
    except jsonschema.ValidationError as exc:
        raise SchemaValidationError(f"Predicate schema validation failed at {list(exc.path)}: {exc.message}") from exc

    # Verify the 7 mandatory fields are non-empty and semantically valid
    locator = predicate["identity"]["locator"]
    owner = predicate["ownership"]["owner"]
    attested_by = predicate["provenance"]["attested_by"]
    content_sha256 = predicate["integrity"]["content_sha256"]
    tier = predicate["classification"]["tier"]
    policy = predicate["handling"]["policy"]
    expires_at_str = predicate["lifecycle"]["expires_at"]

    if not all([locator, owner, attested_by, content_sha256, tier, policy, expires_at_str]):
        raise SchemaValidationError("One or more of the 7 mandatory fields are empty.")

    # Verify sensitive_categories never leak raw values (only category, count, max_confidence, column_or_field)
    for item in predicate["classification"].get("sensitive_categories", []):
        if "value" in item or "sample" in item or "raw" in item:
            raise SchemaValidationError("Classification findings must record types and counts only, never raw values.")

    # Verify minimum clearance is at least as strict as the classification tier
    min_clearance = policy["minimum_clearance"]
    if CLEARANCE_ORDER[min_clearance] < TIER_ORDER[tier]:
        raise SchemaValidationError(
            f"handling.policy.minimum_clearance ({min_clearance}) cannot be lower than classification.tier ({tier})."
        )

    # Verify expiry timestamp and max TTL by tier
    expires_at = parse_iso8601(expires_at_str)
    issued_at_str = predicate["lifecycle"].get("issued_at")
    if issued_at_str:
        issued_at = parse_iso8601(issued_at_str)
        if expires_at <= issued_at:
            raise SchemaValidationError("lifecycle.expires_at must be strictly after lifecycle.issued_at.")
        max_days = TIER_MAX_TTL_DAYS[tier]
        delta_seconds = (expires_at - issued_at).total_seconds()
        # Allow up to 60 seconds clock skew tolerance on max_days
        if delta_seconds > (max_days * 86400) + 60:
            raise SchemaValidationError(
                f"Tier '{tier}' records have a maximum TTL of {max_days} days, but record expires in {delta_seconds / 86400:.2f} days."
            )

    # Verify dual-approval invariant if status is tier_lowered
    if predicate["lifecycle"].get("status") == "tier_lowered":
        approvals = predicate["lifecycle"].get("tier_lower_approvals", [])
        if len(approvals) < 2:
            raise SchemaValidationError("Lowering a classification tier requires dual approval (at least 2 approvals).")
        approvers = {a["approver_id"] for a in approvals}
        if len(approvers) < 2:
            raise SchemaValidationError("Dual approval requires two distinct approver_id principals.")


def validate_intoto_statement(statement: dict[str, Any], expected_predicate_type: str = ATTESTATION_PREDICATE_TYPE) -> None:
    """Validate an in-toto v1 Statement and its inner predicate."""
    if not isinstance(statement, dict):
        raise SchemaValidationError("in-toto Statement must be a JSON object.")
    if statement.get("_type") != INTOTO_STATEMENT_TYPE:
        raise SchemaValidationError(f"Expected _type '{INTOTO_STATEMENT_TYPE}', got '{statement.get('_type')}'.")
    if statement.get("predicateType") != expected_predicate_type:
        raise SchemaValidationError(
            f"Expected predicateType '{expected_predicate_type}', got '{statement.get('predicateType')}'."
        )

    subjects = statement.get("subject")
    if not isinstance(subjects, list) or len(subjects) == 0:
        raise SchemaValidationError("in-toto Statement requires a non-empty 'subject' list.")

    subject = subjects[0]
    if not isinstance(subject, dict) or "name" not in subject or "digest" not in subject:
        raise SchemaValidationError("in-toto subject[0] must contain 'name' and 'digest'.")
    sha256_digest = subject.get("digest", {}).get("sha256")
    if not isinstance(sha256_digest, str) or not re.fullmatch(r"[a-f0-9]{64}", sha256_digest):
        raise SchemaValidationError("in-toto subject[0].digest.sha256 must be a 64-character lowercase hex SHA-256 string.")

    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        raise SchemaValidationError("in-toto Statement must contain a 'predicate' object.")

    if expected_predicate_type == ATTESTATION_PREDICATE_TYPE:
        validate_attestation_predicate(predicate)
        if subject["name"] != predicate["identity"]["locator"]:
            raise SchemaValidationError(
                f"in-toto subject[0].name ('{subject['name']}') does not match predicate.identity.locator ('{predicate['identity']['locator']}')."
            )
        if sha256_digest != predicate["integrity"]["content_sha256"]:
            raise SchemaValidationError(
                "in-toto subject[0].digest.sha256 does not match predicate.integrity.content_sha256."
            )
    elif expected_predicate_type == SNAPSHOT_PREDICATE_TYPE:
        validate_snapshot_predicate(predicate)


def validate_snapshot_predicate(predicate: dict[str, Any]) -> None:
    """Validate a snapshot predicate against `schemas/snapshot-predicate.schema.json`."""
    try:
        jsonschema.validate(instance=predicate, schema=SNAPSHOT_SCHEMA)
    except jsonschema.ValidationError as exc:
        raise SchemaValidationError(f"Snapshot schema validation failed at {list(exc.path)}: {exc.message}") from exc

    issued_at = parse_iso8601(predicate["issued_at"])
    expires_at = parse_iso8601(predicate["expires_at"])
    if expires_at <= issued_at:
        raise SchemaValidationError("Snapshot expires_at must be strictly after issued_at.")


def validate_dsse_envelope_structure(envelope: dict[str, Any]) -> None:
    """Validate outer DSSE envelope JSON structure."""
    try:
        jsonschema.validate(instance=envelope, schema=DSSE_SCHEMA)
    except jsonschema.ValidationError as exc:
        raise SchemaValidationError(f"DSSE envelope validation failed at {list(exc.path)}: {exc.message}") from exc
