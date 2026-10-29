"""Local key management, DSSE v1 signing, and Sigstore-compatible verification toolkit."""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from registry.schema_validator import (
    ATTESTATION_PREDICATE_TYPE,
     DEFAULT_HANDLING_BY_TIER,
    DSSE_PAYLOAD_TYPE,
    INTOTO_STATEMENT_TYPE,
    SNAPSHOT_PREDICATE_TYPE,
    TIER_MAX_TTL_DAYS,
    format_iso8601,
    parse_iso8601,
    validate_dsse_envelope_structure,
    validate_intoto_statement,
)


class SignatureVerificationError(ValueError):
    """Raised when DSSE signature or content integrity verification fails."""


def compute_bytes_sha256(data: bytes) -> str:
    """Return lowercase 64-character hex SHA-256 digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def compute_file_sha256(path: str | Path) -> str:
    """Return lowercase 64-character hex SHA-256 digest of a file on disk."""
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def dsse_pae(payload_type: str, payload_bytes: bytes) -> bytes:
    """Compute DSSE v1 Pre-Authentication Encoding (PAE) per the DSSE specification.

    PAE(type, body) = "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(body) + SP + body
    """
    pt_bytes = payload_type.encode("utf-8")
    prefix = f"DSSEv1 {len(pt_bytes)} ".encode("utf-8") + pt_bytes + f" {len(payload_bytes)} ".encode("utf-8")
    return prefix + payload_bytes


def compute_spki_keyid(public_key: ed25519.Ed25519PublicKey | ec.EllipticCurvePublicKey) -> str:
    """Compute deterministic keyid from SHA-256 of SubjectPublicKeyInfo (DER)."""
    spki_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki_der).hexdigest()[:16]


@dataclass
class VerificationResult:
    """Structured result returned when verifying a DSSE attestation or snapshot envelope."""

    verified: bool
    keyid: str
    algorithm: str
    statement: dict[str, Any]
    predicate_type: str
    subject_name: str
    subject_sha256: str


class Keyring:
    """In-boundary operator keyring supporting key generation, rotation, and historical verification."""

    def __init__(self, key_dir: str | Path) -> None:
        self.key_dir = Path(key_dir)
        self.key_dir.mkdir(parents=True, exist_ok=True)
        self.keyring_file = self.key_dir / "keyring.json"
        if not self.keyring_file.exists():
            self._save_data({"active_keyid": None, "keys": {}})

    def _load_data(self) -> dict[str, Any]:
        with self.keyring_file.open("r", encoding="utf-8") as f:
            return json.load(f)

    def _save_data(self, data: dict[str, Any]) -> None:
        with self.keyring_file.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)

    def generate_key(
        self,
        algorithm: str = "Ed25519",
        operator_id: str = "pod-operator",
        activate: bool = True,
    ) -> dict[str, Any]:
        """Generate a new local keypair (Ed25519 or ECDSA_P256_SHA256) and register it in the keyring."""
        if algorithm == "Ed25519":
            private_key = ed25519.Ed25519PrivateKey.generate()
        elif algorithm == "ECDSA_P256_SHA256":
            private_key = ec.generate_private_key(ec.SECP256R1())
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        public_key = private_key.public_key()
        keyid = compute_spki_keyid(public_key)
        now_str = format_iso8601(datetime.now(timezone.utc))

        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        priv_path = self.key_dir / f"{keyid}.priv.pem"
        pub_path = self.key_dir / f"{keyid}.pub.pem"
        priv_path.write_text(priv_pem, encoding="utf-8")
        pub_path.write_text(pub_pem, encoding="utf-8")

        data = self._load_data()
        if activate and data.get("active_keyid"):
            old_id = data["active_keyid"]
            if old_id in data["keys"] and data["keys"][old_id]["status"] == "active":
                data["keys"][old_id]["status"] = "rotated"
                data["keys"][old_id]["rotated_at"] = now_str

        entry = {
            "keyid": keyid,
            "algorithm": algorithm,
            "operator_id": operator_id,
            "status": "active" if activate else "standby",
            "created_at": now_str,
            "rotated_at": None,
            "revoked_at": None,
            "public_key_pem": pub_pem,
            "private_key_file": priv_path.name,
        }
        data["keys"][keyid] = entry
        if activate:
            data["active_keyid"] = keyid
        self._save_data(data)
        return entry

    def rotate_key(self, algorithm: str = "Ed25519", operator_id: str = "pod-operator") -> dict[str, Any]:
        """Rotate the active signing key; previously active key moves to 'rotated' state for historical verification."""
        return self.generate_key(algorithm=algorithm, operator_id=operator_id, activate=True)

    def revoke_key(self, keyid: str) -> None:
        """Mark a key as compromised/revoked; any signature made by a revoked key fails verification immediately."""
        data = self._load_data()
        if keyid not in data["keys"]:
            raise KeyError(f"Unknown keyid: {keyid}")
        now_str = format_iso8601(datetime.now(timezone.utc))
        data["keys"][keyid]["status"] = "revoked"
        data["keys"][keyid]["revoked_at"] = now_str
        if data.get("active_keyid") == keyid:
            data["active_keyid"] = None
        self._save_data(data)

    def ensure_active_key(self) -> dict[str, Any]:
        """Return the active key metadata, generating a default Ed25519 key if none exists."""
        data = self._load_data()
        active_id = data.get("active_keyid")
        if active_id and active_id in data["keys"] and data["keys"][active_id]["status"] == "active":
            return data["keys"][active_id]
        return self.generate_key(algorithm="Ed25519")

    def get_key_metadata(self, keyid: str) -> dict[str, Any]:
        data = self._load_data()
        if keyid not in data["keys"]:
            raise SignatureVerificationError(f"Key ID '{keyid}' is not present in the local operator keyring.")
        return data["keys"][keyid]

    def list_keys(self) -> list[dict[str, Any]]:
        data = self._load_data()
        return list(data["keys"].values())

    def load_private_key(self, keyid: str | None = None) -> tuple[str, str, Any]:
        data = self._load_data()
        target_id = keyid or data.get("active_keyid")
        if not target_id or target_id not in data["keys"]:
            meta = self.ensure_active_key()
            target_id = meta["keyid"]
        else:
            meta = data["keys"][target_id]

        if meta["status"] != "active":
            raise SignatureVerificationError(f"Cannot sign with non-active key '{target_id}' (status={meta['status']}).")

        priv_path = self.key_dir / meta["private_key_file"]
        priv_bytes = priv_path.read_bytes()
        private_key = serialization.load_pem_private_key(priv_bytes, password=None)
        return target_id, meta["algorithm"], private_key

    def load_public_key(self, keyid: str) -> tuple[dict[str, Any], Any]:
        meta = self.get_key_metadata(keyid)
        pub_bytes = meta["public_key_pem"].encode("utf-8")
        public_key = serialization.load_pem_public_key(pub_bytes)
        return meta, public_key


def sign_statement(statement: dict[str, Any], keyring: Keyring, keyid: str | None = None) -> dict[str, Any]:
    """Validate an in-toto Statement and wrap it in a signed DSSE v1 envelope with Sigstore local bundle metadata."""
    predicate_type = statement.get("predicateType", ATTESTATION_PREDICATE_TYPE)
    validate_intoto_statement(statement, expected_predicate_type=predicate_type)

    canonical_payload = json.dumps(statement, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_b64 = base64.b64encode(canonical_payload).decode("ascii")
    pae_bytes = dsse_pae(DSSE_PAYLOAD_TYPE, canonical_payload)

    signing_keyid, algorithm, private_key = keyring.load_private_key(keyid)
    if algorithm == "Ed25519":
        sig_bytes = private_key.sign(pae_bytes)
    elif algorithm == "ECDSA_P256_SHA256":
        sig_bytes = private_key.sign(pae_bytes, ec.ECDSA(hashes.SHA256()))
    else:
        raise ValueError(f"Unsupported key algorithm: {algorithm}")

    sig_b64 = base64.b64encode(sig_bytes).decode("ascii")

    envelope = {
        "payloadType": DSSE_PAYLOAD_TYPE,
        "payload": payload_b64,
        "signatures": [
            {
                "keyid": signing_keyid,
                "sig": sig_b64,
            }
        ],
        "sigstoreBundle": {
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {
                "publicKey": {
                    "hint": signing_keyid,
                    "algorithm": algorithm,
                }
            },
        },
    }
    validate_dsse_envelope_structure(envelope)
    return envelope


def verify_dsse_envelope(
    envelope: dict[str, Any],
    keyring: Keyring,
    expected_predicate_type: str | None = None,
    expected_content_sha256: str | None = None,
    check_expiry: bool = True,
    now: datetime | None = None,
) -> VerificationResult:
    """Verify DSSE envelope signature, key validity window, in-toto statement schema, and optional content hash."""
    try:
        validate_dsse_envelope_structure(envelope)
    except Exception as exc:
        raise SignatureVerificationError(f"Malformed DSSE envelope: {exc}") from exc

    try:
        payload_bytes = base64.b64decode(envelope["payload"], validate=True)
        statement = json.loads(payload_bytes.decode("utf-8"))
    except Exception as exc:
        raise SignatureVerificationError(f"Failed to decode DSSE payload: {exc}") from exc

    actual_predicate_type = statement.get("predicateType")
    target_predicate_type = expected_predicate_type or actual_predicate_type
    if target_predicate_type not in (ATTESTATION_PREDICATE_TYPE, SNAPSHOT_PREDICATE_TYPE):
        raise SignatureVerificationError(f"Unsupported predicateType: {target_predicate_type}")

    try:
        validate_intoto_statement(statement, expected_predicate_type=target_predicate_type)
    except Exception as exc:
        raise SignatureVerificationError(f"Statement validation failed: {exc}") from exc

    pae_bytes = dsse_pae(envelope["payloadType"], payload_bytes)
    sig_entry = envelope["signatures"][0]
    keyid = sig_entry["keyid"]
    try:
        sig_bytes = base64.b64decode(sig_entry["sig"], validate=True)
    except Exception as exc:
        raise SignatureVerificationError("Invalid base64 signature encoding.") from exc

    meta, public_key = keyring.load_public_key(keyid)
    if meta["status"] == "revoked":
        raise SignatureVerificationError(f"Signing key '{keyid}' has been revoked.")

    algorithm = meta["algorithm"]
    try:
        if algorithm == "Ed25519":
            public_key.verify(sig_bytes, pae_bytes)
        elif algorithm == "ECDSA_P256_SHA256":
            public_key.verify(sig_bytes, pae_bytes, ec.ECDSA(hashes.SHA256()))
        else:
            raise SignatureVerificationError(f"Unsupported algorithm: {algorithm}")
    except InvalidSignature as exc:
        raise SignatureVerificationError("Cryptographic DSSE signature verification failed (payload or signature tampered).") from exc

    # Verify rotated key validity window if the key was rotated
    predicate = statement["predicate"]
    issued_at_str = (
        predicate.get("lifecycle", {}).get("issued_at")
        if target_predicate_type == ATTESTATION_PREDICATE_TYPE
        else predicate.get("issued_at")
    )
    if meta["status"] == "rotated" and meta.get("rotated_at") and issued_at_str:
        issued_at = parse_iso8601(issued_at_str)
        rotated_at = parse_iso8601(meta["rotated_at"])
        # Allow 5 seconds clock tolerance for rotation boundary
        if issued_at > rotated_at + timedelta(seconds=5):
            raise SignatureVerificationError(
                f"Record claims issued_at ({issued_at_str}) after key '{keyid}' was rotated ({meta['rotated_at']})."
            )

    current_time = now or datetime.now(timezone.utc)
    if check_expiry:
        if target_predicate_type == ATTESTATION_PREDICATE_TYPE:
            lifecycle = predicate["lifecycle"]
            if lifecycle.get("status") == "revoked":
                raise SignatureVerificationError("Attestation record is revoked.")
            expires_at = parse_iso8601(lifecycle["expires_at"])
            if current_time >= expires_at:
                raise SignatureVerificationError(f"Attestation record expired at {lifecycle['expires_at']}.")
        elif target_predicate_type == SNAPSHOT_PREDICATE_TYPE:
            expires_at = parse_iso8601(predicate["expires_at"])
            if current_time >= expires_at:
                raise SignatureVerificationError(f"Snapshot expired at {predicate['expires_at']}.")

    subject = statement["subject"][0]
    subject_sha256 = subject["digest"]["sha256"]
    if expected_content_sha256 is not None and expected_content_sha256.lower() != subject_sha256:
        raise SignatureVerificationError(
            f"Content SHA-256 mismatch: object has '{expected_content_sha256.lower()}', attested record has '{subject_sha256}'."
        )

    return VerificationResult(
        verified=True,
        keyid=keyid,
        algorithm=algorithm,
        statement=statement,
        predicate_type=target_predicate_type,
        subject_name=subject["name"],
        subject_sha256=subject_sha256,
    )


def build_attestation_statement(
    *,
    locator: str,
    content_sha256: str,
    tier: str,
    owner: str,
    attested_by: str = "pod-engine-v0.1",
    record_id: str | None = None,
    object_type: str = "file",
    display_name: str | None = None,
    environment: str = "production",
    steward: str | None = None,
    org_unit: str | None = None,
    jurisdiction: str | None = "GLOBAL",
    source_system: str = "tika+presidio",
    scanner_version: str = "0.1.0",
    derived_from: list[dict[str, Any]] | None = None,
    schema_sha256: str | None = None,
    size_bytes: int | None = None,
    row_count: int | None = None,
    fingerprint_method: str = "raw_bytes_sha256",
    confidence: float = 0.95,
    sensitive_categories: list[dict[str, Any]] | None = None,
    classifier_engine: str = "presidio",
    policy: dict[str, str] | None = None,
    allow_rag_indexing: bool | None = None,
    allow_model_training: bool = False,
    redaction_categories: list[str] | None = None,
    status: str = "issued",
    ttl_days: int | None = None,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    previous_record_id: str | None = None,
    revoked_at: str | None = None,
    revocation_reason: str | None = None,
    tier_lower_approvals: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Construct a complete, schema-valid in-toto v1 Attestation Statement."""
    now_dt = issued_at or datetime.now(timezone.utc)
    max_ttl = TIER_MAX_TTL_DAYS[tier]
    effective_ttl = ttl_days if ttl_days is not None else max_ttl
    exp_dt = expires_at or (now_dt + timedelta(days=effective_ttl))

    rec_id = record_id or f"pod-rec-{uuid.uuid4().hex[:16]}"
    effective_policy = dict(DEFAULT_HANDLING_BY_TIER[tier])
    if policy:
        effective_policy.update(policy)

    if allow_rag_indexing is None:
        allow_rag_indexing = tier in ("Public", "Internal")

    cats = sensitive_categories or []
    redact_cats = redaction_categories if redaction_categories is not None else [c["category"] for c in cats]

    predicate: dict[str, Any] = {
        "schema_version": "0.1.0",
        "identity": {
            "record_id": rec_id,
            "locator": locator,
            "object_type": object_type,
            "display_name": display_name or locator.rsplit("/", 1)[-1],
            "environment": environment,
        },
        "ownership": {
            "owner": owner,
            "steward": steward,
            "org_unit": org_unit,
            "jurisdiction": jurisdiction,
        },
        "provenance": {
            "attested_by": attested_by,
            "source_system": source_system,
            "scanner_version": scanner_version,
            "discovered_at": format_iso8601(now_dt),
            "derived_from": derived_from or [],
        },
        "integrity": {
            "content_sha256": content_sha256.lower(),
            "schema_sha256": schema_sha256.lower() if schema_sha256 else None,
            "size_bytes": size_bytes,
            "row_count": row_count,
            "fingerprint_method": fingerprint_method,
        },
        "classification": {
            "tier": tier,
            "confidence": round(float(confidence), 4),
            "sensitive_categories": cats,
            "classifier_engine": classifier_engine,
        },
        "handling": {
            "policy": effective_policy,
            "allow_rag_indexing": allow_rag_indexing,
            "allow_model_training": allow_model_training,
            "redaction_categories": redact_cats,
        },
        "lifecycle": {
            "status": status,
            "issued_at": format_iso8601(now_dt),
            "expires_at": format_iso8601(exp_dt),
            "ttl_days": effective_ttl,
            "previous_record_id": previous_record_id,
            "revoked_at": revoked_at,
            "revocation_reason": revocation_reason,
            "tier_lower_approvals": tier_lower_approvals or [],
        },
    }

    statement = {
        "_type": INTOTO_STATEMENT_TYPE,
        "subject": [
            {
                "name": locator,
                "digest": {
                    "sha256": content_sha256.lower(),
                },
            }
        ],
        "predicateType": ATTESTATION_PREDICATE_TYPE,
        "predicate": predicate,
    }
    validate_intoto_statement(statement, expected_predicate_type=ATTESTATION_PREDICATE_TYPE)
    return statement
