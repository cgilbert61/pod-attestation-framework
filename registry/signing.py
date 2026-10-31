"""Local key management, DSSE v1 signing, and Sigstore-compatible verification toolkit."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import unicodedata
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


def normalize_canonical_text(text: str) -> bytes:
    """Canonical text normalization: UTF-8 NFC, strip \\r, collapse consecutive whitespace/newlines into a single space, .strip()."""
    nfc = unicodedata.normalize("NFC", text or "")
    no_cr = nfc.replace("\r", "")
    collapsed = re.sub(r"\s+", " ", no_cr).strip()
    return collapsed.encode("utf-8")


def compute_extracted_text_and_chunk_hashes(text: str) -> tuple[str, list[str]]:
    """Compute canonical `extracted_text_sha256` and deterministic `chunk_hashes` for paragraphs, rows, lines, and sliding 500-char windows."""
    norm_full = normalize_canonical_text(text)
    extracted_text_sha256 = hashlib.sha256(norm_full).hexdigest()

    seen: dict[str, None] = {}

    def _add_chunk(candidate: str) -> None:
        if len(seen) >= 256:
            return
        norm_bytes = normalize_canonical_text(candidate)
        if norm_bytes:
            seen[hashlib.sha256(norm_bytes).hexdigest()] = None
        if len(seen) < 256:
            raw_bytes = candidate.encode("utf-8")
            if raw_bytes:
                seen[hashlib.sha256(raw_bytes).hexdigest()] = None

    if text:
        _add_chunk(text)
        no_cr = unicodedata.normalize("NFC", text).replace("\r", "")
        # 1. Paragraph boundaries
        for para in re.split(r"\n\s*\n", no_cr)[:120]:
            para_s = para.strip()
            if not para_s:
                continue
            _add_chunk(para_s)
            # Sliding 500-character windows if paragraph exceeds 500 chars
            if len(para_s) > 500:
                for start in range(0, min(len(para_s), 5000), 250):
                    window = para_s[start : start + 500]
                    if window.strip():
                        _add_chunk(window)
                    if start + 500 >= len(para_s):
                        break

        # 2. Row / line boundaries
        lines = [ln.strip() for ln in no_cr.splitlines() if ln.strip()][:150]
        for ln in lines:
            _add_chunk(ln)
            # Strip markdown heading prefix (#, ##, etc.) so heading text matches cleanly
            if ln.startswith("#"):
                heading_clean = ln.lstrip("#").strip()
                if heading_clean:
                    _add_chunk(heading_clean)
            # For pipe-delimited spreadsheet/CSV rows, include contiguous cell slices
            if " | " in ln:
                cells = [c.strip() for c in ln.split(" | ") if c.strip()]
                n_cells = len(cells)
                if 1 < n_cells <= 12:
                    for i in range(n_cells):
                        for j in range(i + 1, n_cells + 1):
                            _add_chunk(" | ".join(cells[i:j]))
            if len(ln) > 500:
                for start in range(0, min(len(ln), 5000), 250):
                    window = ln[start : start + 500]
                    if window.strip():
                        _add_chunk(window)
                    if start + 500 >= len(ln):
                        break

        # 3. Contiguous multi-line spans (up to 6 consecutive lines)
        if 1 < len(lines) <= 40:
            for i in range(len(lines)):
                for span_len in range(2, min(7, len(lines) - i + 1)):
                    _add_chunk("\n".join(lines[i : i + span_len]))

    return extracted_text_sha256, list(seen.keys())[:256]


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
    """In-boundary operator keyring supporting privilege-separated private signing keys and public verification keys."""

    def __init__(
        self,
        key_dir: str | Path | None = None,
        *,
        private_key_dir: str | Path | None = None,
        public_key_dir: str | Path | None = None,
        verification_only: bool = False,
    ) -> None:
        default_base = Path(key_dir or os.environ.get("POD_KEY_DIR", "./.pod_keys"))
        if public_key_dir is not None:
            self.public_key_dir = Path(public_key_dir)
        elif key_dir is None and os.environ.get("POD_PUBLIC_KEY_DIR"):
            self.public_key_dir = Path(os.environ["POD_PUBLIC_KEY_DIR"])
        else:
            self.public_key_dir = default_base

        self.verification_only = verification_only
        if verification_only:
            self.private_key_dir: Path | None = None
        elif private_key_dir is not None:
            self.private_key_dir = Path(private_key_dir)
        elif key_dir is None and os.environ.get("POD_PRIVATE_KEY_DIR"):
            self.private_key_dir = Path(os.environ["POD_PRIVATE_KEY_DIR"])
        else:
            self.private_key_dir = default_base

        # Maintain `self.key_dir` alias pointing to public_key_dir for backward compatibility
        self.key_dir = self.public_key_dir
        self.keyring_file = self.public_key_dir / "keyring.json"

        if not self.verification_only:
            self.public_key_dir.mkdir(parents=True, exist_ok=True)
            if self.private_key_dir is not None:
                self.private_key_dir.mkdir(parents=True, exist_ok=True)
            if not self.keyring_file.exists():
                self._save_data({"active_keyid": None, "active_keys_by_purpose": {}, "keys": {}})
        else:
            self.assert_no_private_keys_exposed()

    def assert_no_private_keys_exposed(self) -> None:
        """Fail closed if a verification-only or split-directory consumer detects any `*.priv.pem` file in its public key directory."""
        is_split_or_verifier = self.verification_only or (
            self.private_key_dir is not None and self.private_key_dir.resolve() != self.public_key_dir.resolve()
        )
        if is_split_or_verifier and self.public_key_dir.exists():
            leaked_priv = list(self.public_key_dir.glob("*.priv.pem"))
            if leaked_priv:
                raise SignatureVerificationError(
                    f"Cryptographic privilege separation violation: private key file(s) {[p.name for p in leaked_priv]} "
                    f"detected in verification-only public key directory '{self.public_key_dir}'."
                )

    def _load_data(self) -> dict[str, Any]:
        if not self.keyring_file.exists():
            return {"active_keyid": None, "active_keys_by_purpose": {}, "keys": {}}
        with self.keyring_file.open("r", encoding="utf-8") as f:
            return json.load(f)

    def _save_data(self, data: dict[str, Any]) -> None:
        if self.verification_only:
            raise SignatureVerificationError("Verification-only Keyring cannot modify keyring.json.")
        self.public_key_dir.mkdir(parents=True, exist_ok=True)
        with self.keyring_file.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)

    def generate_key(
        self,
        algorithm: str = "Ed25519",
        operator_id: str = "pod-operator",
        activate: bool = True,
        key_purpose: list[str] | None = None,
    ) -> dict[str, Any]:
        """Generate a new local keypair (Ed25519 or ECDSA_P256_SHA256) and register public metadata in the keyring."""
        if self.verification_only or self.private_key_dir is None:
            raise SignatureVerificationError("Verification-only Keyring cannot generate private signing keys.")

        if algorithm == "Ed25519":
            private_key = ed25519.Ed25519PrivateKey.generate()
        elif algorithm == "ECDSA_P256_SHA256":
            private_key = ec.generate_private_key(ec.SECP256R1())
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        public_key = private_key.public_key()
        keyid = compute_spki_keyid(public_key)
        now_str = format_iso8601(datetime.now(timezone.utc))
        purposes = list(key_purpose or ["attestation", "snapshot"])

        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        self.private_key_dir.mkdir(parents=True, exist_ok=True)
        self.public_key_dir.mkdir(parents=True, exist_ok=True)
        priv_path = self.private_key_dir / f"{keyid}.priv.pem"
        pub_path = self.public_key_dir / f"{keyid}.pub.pem"
        priv_path.write_text(priv_pem, encoding="utf-8")
        pub_path.write_text(pub_pem, encoding="utf-8")

        data = self._load_data()
        data.setdefault("active_keys_by_purpose", {})
        if activate and data.get("active_keyid"):
            old_id = data["active_keyid"]
            if old_id in data["keys"] and data["keys"][old_id]["status"] == "active":
                old_purposes = set(data["keys"][old_id].get("key_purpose", ["attestation", "snapshot"]))
                if old_purposes.issubset(set(purposes)):
                    data["keys"][old_id]["status"] = "rotated"
                    data["keys"][old_id]["rotated_at"] = now_str

        entry = {
            "keyid": keyid,
            "algorithm": algorithm,
            "operator_id": operator_id,
            "key_purpose": purposes,
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
            for p in purposes:
                data["active_keys_by_purpose"][p] = keyid
        self._save_data(data)
        return entry

    def rotate_key(
        self,
        algorithm: str = "Ed25519",
        operator_id: str = "pod-operator",
        key_purpose: list[str] | None = None,
    ) -> dict[str, Any]:
        """Rotate the active signing key; previously active key moves to 'rotated' state for historical verification."""
        return self.generate_key(algorithm=algorithm, operator_id=operator_id, activate=True, key_purpose=key_purpose)

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
        for p, k_id in list(data.get("active_keys_by_purpose", {}).items()):
            if k_id == keyid:
                data["active_keys_by_purpose"][p] = None
        self._save_data(data)

    def ensure_active_key(
        self,
        purpose: str | None = None,
        operator_id: str = "pod-operator",
    ) -> dict[str, Any]:
        """Return the active key metadata (optionally scoped to `purpose`), generating an Ed25519 key if none exists."""
        data = self._load_data()
        if purpose:
            by_purpose = data.get("active_keys_by_purpose", {}).get(purpose)
            if by_purpose and by_purpose in data["keys"] and data["keys"][by_purpose]["status"] == "active":
                return data["keys"][by_purpose]
            for k_meta in data["keys"].values():
                if k_meta.get("status") == "active" and purpose in k_meta.get("key_purpose", ["attestation", "snapshot"]):
                    priv_file = (self.private_key_dir / k_meta["private_key_file"]) if self.private_key_dir else None
                    if priv_file and priv_file.exists():
                        return k_meta
            return self.generate_key(algorithm="Ed25519", operator_id=operator_id, activate=True, key_purpose=[purpose])

        active_id = data.get("active_keyid")
        if active_id and active_id in data["keys"] and data["keys"][active_id]["status"] == "active":
            priv_file = (self.private_key_dir / data["keys"][active_id]["private_key_file"]) if self.private_key_dir else None
            if priv_file is None or priv_file.exists():
                return data["keys"][active_id]
        return self.generate_key(algorithm="Ed25519", operator_id=operator_id)

    def get_key_metadata(self, keyid: str) -> dict[str, Any]:
        if self.verification_only:
            self.assert_no_private_keys_exposed()
        data = self._load_data()
        if keyid not in data["keys"]:
            raise SignatureVerificationError(f"Key ID '{keyid}' is not present in the local operator keyring.")
        return data["keys"][keyid]

    def list_keys(self) -> list[dict[str, Any]]:
        data = self._load_data()
        return list(data["keys"].values())

    def load_private_key(self, keyid: str | None = None, purpose: str | None = None) -> tuple[str, str, Any]:
        if self.verification_only or self.private_key_dir is None:
            raise SignatureVerificationError("Cannot load private key from verification-only Keyring.")
        data = self._load_data()
        target_id = keyid
        if not target_id and purpose:
            target_id = data.get("active_keys_by_purpose", {}).get(purpose)
        if not target_id:
            target_id = data.get("active_keyid")
        if not target_id or target_id not in data["keys"]:
            meta = self.ensure_active_key(purpose=purpose)
            target_id = meta["keyid"]
        else:
            meta = data["keys"][target_id]
            priv_candidate = self.private_key_dir / meta.get("private_key_file", f"{target_id}.priv.pem")
            if not priv_candidate.exists():
                meta = self.ensure_active_key(purpose=purpose)
                target_id = meta["keyid"]

        if meta["status"] != "active":
            raise SignatureVerificationError(f"Cannot sign with non-active key '{target_id}' (status={meta['status']}).")

        priv_path = self.private_key_dir / meta.get("private_key_file", f"{target_id}.priv.pem")
        priv_bytes = priv_path.read_bytes()
        private_key = serialization.load_pem_private_key(priv_bytes, password=None)
        return target_id, meta["algorithm"], private_key

    def load_public_key(self, keyid: str) -> tuple[dict[str, Any], Any]:
        if self.verification_only:
            self.assert_no_private_keys_exposed()
        meta = self.get_key_metadata(keyid)
        pub_pem_str = meta.get("public_key_pem")
        if not pub_pem_str:
            pub_file = self.public_key_dir / f"{keyid}.pub.pem"
            pub_pem_str = pub_file.read_text(encoding="utf-8")
        public_key = serialization.load_pem_public_key(pub_pem_str.encode("utf-8"))
        return meta, public_key

    def verify_dsse(
        self,
        envelope: dict[str, Any],
        expected_predicate_type: str | None = None,
        expected_content_sha256: str | None = None,
        check_expiry: bool = True,
        now: datetime | None = None,
    ) -> VerificationResult:
        """Verify a DSSE envelope using only the public verification keyring."""
        self.assert_no_private_keys_exposed()
        return verify_dsse_envelope(
            envelope=envelope,
            keyring=self,
            expected_predicate_type=expected_predicate_type,
            expected_content_sha256=expected_content_sha256,
            check_expiry=check_expiry,
            now=now,
        )


def sign_statement(
    statement: dict[str, Any],
    keyring: Keyring,
    keyid: str | None = None,
    purpose: str | None = None,
) -> dict[str, Any]:
    """Validate an in-toto Statement and wrap it in a signed DSSE v1 envelope with Sigstore local bundle metadata."""
    predicate_type = statement.get("predicateType", ATTESTATION_PREDICATE_TYPE)
    validate_intoto_statement(statement, expected_predicate_type=predicate_type)

    canonical_payload = json.dumps(statement, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_b64 = base64.b64encode(canonical_payload).decode("ascii")
    pae_bytes = dsse_pae(DSSE_PAYLOAD_TYPE, canonical_payload)

    inferred_purpose = purpose or ("snapshot" if predicate_type == SNAPSHOT_PREDICATE_TYPE else "attestation")
    signing_keyid, algorithm, private_key = keyring.load_private_key(keyid, purpose=inferred_purpose)
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
    extracted_text_sha256: str | None = None,
    chunk_hashes: list[str] | None = None,
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

    default_stewards = {
        "Restricted": "privacy-compliance-steward@contoso.com",
        "Confidential": "dlp-security-steward@contoso.com",
        "Internal": "engineering-data-steward@contoso.com",
        "Public": "open-data-steward@contoso.com",
    }
    effective_steward = steward if steward is not None else default_stewards.get(tier, "data-governance-steward@contoso.com")
    if org_unit is not None:
        effective_org_unit = org_unit
    elif object_type in ("database_table", "database_view", "warehouse_table"):
        effective_org_unit = "Enterprise Data Platform & Warehouse"
    elif locator.startswith(("s3://", "azblob://", "abfss://", "gs://")):
        effective_org_unit = "Cloud Lakehouse & AI Corpus Operations"
    else:
        effective_org_unit = "Enterprise Data & AI Governance"

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
            "steward": effective_steward,
            "org_unit": effective_org_unit,
            "jurisdiction": jurisdiction or "GLOBAL",
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
            "extracted_text_sha256": extracted_text_sha256.lower() if extracted_text_sha256 else None,
            "chunk_hashes": [h.lower() for h in (chunk_hashes or [])],
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
