"""In-memory Snapshot Enforcer and `<pod:object>` tag parser/stripper for the Prevalidator."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import jwt

from engine.classifier import RESTRICTED_CATEGORIES, PresidioClassifier
from registry.schema_validator import (
    CLEARANCE_ORDER,
    EGRESS_ORDER,
    SNAPSHOT_PREDICATE_TYPE,
    format_iso8601,
    parse_iso8601,
)
from registry.signing import Keyring, verify_dsse_envelope

# Uniform denial message mandated by Phase 2 Consumer Conformance Suite (never leaks which rule fired)
UNIFORM_DENIAL_MESSAGE = "Request denied by data attestation policy."
UNIFORM_DENIAL_CODE = "policy_denied"

# Regex matching inline <pod:object locator="..." [sha256="..."]>...</pod:object> blocks
POD_OBJECT_TAG_RE = re.compile(
    r'<pod:object\s+locator="([^"]+)"(?:\s+sha256="([a-fA-F0-9]{64})")?\s*>(.*?)</pod:object>',
    re.DOTALL,
)


@dataclass
class AuditLogEntry:
    """Operator audit log entry recording exact reason codes (never exposed in client error responses)."""

    timestamp: str
    mode: str  # "enforce" | "observe"
    decision: str  # "allow" | "strip" | "deny" | "observe_would_deny"
    reason_codes: list[str]
    locators_evaluated: list[str]
    caller_clearance: str
    target_egress: str
    stripped_locators: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "mode": self.mode,
            "decision": self.decision,
            "reason_codes": self.reason_codes,
            "locators_evaluated": self.locators_evaluated,
            "caller_clearance": self.caller_clearance,
            "target_egress": self.target_egress,
            "stripped_locators": self.stripped_locators,
        }


@dataclass
class EnforcementOutcome:
    """Result of evaluating an incoming LLM request against the in-memory snapshot."""

    allowed_to_forward: bool
    transformed_payload: dict[str, Any]
    client_denial_body: dict[str, Any] | None
    audit_entry: AuditLogEntry


class InMemorySnapshotStore:
    """Holds the latest verified DSSE snapshot in memory, enforcing monotonic sequence numbers and TTL fail-closed."""

    def __init__(self, keyring: Keyring) -> None:
        self.keyring = keyring
        self._snapshot_predicate: dict[str, Any] | None = None
        self._highest_sequence: int = 0

    def load_from_envelope(self, envelope: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
        """Verify DSSE signature and sequence number before atomically updating the in-memory snapshot."""
        ver = verify_dsse_envelope(
            envelope=envelope,
            keyring=self.keyring,
            expected_predicate_type=SNAPSHOT_PREDICATE_TYPE,
            check_expiry=True,
            now=now,
        )
        pred = ver.statement["predicate"]
        seq = int(pred["sequence_number"])
        if seq < self._highest_sequence:
            raise ValueError(
                f"Snapshot rollback rejected: incoming sequence_number ({seq}) < current ({self._highest_sequence})."
            )
        self._highest_sequence = seq
        self._snapshot_predicate = pred
        return pred

    def load_from_file(self, path: str | Path, now: datetime | None = None) -> dict[str, Any]:
        envelope = json.loads(Path(path).read_text(encoding="utf-8"))
        return self.load_from_envelope(envelope, now=now)

    def get_active_snapshot(self, now: datetime | None = None) -> dict[str, Any] | None:
        """Return the in-memory snapshot predicate ONLY if loaded and not past `expires_at` (fail-closed)."""
        if self._snapshot_predicate is None:
            return None
        current_time = now or datetime.now(timezone.utc)
        expires_at = parse_iso8601(self._snapshot_predicate["expires_at"])
        if current_time >= expires_at:
            return None
        return self._snapshot_predicate


class PrevalidatorEnforcer:
    """Evaluates OpenAI and Anthropic request payloads against the in-memory signed snapshot."""

    def __init__(
        self,
        snapshot_store: InMemorySnapshotStore,
        mode: str = "enforce",  # "enforce" | "observe"
        route_egress_map: dict[str, str] | None = None,
        default_egress_class: str = "public_api",
        caller_key_clearance_map: dict[str, str] | None = None,
        jwt_secret: str | None = None,
        enable_presidio_fallback: bool = True,
    ) -> None:
        if mode not in ("enforce", "observe"):
            raise ValueError("mode must be 'enforce' or 'observe'")
        self.snapshot_store = snapshot_store
        self.mode = mode
        self.route_egress_map = route_egress_map or {
            "local-model": "local_only",
            "ollama": "local_only",
            "vpc-model": "private_cloud",
            "gpt-4o": "public_api",
            "claude-3-5-sonnet": "public_api",
        }
        self.default_egress_class = default_egress_class
        self.caller_key_clearance_map = caller_key_clearance_map or {
            "pod-key-public": "Public",
            "pod-key-internal": "Internal",
            "pod-key-confidential": "Confidential",
            "pod-key-restricted": "Restricted",
        }
        self.jwt_secret = jwt_secret or "pod-local-jwt-secret-key-minimum-32-bytes-long"
        self.enable_presidio_fallback = enable_presidio_fallback
        self.classifier = PresidioClassifier()
        self.audit_log: list[AuditLogEntry] = []

    def resolve_caller_clearance(self, headers: dict[str, str]) -> str:
        """Resolve caller clearance from verified JWT or configured caller API key (defaults to 'Public')."""
        norm_headers = {k.lower(): v for k, v in headers.items()}

        # 1. Check signed JWT in X-POD-Caller-Token
        jwt_token = norm_headers.get("x-pod-caller-token")
        if jwt_token:
            try:
                decoded = jwt.decode(jwt_token, self.jwt_secret, algorithms=["HS256"])
                clearance = decoded.get("clearance", "Public")
                if clearance in CLEARANCE_ORDER:
                    return clearance
            except Exception:
                return "Public"

        # 2. Check configured caller key map in X-POD-Caller-Key
        caller_key = norm_headers.get("x-pod-caller-key")
        if caller_key and caller_key in self.caller_key_clearance_map:
            return self.caller_key_clearance_map[caller_key]

        return "Public"

    def resolve_target_egress(self, model_name: str | None, route_override: str | None = None) -> str:
        """Resolve destination egress class from configured route/model map."""
        if route_override and route_override in EGRESS_ORDER:
            return route_override
        if model_name:
            for prefix, egress in self.route_egress_map.items():
                if model_name == prefix or model_name.startswith(prefix):
                    return egress
        return self.default_egress_class

    def _evaluate_single_locator(
        self,
        locator: str,
        inline_sha256: str | None,
        entries: dict[str, Any],
        caller_clearance: str,
        target_egress: str,
        now_dt: datetime,
    ) -> tuple[str, str | None]:
        """Return `(action, reason_code)` where action is `'allow' | 'strip' | 'deny'`."""
        entry = entries.get(locator)
        if not entry:
            return "deny", "UNATTESTED"

        status = entry.get("status", "active")
        if status == "revoked":
            return "deny", "REVOKED"

        rec_exp = parse_iso8601(entry["record_expires_at"])
        if status == "expired" or now_dt >= rec_exp:
            return "deny", "EXPIRED"

        # If caller supplied an explicit SHA-256 on the block and it mismatches the attested fingerprint, treat as UNATTESTED
        if inline_sha256 and inline_sha256.lower() != entry["content_sha256"].lower():
            return "deny", "UNATTESTED"

        # Check caller clearance against record minimum_clearance
        req_clearance = entry["minimum_clearance"]
        if CLEARANCE_ORDER[caller_clearance] < CLEARANCE_ORDER[req_clearance]:
            return "deny", "INSUFFICIENT_CLEARANCE"

        # Check destination egress class against record egress_class
        allowed_egress = entry["egress_class"]
        if EGRESS_ORDER[target_egress] > EGRESS_ORDER[allowed_egress]:
            return "deny", "EGRESS_DENIED"

        # Check AI eligibility ('allow' | 'strip' | 'deny')
        ai_elig = entry["ai_eligibility"]
        if ai_elig == "deny":
            return "deny", "EGRESS_DENIED"
        if ai_elig == "strip":
            return "strip", None
        return "allow", None

    @staticmethod
    def _uniform_denial_response() -> dict[str, Any]:
        return {
            "error": {
                "message": UNIFORM_DENIAL_MESSAGE,
                "type": "pod_policy_denial",
                "code": UNIFORM_DENIAL_CODE,
            }
        }

    def evaluate_request(
        self,
        payload: dict[str, Any],
        headers: dict[str, str] | None = None,
        now: datetime | None = None,
    ) -> EnforcementOutcome:
        """Evaluate an OpenAI `/v1/chat/completions` or Anthropic `/v1/messages` request payload."""
        now_dt = now or datetime.now(timezone.utc)
        now_str = format_iso8601(now_dt)
        hdrs = headers or {}
        norm_hdrs = {k.lower(): v for k, v in hdrs.items()}

        caller_clearance = self.resolve_caller_clearance(hdrs)
        target_egress = self.resolve_target_egress(payload.get("model"))

        snapshot = self.snapshot_store.get_active_snapshot(now=now_dt)
        if snapshot is None:
            # Staleness or missing snapshot MUST fail closed
            audit = AuditLogEntry(
                timestamp=now_str,
                mode=self.mode,
                decision="deny",
                reason_codes=["EXPIRED"],
                locators_evaluated=[],
                caller_clearance=caller_clearance,
                target_egress=target_egress,
            )
            self.audit_log.append(audit)
            return EnforcementOutcome(
                allowed_to_forward=False,
                transformed_payload=payload,
                client_denial_body=self._uniform_denial_response(),
                audit_entry=audit,
            )

        entries = snapshot.get("entries", {})
        reason_codes: list[str] = []
        locators_seen: list[str] = []
        stripped_locators: list[str] = []

        # 1. Evaluate request-level header locators (`X-POD-Locators`: comma-separated locators)
        header_loc_str = norm_hdrs.get("x-pod-locators", "").strip()
        if header_loc_str:
            for raw_loc in [x.strip() for x in header_loc_str.split(",") if x.strip()]:
                locators_seen.append(raw_loc)
                action, r_code = self._evaluate_single_locator(
                    locator=raw_loc,
                    inline_sha256=None,
                    entries=entries,
                    caller_clearance=caller_clearance,
                    target_egress=target_egress,
                    now_dt=now_dt,
                )
                if action == "deny" and r_code:
                    reason_codes.append(r_code)
                elif action == "strip":
                    # Header-level locator has no inline block boundary to strip -> must deny whole request
                    reason_codes.append("EGRESS_DENIED")

        # 2. Evaluate and transform message texts (inline `<pod:object ...>` blocks + fallback Presidio scan)
        new_payload = json.loads(json.dumps(payload))

        def process_text(text: str) -> str:
            nonlocal reason_codes, locators_seen, stripped_locators

            # Track untagged segments outside <pod:object> blocks for fallback Presidio inspection
            untagged_parts: list[str] = []
            last_end = 0
            out_segments: list[str] = []

            for match in POD_OBJECT_TAG_RE.finditer(text):
                untagged_parts.append(text[last_end : match.start()])
                last_end = match.end()

                loc = match.group(1)
                sha = match.group(2)
                inner_content = match.group(3)
                locators_seen.append(loc)

                action, r_code = self._evaluate_single_locator(
                    locator=loc,
                    inline_sha256=sha,
                    entries=entries,
                    caller_clearance=caller_clearance,
                    target_egress=target_egress,
                    now_dt=now_dt,
                )
                if action == "deny":
                    if r_code:
                        reason_codes.append(r_code)
                    if self.mode == "observe":
                        out_segments.append(inner_content)
                elif action == "strip":
                    stripped_locators.append(loc)
                    if self.mode == "observe":
                        out_segments.append(inner_content)
                    else:
                        out_segments.append("[POD:STRIPPED]")
                else:
                    # Allowed -> unwrap <pod:object> tags and forward clean content
                    out_segments.append(inner_content)

            untagged_parts.append(text[last_end:])
            untagged_joined = " ".join(p for p in untagged_parts if p.strip())

            # Fallback content inspection (Presidio) ONLY on untagged free text carrying no object identity
            if self.enable_presidio_fallback and untagged_joined:
                findings = self.classifier.scan_text_segment(untagged_joined)
                restricted_hits = [f for f in findings if f.category in RESTRICTED_CATEGORIES]
                if restricted_hits:
                    reason_codes.append("UNATTESTED")

            # Reconstruct full text with transformed inline blocks
            if locators_seen:
                rebuilt: list[str] = []
                idx = 0
                seg_idx = 0
                for match in POD_OBJECT_TAG_RE.finditer(text):
                    rebuilt.append(text[idx : match.start()])
                    if seg_idx < len(out_segments):
                        rebuilt.append(out_segments[seg_idx])
                        seg_idx += 1
                    idx = match.end()
                rebuilt.append(text[idx:])
                return "".join(rebuilt).strip()
            return text

        # Transform top-level Anthropic `system` prompt if present
        if isinstance(new_payload.get("system"), str):
            new_payload["system"] = process_text(new_payload["system"])
        elif isinstance(new_payload.get("system"), list):
            for block in new_payload["system"]:
                if isinstance(block, dict) and isinstance(block.get("text"), str):
                    block["text"] = process_text(block["text"])

        # Transform `messages` array (OpenAI & Anthropic formats)
        for msg in new_payload.get("messages", []):
            content = msg.get("content")
            if isinstance(content, str):
                msg["content"] = process_text(content)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and isinstance(part.get("text"), str):
                        part["text"] = process_text(part["text"])

        # Deduplicate reason codes preserving discovery order
        unique_reasons = list(dict.fromkeys(reason_codes))

        if unique_reasons:
            if self.mode == "observe":
                audit = AuditLogEntry(
                    timestamp=now_str,
                    mode="observe",
                    decision="observe_would_deny",
                    reason_codes=unique_reasons,
                    locators_evaluated=locators_seen,
                    caller_clearance=caller_clearance,
                    target_egress=target_egress,
                    stripped_locators=stripped_locators,
                )
                self.audit_log.append(audit)
                return EnforcementOutcome(
                    allowed_to_forward=True,
                    transformed_payload=new_payload,
                    client_denial_body=None,
                    audit_entry=audit,
                )

            audit = AuditLogEntry(
                timestamp=now_str,
                mode="enforce",
                decision="deny",
                reason_codes=unique_reasons,
                locators_evaluated=locators_seen,
                caller_clearance=caller_clearance,
                target_egress=target_egress,
                stripped_locators=stripped_locators,
            )
            self.audit_log.append(audit)
            return EnforcementOutcome(
                allowed_to_forward=False,
                transformed_payload=new_payload,
                client_denial_body=self._uniform_denial_response(),
                audit_entry=audit,
            )

        decision_str = "strip" if stripped_locators else "allow"
        audit = AuditLogEntry(
            timestamp=now_str,
            mode=self.mode,
            decision=decision_str,
            reason_codes=[],
            locators_evaluated=locators_seen,
            caller_clearance=caller_clearance,
            target_egress=target_egress,
            stripped_locators=stripped_locators,
        )
        self.audit_log.append(audit)
        return EnforcementOutcome(
            allowed_to_forward=True,
            transformed_payload=new_payload,
            client_denial_body=None,
            audit_entry=audit,
        )
