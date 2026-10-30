"""In-memory Snapshot Enforcer and `<pod:object>` tag parser/stripper for the Prevalidator."""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
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
from registry.signing import Keyring, normalize_canonical_text, verify_dsse_envelope

# Uniform denial message mandated by Phase 2 Consumer Conformance Suite (never leaks which rule fired)
UNIFORM_DENIAL_MESSAGE = "Request denied by data attestation policy."
UNIFORM_DENIAL_CODE = "policy_denied"

# Security reason codes
REASON_HASH_MISMATCH = "REASON_HASH_MISMATCH"
REASON_UNVERIFIED_INLINE_CONTENT = "REASON_UNVERIFIED_INLINE_CONTENT"
REASON_MALFORMED_POD_TAG = "REASON_MALFORMED_POD_TAG"
REASON_UNATTESTED_CONTEXT_OVERFLOW = "REASON_UNATTESTED_CONTEXT_OVERFLOW"

# Strict regexes for <pod:object> structural validation
POD_OPEN_TAG_STRICT_RE = re.compile(
    r'^<pod:object\s+locator="([^"<>]+)"(?:\s+sha256="([a-fA-F0-9]{64})")?\s*>$'
)
POD_CLOSE_TAG_STRICT_RE = re.compile(r"^</pod:object>$")
POD_ANY_TAG_TOKEN_RE = re.compile(r"<\s*/?\s*pod:object\b[^>]*>?|<\s*/?\s*pod:object", re.IGNORECASE)

# Regex matching balanced inline <pod:object locator="..." [sha256="..."]>...</pod:object> blocks
POD_OBJECT_TAG_RE = re.compile(
    r'<pod:object\s+locator="([^"<>]+)"(?:\s+sha256="([a-fA-F0-9]{64})")?\s*>(.*?)</pod:object>',
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
    decision_latency_ms: float = 0.0
    decision_latency_us: float = 0.0

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
            "decision_latency_ms": self.decision_latency_ms,
            "decision_latency_us": self.decision_latency_us,
        }


@dataclass
class EnforcementOutcome:
    """Result of evaluating an incoming LLM request against the in-memory snapshot."""

    allowed_to_forward: bool
    transformed_payload: dict[str, Any]
    client_denial_body: dict[str, Any] | None
    audit_entry: AuditLogEntry
    decision_latency_ms: float = 0.0
    decision_latency_us: float = 0.0


class InMemorySnapshotStore:
    """Holds the latest verified DSSE snapshot in memory, enforcing monotonic sequence numbers and TTL fail-closed."""

    def __init__(self, keyring: Keyring) -> None:
        self.keyring = keyring
        self._snapshot_predicate: dict[str, Any] | None = None
        self._highest_sequence: int = 0

    def load_from_envelope(self, envelope: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
        """Verify DSSE signature and sequence number before atomically updating the in-memory snapshot."""
        ver = self.keyring.verify_dsse(
            envelope=envelope,
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
        allow_header_only_objects: bool | None = None,
        strict_inline_hash: bool | None = None,
        max_untagged_chars: int | None = None,
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
        self.allow_header_only_objects = (
            allow_header_only_objects
            if allow_header_only_objects is not None
            else os.environ.get("POD_ALLOW_HEADER_ONLY_OBJECTS", "false").lower() in ("1", "true", "yes")
        )
        self.strict_inline_hash = (
            strict_inline_hash
            if strict_inline_hash is not None
            else os.environ.get("POD_STRICT_INLINE_HASH", "true").lower() in ("1", "true", "yes")
        )
        self.max_untagged_chars = (
            max_untagged_chars
            if max_untagged_chars is not None
            else int(os.environ.get("POD_MAX_UNTAGGED_CHARS", "2000"))
        )
        self.classifier = PresidioClassifier()
        self.audit_log: list[AuditLogEntry] = []
        self.latency_samples_ms: list[float] = []
        self.total_evaluations: int = 0
        self.last_directory_scan_metrics: dict[str, Any] = {
            "total_files": 0,
            "total_wall_ms": 0.0,
            "in_memory_enforcer_ms": 0.0,
            "avg_per_file_us": 0.0,
            "files_per_sec": 0.0,
        }

    def _record_latency_ns(self, elapsed_ns: int) -> tuple[float, float]:
        ms = round(max(elapsed_ns, 100) / 1_000_000.0, 4)
        us = round(max(elapsed_ns, 100) / 1_000.0, 2)
        self.total_evaluations += 1
        self.latency_samples_ms.append(ms)
        if len(self.latency_samples_ms) > 500:
            self.latency_samples_ms = self.latency_samples_ms[-500:]
        return ms, us

    def get_latency_telemetry(self) -> dict[str, Any]:
        """Return real-time sub-millisecond latency clock metrics for the Prevalidator."""
        samples = list(self.latency_samples_ms)
        if not samples:
            return {
                "last_decision_ms": 0.0,
                "last_decision_us": 0.0,
                "avg_ms": 0.0,
                "p50_ms": 0.0,
                "p95_ms": 0.0,
                "p99_ms": 0.0,
                "min_ms": 0.0,
                "max_ms": 0.0,
                "total_evaluations": self.total_evaluations,
                "sla_budget_ms": 5.0,
                "sla_compliant_pct": 100.0,
                "recent_samples_ms": [],
                "last_directory_scan": self.last_directory_scan_metrics,
            }
        sorted_s = sorted(samples)
        n = len(sorted_s)

        def _pct(p: float) -> float:
            idx = min(n - 1, max(0, int(round((p / 100.0) * (n - 1)))))
            return round(sorted_s[idx], 4)

        last_ms = samples[-1]
        compliant = sum(1 for x in samples if x <= 5.0)
        return {
            "last_decision_ms": round(last_ms, 4),
            "last_decision_us": round(last_ms * 1000.0, 2),
            "avg_ms": round(sum(samples) / n, 4),
            "p50_ms": _pct(50.0),
            "p95_ms": _pct(95.0),
            "p99_ms": _pct(99.0),
            "min_ms": round(sorted_s[0], 4),
            "max_ms": round(sorted_s[-1], 4),
            "total_evaluations": self.total_evaluations,
            "sla_budget_ms": 5.0,
            "sla_compliant_pct": round((compliant / n) * 100.0, 2),
            "recent_samples_ms": [round(x, 4) for x in samples[-24:]],
            "last_directory_scan": self.last_directory_scan_metrics,
        }

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

    @staticmethod
    def _validate_pod_tag_structure(text: str) -> tuple[bool, list[tuple[int, int, str, str | None, str]]]:
        """Strictly validate `<pod:object>` tag balance, syntax, and absence of nesting or early-close smuggling.

        Returns `(is_valid, parsed_blocks)` where each block is `(start, end, locator, sha256, inner_text)`.
        """
        tokens = list(POD_ANY_TAG_TOKEN_RE.finditer(text))
        if not tokens:
            return True, []

        blocks: list[tuple[int, int, str, str | None, str]] = []
        open_token: tuple[int, int, str, str | None] | None = None

        for tok in tokens:
            raw_tok = tok.group(0)
            if raw_tok.lower().startswith("</") or re.match(r"^<\s*/", raw_tok):
                # Closing tag
                if not POD_CLOSE_TAG_STRICT_RE.match(raw_tok):
                    return False, []
                if open_token is None:
                    # Early or orphan closing tag
                    return False, []
                o_start, o_end, loc, sha = open_token
                inner_text = text[o_end : tok.start()]
                # Ensure no nested or partial pod:object markers inside inner_text
                if "pod:object" in inner_text.lower():
                    return False, []
                blocks.append((o_start, tok.end(), loc, sha, inner_text))
                open_token = None
            else:
                # Opening tag
                if open_token is not None:
                    # Nested or unclosed previous opening tag
                    return False, []
                m = POD_OPEN_TAG_STRICT_RE.match(raw_tok)
                if not m:
                    return False, []
                open_token = (tok.start(), tok.end(), m.group(1), m.group(2))

        if open_token is not None:
            # Unclosed opening tag at end of text
            return False, []

        return True, blocks

    @staticmethod
    def _verify_inner_text_cryptographically(
        inner_text: str,
        inline_sha256: str | None,
        entry: dict[str, Any],
    ) -> bool:
        """Verify live SHA-256 of `inner_text` against `content_sha256`, `extracted_text_sha256`, or `chunk_hashes`."""
        raw_inner_sha256 = hashlib.sha256(inner_text.encode("utf-8")).hexdigest()
        norm_inner_sha256 = hashlib.sha256(normalize_canonical_text(inner_text)).hexdigest()

        # Never trust a caller-supplied sha256 attribute that contradicts the live digest of inner_text
        if inline_sha256 is not None:
            supplied = inline_sha256.lower()
            if supplied not in (raw_inner_sha256, norm_inner_sha256):
                return False

        att_content_sha = (entry.get("content_sha256") or "").lower()
        att_text_sha = (entry.get("extracted_text_sha256") or "").lower()
        att_chunks = {h.lower() for h in (entry.get("chunk_hashes") or [])}

        # 1. Whole-object content_sha256 match
        if raw_inner_sha256 == att_content_sha or norm_inner_sha256 == att_content_sha:
            return True

        # 2. Full normalized extracted_text_sha256 match
        if att_text_sha and (norm_inner_sha256 == att_text_sha or raw_inner_sha256 == att_text_sha):
            return True

        # 3. Deterministic chunk_hashes match
        if norm_inner_sha256 in att_chunks or raw_inner_sha256 in att_chunks:
            return True

        # 4. Multi-paragraph / multi-line composition strictly from attested chunk_hashes
        if att_chunks and "\n" in inner_text:
            sub_lines = [ln.strip() for ln in inner_text.splitlines() if ln.strip()]
            if sub_lines and all(
                hashlib.sha256(normalize_canonical_text(ln)).hexdigest() in att_chunks
                for ln in sub_lines
            ):
                return True

        return False

    def _evaluate_single_locator(
        self,
        locator: str,
        inline_sha256: str | None,
        entries: dict[str, Any],
        caller_clearance: str,
        target_egress: str,
        now_dt: datetime,
        inner_text: str | None = None,
    ) -> tuple[str, list[str]]:
        """Return `(action, reason_codes)` where action is `'allow' | 'strip' | 'deny'`."""
        entry = entries.get(locator)
        if not entry:
            return "deny", ["UNATTESTED"]

        status = entry.get("status", "active")
        if status == "revoked":
            return "deny", ["REVOKED"]

        rec_exp = parse_iso8601(entry["record_expires_at"])
        if status == "expired" or now_dt >= rec_exp:
            return "deny", ["EXPIRED"]

        # Live cryptographic verification of inline <pod:object> content
        if inner_text is not None and self.strict_inline_hash:
            if not self._verify_inner_text_cryptographically(inner_text, inline_sha256, entry):
                return "deny", [REASON_HASH_MISMATCH, "HASH_DRIFT"]
        elif inline_sha256 and inline_sha256.lower() != entry["content_sha256"].lower():
            return "deny", [REASON_HASH_MISMATCH, "HASH_DRIFT"]

        # Check caller clearance against record minimum_clearance
        req_clearance = entry["minimum_clearance"]
        if CLEARANCE_ORDER[caller_clearance] < CLEARANCE_ORDER[req_clearance]:
            return "deny", ["INSUFFICIENT_CLEARANCE"]

        # Check destination egress class against record egress_class
        allowed_egress = entry["egress_class"]
        if EGRESS_ORDER[target_egress] > EGRESS_ORDER[allowed_egress]:
            return "deny", ["EGRESS_DENIED"]

        # Check AI eligibility ('allow' | 'strip' | 'deny')
        ai_elig = entry["ai_eligibility"]
        if ai_elig == "deny":
            return "deny", ["EGRESS_DENIED"]
        if ai_elig == "strip":
            return "strip", []
        return "allow", []

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
        t0_ns = time.perf_counter_ns()
        now_dt = now or datetime.now(timezone.utc)
        now_str = format_iso8601(now_dt)
        hdrs = headers or {}
        norm_hdrs = {k.lower(): v for k, v in hdrs.items()}

        caller_clearance = self.resolve_caller_clearance(hdrs)
        target_egress = self.resolve_target_egress(payload.get("model"))

        snapshot = self.snapshot_store.get_active_snapshot(now=now_dt)
        if snapshot is None:
            # Staleness or missing snapshot MUST fail closed
            lat_ms, lat_us = self._record_latency_ns(time.perf_counter_ns() - t0_ns)
            audit = AuditLogEntry(
                timestamp=now_str,
                mode=self.mode,
                decision="deny",
                reason_codes=["EXPIRED"],
                locators_evaluated=[],
                caller_clearance=caller_clearance,
                target_egress=target_egress,
                decision_latency_ms=lat_ms,
                decision_latency_us=lat_us,
            )
            self.audit_log.append(audit)
            return EnforcementOutcome(
                allowed_to_forward=False,
                transformed_payload=payload,
                client_denial_body=self._uniform_denial_response(),
                audit_entry=audit,
                decision_latency_ms=lat_ms,
                decision_latency_us=lat_us,
            )

        entries = snapshot.get("entries", {})
        reason_codes: list[str] = []
        locators_seen: list[str] = []
        inline_verified_locators: set[str] = set()
        stripped_locators: list[str] = []
        total_untagged_chars = 0
        has_inline_pod_tags = False

        # 1. Evaluate and transform message texts (strict `<pod:object>` parser + live inner-text SHA-256 + fallback Presidio)
        new_payload = json.loads(json.dumps(payload))

        def process_text(text: str) -> str:
            nonlocal reason_codes, locators_seen, stripped_locators, total_untagged_chars, has_inline_pod_tags

            is_valid_structure, parsed_blocks = self._validate_pod_tag_structure(text)
            if not is_valid_structure:
                reason_codes.append(REASON_MALFORMED_POD_TAG)
                return text

            if parsed_blocks:
                has_inline_pod_tags = True

            untagged_parts: list[str] = []
            last_end = 0
            out_segments: list[str] = []

            for start_idx, end_idx, loc, sha, inner_content in parsed_blocks:
                untagged_seg = text[last_end:start_idx]
                untagged_parts.append(untagged_seg)
                last_end = end_idx

                locators_seen.append(loc)
                inline_verified_locators.add(loc)

                action, r_codes = self._evaluate_single_locator(
                    locator=loc,
                    inline_sha256=sha,
                    entries=entries,
                    caller_clearance=caller_clearance,
                    target_egress=target_egress,
                    now_dt=now_dt,
                    inner_text=inner_content,
                )
                if action == "deny":
                    reason_codes.extend(r_codes)
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

            tail_seg = text[last_end:]
            untagged_parts.append(tail_seg)
            for p in untagged_parts:
                total_untagged_chars += len(p.strip())
            untagged_joined = " ".join(p for p in untagged_parts if p.strip())

            # Fallback content inspection (Presidio) ONLY on untagged free text carrying no object identity
            if self.enable_presidio_fallback and untagged_joined:
                findings = self.classifier.scan_text_segment(untagged_joined)
                restricted_hits = [f for f in findings if f.category in RESTRICTED_CATEGORIES]
                if restricted_hits:
                    reason_codes.append("UNATTESTED")

            # Reconstruct full text with transformed inline blocks
            if parsed_blocks:
                rebuilt: list[str] = []
                idx = 0
                seg_idx = 0
                for start_idx, end_idx, _loc, _sha, _inner in parsed_blocks:
                    rebuilt.append(text[idx:start_idx])
                    if seg_idx < len(out_segments):
                        rebuilt.append(out_segments[seg_idx])
                        seg_idx += 1
                    idx = end_idx
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

        # 2. Enforce Untagged Context Quota when <pod:object> tags or X-POD-Require-Attested-Context: true are present
        require_attested_ctx = norm_hdrs.get("x-pod-require-attested-context", "").lower() in ("1", "true", "yes")
        if (has_inline_pod_tags or require_attested_ctx) and total_untagged_chars > self.max_untagged_chars:
            reason_codes.append(REASON_UNATTESTED_CONTEXT_OVERFLOW)

        # 3. Evaluate request-level header locators (`X-POD-Locators` or `X-POD-Objects`)
        header_loc_str = ",".join(
            s for s in (norm_hdrs.get("x-pod-locators", "").strip(), norm_hdrs.get("x-pod-objects", "").strip()) if s
        )
        if header_loc_str:
            for raw_loc in [x.strip() for x in header_loc_str.split(",") if x.strip()]:
                if raw_loc not in locators_seen:
                    locators_seen.append(raw_loc)
                if self.strict_inline_hash and not self.allow_header_only_objects and raw_loc not in inline_verified_locators:
                    reason_codes.append(REASON_UNVERIFIED_INLINE_CONTENT)
                    continue
                action, r_codes = self._evaluate_single_locator(
                    locator=raw_loc,
                    inline_sha256=None,
                    entries=entries,
                    caller_clearance=caller_clearance,
                    target_egress=target_egress,
                    now_dt=now_dt,
                    inner_text=None,
                )
                if action == "deny":
                    reason_codes.extend(r_codes)
                elif action == "strip":
                    # Header-level locator has no inline block boundary to strip -> must deny whole request
                    reason_codes.append("EGRESS_DENIED")

        # Deduplicate reason codes preserving discovery order
        unique_reasons = list(dict.fromkeys(reason_codes))

        if unique_reasons:
            lat_ms, lat_us = self._record_latency_ns(time.perf_counter_ns() - t0_ns)
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
                    decision_latency_ms=lat_ms,
                    decision_latency_us=lat_us,
                )
                self.audit_log.append(audit)
                return EnforcementOutcome(
                    allowed_to_forward=True,
                    transformed_payload=new_payload,
                    client_denial_body=None,
                    audit_entry=audit,
                    decision_latency_ms=lat_ms,
                    decision_latency_us=lat_us,
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
                decision_latency_ms=lat_ms,
                decision_latency_us=lat_us,
            )
            self.audit_log.append(audit)
            return EnforcementOutcome(
                allowed_to_forward=False,
                transformed_payload=new_payload,
                client_denial_body=self._uniform_denial_response(),
                audit_entry=audit,
                decision_latency_ms=lat_ms,
                decision_latency_us=lat_us,
            )

        lat_ms, lat_us = self._record_latency_ns(time.perf_counter_ns() - t0_ns)
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
            decision_latency_ms=lat_ms,
            decision_latency_us=lat_us,
        )
        self.audit_log.append(audit)
        return EnforcementOutcome(
            allowed_to_forward=True,
            transformed_payload=new_payload,
            client_denial_body=None,
            audit_entry=audit,
            decision_latency_ms=lat_ms,
            decision_latency_us=lat_us,
        )
