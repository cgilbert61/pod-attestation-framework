"""Reference Consumer Simulator implementing the POD Consumer Contract from public specifications."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from prevalidator.enforcer import (
    UNIFORM_DENIAL_CODE,
    UNIFORM_DENIAL_MESSAGE,
    InMemorySnapshotStore,
    PrevalidatorEnforcer,
)
from registry.signing import Keyring


@dataclass
class ConsumerDecision:
    """Standardized decision output from any compliant POD enforcement consumer."""

    allowed: bool
    status_code: int
    response_body: dict[str, Any]
    internal_reason_codes: list[str]
    transformed_payload: dict[str, Any]


class ReferenceConsumerSimulator:
    """Reference consumer simulator tested by the Conformance Suite."""

    def __init__(self, keyring: Keyring, mode: str = "enforce") -> None:
        self.snapshot_store = InMemorySnapshotStore(keyring)
        self.enforcer = PrevalidatorEnforcer(snapshot_store=self.snapshot_store, mode=mode)

    def load_snapshot(self, envelope: dict[str, Any], now: datetime | None = None) -> None:
        self.snapshot_store.load_from_envelope(envelope, now=now)

    def check_request(
        self,
        payload: dict[str, Any],
        headers: dict[str, str] | None = None,
        now: datetime | None = None,
    ) -> ConsumerDecision:
        outcome = self.enforcer.evaluate_request(payload=payload, headers=headers, now=now)
        if not outcome.allowed_to_forward:
            return ConsumerDecision(
                allowed=False,
                status_code=403,
                response_body=outcome.client_denial_body
                or {
                    "error": {
                        "message": UNIFORM_DENIAL_MESSAGE,
                        "type": "pod_policy_denial",
                        "code": UNIFORM_DENIAL_CODE,
                    }
                },
                internal_reason_codes=outcome.audit_entry.reason_codes,
                transformed_payload=outcome.transformed_payload,
            )

        return ConsumerDecision(
            allowed=True,
            status_code=200,
            response_body={"status": "forwarded"},
            internal_reason_codes=outcome.audit_entry.reason_codes,
            transformed_payload=outcome.transformed_payload,
        )
