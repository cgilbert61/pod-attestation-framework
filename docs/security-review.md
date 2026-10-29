# Phase 4 Security Review & Threat Model Audit

Because the Registry is a map of an operator's sensitive data holdings, its access controls, key handling, and enforcement boundaries enforce the following security invariants:

## 1. Registry Access Control
- Every Registry lookup and lifecycle mutation endpoint (`/v1/records/*`, `/v1/reviews/*`) requires administrative authentication via `X-POD-Admin-Key` or `Authorization: Bearer <token>`.
- Classification findings stored in the Registry and signed into predicates contain **only entity category names and integer counts** (`category`, `count`, `max_confidence`, `column_or_field`) — never raw PII, secrets, or cell values. Schema validation (`validate_attestation_predicate`) actively rejects any finding entry containing `value`, `raw`, or `sample` keys.

## 2. Cryptographic Key Handling & Rotation
- Operator signing keys live strictly in mounted host/volume directories (`/var/lib/pod/keys`), never baked into container images.
- The Prevalidator mounts the keyring and snapshot directories read-only (`:ro`) and never needs access to private signing keys in production (only public verification keys in `keyring.json`).
- Key rotation (`pod keygen --rotate`) transitions the prior active key to `rotated` with a `rotated_at` timestamp. Verification (`verify_dsse_envelope`) honors records signed by a rotated key only if `issued_at <= rotated_at`, preventing backdated forgery with retired keys.
- Key revocation (`keyring.revoke_key(keyid)`) immediately invalidates all records and snapshots signed by that key.

## 3. Fail-Closed Enforcement & Anti-Oracle Design
- **Zero-DB Request Path**: The Prevalidator never queries the Registry database during LLM request processing, eliminating database DoS amplification and keeping enforcement overhead sub-millisecond.
- **Staleness & Rollback Protection**: Every snapshot carries a short `expires_at` TTL and a monotonically increasing `sequence_number`. If the snapshot expires or a replay attack attempts to load an older `sequence_number`, the Prevalidator fails closed.
- **Anti-Oracle Uniform Denials**: All client-facing 403 refusal responses return an identical error payload (`policy_denied`) so an attacker probing locators cannot distinguish whether an object is `Restricted`, `Revoked`, `Expired`, or `Unattested`.
