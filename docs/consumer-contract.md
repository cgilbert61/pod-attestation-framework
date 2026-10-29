# POD Consumer Contract Specification (v0.1)

This specification defines how any enforcement consumer (including the POD Prevalidator or a third-party AI gateway plugin) verifies and enforces POD snapshots without reading the Attestation Engine's code or querying the Registry database in the request path.

---

## 1. Snapshot Format (`https://schemas.proofofdata.dev/snapshot/v0.1`)

Consumers ingest signed point-in-time snapshots validated against `schemas/snapshot-predicate.schema.json` and wrapped in a DSSE v1 envelope (`schemas/dsse-envelope.schema.json`).

### Required Snapshot Verification Steps
When loading a snapshot, a compliant consumer MUST:
1. Verify the outer DSSE signature over the `DSSEv1` PAE using the operator's local keyring (`keyring.json`).
2. Verify that the signing key is not `revoked`, and if `rotated`, that `predicate.issued_at` falls within the key's active window.
3. Verify `statement.predicateType == "https://schemas.proofofdata.dev/snapshot/v0.1"`.
4. Verify `predicate.sequence_number >= current_highest_sequence_number` (rejecting any rollback/replay of an older snapshot).
5. Verify `now < predicate.expires_at`.

### Active Entries & Tombstones
To allow consumers to distinguish `UNATTESTED`, `EXPIRED`, and `REVOKED` states using in-memory lookups alone, `predicate.entries` maps each canonical `locator` URI to:
- `status`: `"active"` | `"expired"` | `"revoked"`
- `content_sha256`: 64-character hex SHA-256 digest
- `tier`: `"Public"` | `"Internal"` | `"Confidential"` | `"Restricted"`
- `ai_eligibility`: `"allow"` | `"strip"` | `"deny"`
- `minimum_clearance`: `"Public"` | `"Internal"` | `"Confidential"` | `"Restricted"`
- `egress_class`: `"local_only"` | `"private_cloud"` | `"public_api"`
- `record_expires_at`: ISO-8601 UTC timestamp

---

## 2. Request Binding Protocol

Callers bind LLM context segments to attested objects in two ways:

1. **Inline `<pod:object>` Content Blocks** (supports `allow`, `strip`, and `deny`):
   ```xml
   <pod:object locator="file://estate/fileshare/product_overview_public.md" sha256="e3b0c442...">
   Document text or RAG chunk content...
   </pod:object>
   ```
   - On `allow`: the consumer strips the `<pod:object ...>` and `</pod:object>` wrapper tags and forwards the inner content cleanly.
   - On `strip`: the consumer replaces the entire `<pod:object>...</pod:object>` block with `[POD:STRIPPED]` and forwards the remainder of the request.
   - On `deny`: the consumer refuses the request.

2. **Request-Level Header (`X-POD-Locators`)**:
   - Comma-separated canonical locators referenced by the request. Because header-level references lack inline boundaries, both `strip` and `deny` policies result in request refusal.

---

## 3. Enforcement Rules & Reason Codes

For every referenced locator, the consumer evaluates rules in the following order:

1. **Snapshot Staleness**: If no valid snapshot is loaded or `now >= snapshot.expires_at`, **fail closed** (refuse request).
2. **`UNATTESTED`**: Locator is absent from `snapshot.entries`, or the inline `sha256` attribute does not match `entry.content_sha256`, or fallback Presidio inspection detects untagged `Restricted` entities.
3. **`REVOKED`**: `entry.status == "revoked"`.
4. **`EXPIRED`**: `entry.status == "expired"` or `now >= entry.record_expires_at`.
5. **`INSUFFICIENT_CLEARANCE`**: Caller's verified clearance is lower than `entry.minimum_clearance`.
6. **`EGRESS_DENIED`**: Target gateway/model route `egress_class` exceeds `entry.egress_class`, or `entry.ai_eligibility == "deny"`.

---

## 4. Uniform Denial Response Requirement

In **Enforce Mode**, whenever a request is refused for *any* reason above, the consumer MUST return HTTP `403 Forbidden` with the exact uniform JSON body below, never leaking which rule fired or the classification tier of the object:

```json
{
  "error": {
    "message": "Request denied by data attestation policy.",
    "type": "pod_policy_denial",
    "code": "policy_denied"
  }
}
```

Specific reason codes (`UNATTESTED`, `EXPIRED`, `REVOKED`, `INSUFFICIENT_CLEARANCE`, `EGRESS_DENIED`) are written exclusively to the operator's internal audit log.
