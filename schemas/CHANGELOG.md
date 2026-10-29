# Schema Version History

## v0.1.0 (Phase 0 Freeze)
- **`attestation-predicate.schema.json`** (`https://schemas.proofofdata.dev/attestation/v0.1`):
  - Ratified Phase 0 schema decisions:
    1. Cryptographic signatures live strictly in the outer DSSE envelope (`signatures[]`), never inside the predicate.
    2. Predicate-type URI anchored under `https://schemas.proofofdata.dev/attestation/v0.1`.
    3. Named clearance levels (`Public`, `Internal`, `Confidential`, `Restricted`) aligned 1:1 with the four classification tiers.
    4. Seven field groups (`identity`, `ownership`, `provenance`, `integrity`, `classification`, `handling`, `lifecycle`) with seven mandatory fields (`identity.locator`, `ownership.owner`, `provenance.attested_by`, `integrity.content_sha256`, `classification.tier`, `handling.policy`, `lifecycle.expires_at`).
    5. Tier-bounded maximum TTLs enforced (`Restricted`: 30 days, `Confidential`: 90 days, `Internal`: 180 days, `Public`: 365 days).
- **`snapshot-predicate.schema.json`** (`https://schemas.proofofdata.dev/snapshot/v0.1`):
  - Short-TTL DSSE-signed snapshot carrying monotonic `sequence_number` and active + `expired`/`revoked` tombstones for zero-DB request-path enforcement.
- **`dsse-envelope.schema.json`** (`https://schemas.proofofdata.dev/dsse-envelope/v0.1`):
  - Standard DSSE v1 envelope (`application/vnd.in-toto+json`) with Sigstore v0.3 local verification material metadata.
