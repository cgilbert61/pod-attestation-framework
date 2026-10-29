# POD Record Format Specification (v0.1)

## 1. Envelope & Statement Structure

Every POD attestation record is an [in-toto Attestation Framework v1.0 Statement](https://github.com/in-toto/attestation) serialized as canonical UTF-8 JSON and signed inside a [Dead Simple Signing Envelope (DSSE v1)](https://github.com/secure-systems-lab/dsse).

- **Outer Envelope Schema**: `schemas/dsse-envelope.schema.json` (`https://schemas.proofofdata.dev/dsse-envelope/v0.1`)
- **Payload Type**: `application/vnd.in-toto+json`
- **in-toto `_type`**: `https://in-toto.io/Statement/v1`
- **Predicate Type URI**: `https://schemas.proofofdata.dev/attestation/v0.1`
- **Predicate Schema**: `schemas/attestation-predicate.schema.json`

### Key Invariant: Signature Outside the Predicate
Cryptographic signatures MUST reside exclusively in the outer DSSE `signatures[]` array (computed over the `DSSEv1` Pre-Authentication Encoding of `payloadType` and `payload`). Any predicate containing a `signature` or `signatures` field is rejected by schema validation.

### DSSE Pre-Authentication Encoding (PAE)
```text
DSSEv1 <byte_length(payloadType)> <payloadType> <byte_length(payload_bytes)> <payload_bytes>
```

---

## 2. The Seven Field Groups & Seven Mandatory Fields

An object missing any of the **seven mandatory fields** does not receive a record, and without a valid record it is treated as nonexistent (`UNATTESTED`) by every consumer.

| Group | Mandatory Field | Additional Fields in Group |
| :--- | :--- | :--- |
| **1. `identity`** | `identity.locator` | `record_id`, `object_type`, `display_name`, `environment` |
| **2. `ownership`** | `ownership.owner` | `steward`, `org_unit`, `jurisdiction` |
| **3. `provenance`** | `provenance.attested_by` | `source_system`, `scanner_version`, `discovered_at`, `derived_from` |
| **4. `integrity`** | `integrity.content_sha256` | `schema_sha256`, `size_bytes`, `row_count`, `fingerprint_method` |
| **5. `classification`** | `classification.tier` | `confidence`, `sensitive_categories` (`category`, `count`, `max_confidence`, `column_or_field`), `classifier_engine` |
| **6. `handling`** | `handling.policy` (`ai_eligibility`, `minimum_clearance`, `egress_class`) | `allow_rag_indexing`, `allow_model_training`, `redaction_categories` |
| **7. `lifecycle`** | `lifecycle.expires_at` | `status`, `issued_at`, `ttl_days`, `previous_record_id`, `revoked_at`, `revocation_reason`, `tier_lower_approvals` |

> **Privacy Invariant**: `classification.sensitive_categories` records entity types and occurrence counts only — **never raw values or samples**.

---

## 3. Classification Tiers, Minimum Clearance, and Maximum TTLs

Eligibility is rented, never owned. Every record carries an `expires_at` timestamp bounded by its classification tier:

| Tier | Max TTL | Default `minimum_clearance` | Default `egress_class` | Default `ai_eligibility` |
| :--- | :--- | :--- | :--- | :--- |
| **Restricted** | **30 days** | `Restricted` | `local_only` | `deny` |
| **Confidential** | **90 days** | `Confidential` | `local_only` | `strip` |
| **Internal** | **180 days** | `Internal` | `private_cloud` | `allow` |
| **Public** | **365 days** | `Public` | `public_api` | `allow` |

---

## 4. Load-Bearing Lifecycle Asymmetries

1. **Raising a tier is free and immediate**: Any authorized operator or upstream lineage change can elevate an object's tier immediately, issuing a new signed record (`status: "tier_raised"`).
2. **Lowering a tier requires dual approval**: Lowering a record's tier requires at least **two distinct `approver_id` principals** recorded in `lifecycle.tier_lower_approvals` (`status: "tier_lowered"`).
3. **Changed content fingerprint triggers re-classification, not a re-stamp**: Renewing a record (`status: "renewed"`) is permitted only when the observed `content_sha256` matches the attested `content_sha256`. If the hash changes, renewal fails with `FingerprintChangedError` and the object must be re-classified.
4. **Database table fingerprinting**: Database tables are attested at the `postgres://host:port/db/schema/table` level with column-level findings inside `classification.sensitive_categories` and a deterministic `content_sha256` computed over the canonical column schema DDL digest plus sorted canonical row digests.
