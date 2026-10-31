<p align="center">
  <img src="prevalidator/g1_logo.png" alt="G1 Logo" width="110" />
</p>

# G1 Docket — by G1163RT Security Labs

**Cryptographic Data Attestation Framework & Zero-DB-Call AI Gateway Prevalidator (`v0.1`) — G1163RT Security Labs.**

AI gateways govern requests. Nothing attests the data those requests touch. **G1 Docket** closes that gap with three components and one open contract:

1. **The Attestation Engine (`engine/`)** — Discovers data where it lives (files, spreadsheets, databases via Apache Tika, OpenMetadata, and the **3-Stage Microsoft Purview & Multi-Cloud DLP Connector**), classifies it with Microsoft Presidio and embedded sensitivity labels (recording sensitive entity types and counts, never raw values), and issues a DSSE-signed in-toto v1 attestation record per object.
2. **The Registry (`registry/`)** — The authoritative catalog of signed records on PostgreSQL/SQLAlchemy, enforcing tier-based expiry (`Restricted`: 30d, `Confidential`: 90d, `Internal`: 180d, `Public`: 365d), human-review queues for `Restricted` and low-confidence findings, immediate tier elevation, dual-approval tier lowering, and re-classification on content hash drift.
3. **The Signed Snapshot Publisher (`snapshot/`) & Consumer Conformance Suite (`conformance/`)** — Publishes short-TTL, DSSE-signed snapshots with monotonic sequence numbers and active + `expired`/`revoked` tombstones so downstream consumers enforce policy in memory with zero Registry calls in the request path.
4. **The Prevalidator (`prevalidator/`)** — A fast proxy placed in front of any AI gateway speaking standard OpenAI (`/v1/chat/completions`) or Anthropic (`/v1/messages`) formats (including SSE streaming). It evaluates `<pod:object>` blocks and request headers against the in-memory snapshot to forward, strip, or refuse requests before the gateway sees them.

---

## Repository Layout

- `schemas/` — JSON Schemas (`attestation-predicate.schema.json`, `snapshot-predicate.schema.json`, `dsse-envelope.schema.json`) and `CHANGELOG.md`
- `engine/` — Discovery and classification pipelines (OpenMetadata connector, Apache Tika extractor, Microsoft Presidio classifier, OpenLineage intake)
- `registry/` — Registry service, lifecycle state machine, human-review queue, hardened FastAPI server, local DSSE/Sigstore signing toolkit, and `pod` CLI
- `snapshot/` — Signed Snapshot Publisher service and API
- `prevalidator/` — OpenAI & Anthropic Prevalidator proxy (Enforce & Observe modes)
- `conformance/` — Reference consumer simulator and Consumer Conformance Test Suite
- `examples/` — Phase 0 worked example, Golden Synthetic Sample Estate generator, LiteLLM gateway config, and reproducible end-to-end demo
- `docs/` — [Record Format Spec](docs/record-format.md), [Consumer Contract Spec](docs/consumer-contract.md), and [Security Review](docs/security-review.md)

---

## Quickstart (Local Evaluation & Demo)

### 1. Run the Reproducible End-to-End Demo (Phases 0–3)
```bash
python -m examples.run_demo
```
This executes:
- **Phase 0**: Attests a single synthetic clinical file end-to-end, verifies the DSSE signature, and confirms that tampered files and tampered envelopes fail verification.
- **Phase 1**: Generates the synthetic estate (documents, `.xlsx` spreadsheets, and database tables), crawls both paths, holds low-confidence findings in the review queue, and exercises `raise_tier`, dual-approved `lower_tier`, and `renew`.
- **Phase 2**: Publishes a DSSE-signed snapshot (`pod_snapshot.dsse.json`).
- **Phase 3**: Runs the Prevalidator proxy against OpenAI `/v1/chat/completions` and Anthropic `/v1/messages`, verifying allowed requests, inline Confidential block stripping (`[POD:STRIPPED]`), and uniform 403 refusal on `Restricted` and `Unattested` objects.

### 2. Run the Full Test & Conformance Suite
```bash
pytest -v
```

### 3. Exercise the `pod` CLI
```bash
# Generate or rotate local operator keys
python -m registry.cli keygen

# Attest a file, directory share, or database
python -m registry.cli attest ./examples/out_demo/estate/fileshare --owner security@example.org

# Look up a record by canonical locator
python -m registry.cli lookup "file://estate/fileshare/product_overview_public.md"

# Publish a signed snapshot for the Prevalidator
python -m registry.cli publish-snapshot --output ./pod_snapshot.dsse.json
```

---

## Docker Compose Profiles

Three Compose profiles are provided in `docker-compose.yml`:

```bash
# 1. Core profile: Engine, Registry, Snapshot Publisher, Postgres
docker compose --profile core up -d --build

# 2. Demo profile: Everything in core + Prevalidator + Local AI Gateway + automated synthetic estate bootstrap
docker compose --profile demo up -d --build
python -m examples.verify_docker_stack

# 3. Prevalidator profile: The proxy alone, deployed beside an existing AI gateway
docker compose --profile prevalidator up -d --build
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
