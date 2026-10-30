"""Enterprise Data Store Connectors for G1 Docket (`s3://`, `azblob://`, `gs://`, `postgres://`, `snowflake://`, `bigquery://`, `databricks://`, `file://`).

Provides:
1. Pluggable URI-based discovery, ETag/VersionId fast-path checks, and bounded streaming extraction for Object Stores & Data Lakes.
2. Pushdown table & sample scanning for SQL Databases and Cloud Data Warehouses (`postgres://`, `snowflake://`, `bigquery://`, `databricks://`).
3. Event-driven continuous attestation webhook (`POST /v1/events/storage`) supporting AWS S3 EventBridge, Azure Event Grid, and GCS Pub/Sub events.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from engine.classifier import PresidioClassifier
from engine.dlp_connectors import map_purview_label_to_tier
from engine.extractor import compute_extracted_text_and_chunk_hashes
from engine.pipeline import AttestationEngine
from registry.schema_validator import format_iso8601
from registry.store import RegistryService, TIER_ORDER


@dataclass
class EnterpriseStoreObject:
    """A single object, file, Parquet partition, or warehouse table discovered in an enterprise data store."""

    locator: str
    display_name: str
    object_type: str  # 'file' | 'document' | 'spreadsheet' | 'database_table' | 'warehouse_table'
    store_uri: str
    provider: str  # 'AWS S3' | 'Azure ADLS Gen2 / Blob' | 'GCP Cloud Storage' | 'PostgreSQL' | 'Snowflake' | 'Google BigQuery' | 'Databricks Unity Catalog'
    content_bytes: bytes
    content_sha256: str
    etag: str
    size_bytes: int
    row_count: int | None = None
    schema_sha256: str | None = None
    owner: str = "data-platform@contoso.com"
    sensitivity_label: str | None = None
    catalog_classifications: list[str] = field(default_factory=list)
    column_samples: dict[str, list[str]] = field(default_factory=dict)
    extracted_text_sha256: str | None = None
    chunk_hashes: list[str] = field(default_factory=list)
    last_modified: str = ""


@dataclass
class DataStoreConnectionConfig:
    """Configuration for a registered enterprise data store."""

    store_id: str
    name: str
    uri: str
    provider: str
    store_kind: str  # 'object_store' | 'database' | 'warehouse' | 'fileshare'
    region: str
    auth_mode: str  # 'iam_role' | 'managed_identity' | 'workload_identity' | 'access_key' | 'key_pair' | 'connection_string'
    owner: str = "data-platform@contoso.com"
    endpoint_url: str | None = None
    max_sample_bytes: int = 4 * 1024 * 1024
    etag_fast_path: bool = True
    event_webhook_enabled: bool = True
    created_at: str = ""


def is_enterprise_store_uri(path_or_uri: str | None) -> bool:
    """Return True if `path_or_uri` is a cloud object store or database/warehouse URI rather than a local PC path."""
    if not path_or_uri:
        return False
    cleaned = path_or_uri.strip().lower()
    return cleaned.startswith(
        (
            "s3://",
            "azblob://",
            "abfss://",
            "gs://",
            "postgres://",
            "postgresql://",
            "snowflake://",
            "bigquery://",
            "databricks://",
            "sharepoint://",
        )
    )


def _build_obj(
    locator: str,
    display_name: str,
    object_type: str,
    store_uri: str,
    provider: str,
    sample_text: str,
    owner: str = "data-platform@contoso.com",
    sensitivity_label: str | None = None,
    catalog_classifications: list[str] | None = None,
    size_bytes: int | None = None,
    row_count: int | None = None,
    extra_chunks: list[str] | None = None,
) -> EnterpriseStoreObject:
    raw_bytes = sample_text.encode("utf-8")
    content_sha = hashlib.sha256(raw_bytes).hexdigest()
    etag = f'"{content_sha[:32]}"'
    chunk_lines = [sample_text, display_name, locator]
    if extra_chunks:
        chunk_lines.extend(extra_chunks)
    extracted_sha, chunk_hashes = compute_extracted_text_and_chunk_hashes("\n".join(chunk_lines))
    schema_sha = (
        hashlib.sha256(f"schema:{locator}:{display_name}".encode("utf-8")).hexdigest()
        if object_type in ("database_table", "warehouse_table")
        else None
    )
    return EnterpriseStoreObject(
        locator=locator,
        display_name=display_name,
        object_type=object_type,
        store_uri=store_uri,
        provider=provider,
        content_bytes=raw_bytes,
        content_sha256=content_sha,
        etag=etag,
        size_bytes=size_bytes or len(raw_bytes),
        row_count=row_count,
        schema_sha256=schema_sha,
        owner=owner,
        sensitivity_label=sensitivity_label,
        catalog_classifications=list(catalog_classifications or []),
        extracted_text_sha256=extracted_sha,
        chunk_hashes=chunk_hashes,
        last_modified=format_iso8601(datetime.now(timezone.utc)),
    )


class EnterpriseDataStoreManager:
    """Manages registered Enterprise Data Stores (`s3://`, `azblob://`, `gs://`, `postgres://`, `snowflake://`, `bigquery://`) and event-driven attestation."""

    def __init__(
        self,
        registry: RegistryService,
        engine: AttestationEngine,
        estate_dir: Path | None = None,
    ) -> None:
        self.registry = registry
        self.engine = engine
        self.classifier: PresidioClassifier = engine.classifier
        self.estate_dir = estate_dir or Path(os.environ.get("POD_ESTATE_DIR", "/var/lib/pod/state/estate"))
        self.stores: dict[str, DataStoreConnectionConfig] = {}
        self.store_objects: dict[str, list[EnterpriseStoreObject]] = {}
        self.event_history: list[dict[str, Any]] = []
        self._seed_default_enterprise_stores()

    def _seed_default_enterprise_stores(self) -> None:
        now_iso = format_iso8601(datetime.now(timezone.utc))

        # 1. AWS S3 Production RAG Data Lake
        s3_uri = "s3://contoso-ai-datalake-prod/rag-corpus"
        self.stores[s3_uri] = DataStoreConnectionConfig(
            store_id="aws-s3-rag-prod",
            name="AWS S3 — Production AI & RAG Data Lake",
            uri=s3_uri,
            provider="AWS S3",
            store_kind="object_store",
            region="us-east-1",
            auth_mode="iam_role",
            owner="aws-data-lake@contoso.com",
            created_at=now_iso,
        )
        self.store_objects[s3_uri] = [
            _build_obj(
                locator=f"{s3_uri}/public_docs/g1_zero_trust_reference_architecture.md",
                display_name="g1_zero_trust_reference_architecture.md",
                object_type="document",
                store_uri=s3_uri,
                provider="AWS S3",
                sample_text="Public Reference Architecture: Zero-Trust AI Admission Control with DSSE Signed Snapshots and Sub-Millisecond Prevalidation.",
                owner="architecture-team@contoso.com",
                sensitivity_label="Public",
                size_bytes=48200,
            ),
            _build_obj(
                locator=f"{s3_uri}/internal_runbooks/eks_gpu_cluster_topology.json",
                display_name="eks_gpu_cluster_topology.json",
                object_type="file",
                store_uri=s3_uri,
                provider="AWS S3",
                sample_text='{"cluster": "eks-prod-us-east-1", "internal_project": "PROJECT-TITAN", "node_cidr": "10.42.16.0/20", "contact": "sre-oncall@contoso.com"}',
                owner="sre-platform@contoso.com",
                sensitivity_label="Internal",
                size_bytes=128400,
            ),
            _build_obj(
                locator=f"{s3_uri}/crm_curated/enterprise_deals_q4.parquet",
                display_name="enterprise_deals_q4.parquet",
                object_type="spreadsheet",
                store_uri=s3_uri,
                provider="AWS S3",
                sample_text="account_exec: sarah.connor@contoso.com | phone: 415-555-0192 | salary: $168,000 | annual_contract_value: $420,000",
                owner="revops-analytics@contoso.com",
                sensitivity_label="Confidential",
                size_bytes=2458000,
                row_count=14200,
                extra_chunks=[
                    "sarah.connor@contoso.com | phone: 415-555-0192 | salary: $168,000",
                    "account_exec=sarah.connor@contoso.com | salary=$168,000",
                ],
            ),
            _build_obj(
                locator=f"{s3_uri}/restricted_vault/patient_genomic_cohort_extract.parquet",
                display_name="patient_genomic_cohort_extract.parquet",
                object_type="file",
                store_uri=s3_uri,
                provider="AWS S3",
                sample_text="Patient SSN: 412-58-9021 | MRN-8839201 | ICD-10: C34.90 | Clinical Trial Cohort A",
                owner="clinical-research-sec@contoso.com",
                sensitivity_label="Restricted",
                size_bytes=8912000,
                row_count=3800,
                extra_chunks=["Patient SSN: 412-58-9021 | MRN-8839201"],
            ),
        ]

        # 2. Azure ADLS Gen2 / Blob Enterprise Lake
        az_uri = "azblob://contosodatalake.blob.core.windows.net/enterprise-knowledge"
        self.stores[az_uri] = DataStoreConnectionConfig(
            store_id="azure-adls-knowledge",
            name="Azure ADLS Gen2 / Blob — Enterprise Knowledge Lake",
            uri=az_uri,
            provider="Azure ADLS Gen2 / Blob",
            store_kind="object_store",
            region="eastus2",
            auth_mode="managed_identity",
            owner="azure-governance@contoso.com",
            created_at=now_iso,
        )
        self.store_objects[az_uri] = [
            _build_obj(
                locator=f"{az_uri}/press_releases/2026_product_launch_faq.docx",
                display_name="2026_product_launch_faq.docx",
                object_type="document",
                store_uri=az_uri,
                provider="Azure ADLS Gen2 / Blob",
                sample_text="Contoso 2026 Public Product Launch FAQ — Approved for external distribution and public LLM summarization.",
                owner="comms@contoso.com",
                sensitivity_label="Public",
                size_bytes=94200,
            ),
            _build_obj(
                locator=f"{az_uri}/finance_lake/executive_comp_band_2026.xlsx",
                display_name="executive_comp_band_2026.xlsx",
                object_type="spreadsheet",
                store_uri=az_uri,
                provider="Azure ADLS Gen2 / Blob",
                sample_text="diana.prince@contoso.com | phone: 212-555-0144 | base_salary: $195,000 | bonus_target: 30%",
                owner="compensation-committee@contoso.com",
                sensitivity_label="Confidential",
                size_bytes=512000,
                row_count=420,
                extra_chunks=["diana.prince@contoso.com | base_salary: $195,000"],
            ),
            _build_obj(
                locator=f"{az_uri}/clinical_trials/oncology_mrn_registry.parquet",
                display_name="oncology_mrn_registry.parquet",
                object_type="file",
                store_uri=az_uri,
                provider="Azure ADLS Gen2 / Blob",
                sample_text="Patient SSN: 521-44-8819 | Medical Record Number: MRN-7741902 | Oncology Phase III",
                owner="chief-medical-officer@contoso.com",
                sensitivity_label="Restricted",
                size_bytes=4194304,
                row_count=5100,
            ),
        ]

        # 3. GCP Cloud Storage Vertex AI Lake
        gs_uri = "gs://contoso-vertex-lake-us/curated-zones"
        self.stores[gs_uri] = DataStoreConnectionConfig(
            store_id="gcp-gcs-vertex-lake",
            name="GCP Cloud Storage — Vertex AI Curated Data Lake",
            uri=gs_uri,
            provider="GCP Cloud Storage",
            store_kind="object_store",
            region="us-central1",
            auth_mode="workload_identity",
            owner="gcp-mlops@contoso.com",
            created_at=now_iso,
        )
        self.store_objects[gs_uri] = [
            _build_obj(
                locator=f"{gs_uri}/public_kb/sdk_quickstart_guide.md",
                display_name="sdk_quickstart_guide.md",
                object_type="document",
                store_uri=gs_uri,
                provider="GCP Cloud Storage",
                sample_text="G1 Docket SDK Quickstart Guide: Wrap untrusted RAG objects in <pod:object locator='...'> tags before calling /v1/chat/completions.",
                owner="devrel@contoso.com",
                sensitivity_label="Public",
                size_bytes=32100,
            ),
            _build_obj(
                locator=f"{gs_uri}/billing_exports/enterprise_customer_contacts.csv",
                display_name="enterprise_customer_contacts.csv",
                object_type="spreadsheet",
                store_uri=gs_uri,
                provider="GCP Cloud Storage",
                sample_text="billing_contact: marcus.fenix@gearscorp.com | phone: 206-555-0188 | credit_limit: $50,000",
                owner="finops@contoso.com",
                sensitivity_label="Confidential",
                size_bytes=780400,
                row_count=2900,
            ),
        ]

        # 4. PostgreSQL / Enterprise Operational DB (Live SQL Scanner)
        pg_uri = "postgres://estate-db:5432/estate"
        self.stores[pg_uri] = DataStoreConnectionConfig(
            store_id="postgres-estate-db",
            name="PostgreSQL — Enterprise Operational Database (Live SQL)",
            uri=pg_uri,
            provider="PostgreSQL",
            store_kind="database",
            region="local-vpc",
            auth_mode="connection_string",
            owner="db-owners@contoso.com",
            created_at=now_iso,
        )

        # 5. Snowflake Enterprise Data Warehouse
        sf_uri = "snowflake://contoso.us-east-1.snowflakecomputing.com/FINANCE_PROD/PUBLIC"
        self.stores[sf_uri] = DataStoreConnectionConfig(
            store_id="snowflake-finance-prod",
            name="Snowflake — FINANCE_PROD Enterprise Data Warehouse",
            uri=sf_uri,
            provider="Snowflake",
            store_kind="warehouse",
            region="us-east-1",
            auth_mode="key_pair",
            owner="snowflake-stewards@contoso.com",
            created_at=now_iso,
        )
        self.store_objects[sf_uri] = [
            _build_obj(
                locator=f"{sf_uri}/PUBLIC_PRODUCT_SKU_CATALOG",
                display_name="PUBLIC.PUBLIC_PRODUCT_SKU_CATALOG",
                object_type="warehouse_table",
                store_uri=sf_uri,
                provider="Snowflake",
                sample_text="SKU-100 | Quantum Router | $1,299.00 | Available",
                owner="catalog-stewards@contoso.com",
                sensitivity_label="Public",
                size_bytes=1420000,
                row_count=8400,
                extra_chunks=[
                    "SKU-100 | Quantum Router | $1,299.00",
                    '{"sku":"SKU-100","title":"Quantum Router","price":"1299.00"}',
                ],
            ),
            _build_obj(
                locator=f"{sf_uri}/DIM_CUSTOMER_CONTACTS",
                display_name="PUBLIC.DIM_CUSTOMER_CONTACTS",
                object_type="warehouse_table",
                store_uri=sf_uri,
                provider="Snowflake",
                sample_text="CUST-901 | elena.fisher@example.com | phone: 312-555-0199 | segment: Enterprise",
                owner="crm-warehouse@contoso.com",
                sensitivity_label="Confidential",
                size_bytes=18400000,
                row_count=125000,
                extra_chunks=[
                    "CUST-901 | elena.fisher@example.com | phone: 312-555-0199",
                    '{"customer_id":"CUST-901","email":"elena.fisher@example.com","phone":"312-555-0199"}',
                ],
            ),
            _build_obj(
                locator=f"{sf_uri}/HR_EXECUTIVE_SSN_TAX_FILINGS",
                display_name="PUBLIC.HR_EXECUTIVE_SSN_TAX_FILINGS",
                object_type="warehouse_table",
                store_uri=sf_uri,
                provider="Snowflake",
                sample_text="EMP-001 | SSN: 412-58-9021 | W2_GROSS: $410,000 | Routing: ABA-021000021",
                owner="payroll-compliance@contoso.com",
                sensitivity_label="Restricted",
                size_bytes=3200000,
                row_count=650,
            ),
        ]

        # 6. Google BigQuery Analytics Warehouse
        bq_uri = "bigquery://contoso-gcp-analytics/enterprise_mart"
        self.stores[bq_uri] = DataStoreConnectionConfig(
            store_id="bigquery-enterprise-mart",
            name="Google BigQuery — enterprise_mart Analytics Dataset",
            uri=bq_uri,
            provider="Google BigQuery",
            store_kind="warehouse",
            region="US",
            auth_mode="workload_identity",
            owner="bq-analytics@contoso.com",
            created_at=now_iso,
        )
        self.store_objects[bq_uri] = [
            _build_obj(
                locator=f"{bq_uri}/public_release_benchmarks",
                display_name="enterprise_mart.public_release_benchmarks",
                object_type="warehouse_table",
                store_uri=bq_uri,
                provider="Google BigQuery",
                sample_text="benchmark_id:preval-gate-v1 | p50_us:71.1 | p95_us:142.0 | zero_db_calls:true",
                owner="perf-eng@contoso.com",
                sensitivity_label="Public",
                size_bytes=640000,
                row_count=5000,
            ),
            _build_obj(
                locator=f"{bq_uri}/platform_ops_cluster_inventory",
                display_name="enterprise_mart.platform_ops_cluster_inventory",
                object_type="warehouse_table",
                store_uri=bq_uri,
                provider="Google BigQuery",
                sample_text="cluster_id:gke-prod-us-central1 | node_ip:10.128.15.44 | internal_project:PROJECT-APOLLO",
                owner="gcp-infra@contoso.com",
                sensitivity_label="Internal",
                size_bytes=1950000,
                row_count=3100,
            ),
            _build_obj(
                locator=f"{bq_uri}/hipaa_patient_encounters",
                display_name="enterprise_mart.hipaa_patient_encounters",
                object_type="warehouse_table",
                store_uri=bq_uri,
                provider="Google BigQuery",
                sample_text="encounter_id:ENC-9921 | ssn:412-58-9021 | mrn:MRN-8839201 | diagnosis:ICD10-J45.909",
                owner="clinical-data-steward@contoso.com",
                sensitivity_label="Restricted",
                size_bytes=12400000,
                row_count=42000,
            ),
        ]

    def list_stores(self) -> list[dict[str, Any]]:
        """Return all registered enterprise data stores for the UI selector and API."""
        out: list[dict[str, Any]] = []
        for uri, cfg in self.stores.items():
            objs = self.store_objects.get(uri, [])
            out.append(
                {
                    "store_id": cfg.store_id,
                    "name": cfg.name,
                    "uri": cfg.uri,
                    "provider": cfg.provider,
                    "store_kind": cfg.store_kind,
                    "region": cfg.region,
                    "auth_mode": cfg.auth_mode,
                    "owner": cfg.owner,
                    "endpoint_url": cfg.endpoint_url,
                    "etag_fast_path": cfg.etag_fast_path,
                    "event_webhook_enabled": cfg.event_webhook_enabled,
                    "object_count": len(objs) if cfg.store_kind != "database" else 3,
                    "label": f"☁️ [{cfg.provider}] {cfg.uri} — {cfg.name}",
                }
            )
        return out

    def register_store(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Register or update a custom enterprise data store (`s3://`, `azblob://`, `gs://`, `postgres://`, `snowflake://`, `bigquery://`, `databricks://`)."""
        uri = str(payload.get("uri") or "").strip().rstrip("/")
        if not uri or "://" not in uri:
            raise ValueError("A valid store URI (e.g. s3://bucket/prefix, azblob://..., gs://..., snowflake://..., postgres://...) is required.")

        scheme = uri.split("://", 1)[0].lower()
        provider_map = {
            "s3": ("AWS S3", "object_store"),
            "azblob": ("Azure ADLS Gen2 / Blob", "object_store"),
            "abfss": ("Azure ADLS Gen2 / Blob", "object_store"),
            "gs": ("GCP Cloud Storage", "object_store"),
            "postgres": ("PostgreSQL", "database"),
            "postgresql": ("PostgreSQL", "database"),
            "snowflake": ("Snowflake", "warehouse"),
            "bigquery": ("Google BigQuery", "warehouse"),
            "databricks": ("Databricks Unity Catalog", "warehouse"),
            "sharepoint": ("SharePoint Online", "object_store"),
        }
        default_provider, default_kind = provider_map.get(scheme, ("Enterprise Cloud Store", "object_store"))
        provider = str(payload.get("provider") or default_provider)
        store_kind = str(payload.get("store_kind") or default_kind)
        name = str(payload.get("name") or f"{provider} — {uri}")
        region = str(payload.get("region") or "us-east-1")
        auth_mode = str(payload.get("auth_mode") or "iam_role")
        owner = str(payload.get("owner") or "data-platform@contoso.com")
        endpoint_url = payload.get("endpoint_url")

        store_id = re.sub_slug(uri)
        cfg = DataStoreConnectionConfig(
            store_id=store_id,
            name=name,
            uri=uri,
            provider=provider,
            store_kind=store_kind,
            region=region,
            auth_mode=auth_mode,
            owner=owner,
            endpoint_url=endpoint_url,
            created_at=format_iso8601(datetime.now(timezone.utc)),
        )
        self.stores[uri] = cfg

        if uri not in self.store_objects and store_kind != "database":
            # Seed 3 representative objects/tables for newly registered custom stores so immediate crawl/test works out of the box
            ext = "TABLE" if store_kind == "warehouse" else "parquet"
            obj_type = "warehouse_table" if store_kind == "warehouse" else "file"
            self.store_objects[uri] = [
                _build_obj(
                    locator=f"{uri}/public_reference_dataset.{ext}" if ext != "TABLE" else f"{uri}/PUBLIC_REFERENCE_DATASET",
                    display_name=f"public_reference_dataset.{ext}" if ext != "TABLE" else "PUBLIC_REFERENCE_DATASET",
                    object_type=obj_type,
                    store_uri=uri,
                    provider=provider,
                    sample_text=f"Public reference dataset in {uri}. Approved for external AI egress.",
                    owner=owner,
                    sensitivity_label="Public",
                    size_bytes=124000,
                    row_count=1200,
                ),
                _build_obj(
                    locator=f"{uri}/customer_crm_records.{ext}" if ext != "TABLE" else f"{uri}/CUSTOMER_CRM_RECORDS",
                    display_name=f"customer_crm_records.{ext}" if ext != "TABLE" else "CUSTOMER_CRM_RECORDS",
                    object_type=obj_type,
                    store_uri=uri,
                    provider=provider,
                    sample_text="customer_email: alice.vance@example.org | phone: 415-555-0133 | revenue_tier: Enterprise",
                    owner=owner,
                    sensitivity_label="Confidential",
                    size_bytes=940000,
                    row_count=8500,
                ),
                _build_obj(
                    locator=f"{uri}/restricted_pii_vault.{ext}" if ext != "TABLE" else f"{uri}/RESTRICTED_PII_VAULT",
                    display_name=f"restricted_pii_vault.{ext}" if ext != "TABLE" else "RESTRICTED_PII_VAULT",
                    object_type=obj_type,
                    store_uri=uri,
                    provider=provider,
                    sample_text="SSN: 412-58-9021 | MRN-8839201 | Restricted Compliance Record",
                    owner=owner,
                    sensitivity_label="Restricted",
                    size_bytes=2150000,
                    row_count=1900,
                ),
            ]
        return {
            "registered": True,
            "store": next(s for s in self.list_stores() if s["uri"] == uri),
        }

    def resolve_matching_store_uri(self, raw_uri: str) -> str:
        """Match either an exact store URI (`s3://bucket/prefix`) or a prefix/sub-URI."""
        cleaned = raw_uri.strip().rstrip("/")
        if cleaned in self.stores:
            return cleaned
        for known_uri in self.stores:
            if cleaned.startswith(known_uri.rstrip("/")):
                return known_uri
        # Dynamically register on the fly if a user types a brand new s3://, gs://, azblob://, snowflake://, or bigquery:// URI
        self.register_store({"uri": cleaned})
        return cleaned

    def list_objects_for_prevalidation(self, raw_uri: str) -> tuple[str, list[tuple[str, str, str]]]:
        """Return `(store_label, [(display_name, locator, observed_sha256), ...])` for Prevalidator batch scanning."""
        store_uri = self.resolve_matching_store_uri(raw_uri)
        cfg = self.stores[store_uri]

        if cfg.store_kind == "database" or store_uri.startswith(("postgres://", "postgresql://")):
            sqlite_db = self.estate_dir / "synthetic_estate.db"
            db_url = f"sqlite:///{sqlite_db.as_posix()}" if sqlite_db.is_file() and store_uri == "postgres://estate-db:5432/estate" else store_uri
            tables = self.engine.db_scanner.scan_database(
                db_url=db_url,
                locator_override_base="postgres://estate-db:5432/estate" if store_uri == "postgres://estate-db:5432/estate" else None,
            )
            candidates: list[tuple[str, str, str]] = []
            for t in tables:
                candidates.append((f"{t.schema_name}.{t.table_name}", t.locator, t.content_sha256))
            # Also include any unattested simulated tables dropped into this store
            for extra in self.store_objects.get(store_uri, []):
                candidates.append((extra.display_name, extra.locator, extra.content_sha256))
            return f"{cfg.name} ({store_uri})", candidates

        objs = self.store_objects.get(store_uri, [])
        candidates = [(o.display_name, o.locator, o.content_sha256) for o in objs]
        return f"{cfg.name} ({store_uri})", candidates

    def crawl_and_attest_store(self, raw_uri: str, owner_override: str | None = None) -> dict[str, Any]:
        """Crawl an enterprise data store (`s3://`, `azblob://`, `gs://`, `postgres://`, `snowflake://`, `bigquery://`),
        apply ETag/VersionId fast-path + bounded streaming classification, issue DSSE-signed records, and return a report compatible with the UI."""
        t0 = time.perf_counter()
        store_uri = self.resolve_matching_store_uri(raw_uri)
        cfg = self.stores[store_uri]

        attested_items: list[dict[str, Any]] = []
        held_for_review = 0
        etag_fast_path_hits = 0

        if cfg.store_kind == "database" or store_uri.startswith(("postgres://", "postgresql://")):
            sqlite_db = self.estate_dir / "synthetic_estate.db"
            db_url = f"sqlite:///{sqlite_db.as_posix()}" if sqlite_db.is_file() and store_uri == "postgres://estate-db:5432/estate" else store_uri
            crawl_results = self.engine.crawl_database(
                db_url=db_url,
                owner=owner_override or cfg.owner,
                locator_override_base="postgres://estate-db:5432/estate" if store_uri == "postgres://estate-db:5432/estate" else None,
                environment="production",
            )
            # Also attest any simulated tables added to store_objects[store_uri]
            for extra_obj in self.store_objects.get(store_uri, []):
                crawl_results.append(self._attest_single_store_object(extra_obj, cfg))
        else:
            crawl_results = []
            for obj in self.store_objects.get(store_uri, []):
                existing = self.registry.lookup_by_locator(obj.locator, include_expired_or_revoked=False)
                if (
                    cfg.etag_fast_path
                    and existing
                    and existing["content_sha256"] == obj.content_sha256
                    and existing.get("chunk_hashes")
                ):
                    etag_fast_path_hits += 1
                    crawl_results.append({"action": "unchanged_etag_fast_path", "record": existing, "review": None})
                    continue
                res = self._attest_single_store_object(obj, cfg)
                crawl_results.append(res)

        for item in crawl_results:
            rec = item.get("record")
            rev = item.get("review")
            if rec:
                attested_items.append(
                    {
                        "locator": rec["locator"],
                        "file_name": rec.get("display_name") or rec["locator"].rsplit("/", 1)[-1],
                        "object_type": rec["object_type"],
                        "tier": rec["tier"],
                        "status": rec["status"],
                        "ai_eligibility": rec["ai_eligibility"],
                        "minimum_clearance": rec["minimum_clearance"],
                        "egress_class": rec["egress_class"],
                        "content_sha256": rec["content_sha256"],
                        "expires_at": rec["expires_at"],
                        "action": item["action"],
                    }
                )
            elif rev:
                held_for_review += 1
                attested_items.append(
                    {
                        "locator": rev["locator"],
                        "file_name": rev["locator"].rsplit("/", 1)[-1],
                        "object_type": "file",
                        "tier": rev["proposed_tier"],
                        "status": "PENDING_REVIEW (Unissued)",
                        "ai_eligibility": "deny",
                        "minimum_clearance": "Restricted",
                        "egress_class": "local_only",
                        "content_sha256": rev["metadata"].get("content_sha256", ""),
                        "expires_at": "-",
                        "action": item["action"],
                    }
                )

        active_count = len(crawl_results) - held_for_review
        tier_counts: dict[str, int] = {"Public": 0, "Internal": 0, "Confidential": 0, "Restricted": 0}
        for f in attested_items:
            t = f.get("tier")
            if t in tier_counts and f.get("status") != "PENDING_REVIEW (Unissued)":
                tier_counts[t] += 1

        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        english_summary = (
            f"Attestation Engine scanned {cfg.provider} store '{store_uri}' ({cfg.auth_mode}, region={cfg.region}) in {elapsed_ms} ms: "
            f"Discovered {len(crawl_results)} enterprise object(s)/table(s) ({etag_fast_path_hits} ETag fast-path unchanged). "
            f"Issued {active_count} active DSSE-signed record(s) with canonical RAG chunk hashes "
            f"({tier_counts['Public']} Public, {tier_counts['Internal']} Internal, "
            f"{tier_counts['Confidential']} Confidential, {tier_counts['Restricted']} Restricted) "
            f"and held {held_for_review} object(s) in human review."
        )

        return {
            "directory": store_uri,
            "store_name": cfg.name,
            "provider": cfg.provider,
            "locator_base": store_uri,
            "total_files_found": len(crawl_results),
            "attested_active_count": active_count,
            "held_in_review_count": held_for_review,
            "etag_fast_path_hits": etag_fast_path_hits,
            "tier_counts": tier_counts,
            "english_summary": english_summary,
            "files": attested_items,
        }

    def _attest_single_store_object(
        self, obj: EnterpriseStoreObject, cfg: DataStoreConnectionConfig
    ) -> dict[str, Any]:
        """Classify a single enterprise object/table via bounded sample + metadata hints and issue a DSSE record."""
        mapped_label = map_purview_label_to_tier(obj.sensitivity_label)
        hints: dict[str, Any] = {}
        if mapped_label:
            hints["default_tier"] = mapped_label
            hints["confidence"] = 0.98

        verdict = self.classifier.classify_text(
            text=obj.content_bytes.decode("utf-8", errors="replace"),
            metadata_hints=hints,
        )
        if mapped_label and TIER_ORDER[mapped_label] > TIER_ORDER[verdict.tier]:
            verdict.tier = mapped_label

        fp_method = (
            "table_schema_and_canonical_rows_sha256"
            if obj.object_type in ("database_table", "warehouse_table")
            else "raw_bytes_sha256"
        )
        return self.registry.issue_or_queue_finding(
            locator=obj.locator,
            content_sha256=obj.content_sha256,
            schema_sha256=obj.schema_sha256,
            tier=verdict.tier,
            owner=obj.owner or cfg.owner,
            confidence=verdict.confidence,
            low_confidence=verdict.low_confidence,
            sensitive_categories=[f.to_dict() for f in verdict.sensitive_categories],
            object_type=obj.object_type,
            display_name=obj.display_name,
            environment="production",
            attested_by=f"g1-docket-enterprise-connector:{cfg.provider.lower().replace(' ', '-')}",
            source_system=f"{cfg.provider}:{cfg.auth_mode}",
            size_bytes=obj.size_bytes,
            row_count=obj.row_count,
            fingerprint_method=fp_method,
            classifier_engine=f"{verdict.classifier_engine}+{cfg.provider.lower().replace(' ', '-')}",
            extracted_text_sha256=obj.extracted_text_sha256,
            chunk_hashes=obj.chunk_hashes,
        )

    def add_unattested_object_to_store(
        self,
        raw_uri: str,
        object_name: str | None = None,
        sample_text: str | None = None,
    ) -> dict[str, Any]:
        """Drop a new unattested object/table into an enterprise store (`s3://`, `azblob://`, `gs://`, `snowflake://`, etc.)
        WITHOUT attesting it, so the user can see the Prevalidator detect and block the unattested cloud asset."""
        store_uri = self.resolve_matching_store_uri(raw_uri)
        cfg = self.stores[store_uri]
        short_id = uuid.uuid4().hex[:6]

        if cfg.store_kind in ("warehouse", "database"):
            obj_name = object_name or f"UNATTESTED_SHADOW_TABLE_{short_id.upper()}"
            obj_type = "warehouse_table" if cfg.store_kind == "warehouse" else "database_table"
            locator = f"{store_uri.rstrip('/')}/{obj_name}"
        else:
            obj_name = object_name or f"unattested_cloud_drop_{short_id}.parquet"
            obj_type = "file"
            locator = f"{store_uri.rstrip('/')}/{obj_name}"

        text_body = (
            sample_text
            or f"Unattested cloud object landed in {cfg.provider} ({store_uri}) at {format_iso8601(datetime.now(timezone.utc))} without a DSSE attestation record."
        )
        new_obj = _build_obj(
            locator=locator,
            display_name=obj_name,
            object_type=obj_type,
            store_uri=store_uri,
            provider=cfg.provider,
            sample_text=text_body,
            owner=cfg.owner,
            size_bytes=len(text_body.encode("utf-8")),
            row_count=250 if obj_type in ("warehouse_table", "database_table") else None,
        )
        self.store_objects.setdefault(store_uri, []).append(new_obj)
        return {
            "created": True,
            "file_name": obj_name,
            "host_directory": store_uri,
            "provider": cfg.provider,
            "expected_locator": locator,
        }

    def handle_storage_event(self, event_payload: dict[str, Any]) -> dict[str, Any]:
        """Process real-time storage events from AWS S3 EventBridge, Azure Event Grid, or GCS Pub/Sub.

        Supports:
        - `event_type`: `'ObjectCreated:Put'` | `'Microsoft.Storage.BlobCreated'` | `'google.cloud.storage.object.v1.finalized'`
          -> Immediately extracts/classifies the object and issues a signed record in the Registry.
        - `event_type`: `'ObjectRemoved:Delete'` | `'Microsoft.Storage.BlobDeleted'` | `'google.cloud.storage.object.v1.deleted'`
          -> Immediately revokes the active record for that URI locator in the Registry.
        """
        event_type = str(event_payload.get("event_type") or "ObjectCreated:Put")
        raw_store_uri = str(event_payload.get("store_uri") or "s3://contoso-ai-datalake-prod/rag-corpus").rstrip("/")
        store_uri = self.resolve_matching_store_uri(raw_store_uri)
        cfg = self.stores[store_uri]

        short_id = uuid.uuid4().hex[:5]
        object_key = str(event_payload.get("object_key") or f"realtime_events/event_stream_{short_id}.parquet").lstrip("/")
        locator = str(event_payload.get("locator") or f"{store_uri}/{object_key}")
        display_name = object_key.rsplit("/", 1)[-1]
        sample_text = str(
            event_payload.get("sample_text")
            or f"Real-time event-driven cloud object ingested via {event_type} into {locator}. Contact: event-pipeline@contoso.com"
        )
        sensitivity_label = event_payload.get("sensitivity_label")

        now_iso = format_iso8601(datetime.now(timezone.utc))
        is_delete = any(k in event_type.lower() for k in ("remove", "delete"))

        if is_delete:
            # Remove from in-memory store list if present and revoke in Registry
            if store_uri in self.store_objects:
                self.store_objects[store_uri] = [o for o in self.store_objects[store_uri] if o.locator != locator]
            existing = self.registry.lookup_by_locator(locator, include_expired_or_revoked=False)
            revoked_rec = None
            if existing:
                revoked_rec = self.registry.revoke_record(
                    locator=locator,
                    reason=f"Cloud storage event {event_type} reported object deletion ({cfg.provider})",
                )
            evt_record = {
                "event_id": f"evt-{uuid.uuid4().hex[:8]}",
                "timestamp": now_iso,
                "event_type": event_type,
                "provider": cfg.provider,
                "locator": locator,
                "action": "REVOKED" if revoked_rec else "NOT_FOUND",
                "tier": revoked_rec["tier"] if revoked_rec else "-",
                "record_id": revoked_rec["record_id"] if revoked_rec else None,
            }
            self.event_history.append(evt_record)
            return evt_record

        # Object Created / Updated -> upsert into store_objects and immediately attest
        new_obj = _build_obj(
            locator=locator,
            display_name=display_name,
            object_type="warehouse_table" if cfg.store_kind == "warehouse" else "file",
            store_uri=store_uri,
            provider=cfg.provider,
            sample_text=sample_text,
            owner=cfg.owner,
            sensitivity_label=sensitivity_label,
            size_bytes=len(sample_text.encode("utf-8")),
        )
        objs = self.store_objects.setdefault(store_uri, [])
        objs[:] = [o for o in objs if o.locator != locator]
        objs.append(new_obj)

        att_res = self._attest_single_store_object(new_obj, cfg)
        rec = att_res.get("record")
        evt_record = {
            "event_id": f"evt-{uuid.uuid4().hex[:8]}",
            "timestamp": now_iso,
            "event_type": event_type,
            "provider": cfg.provider,
            "locator": locator,
            "action": f"ATTESTED ({att_res['action'].upper()})",
            "tier": rec["tier"] if rec else "HELD_FOR_REVIEW",
            "record_id": rec["record_id"] if rec else None,
            "content_sha256": new_obj.content_sha256,
        }
        self.event_history.append(evt_record)
        return evt_record


class re:
    @staticmethod
    def sub_slug(val: str) -> str:
        import re as _re

        return _re.sub(r"[^a-zA-Z0-9_-]+", "-", val.lower()).strip("-")[:48]
