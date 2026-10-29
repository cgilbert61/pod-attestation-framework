"""OpenMetadata catalog connector & deterministic database table fingerprinter.

Treats OpenMetadata classifications strictly as findings that feed the attestation stage;
the signed record in the Registry is the sole authoritative verdict.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx
from sqlalchemy import create_engine, inspect, text


@dataclass
class TableDiscoveryFinding:
    """Combined discovery, schema/content hash, and OpenMetadata classification findings for a DB table."""

    locator: str
    table_name: str
    schema_name: str
    database_name: str
    schema_sha256: str
    content_sha256: str
    row_count: int
    size_bytes: int
    column_samples: dict[str, list[str]]
    openmetadata_findings: list[dict[str, Any]] = field(default_factory=list)
    owner_hint: str | None = None
    derived_from: list[dict[str, Any]] = field(default_factory=list)


# Mapping from OpenMetadata tag FQN patterns to POD sensitive category names
OM_TAG_TO_CATEGORY: dict[str, str] = {
    "PII.Sensitive": "US_SSN",
    "PII.NonSensitive": "EMAIL_ADDRESS",
    "PersonalData.Personal": "EMAIL_ADDRESS",
    "PersonalData.SpecialCategory": "MEDICAL_RECORD_NUMBER",
    "Secrets.Credential": "API_KEY",
    "Financial.Compensation": "SALARY_COMPENSATION",
    "Financial.PaymentCard": "CREDIT_CARD",
}


class OpenMetadataDatabaseScanner:
    """Discovers database tables, fetches OpenMetadata classification findings, and computes table SHA-256 digests."""

    def __init__(
        self,
        openmetadata_url: str | None = None,
        openmetadata_jwt: str | None = None,
        sample_limit: int = 500,
    ) -> None:
        raw_url = openmetadata_url or os.environ.get("OPENMETADATA_SERVER_URL", "")
        self.openmetadata_url = raw_url.rstrip("/") if raw_url else ""
        self.openmetadata_jwt = openmetadata_jwt or os.environ.get("OPENMETADATA_JWT_TOKEN", "")
        self.sample_limit = sample_limit

    def build_table_locator(self, db_url: str, schema_name: str, table_name: str) -> str:
        """Build canonical `postgres://host:port/db/schema/table` locator."""
        parsed = urlparse(db_url)
        if parsed.scheme.startswith("sqlite"):
            db_path = (parsed.path or "memory").lstrip("/").replace("\\", "/")
            return f"postgres://local-db:5432/{db_path}/{schema_name}/{table_name}"
        host = parsed.hostname or "localhost"
        port = parsed.port or 5432
        db_name = (parsed.path or "/postgres").lstrip("/")
        return f"postgres://{host}:{port}/{db_name}/{schema_name}/{table_name}"

    def fetch_openmetadata_findings(self, database_name: str, schema_name: str, table_name: str) -> dict[str, Any]:
        """Query OpenMetadata `/v1/tables/name/{fqn}` for column tags, classification confidence, owner, and lineage."""
        headers: dict[str, str] = {"Accept": "application/json"}
        if self.openmetadata_jwt:
            headers["Authorization"] = f"Bearer {self.openmetadata_jwt}"

        result: dict[str, Any] = {"findings": [], "owner": None, "derived_from": []}
        if not self.openmetadata_url:
            return result
        try:
            with httpx.Client(timeout=5.0, headers=headers) as client:
                resp = client.get(
                    f"{self.openmetadata_url}/v1/tables",
                    params={"database": database_name, "fields": "columns,tags,owners,lineage", "limit": 100},
                )
                if resp.status_code != 200:
                    return result

                tables = resp.json().get("data", [])
                for tbl in tables:
                    if tbl.get("name") != table_name:
                        continue
                    owners = tbl.get("owners") or []
                    if owners:
                        result["owner"] = owners[0].get("name") or owners[0].get("fullyQualifiedName")

                    for col in tbl.get("columns", []):
                        col_name = col.get("name")
                        for tag in col.get("tags", []):
                            tag_fqn = tag.get("tagFQN", "")
                            category = OM_TAG_TO_CATEGORY.get(tag_fqn, tag_fqn.replace(".", "_").upper())
                            confidence = float(tag.get("confidence", 0.90))
                            result["findings"].append(
                                {
                                    "category": category,
                                    "column": col_name,
                                    "count": 1,
                                    "confidence": confidence,
                                    "source": "openmetadata",
                                }
                            )
        except Exception:
            pass
        return result

    def scan_database(
        self,
        db_url: str,
        locator_override_base: str | None = None,
        injected_om_findings: dict[str, list[dict[str, Any]]] | None = None,
    ) -> list[TableDiscoveryFinding]:
        """Scan all user tables in a database, computing deterministic schema + content SHA-256 fingerprints."""
        norm_url = "postgresql+psycopg2://" + db_url[len("postgresql://") :] if db_url.startswith("postgresql://") else db_url
        engine = create_engine(norm_url)
        inspector = inspect(engine)
        parsed = urlparse(db_url)
        db_name = (parsed.path or "/estate").lstrip("/").split("/")[-1].replace(".db", "") or "estate"

        results: list[TableDiscoveryFinding] = []
        schemas = inspector.get_schema_names()
        for schema_name in schemas:
            if schema_name in ("information_schema", "pg_catalog"):
                continue
            effective_schema = "public" if schema_name == "main" else schema_name
            table_names = sorted(inspector.get_table_names(schema=schema_name))

            for table_name in table_names:
                columns = inspector.get_columns(table_name, schema=schema_name)
                canonical_cols = [
                    {"name": col["name"], "type": str(col["type"]).upper(), "nullable": bool(col.get("nullable", True))}
                    for col in sorted(columns, key=lambda c: c["name"])
                ]
                schema_json = json.dumps(canonical_cols, separators=(",", ":"), sort_keys=True).encode("utf-8")
                schema_sha256 = hashlib.sha256(schema_json).hexdigest()

                col_names = [c["name"] for c in canonical_cols]
                quoted_cols = ", ".join(f'"{c}"' for c in col_names)
                qualified_table = f'"{schema_name}"."{table_name}"' if schema_name != "main" else f'"{table_name}"'

                row_hashes: list[str] = []
                column_samples: dict[str, list[str]] = {c: [] for c in col_names}
                total_bytes = len(schema_json)
                row_count = 0

                with engine.connect() as conn:
                    count_row = conn.execute(text(f"SELECT COUNT(*) FROM {qualified_table}")).scalar()
                    row_count = int(count_row or 0)
                    rows = conn.execute(text(f"SELECT {quoted_cols} FROM {qualified_table}")).fetchall()
                    for idx, row in enumerate(rows):
                        row_dict = {col_names[i]: (str(row[i]) if row[i] is not None else None) for i in range(len(col_names))}
                        row_bytes = json.dumps(row_dict, separators=(",", ":"), sort_keys=True).encode("utf-8")
                        total_bytes += len(row_bytes)
                        row_hashes.append(hashlib.sha256(row_bytes).hexdigest())
                        if idx < self.sample_limit:
                            for i, c_name in enumerate(col_names):
                                if row[i] is not None:
                                    column_samples[c_name].append(str(row[i]))

                # Deterministic table content fingerprint = SHA-256(schema_sha256 + sorted row hashes)
                row_hashes.sort()
                composite_hasher = hashlib.sha256()
                composite_hasher.update(schema_sha256.encode("ascii"))
                for rh in row_hashes:
                    composite_hasher.update(rh.encode("ascii"))
                content_sha256 = composite_hasher.hexdigest()

                if locator_override_base:
                    locator = f"{locator_override_base.rstrip('/')}/{effective_schema}/{table_name}"
                else:
                    locator = self.build_table_locator(db_url, effective_schema, table_name)

                om_meta = self.fetch_openmetadata_findings(db_name, effective_schema, table_name)
                om_findings = list(om_meta["findings"])
                if injected_om_findings and table_name in injected_om_findings:
                    om_findings.extend(injected_om_findings[table_name])

                results.append(
                    TableDiscoveryFinding(
                        locator=locator,
                        table_name=table_name,
                        schema_name=effective_schema,
                        database_name=db_name,
                        schema_sha256=schema_sha256,
                        content_sha256=content_sha256,
                        row_count=row_count,
                        size_bytes=total_bytes,
                        column_samples=column_samples,
                        openmetadata_findings=om_findings,
                        owner_hint=om_meta.get("owner"),
                        derived_from=om_meta.get("derived_from", []),
                    )
                )

        engine.dispose()
        return results
