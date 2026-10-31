"""Docker Compose Bootstrap: seeds the synthetic estate into Postgres and shared volumes, attests all objects, publishes the signed snapshot, and reloads the Prevalidator."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import httpx
from sqlalchemy import create_engine, text

from engine.pipeline import AttestationEngine
from examples.synthetic_estate import build_synthetic_estate
from registry.store import RegistryService
from snapshot.publisher import SnapshotPublisher


def main() -> int:
    db_url = os.environ.get("POD_REGISTRY_DB_URL", "postgresql+psycopg2://pod:pod_password@postgres:5432/pod_registry")
    if db_url.startswith("postgresql://"):
        db_url = "postgresql+psycopg2://" + db_url[len("postgresql://") :]
    snapshot_file = Path(os.environ.get("POD_SNAPSHOT_FILE", "/var/lib/pod/state/snapshots/pod_snapshot.dsse.json"))
    estate_dir = Path(os.environ.get("POD_ESTATE_DIR", "/var/lib/pod/state/estate"))
    prevalidator_url = os.environ.get("POD_PREVALIDATOR_URL", "http://prevalidator:8082")
    snapshot_publisher_url = os.environ.get("POD_SNAPSHOT_PUBLISHER_URL", "").rstrip("/")
    admin_key = os.environ.get("POD_ADMIN_API_KEY", "pod-dev-admin-key")
    control_token = os.environ.get("POD_CONTROL_PLANE_TOKEN", "pod-dev-control-plane-token")

    # 1. Build synthetic fileshare on volume
    estate = build_synthetic_estate(estate_dir)

    # 2. Seed a dedicated `estate_data` schema inside Postgres so `crawl_database` scans real Postgres tables
    pg_engine = create_engine(db_url)
    with pg_engine.begin() as conn:
        conn.execute(text("CREATE SCHEMA IF NOT EXISTS estate_data"))
        conn.execute(text("DROP TABLE IF EXISTS estate_data.public_catalog"))
        conn.execute(text("DROP TABLE IF EXISTS estate_data.customer_contacts"))
        conn.execute(text("DROP TABLE IF EXISTS estate_data.patient_biomarkers"))

        conn.execute(
            text(
                "CREATE TABLE estate_data.public_catalog ("
                "  sku_id TEXT PRIMARY KEY,"
                "  title TEXT NOT NULL,"
                "  category TEXT NOT NULL"
                ")"
            )
        )
        conn.execute(
            text(
                "INSERT INTO estate_data.public_catalog (sku_id, title, category) VALUES "
                "('SKU-001', 'Standard Gateway Adapter', 'Software'),"
                "('SKU-002', 'Open Schema Validator', 'Tooling')"
            )
        )

        conn.execute(
            text(
                "CREATE TABLE estate_data.customer_contacts ("
                "  customer_id TEXT PRIMARY KEY,"
                "  email TEXT NOT NULL,"
                "  phone TEXT NOT NULL"
                ")"
            )
        )
        conn.execute(
            text(
                "INSERT INTO estate_data.customer_contacts (customer_id, email, phone) VALUES "
                "('CUST-101', 'buyer.one@example.com', '212-555-0181'),"
                "('CUST-102', 'buyer.two@example.com', '212-555-0182')"
            )
        )

        conn.execute(
            text(
                "CREATE TABLE estate_data.patient_biomarkers ("
                "  subject_id TEXT PRIMARY KEY,"
                "  ssn TEXT NOT NULL,"
                "  mrn TEXT NOT NULL,"
                "  variant_id TEXT NOT NULL"
                ")"
            )
        )
        conn.execute(
            text(
                "INSERT INTO estate_data.patient_biomarkers (subject_id, ssn, mrn, variant_id) VALUES "
                "('SUBJ-01', '521-44-8192', 'MRN-7710293', 'rs121913529')"
            )
        )
    pg_engine.dispose()

    # 3. Run AttestationEngine over fileshare and sqlite/postgres estate
    registry = RegistryService(db_url=db_url)
    engine = AttestationEngine(registry=registry)

    file_results = engine.crawl_file_share(
        root_dir=estate["fileshare_dir"],
        owner="fileshare-steward@example.org",
        locator_base="file://estate/fileshare",
        environment="production",
    )
    db_results = engine.crawl_database(
        db_url=estate["db_url"],
        owner="data-platform@example.org",
        locator_override_base="postgres://estate-db:5432/estate",
        environment="production",
    )

    # 4. Publish signed DSSE snapshot via Snapshot Publisher (or local publisher in single-process mode)
    ctrl_headers = {
        "X-POD-Control-Token": control_token,
        "X-POD-Admin-Key": admin_key,
        "Authorization": f"Bearer {control_token}",
    }
    if snapshot_publisher_url:
        envelope = None
        for _ in range(15):
            try:
                with httpx.Client(timeout=45.0) as client:
                    r_pub = client.post(f"{snapshot_publisher_url}/v1/publish", headers=ctrl_headers)
                    if r_pub.status_code == 200:
                        envelope = r_pub.json()
                        break
            except Exception:
                pass
            time.sleep(1.0)
        if envelope is None:
            raise RuntimeError(f"Failed to trigger snapshot publish at {snapshot_publisher_url}/v1/publish")
    else:
        publisher = SnapshotPublisher(registry=registry, ttl_seconds=3600, snapshot_output_path=snapshot_file)
        envelope = publisher.publish_snapshot()
    registry.close()

    # 5. Notify Prevalidator to reload snapshot in memory
    reloaded = False
    for _ in range(15):
        try:
            with httpx.Client(timeout=3.0) as client:
                r = client.post(
                    f"{prevalidator_url.rstrip('/')}/v1/admin/reload-snapshot",
                    headers=ctrl_headers,
                    json={"envelope": envelope},
                )
                if r.status_code == 200:
                    reloaded = True
                    break
        except Exception:
            time.sleep(1.0)

    print(
        json.dumps(
            {
                "bootstrap": "completed",
                "files_attested": len(file_results),
                "tables_attested": len(db_results),
                "snapshot_file": str(snapshot_file),
                "prevalidator_reloaded": reloaded,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
