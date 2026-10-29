"""Golden Synthetic Estate Generator: creates documents, spreadsheets (.xlsx/.csv), and database tables with known ground-truth classifications."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import openpyxl
from sqlalchemy import create_engine, text


def build_synthetic_estate(estate_dir: str | Path) -> dict[str, Any]:
    """Create a deterministic synthetic sample estate on disk for testing and evaluation."""
    root = Path(estate_dir).resolve()
    fileshare = root / "fileshare"
    fileshare.mkdir(parents=True, exist_ok=True)

    # 1. Public document (no PII/secrets)
    pub_doc = fileshare / "product_overview_public.md"
    pub_doc.write_text(
        "# Open Source AI Architecture Overview\n\n"
        "This whitepaper describes standard request routing and public documentation practices.\n",
        encoding="utf-8",
    )

    # 2. Internal document (internal project codes & internal IP addresses)
    int_doc = fileshare / "engineering_runbook_internal.txt"
    int_doc.write_text(
        "INTERNAL-ONLY Engineering Runbook\n"
        "Project Code: PROJ-ATLAS42\n"
        "Cluster Bastion Subnet: 10.24.18.92\n"
        "Assigned Engineer ID: EMP-40912\n",
        encoding="utf-8",
    )

    # 3. Confidential Excel spreadsheet (.xlsx) with employee emails & salary compensation
    conf_xlsx = fileshare / "dept_compensation_confidential.xlsx"
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Compensation_Q4"
    ws.append(["employee_id", "work_email", "compensation_note", "office_phone"])
    ws.append(["EMP-10021", "diana.prince@example.org", "salary: $145,000", "415-555-0192"])
    ws.append(["EMP-10022", "clark.kent@example.org", "salary: $138,500", "415-555-0144"])
    wb.save(conf_xlsx)
    wb.close()

    # 4. Restricted clinical/PII document (US SSN, Medical Record Number, ICD-10, Genomic variant)
    rest_doc = fileshare / "clinical_intake_restricted.txt"
    rest_doc.write_text(
        "Synthetic Patient Intake Record (DO NOT EXPORT)\n"
        "Patient SSN: 412-58-9021\n"
        "Medical Record: MRN-8839201\n"
        "Primary Diagnosis: ICD10-E11.9\n"
        "Genomic Marker: chr17:43094464:G>A (rs80357906)\n",
        encoding="utf-8",
    )

    # 5. Low-confidence ambiguous reference file (triggers PENDING_REVIEW hold)
    low_conf_doc = fileshare / "unverified_notes_ambiguous.txt"
    low_conf_doc.write_text(
        "Legacy Archive Notes\n"
        "Reference marker: AMBIGUOUS_REF_9042\n",
        encoding="utf-8",
    )

    # 6. Relational database with 3 tables: public_catalog, customer_contacts, patient_biomarkers
    db_path = root / "synthetic_estate.db"
    if db_path.exists():
        db_path.unlink()
    db_url = f"sqlite:///{db_path.as_posix()}"
    engine = create_engine(db_url)
    with engine.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE public_catalog ("
                "  sku_id TEXT PRIMARY KEY,"
                "  title TEXT NOT NULL,"
                "  category TEXT NOT NULL"
                ")"
            )
        )
        conn.execute(
            text(
                "INSERT INTO public_catalog (sku_id, title, category) VALUES "
                "('SKU-001', 'Standard Gateway Adapter', 'Software'),"
                "('SKU-002', 'Open Schema Validator', 'Tooling')"
            )
        )

        conn.execute(
            text(
                "CREATE TABLE customer_contacts ("
                "  customer_id TEXT PRIMARY KEY,"
                "  email TEXT NOT NULL,"
                "  phone TEXT NOT NULL"
                ")"
            )
        )
        conn.execute(
            text(
                "INSERT INTO customer_contacts (customer_id, email, phone) VALUES "
                "('CUST-101', 'buyer.one@example.com', '212-555-0181'),"
                "('CUST-102', 'buyer.two@example.com', '212-555-0182')"
            )
        )

        conn.execute(
            text(
                "CREATE TABLE patient_biomarkers ("
                "  subject_id TEXT PRIMARY KEY,"
                "  ssn TEXT NOT NULL,"
                "  mrn TEXT NOT NULL,"
                "  variant_id TEXT NOT NULL"
                ")"
            )
        )
        conn.execute(
            text(
                "INSERT INTO patient_biomarkers (subject_id, ssn, mrn, variant_id) VALUES "
                "('SUBJ-01', '521-44-8192', 'MRN-7710293', 'rs121913529')"
            )
        )
    engine.dispose()

    return {
        "root_dir": str(root),
        "fileshare_dir": str(fileshare),
        "db_url": db_url,
        "files": {
            "public": str(pub_doc),
            "internal": str(int_doc),
            "confidential_xlsx": str(conf_xlsx),
            "restricted": str(rest_doc),
            "low_confidence": str(low_conf_doc),
        },
        "expected_tiers": {
            "file://estate/fileshare/product_overview_public.md": "Public",
            "file://estate/fileshare/engineering_runbook_internal.txt": "Internal",
            "file://estate/fileshare/dept_compensation_confidential.xlsx": "Confidential",
            "file://estate/fileshare/clinical_intake_restricted.txt": "Restricted",
            "postgres://estate-db:5432/estate/public/public_catalog": "Public",
            "postgres://estate-db:5432/estate/public/customer_contacts": "Confidential",
            "postgres://estate-db:5432/estate/public/patient_biomarkers": "Restricted",
        },
    }
