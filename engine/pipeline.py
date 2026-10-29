"""Attestation Engine orchestrating file-share and database discovery, classification, and Registry issuance."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from engine.classifier import CategoryFinding, PresidioClassifier
from engine.directory_bridge import iter_scannable_files
from engine.dlp_connectors import extract_purview_label_from_file
from engine.extractor import TikaDocumentExtractor
from engine.openlineage_intake import OpenLineageIntake
from engine.openmetadata_connector import OpenMetadataDatabaseScanner
from registry.store import RegistryService


class AttestationEngine:
    """Discovers data across file shares and databases, classifies it, and issues signed records via the Registry."""

    def __init__(
        self,
        registry: RegistryService,
        extractor: TikaDocumentExtractor | None = None,
        classifier: PresidioClassifier | None = None,
        db_scanner: OpenMetadataDatabaseScanner | None = None,
        lineage_intake: OpenLineageIntake | None = None,
        engine_id: str = "pod-engine-v0.1",
    ) -> None:
        self.registry = registry
        self.extractor = extractor or TikaDocumentExtractor()
        self.classifier = classifier or PresidioClassifier()
        self.db_scanner = db_scanner or OpenMetadataDatabaseScanner()
        self.lineage_intake = lineage_intake or OpenLineageIntake()
        self.engine_id = engine_id

    def ingest_openlineage_event(self, event: dict[str, Any]) -> int:
        """Ingest an OpenLineage RunEvent to populate `derived_from` provenance links."""
        links = self.lineage_intake.ingest_event(event)
        return len(links)

    def attest_file(
        self,
        file_path: str | Path,
        owner: str = "data-owners@example.org",
        locator_override: str | None = None,
        environment: str = "production",
        force_rescan: bool = False,
    ) -> dict[str, Any]:
        """Extract, classify, and attest a single file or spreadsheet."""
        doc = self.extractor.extract_file(file_path)
        locator = locator_override or doc.locator

        existing = self.registry.lookup_by_locator(locator, include_expired_or_revoked=False)
        if (
            existing
            and not force_rescan
            and existing["content_sha256"] == doc.content_sha256
            and existing.get("chunk_hashes")
        ):
            return {"action": "unchanged", "record": existing, "review": None}

        # Stage 1 (Labels-First Fast Lane): Read embedded Purview / MIP sensitivity label directly off the file if present
        embedded_label = extract_purview_label_from_file(file_path, doc.metadata)
        findings = self.classifier.scan_text_segment(doc.text)
        metadata_hints: dict[str, Any] = {}
        classifier_engine_label = "presidio"
        source_sys_label = f"{doc.extractor_used}+presidio"
        if embedded_label.has_label and embedded_label.mapped_tier:
            findings.append(
                CategoryFinding(
                    category=f"PURVIEW_LABEL_{embedded_label.mapped_tier.upper()}",
                    count=1,
                    max_confidence=0.99,
                    column_or_field=embedded_label.source_property or "msip_label",
                )
            )
            metadata_hints["default_tier"] = embedded_label.mapped_tier
            metadata_hints["purview_label"] = embedded_label.raw_label_name
            classifier_engine_label = "msip-purview-label+presidio"
            source_sys_label = f"{doc.extractor_used}+msip-purview-label"

        verdict = self.classifier.evaluate_findings(
            findings=findings,
            metadata_hints=metadata_hints,
            classifier_engine=classifier_engine_label,
        )
        derived_from = self.lineage_intake.get_derived_from(locator)

        return self.registry.issue_or_queue_finding(
            locator=locator,
            content_sha256=doc.content_sha256,
            tier=verdict.tier,
            owner=owner,
            confidence=verdict.confidence,
            low_confidence=verdict.low_confidence,
            sensitive_categories=[f.to_dict() for f in verdict.sensitive_categories],
            object_type=doc.object_type,
            display_name=doc.file_path.name,
            environment=environment,
            attested_by=self.engine_id,
            source_system=source_sys_label,
            derived_from=derived_from,
            size_bytes=doc.size_bytes,
            row_count=doc.row_count,
            fingerprint_method="raw_bytes_sha256",
            extracted_text_sha256=doc.extracted_text_sha256,
            chunk_hashes=doc.chunk_hashes,
            classifier_engine=verdict.classifier_engine,
        )

    def crawl_file_share(
        self,
        root_dir: str | Path,
        owner: str = "fileshare-owners@example.org",
        locator_base: str | None = None,
        environment: str = "production",
        max_files: int = 120,
    ) -> list[dict[str, Any]]:
        """Crawl a directory tree or entire drive, extract with Tika, classify with Presidio, and issue/update records."""
        root = Path(root_dir).resolve()
        if not root.is_dir():
            raise NotADirectoryError(f"Directory not found: {root}")

        results: list[dict[str, Any]] = []
        for path in iter_scannable_files(root, max_files=max_files):
            try:
                rel = path.relative_to(root).as_posix()
                loc_override = f"{locator_base.rstrip('/')}/{rel}" if locator_base else None
                res = self.attest_file(
                    file_path=path,
                    owner=owner,
                    locator_override=loc_override,
                    environment=environment,
                )
                results.append(res)
            except Exception:
                continue
        return results

    def crawl_database(
        self,
        db_url: str,
        owner: str = "db-owners@example.org",
        locator_override_base: str | None = None,
        environment: str = "production",
        injected_om_findings: dict[str, list[dict[str, Any]]] | None = None,
    ) -> list[dict[str, Any]]:
        """Crawl a database via OpenMetadata + deterministic schema/row hashing and issue records."""
        tables = self.db_scanner.scan_database(
            db_url=db_url,
            locator_override_base=locator_override_base,
            injected_om_findings=injected_om_findings,
        )
        results: list[dict[str, Any]] = []
        for tbl in tables:
            existing = self.registry.lookup_by_locator(tbl.locator, include_expired_or_revoked=False)
            if existing and existing["content_sha256"] == tbl.content_sha256:
                results.append({"action": "unchanged", "record": existing, "review": None})
                continue

            verdict = self.classifier.classify_columns(
                column_samples=tbl.column_samples,
                openmetadata_findings=tbl.openmetadata_findings,
            )
            lineage_links = self.lineage_intake.get_derived_from(tbl.locator) or tbl.derived_from

            res = self.registry.issue_or_queue_finding(
                locator=tbl.locator,
                content_sha256=tbl.content_sha256,
                schema_sha256=tbl.schema_sha256,
                tier=verdict.tier,
                owner=tbl.owner_hint or owner,
                confidence=verdict.confidence,
                low_confidence=verdict.low_confidence,
                sensitive_categories=[f.to_dict() for f in verdict.sensitive_categories],
                object_type="database_table",
                display_name=f"{tbl.schema_name}.{tbl.table_name}",
                environment=environment,
                attested_by=self.engine_id,
                source_system="openmetadata+presidio",
                derived_from=lineage_links,
                size_bytes=tbl.size_bytes,
                row_count=tbl.row_count,
                fingerprint_method="table_schema_and_canonical_rows_sha256",
                classifier_engine=verdict.classifier_engine,
            )
            results.append(res)
        return results
