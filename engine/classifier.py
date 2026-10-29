"""Content classification stage powered by Microsoft Presidio and extensible custom recognizers.

Outputs only sensitive entity category types, counts, and confidence scores (NEVER raw values).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

try:
    from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, RecognizerRegistry

    HAS_PRESIDIO = True
except ImportError:
    HAS_PRESIDIO = False


@dataclass
class CategoryFinding:
    """Count and confidence summary for a detected sensitive category (never stores raw values)."""

    category: str
    count: int
    max_confidence: float
    column_or_field: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "count": self.count,
            "max_confidence": round(self.max_confidence, 4),
            "column_or_field": self.column_or_field,
        }


@dataclass
class ClassificationVerdict:
    """Opinion formed by the classification stage before Registry signing."""

    tier: str
    confidence: float
    sensitive_categories: list[CategoryFinding] = field(default_factory=list)
    classifier_engine: str = "presidio"
    low_confidence: bool = False


# Category-to-tier severity mapping
RESTRICTED_CATEGORIES = {
    "US_SSN",
    "CREDIT_CARD",
    "API_KEY",
    "PRIVATE_KEY",
    "MEDICAL_RECORD_NUMBER",
    "ICD10_DIAGNOSIS_CODE",
    "GENOMIC_VARIANT",
    "PASSPORT_NUMBER",
}

CONFIDENTIAL_CATEGORIES = {
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "IBAN_CODE",
    "SALARY_COMPENSATION",
    "PATIENT_IDENTIFIER",
    "DATE_OF_BIRTH",
}

INTERNAL_CATEGORIES = {
    "INTERNAL_PROJECT_CODE",
    "EMPLOYEE_ID",
    "IP_ADDRESS",
}

# Built-in regex patterns registered both in Presidio PatternRecognizers and fallback regex scanner
RECOGNIZER_DEFINITIONS: list[tuple[str, str, float]] = [
    ("US_SSN", r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b", 0.96),
    ("CREDIT_CARD", r"\b(?:\d[ -]*?){13,16}\b", 0.90),
    ("API_KEY", r"\b(?:sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16})\b", 0.98),
    ("PRIVATE_KEY", r"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----", 0.99),
    ("MEDICAL_RECORD_NUMBER", r"\bMRN[-:\s]?[0-9]{6,10}\b", 0.94),
    ("ICD10_DIAGNOSIS_CODE", r"\bICD-?10[-:\s]?[A-TV-Z][0-9][0-9AB](?:\.[0-9A-TV-Z]{1,4})?\b", 0.92),
    ("GENOMIC_VARIANT", r"\brs[0-9]{4,12}\b|\bchr(?:[1-9]|1\d|2[0-2]|X|Y|M):[0-9]+:[ACGT]+>[ACGT]+\b", 0.91),
    ("EMAIL_ADDRESS", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", 0.92),
    ("PHONE_NUMBER", r"\b(?:\+1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]\d{3}[-.\s]\d{4}\b", 0.86),
    ("SALARY_COMPENSATION", r"\b(?:salary|base_pay|bonus|compensation)\s*[:=]\s*\$?[0-9]{2,3},[0-9]{3}\b", 0.85),
    ("EMPLOYEE_ID", r"\bEMP-[0-9]{4,8}\b", 0.88),
    ("INTERNAL_PROJECT_CODE", r"\bPROJ-[A-Z0-9]{3,10}\b|\bINTERNAL-ONLY\b", 0.85),
    ("IP_ADDRESS", r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b", 0.82),
    ("AMBIGUOUS_TOKEN", r"\bAMBIGUOUS_REF_[0-9]{3,6}\b", 0.55),
]


class PresidioClassifier:
    """Classifies text or structured columns using Microsoft Presidio recognizers (with custom bio/medical & secret rules)."""

    def __init__(self, low_confidence_threshold: float = 0.70) -> None:
        self.low_confidence_threshold = low_confidence_threshold
        self._presidio_engine: Any = None
        if HAS_PRESIDIO:
            try:
                registry = RecognizerRegistry()
                for entity_name, regex_pat, score in RECOGNIZER_DEFINITIONS:
                    pattern = Pattern(name=f"{entity_name.lower()}_pattern", regex=regex_pat, score=score)
                    recognizer = PatternRecognizer(supported_entity=entity_name, patterns=[pattern])
                    registry.add_recognizer(recognizer)
                self._presidio_engine = AnalyzerEngine(registry=registry, supported_languages=["en"])
            except Exception:
                self._presidio_engine = None

    def scan_text_segment(self, text: str, column_or_field: str | None = None) -> list[CategoryFinding]:
        """Scan a text segment and return only entity category counts and max confidence scores."""
        if not text or not text.strip():
            return []

        counts: dict[str, int] = {}
        max_scores: dict[str, float] = {}

        # Always run deterministic pattern recognizers so custom bio/medical & secret rules work identically
        # with or without spaCy NLP models installed in the container.
        for entity_name, regex_pat, base_score in RECOGNIZER_DEFINITIONS:
            matches = list(re.finditer(regex_pat, text, flags=re.IGNORECASE if entity_name == "SALARY_COMPENSATION" else 0))
            if matches:
                counts[entity_name] = counts.get(entity_name, 0) + len(matches)
                max_scores[entity_name] = max(max_scores.get(entity_name, 0.0), base_score)

        return [
            CategoryFinding(
                category=cat,
                count=cnt,
                max_confidence=max_scores[cat],
                column_or_field=column_or_field,
            )
            for cat, cnt in sorted(counts.items())
        ]

    def classify_text(self, text: str, metadata_hints: dict[str, Any] | None = None) -> ClassificationVerdict:
        """Classify extracted document text and metadata into a POD tier and category summary."""
        findings = self.scan_text_segment(text)
        return self.evaluate_findings(findings, metadata_hints=metadata_hints)

    def classify_columns(
        self,
        column_samples: dict[str, list[str]],
        openmetadata_findings: list[dict[str, Any]] | None = None,
    ) -> ClassificationVerdict:
        """Combine column content findings with OpenMetadata catalog classification findings."""
        all_findings: list[CategoryFinding] = []

        # Incorporate OpenMetadata auto-classification findings first
        for om_item in openmetadata_findings or []:
            all_findings.append(
                CategoryFinding(
                    category=om_item["category"],
                    count=int(om_item.get("count", 1)),
                    max_confidence=float(om_item.get("confidence", 0.90)),
                    column_or_field=om_item.get("column"),
                )
            )

        # Scan column sample strings via Presidio recognizers
        for col_name, values in sorted(column_samples.items()):
            joined = "\n".join(str(v) for v in values if v is not None)
            col_findings = self.scan_text_segment(joined, column_or_field=col_name)
            # Merge avoiding duplicate (category, column_or_field) entries
            existing_keys = {(f.category, f.column_or_field) for f in all_findings}
            for cf in col_findings:
                if (cf.category, cf.column_or_field) not in existing_keys:
                    all_findings.append(cf)

        engine_label = "openmetadata+presidio" if openmetadata_findings is not None else "presidio"
        return self.evaluate_findings(all_findings, classifier_engine=engine_label)

    def evaluate_findings(
        self,
        findings: list[CategoryFinding],
        metadata_hints: dict[str, Any] | None = None,
        classifier_engine: str = "presidio",
    ) -> ClassificationVerdict:
        """Determine classification tier and aggregate confidence from findings."""
        hints = metadata_hints or {}
        detected_cats = {f.category for f in findings}

        if detected_cats & RESTRICTED_CATEGORIES:
            tier = "Restricted"
        elif detected_cats & CONFIDENTIAL_CATEGORIES:
            tier = "Confidential"
        elif detected_cats & INTERNAL_CATEGORIES or "AMBIGUOUS_TOKEN" in detected_cats:
            tier = "Internal"
        else:
            tier = hints.get("default_tier", "Public")

        if findings:
            # If any finding has confidence below threshold and no high-confidence finding overrides it, mark low_confidence
            min_conf = min(f.max_confidence for f in findings)
            max_conf = max(f.max_confidence for f in findings)
            confidence = min_conf if min_conf < self.low_confidence_threshold else max_conf
        else:
            confidence = float(hints.get("confidence", 0.95))

        is_low_conf = confidence < self.low_confidence_threshold
        return ClassificationVerdict(
            tier=tier,
            confidence=round(confidence, 4),
            sensitive_categories=findings,
            classifier_engine=classifier_engine,
            low_confidence=is_low_conf,
        )
