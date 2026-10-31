"""Document and spreadsheet extraction via Apache Tika (with deterministic local extraction for spreadsheets/docs)."""

from __future__ import annotations

import csv
import io
import json
import os
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

try:
    import openpyxl

    HAS_OPENPYXL = True
except ImportError:
    HAS_OPENPYXL = False

from registry.signing import (
    compute_extracted_text_and_chunk_hashes,
    compute_file_sha256,
    normalize_canonical_text,
)


@dataclass
class ExtractedDocument:
    """Extracted text, metadata, and cryptographic integrity fingerprint for a file object."""

    locator: str
    file_path: Path
    object_type: str
    content_sha256: str
    size_bytes: int
    row_count: int | None
    text: str
    metadata: dict[str, Any]
    extractor_used: str
    extracted_text_sha256: str = ""
    chunk_hashes: list[str] = field(default_factory=list)


class TikaDocumentExtractor:
    """Extracts text and metadata from documents and spreadsheets via Apache Tika Server (or local Tika/XML fallback)."""

    def __init__(self, tika_server_url: str | None = None, timeout: float = 2.0) -> None:
        raw_url = tika_server_url or os.environ.get("TIKA_SERVER_ENDPOINT", "")
        self.tika_server_url = raw_url.rstrip("/") if raw_url else ""
        self.timeout = timeout

    def extract_file(self, file_path: str | Path, locator_prefix: str = "file://") -> ExtractedDocument:
        path = Path(file_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {path}")

        content_sha256 = compute_file_sha256(path)
        size_bytes = path.stat().st_size
        suffix = path.suffix.lower()

        if suffix in (".xlsx", ".csv", ".tsv"):
            object_type = "spreadsheet"
        elif suffix in (".pdf", ".docx", ".doc", ".pptx", ".odt", ".rtf", ".md", ".txt"):
            object_type = "document"
        else:
            object_type = "file"

        # Normalize path into canonical URI
        posix_path = path.as_posix()
        if not posix_path.startswith("/"):
            posix_path = "/" + posix_path
        locator = f"{locator_prefix.rstrip('/')}{posix_path}" if locator_prefix == "file://" else locator_prefix

        # 1. Try Apache Tika Server REST endpoint (/rmeta/text) if reachable
        tika_result = self._try_tika_server(path)
        if tika_result is not None:
            text, meta, row_count = tika_result
            extracted_text_sha256, chunk_hashes = compute_extracted_text_and_chunk_hashes(text)
            return ExtractedDocument(
                locator=locator,
                file_path=path,
                object_type=object_type,
                content_sha256=content_sha256,
                size_bytes=size_bytes,
                row_count=row_count,
                text=text,
                metadata=meta,
                extractor_used="apache-tika-server",
                extracted_text_sha256=extracted_text_sha256,
                chunk_hashes=chunk_hashes,
            )

        # 2. Deterministic content extraction for spreadsheets (.xlsx, .csv) and documents (.docx, .txt, .md, .json)
        text, meta, row_count = self._extract_local_content(path, suffix)
        extracted_text_sha256, chunk_hashes = compute_extracted_text_and_chunk_hashes(text)
        return ExtractedDocument(
            locator=locator,
            file_path=path,
            object_type=object_type,
            content_sha256=content_sha256,
            size_bytes=size_bytes,
            row_count=row_count,
            text=text,
            metadata=meta,
            extractor_used="apache-tika-local",
            extracted_text_sha256=extracted_text_sha256,
            chunk_hashes=chunk_hashes,
        )

    def _try_tika_server(self, path: Path) -> tuple[str, dict[str, Any], int | None] | None:
        if not self.tika_server_url:
            return None
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.put(
                    f"{self.tika_server_url}/rmeta/text",
                    content=path.read_bytes(),
                    headers={"Accept": "application/json"},
                )
                if resp.status_code == 200:
                    items = resp.json()
                    if isinstance(items, list) and items:
                        texts = [item.get("X-TIKA:content", "") for item in items]
                        full_text = "\n".join(t.strip() for t in texts if t and t.strip())
                        meta = {
                            k: v
                            for k, v in items[0].items()
                            if not k.startswith("X-TIKA:")
                        }
                        return full_text, meta, None
        except Exception:
            return None
        return None

    def _extract_local_content(self, path: Path, suffix: str) -> tuple[str, dict[str, Any], int | None]:
        meta: dict[str, Any] = {"Content-Name": path.name, "File-Extension": suffix}
        row_count: int | None = None

        if suffix == ".xlsx" and HAS_OPENPYXL:
            wb = openpyxl.load_workbook(path, data_only=True, read_only=True)
            lines: list[str] = []
            total_rows = 0
            for sheet_name in wb.sheetnames:
                ws = wb[sheet_name]
                lines.append(f"[Sheet: {sheet_name}]")
                for row in ws.iter_rows(values_only=True):
                    cells = [str(c) for c in row if c is not None and str(c).strip() != ""]
                    if cells:
                        total_rows += 1
                        lines.append(" | ".join(cells))
            wb.close()
            meta["Sheet-Count"] = len(wb.sheetnames)
            return "\n".join(lines), meta, total_rows

        if suffix in (".csv", ".tsv"):
            raw = path.read_text(encoding="utf-8", errors="replace")
            delim = "\t" if suffix == ".tsv" else ","
            reader = csv.reader(io.StringIO(raw), delimiter=delim)
            rows = list(reader)
            row_count = max(0, len(rows) - 1) if rows else 0
            text = "\n".join(" | ".join(r) for r in rows)
            return text, meta, row_count

        if suffix == ".docx" and zipfile.is_zipfile(path):
            with zipfile.ZipFile(path, "r") as zf:
                if "word/document.xml" in zf.namelist():
                    xml_bytes = zf.read("word/document.xml")
                    try:
                        root = ET.fromstring(xml_bytes)
                    except ET.ParseError:
                        import re as _re

                        xml_str = xml_bytes.decode("utf-8", errors="replace")
                        sanitized = _re.sub(
                            r"&(?!(?:amp|lt|gt|apos|quot|#\d+|#x[0-9a-fA-F]+);)",
                            "&amp;",
                            xml_str,
                        )
                        root = ET.fromstring(sanitized.encode("utf-8"))
                    texts = [elem.text.strip() for elem in root.iter() if elem.text and elem.text.strip()]
                    return "\n".join(texts), meta, None

        if suffix == ".json":
            raw = path.read_text(encoding="utf-8", errors="replace")
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, list):
                    row_count = len(parsed)
            except Exception:
                pass
            return raw, meta, row_count

        return path.read_text(encoding="utf-8", errors="replace"), meta, None
