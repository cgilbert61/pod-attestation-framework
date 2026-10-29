"""Host directory path translator, interactive PC directory browser, and disparate file generator."""

from __future__ import annotations

import base64
import hashlib
import os
import re
import zipfile
from pathlib import Path
from typing import Any

import openpyxl

SKIP_DIR_NAMES: frozenset[str] = frozenset(
    {
        "$recycle.bin",
        "$sysreset",
        "$windows.~bt",
        "$windows.~ws",
        "system volume information",
        "windows",
        "program files",
        "program files (x86)",
        "programdata",
        "perflogs",
        "recovery",
        "onedrivetemp",
        "intel",
        "esd",
        "appdata",
        "application data",
        "local settings",
        "cookies",
        "nethood",
        "printhood",
        "recent",
        "sendto",
        "start menu",
        "templates",
        "saved games",
        "searches",
        "documents and settings",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".git",
        ".pytest_cache",
        "anaconda3",
        "anaconda3test",
        ".conda",
        ".anaconda",
        ".cache",
        ".local",
        ".npm",
        ".docker",
        ".kube",
        ".lmstudio",
        "go",
        "python314",
        "pod_attestation.egg-info",
    }
)

SKIP_FILE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".dll",
        ".exe",
        ".sys",
        ".msi",
        ".cab",
        ".zip",
        ".tar",
        ".gz",
        ".7z",
        ".whl",
        ".pyc",
        ".pyd",
        ".so",
        ".iso",
        ".vhd",
        ".vhdx",
        ".blf",
        ".regtrans-ms",
        ".tmp",
    }
)

MAX_SCANNABLE_FILE_BYTES = 8 * 1024 * 1024  # 8 MB cap per file during directory/drive scans


def iter_scannable_files(root: Path, max_files: int = 120) -> list[Path]:
    """Safely walk a directory or an entire drive (`C:\\`, `D:\\`), skipping OS/system/virtualenv folders and locked files."""
    collected: list[Path] = []
    if not root.is_dir():
        return collected

    for dirpath, dirnames, filenames in os.walk(root, topdown=True, onerror=lambda _e: None):
        # Prune skipped, hidden, and system directories in-place
        kept_dirs: list[str] = []
        for d in sorted(dirnames, key=str.lower):
            if d.startswith(".") or d.startswith("$"):
                continue
            if d.lower() in SKIP_DIR_NAMES:
                continue
            kept_dirs.append(d)
        dirnames[:] = kept_dirs

        for fname in sorted(filenames, key=str.lower):
            if fname.startswith(".") or fname.startswith("$") or fname.startswith("~"):
                continue
            lower_f = fname.lower()
            if lower_f.startswith("ntuser.") or lower_f in ("hiberfil.sys", "pagefile.sys", "swapfile.sys", "dumpstack.log"):
                continue
            ext = Path(fname).suffix.lower()
            if ext in SKIP_FILE_EXTENSIONS:
                continue
            fpath = Path(dirpath) / fname
            try:
                if not fpath.is_file() or fpath.is_symlink():
                    continue
                size = fpath.stat().st_size
                if size > MAX_SCANNABLE_FILE_BYTES:
                    continue
            except OSError:
                continue
            collected.append(fpath)
            if len(collected) >= max_files:
                return collected

    return collected


def discover_selectable_drives_and_directories() -> list[dict[str, str]]:
    """Return all selectable drives (`C:\\`, `D:\\`) and user/project directories on the PC for `<select>` dropdowns."""
    items: list[dict[str, str]] = []
    seen_paths: set[str] = set()

    def _add(path_str: str, label: str) -> None:
        key = path_str.lower().rstrip("\\")
        if key not in seen_paths:
            seen_paths.add(key)
            items.append({"path": path_str, "label": label})

    # 1. Featured Demo & User Directories
    _add(
        "C:\\Users\\chuck\\pc_demo_folder",
        "📁 C:\\Users\\chuck\\pc_demo_folder — Sample Disparate Files (.md, .json, .txt, .docx, .xlsx, .csv)",
    )
    _add(
        "D:\\attestation\\pc_demo_folder",
        "📁 D:\\attestation\\pc_demo_folder — Sample Disparate Files",
    )

    # 2. Entire Drives
    _add("C:\\", "🖴 C:\\ — Entire C: Drive (Recursive Data Scan)")
    _add("D:\\", "🖴 D:\\ — Entire D: Drive (Recursive Data Scan)")

    # 3. Standard User Profile Directories
    user_mount = Path("/host_user") if Path("/host_user").is_dir() else Path("C:/Users/chuck")
    if user_mount.is_dir():
        _add("C:\\Users\\chuck", "📁 C:\\Users\\chuck (User Home Root)")
        for std_sub in ("Desktop", "Documents", "Downloads", "OneDrive"):
            if (user_mount / std_sub).is_dir():
                _add(f"C:\\Users\\chuck\\{std_sub}", f"📁 C:\\Users\\chuck\\{std_sub}")

    # 4. Discover Project Directories in D:\attestation and D:\
    d_ws = Path("/host_workspace") if Path("/host_workspace").is_dir() else Path("D:/attestation")
    if d_ws.is_dir():
        _add("D:\\attestation", "📁 D:\\attestation (POD Framework Workspace)")
        try:
            for child in sorted(d_ws.iterdir(), key=lambda p: p.name.lower()):
                if child.is_dir() and not child.name.startswith(".") and child.name.lower() not in SKIP_DIR_NAMES:
                    _add(f"D:\\attestation\\{child.name}", f"📁 D:\\attestation\\{child.name}")
        except OSError:
            pass

    d_root = Path("/host_d") if Path("/host_d").is_dir() else Path("D:/")
    if d_root.is_dir():
        try:
            for child in sorted(d_root.iterdir(), key=lambda p: p.name.lower()):
                if child.is_dir() and not child.name.startswith(".") and child.name.lower() not in SKIP_DIR_NAMES:
                    _add(f"D:\\{child.name}", f"📁 D:\\{child.name}")
        except OSError:
            pass

    # 5. Discover Top-Level Project Directories on C:\
    c_root = Path("/host_c") if Path("/host_c").is_dir() else Path("C:/")
    if c_root.is_dir():
        try:
            for child in sorted(c_root.iterdir(), key=lambda p: p.name.lower()):
                try:
                    if (
                        child.is_dir()
                        and not child.name.startswith(".")
                        and not child.name.startswith("$")
                        and child.name.lower() not in SKIP_DIR_NAMES
                        and child.name.lower() != "users"
                    ):
                        _add(f"C:\\{child.name}", f"📁 C:\\{child.name}")
                except OSError:
                    continue
        except OSError:
            pass

    # 6. Discover User Project Directories in C:\Users\chuck
    if user_mount.is_dir():
        try:
            for child in sorted(user_mount.iterdir(), key=lambda p: p.name.lower()):
                try:
                    if (
                        child.is_dir()
                        and not child.name.startswith(".")
                        and not child.name.startswith("$")
                        and child.name.lower() not in SKIP_DIR_NAMES
                    ):
                        _add(f"C:\\Users\\chuck\\{child.name}", f"📁 C:\\Users\\chuck\\{child.name}")
                except OSError:
                    continue
        except OSError:
            pass

    return items


def resolve_pc_directory_path(raw_path: str) -> tuple[Path, str]:
    """Translate any Windows host path (`D:\\...`, `C:\\...`) to the mounted path inside the container
    (or direct path on host), returning `(resolved_path, canonical_locator_prefix)`.
    """
    cleaned = raw_path.strip().strip('"').strip("'")
    norm_slashes = cleaned.replace("\\", "/")

    # Compute a deterministic canonical locator base from the full normalized Windows path
    slug = re.sub(r"[^a-zA-Z0-9_.-]+", "_", norm_slashes.strip("/")).strip("_") or "root"
    locator_base = f"file://pc-dir/{slug}"

    lower_norm = norm_slashes.lower().rstrip("/")

    # Alias pc_demo_folder on either C:\Users\chuck\pc_demo_folder or D:\attestation\pc_demo_folder
    # to the live-mounted /host_user/pc_demo_folder inside Docker so Windows Explorer and Docker share the exact same files
    if lower_norm in ("d:/attestation/pc_demo_folder", "c:/users/chuck/pc_demo_folder"):
        locator_base = "file://pc-dir/pc_demo_folder"
        live_user_demo = Path("/host_user/pc_demo_folder")
        if live_user_demo.exists():
            return live_user_demo, locator_base

    # 1. Direct path exists
    direct = Path(cleaned)
    if direct.exists():
        return direct, locator_base

    # 2. Translate D:/attestation/... -> /host_workspace/...
    if lower_norm.startswith("d:/attestation"):
        sub = norm_slashes[len("d:/attestation") :].lstrip("/")
        candidate = Path("/host_workspace") / sub if sub else Path("/host_workspace")
        if candidate.exists():
            return candidate, locator_base

    # 3. Translate any D:/... -> /host_d/...
    if lower_norm.startswith("d:"):
        sub = norm_slashes[2:].lstrip("/")
        candidate = Path("/host_d") / sub if sub else Path("/host_d")
        if candidate.exists():
            return candidate, locator_base

    # 4. Translate C:/Users/chuck/... -> /host_user/...
    if lower_norm.startswith("c:/users/chuck"):
        sub = norm_slashes[len("c:/users/chuck") :].lstrip("/")
        candidate = Path("/host_user") / sub if sub else Path("/host_user")
        if candidate.exists():
            return candidate, locator_base

    # 5. Translate any C:/... -> /host_c/...
    if lower_norm.startswith("c:"):
        sub = norm_slashes[2:].lstrip("/")
        candidate = Path("/host_c") / sub if sub else Path("/host_c")
        if candidate.exists():
            return candidate, locator_base

    raise FileNotFoundError(
        f"Directory not found on PC: '{raw_path}'. Check the path or use the 'Browse PC Folders' button."
    )


def list_pc_subdirectories(raw_path: str) -> dict[str, Any]:
    """List subdirectories and count files in `raw_path` so the user can browse their PC folders in the GUI."""
    resolved, _ = resolve_pc_directory_path(raw_path)
    if not resolved.is_dir():
        raise NotADirectoryError(f"Not a directory: {raw_path}")

    cleaned = raw_path.strip().replace("/", "\\")
    if len(cleaned) == 2 and cleaned[1] == ":":
        cleaned += "\\"

    # Determine parent Windows path
    norm = cleaned.rstrip("\\")
    if "\\" in norm:
        parent_win = norm.rsplit("\\", 1)[0]
        if len(parent_win) == 2 and parent_win[1] == ":":
            parent_win += "\\"
    else:
        parent_win = None

    subdirs: list[dict[str, Any]] = []
    direct_files: list[str] = []

    try:
        for entry in sorted(resolved.iterdir(), key=lambda p: p.name.lower()):
            if entry.name.startswith(".") or entry.name.startswith("$"):
                continue
            try:
                if entry.is_dir():
                    win_child = f"{cleaned.rstrip(chr(92))}\\{entry.name}"
                    subdirs.append({"name": entry.name, "path": win_child})
                elif entry.is_file():
                    direct_files.append(entry.name)
            except PermissionError:
                continue
    except PermissionError:
        pass

    return {
        "current_path": cleaned,
        "parent_path": parent_win,
        "direct_file_count": len(direct_files),
        "sample_files": direct_files[:15],
        "subdirectories": subdirs[:100],
    }


def _create_minimal_docx(path: Path, paragraphs: list[str]) -> None:
    """Create a valid `.docx` Word document containing `paragraphs`."""
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        "</Types>"
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="word/document.xml"/>'
        "</Relationships>"
    )
    body_xml = "".join(f"<w:p><w:r><w:t>{p}</w:t></w:r></w:p>" for p in paragraphs)
    document_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body>{body_xml}</w:body>"
        "</w:document>"
    )
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", rels)
        zf.writestr("word/document.xml", document_xml)


def ensure_sample_pc_demo_folder(target_dir: str | Path) -> Path:
    """Create a sample folder with disparate file types (.md, .txt, .csv, .xlsx, .docx, .json) if it doesn't exist."""
    root = Path(target_dir)
    root.mkdir(parents=True, exist_ok=True)

    (root / "01_public_release_notes.md").write_text(
        "# Release Notes v2.4\n\n"
        "Public feature summary and general availability documentation for customers.\n",
        encoding="utf-8",
    )

    (root / "02_model_routing_config.json").write_text(
        '{\n  "service": "ai-gateway",\n  "timeout_ms": 5000,\n  "retry_count": 2\n}\n',
        encoding="utf-8",
    )

    (root / "03_internal_cluster_ops.txt").write_text(
        "INTERNAL-ONLY Infrastructure Runbook\n"
        "Project Identifier: PROJ-KUBE88\n"
        "Internal Node IP: 10.42.19.105\n"
        "On-Call Engineer ID: EMP-77310\n",
        encoding="utf-8",
    )

    _create_docx_path = root / "04_architecture_review_memo.docx"
    if not _create_docx_path.exists():
        _create_minimal_docx(
            _create_docx_path,
            [
                "Architecture Review Board Memo",
                "Approved for public and internal reference.",
                "Standard API contract version 0.1.",
            ],
        )

    xlsx_path = root / "05_vendor_contacts_confidential.xlsx"
    if not xlsx_path.exists():
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Contacts"
        ws.append(["vendor_id", "contact_email", "phone", "contract_note"])
        ws.append(["VND-01", "account.exec@example.com", "415-555-0133", "salary: $125,000"])
        wb.save(xlsx_path)
        wb.close()

    (root / "06_daily_latency_metrics.csv").write_text(
        "date,endpoint,p50_ms,p99_ms\n"
        "2026-10-28,/v1/chat/completions,0.14,0.42\n"
        "2026-10-29,/v1/messages,0.16,0.48\n",
        encoding="utf-8",
    )

    purview_docx_path = root / "07_purview_labeled_board_strategy.docx"
    if not purview_docx_path.exists():
        from engine.dlp_connectors import create_purview_labeled_docx

        create_purview_labeled_docx(
            purview_docx_path,
            paragraphs=[
                "FY27 Corporate Strategy & Board Briefing",
                "This document contains no regex PII patterns, but carries an embedded Microsoft Purview MSIP Sensitivity Label (Confidential) in docProps/custom.xml.",
                "G1 Docket Stage 1 (Labels-First Fast Lane) reads the Purview sensitivity label directly off the file.",
            ],
            purview_label_name="Confidential",
        )

    return root


def decode_uploaded_files_to_temp(
    uploaded_files: list[dict[str, Any]],
    temp_root: Path,
) -> tuple[Path, str]:
    """Materialize browser-picked folder files (`[{relative_path, content_b64}, ...]`) into `temp_root`."""
    temp_root.mkdir(parents=True, exist_ok=True)
    folder_slug = "picked-folder"
    for item in uploaded_files:
        rel = item["relative_path"].replace("\\", "/").lstrip("/")
        parts = rel.split("/")
        if len(parts) > 1:
            folder_slug = parts[0]
            rel_inside = "/".join(parts[1:])
        else:
            rel_inside = parts[0]
        dest = temp_root / rel_inside
        dest.parent.mkdir(parents=True, exist_ok=True)
        raw_bytes = base64.b64decode(item["content_b64"])
        dest.write_bytes(raw_bytes)

    return temp_root, f"file://pc-dir/{folder_slug}"


def compute_bytes_sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
