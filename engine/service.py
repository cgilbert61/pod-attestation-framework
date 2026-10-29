"""Long-running Attestation Engine Service: continuous discovery/re-scan daemon, PC directory attestation API, OpenLineage intake webhook, and on-demand scan API."""

from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, AsyncIterator

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from engine.directory_bridge import (
    decode_uploaded_files_to_temp,
    discover_selectable_drives_and_directories,
    ensure_sample_pc_demo_folder,
    iter_scannable_files,
    list_pc_subdirectories,
    resolve_pc_directory_path,
)
from engine.dlp_connectors import (
    PurviewMultiCloudConnector,
    create_purview_labeled_docx,
    extract_purview_label_from_file,
)
from engine.pipeline import AttestationEngine
from examples.docker_bootstrap import main as run_bootstrap
from registry.schema_validator import format_iso8601
from registry.store import RegistryService
from snapshot.publisher import SnapshotPublisher


class UploadedFileItem(BaseModel):
    relative_path: str
    content_b64: str


class AttestDirectoryRequest(BaseModel):
    directory_path: str | None = None
    files: list[UploadedFileItem] | None = None
    owner: str = "pc-folder-owner@example.org"
    max_files: int = 120


def _build_selectable_directory_enum() -> Any:
    items = discover_selectable_drives_and_directories()
    members: dict[str, str] = {}
    for idx, item in enumerate(items):
        p = item["path"]
        members[f"OPT_{idx}"] = p
    if not members:
        members["DEFAULT"] = "C:\\Users\\chuck\\pc_demo_folder"
    return Enum("SelectDirectoryOrDrive", members, type=str)


SelectableDirectoryEnum = _build_selectable_directory_enum()
DEFAULT_SELECTABLE_DIR = list(SelectableDirectoryEnum)[0]


class AddUnattestedFileRequest(BaseModel):
    directory_path: str = "D:\\attestation\\pc_demo_folder"
    filename: str | None = None
    content: str | None = None


class EngineDaemonState:
    def __init__(self) -> None:
        self.last_scan_at: str | None = None
        self.scans_completed: int = 0
        self.lineage_events_ingested: int = 0


def create_engine_app() -> FastAPI:
    db_url = os.environ.get("POD_REGISTRY_DB_URL", "postgresql+psycopg2://pod:pod_password@postgres:5432/pod_registry")
    key_dir = Path(os.environ.get("POD_KEY_DIR", "/var/lib/pod/keys"))
    snapshot_file = Path(os.environ.get("POD_SNAPSHOT_FILE", "/var/lib/pod/snapshots/pod_snapshot.dsse.json"))
    estate_dir = Path(os.environ.get("POD_ESTATE_DIR", "/var/lib/pod/data/estate"))
    prevalidator_url = os.environ.get("POD_PREVALIDATOR_URL", "http://prevalidator:8082")
    admin_key = os.environ.get("POD_ADMIN_API_KEY", "pod-dev-admin-key")
    scan_interval = int(os.environ.get("POD_SCAN_INTERVAL_SECONDS", "60"))

    registry = RegistryService(db_url=db_url, key_dir=key_dir)
    engine = AttestationEngine(registry=registry)
    dlp_connector = PurviewMultiCloudConnector(registry=registry, classifier=engine.classifier)
    publisher = SnapshotPublisher(registry=registry, ttl_seconds=3600, snapshot_output_path=snapshot_file)
    state = EngineDaemonState()

    def _publish_and_reload_prevalidator() -> dict[str, Any]:
        env = publisher.publish_snapshot()
        try:
            with httpx.Client(timeout=5.0) as client:
                client.post(
                    f"{prevalidator_url.rstrip('/')}/v1/admin/reload-snapshot",
                    headers={"X-POD-Admin-Key": admin_key},
                    json={"envelope": env},
                )
        except Exception:
            pass
        return env

    def _run_scan_cycle() -> dict[str, Any]:
        fileshare_dir = estate_dir / "fileshare"
        sqlite_db = estate_dir / "synthetic_estate.db"
        f_res = []
        d_res = []
        if fileshare_dir.is_dir():
            f_res = engine.crawl_file_share(
                root_dir=fileshare_dir,
                owner="fileshare-steward@example.org",
                locator_base="file://estate/fileshare",
                environment="production",
            )
        if sqlite_db.is_file():
            d_res = engine.crawl_database(
                db_url=f"sqlite:///{sqlite_db.as_posix()}",
                owner="data-platform@example.org",
                locator_override_base="postgres://estate-db:5432/estate",
                environment="production",
            )
        _publish_and_reload_prevalidator()
        state.last_scan_at = format_iso8601(datetime.now(timezone.utc))
        state.scans_completed += 1
        return {"files_checked": len(f_res), "tables_checked": len(d_res), "last_scan_at": state.last_scan_at}

    async def _periodic_loop() -> None:
        while True:
            await asyncio.sleep(scan_interval)
            try:
                await asyncio.to_thread(_run_scan_cycle)
            except Exception:
                pass

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        # Ensure sample disparate PC demo folder exists on the live-mounted Windows user folder and workspace
        host_user = Path("/host_user")
        if host_user.is_dir():
            ensure_sample_pc_demo_folder(host_user / "pc_demo_folder")
        host_ws = Path("/host_workspace")
        if host_ws.is_dir():
            ensure_sample_pc_demo_folder(host_ws / "pc_demo_folder")
        await asyncio.to_thread(run_bootstrap)
        state.last_scan_at = format_iso8601(datetime.now(timezone.utc))
        state.scans_completed = 1
        task = asyncio.create_task(_periodic_loop())
        try:
            yield
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
            registry.close()

    app = FastAPI(title="G1 Docket by G1163RT Security Labs — Attestation Engine Service", version="0.1.0", lifespan=lifespan)

    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        return RedirectResponse(url="/docs")

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": "pod-attestation-engine",
            "scans_completed": state.scans_completed,
            "last_scan_at": state.last_scan_at,
            "lineage_events_ingested": state.lineage_events_ingested,
        }

    @app.get("/v1/browse-dir")
    def browse_pc_dir(
        path: SelectableDirectoryEnum = Query(  # type: ignore[valid-type]
            default=DEFAULT_SELECTABLE_DIR,
            description="Select an entire drive (C:\\, D:\\) or any directory on your PC from the dropdown.",
        ),
    ) -> dict[str, Any]:
        """Select any drive (C:\\ or D:\\) or directory on the user's PC from the select box and return its subdirectories and direct file count."""
        try:
            raw_val = path.value if isinstance(path, Enum) else str(path)
            return list_pc_subdirectories(raw_val)
        except Exception as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/v1/attest-selected")
    def attest_selected_drive_or_directory(
        directory_or_drive: SelectableDirectoryEnum = Query(  # type: ignore[valid-type]
            default=DEFAULT_SELECTABLE_DIR,
            description="Select an entire drive (C:\\, D:\\) or directory from the dropdown to scan and attest.",
        ),
        max_files: int = Query(default=120, ge=1, le=1000, description="Maximum files to scan when pointing at an entire drive or large folder."),
    ) -> dict[str, Any]:
        """Select an entire drive (C:\\, D:\\) or any directory from the select box and run the Attestation Engine on it."""
        raw_val = directory_or_drive.value if isinstance(directory_or_drive, Enum) else str(directory_or_drive)
        return attest_directory(AttestDirectoryRequest(directory_path=raw_val, max_files=max_files))

    @app.get("/v1/pc-folders")
    def list_pc_folders() -> dict[str, Any]:
        """List all selectable drives (C:\\, D:\\) and directories on the PC for the GUI `<select>` dropdown."""
        user_dir = Path("/host_user")
        if user_dir.is_dir():
            ensure_sample_pc_demo_folder(user_dir / "pc_demo_folder")
        ws = Path("/host_workspace")
        if ws.is_dir():
            ensure_sample_pc_demo_folder(ws / "pc_demo_folder")
        return {"folders": discover_selectable_drives_and_directories()}

    @app.post("/v1/attest-directory")
    def attest_directory(req: AttestDirectoryRequest) -> dict[str, Any]:
        """Crawl a directory or entire drive of disparate files (by PC path or browser folder picker upload), classify and issue signed records, and publish a fresh snapshot."""
        temp_dir: Path | None = None
        try:
            if req.files:
                temp_dir = Path(tempfile.mkdtemp(prefix="pod_upload_attest_"))
                target_dir, locator_base = decode_uploaded_files_to_temp(
                    [f.model_dump() for f in req.files],
                    temp_dir,
                )
            elif req.directory_path:
                target_dir, locator_base = resolve_pc_directory_path(req.directory_path)
            else:
                raise HTTPException(status_code=400, detail="Provide either directory_path or files.")

            crawl_results = engine.crawl_file_share(
                root_dir=target_dir,
                owner=req.owner,
                locator_base=locator_base,
                environment="production",
                max_files=req.max_files,
            )
            env = _publish_and_reload_prevalidator()
            state.last_scan_at = format_iso8601(datetime.now(timezone.utc))
            state.scans_completed += 1

            attested_items: list[dict[str, Any]] = []
            held_for_review = 0
            for item in crawl_results:
                rec = item.get("record")
                rev = item.get("review")
                if rec:
                    attested_items.append(
                        {
                            "locator": rec["locator"],
                            "file_name": rec["locator"].rsplit("/", 1)[-1],
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
            exts: set[str] = set()
            for f in attested_items:
                t = f.get("tier")
                if t in tier_counts and f.get("status") != "PENDING_REVIEW (Unissued)":
                    tier_counts[t] += 1
                fname = f.get("file_name", "")
                if "." in fname:
                    exts.add("." + fname.rsplit(".", 1)[-1].lower())

            ext_list = ", ".join(sorted(exts)) if exts else "various"
            dir_label = req.directory_path or locator_base
            english_summary = (
                f"Attestation Engine scanned directory '{dir_label}': Found {len(crawl_results)} total file(s) "
                f"across {len(exts) or 1} file type(s) ({ext_list}). "
                f"Issued {active_count} signed attestation record(s) "
                f"({tier_counts['Public']} Public, {tier_counts['Internal']} Internal, "
                f"{tier_counts['Confidential']} Confidential, {tier_counts['Restricted']} Restricted) "
                f"and held {held_for_review} file(s) in human review."
            )

            return {
                "directory": dir_label,
                "locator_base": locator_base,
                "total_files_found": len(crawl_results),
                "attested_active_count": active_count,
                "held_in_review_count": held_for_review,
                "tier_counts": tier_counts,
                "english_summary": english_summary,
                "snapshot_signatures": env.get("signatures", []),
                "files": attested_items,
            }
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        finally:
            if temp_dir and temp_dir.exists():
                shutil.rmtree(temp_dir, ignore_errors=True)

    @app.post("/v1/demo-folder/add-unattested")
    def add_unattested_file(req: AddUnattestedFileRequest) -> dict[str, Any]:
        """Drop a new unattested file into the target PC directory WITHOUT attesting it, so the user can see the Prevalidator catch and block it."""
        try:
            target_dir, locator_base = resolve_pc_directory_path(req.directory_path)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

        fname = req.filename or f"unattested_drop_{uuid.uuid4().hex[:6]}.txt"
        body = (
            req.content
            or f"Unattested file added at {format_iso8601(datetime.now(timezone.utc))}.\n"
            "This file exists on disk in the directory, but has NO signed record in the Registry or Snapshot.\n"
        )
        new_file = target_dir / fname
        new_file.write_text(body, encoding="utf-8")
        return {
            "created": True,
            "file_name": fname,
            "host_directory": req.directory_path,
            "expected_locator": f"{locator_base}/{fname}",
        }

    @app.get("/v1/dlp/config")
    def get_dlp_config() -> dict[str, Any]:
        return dlp_connector.get_public_config()

    @app.post("/v1/dlp/config")
    def update_dlp_config(payload: dict[str, Any]) -> dict[str, Any]:
        return dlp_connector.update_config(payload)

    @app.post("/v1/dlp/stage1-inspect-labels")
    def dlp_stage1_inspect_labels(payload: dict[str, Any]) -> dict[str, Any]:
        """Stage 1 (Labels-First Fast Lane): Read embedded Purview / MIP sensitivity labels off files in a directory."""
        raw_dir = payload.get("directory_path") or "C:\\Users\\chuck\\pc_demo_folder"
        try:
            target_dir, locator_base = resolve_pc_directory_path(raw_dir)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

        inspected: list[dict[str, Any]] = []
        labeled_count = 0
        for fpath in iter_scannable_files(target_dir, max_files=100):
            res = extract_purview_label_from_file(fpath)
            rel = fpath.relative_to(target_dir).as_posix()
            if res.has_label:
                labeled_count += 1
            inspected.append(
                {
                    "file_name": rel,
                    "locator": f"{locator_base.rstrip('/')}/{rel}",
                    "has_label": res.has_label,
                    "raw_label_name": res.raw_label_name or "No Embedded Label",
                    "label_guid": res.label_guid or "-",
                    "mapped_tier": res.mapped_tier or "Fallback to Presidio Content Scan",
                    "source_property": res.source_property or "-",
                }
            )
        summary = (
            f"Stage 1 (Labels-First Fast Lane) scanned {len(inspected)} file(s) in '{raw_dir}': "
            f"Found {labeled_count} file(s) with embedded Microsoft Purview / MIP sensitivity labels (mapped 1:1 to G1 Docket tiers with zero API calls) "
            f"and {len(inspected) - labeled_count} unlabeled file(s) routed to Presidio content recognizers."
        )
        return {
            "directory": raw_dir,
            "total_files": len(inspected),
            "labeled_files_count": labeled_count,
            "english_summary": summary,
            "files": inspected,
        }

    @app.post("/v1/dlp/stage1-stamp-sample")
    def dlp_stage1_stamp_sample(payload: dict[str, Any]) -> dict[str, Any]:
        """Create a new .docx file stamped with an authentic Microsoft Purview sensitivity label in the target directory."""
        raw_dir = payload.get("directory_path") or "C:\\Users\\chuck\\pc_demo_folder"
        purview_label = payload.get("purview_label") or "Highly Confidential"
        try:
            target_dir, locator_base = resolve_pc_directory_path(raw_dir)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

        slug = purview_label.lower().replace(" ", "_")
        fname = payload.get("filename") or f"purview_stamped_{slug}_{uuid.uuid4().hex[:4]}.docx"
        out_path = create_purview_labeled_docx(
            target_dir / fname,
            paragraphs=[
                f"Microsoft Purview Sensitivity Label: {purview_label}",
                "Stamped into docProps/custom.xml via MSIP_Label custom property.",
                "G1 Docket Stage 1 reads this label directly off the file with zero tenant API calls.",
            ],
            purview_label_name=purview_label,
        )
        return {
            "created": True,
            "file_name": out_path.name,
            "purview_label": purview_label,
            "directory": raw_dir,
            "locator": f"{locator_base.rstrip('/')}/{out_path.name}",
        }

    @app.post("/v1/dlp/stage2-pull-catalog")
    def dlp_stage2_pull_catalog(payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """Stage 2 (Pull Purview & Multi-Cloud Catalog): Pull classifications across clouds, funnel through evaluate_findings, issue signed records, and publish snapshot."""
        if payload:
            dlp_connector.update_config(payload)
        result = dlp_connector.pull_and_attest_catalog()
        _publish_and_reload_prevalidator()
        state.last_scan_at = format_iso8601(datetime.now(timezone.utc))
        state.scans_completed += 1
        return result

    @app.post("/v1/dlp/stage3-writeback")
    def dlp_stage3_writeback() -> dict[str, Any]:
        """Stage 3 (Catalog Write-Back): Annotate G1 Docket's signed tier, record_id, and expiry back into Purview's Data Map catalog."""
        result = dlp_connector.run_writeback_for_all_catalog_assets()
        _publish_and_reload_prevalidator()
        return {
            "writeback_completed": True,
            "writebacks_performed": result["writebacks_performed"],
            "english_summary": (
                f"Stage 3 Write-Back complete: Annotated {result['writebacks_performed']} signed G1 Docket attestation record(s) "
                f"(tier, record_id, SHA-256, and expiry) back into Microsoft Purview Data Map businessmetadata across "
                f"{len(result['clouds_scanned'])} cloud source(s) ({', '.join(result['clouds_scanned'])})."
            ),
            "writeback_results": result.get("writeback_results", []),
            "writeback_history": dlp_connector.writeback_history[-20:],
            "sync_summary": result,
        }

    @app.post("/v1/scan")
    def trigger_scan() -> dict[str, Any]:
        return _run_scan_cycle()

    @app.post("/v1/lineage")
    def ingest_openlineage(event: dict[str, Any]) -> dict[str, Any]:
        count = engine.ingest_openlineage_event(event)
        state.lineage_events_ingested += 1
        return {"ingested": True, "links_recorded": count}

    return app
