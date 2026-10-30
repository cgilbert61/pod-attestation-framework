"""Enterprise Continuous Background Delta Crawler (Zero File Limits) & Rolling Snapshot Micro-Publisher.

Implements:
1. Pass 1 — Fast `mtime_ns` / `size_bytes` / `ETag` In-Memory Watermark Delta Filter (Microseconds per file).
2. Pass 2 — Deep SHA-256, Canonical Chunk Digest & Presidio/Purview Classification ONLY on Deltas (New / Modified / Deleted).
3. Rolling Snapshot Micro-Publishing — Flushes and publishes a fresh DSSE Snapshot to the Prevalidator every N delta changes or every few seconds.
4. Real-Time Scanner Ticker Feed — Streams the exact file path currently passing under the scanner head, rolling counters, and files/sec throughput.
"""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import threading
import time
from typing import Any, Callable

from engine.directory_bridge import iter_scannable_files_unbounded, resolve_pc_directory_path
from engine.pipeline import AttestationEngine
from engine.storage_connectors import EnterpriseDataStoreManager, is_enterprise_store_uri
from registry.schema_validator import format_iso8601
from registry.store import RegistryService


@dataclass
class WatermarkEntry:
    """In-memory high-speed delta watermark for a single attested object locator."""

    locator: str
    size_bytes: int
    mtime_ns: int | None
    etag: str | None
    content_sha256: str
    tier: str


class ContinuousDeltaCrawler:
    """Persistent background delta crawler with zero artificial file caps and rolling DSSE micro-publishing."""

    def __init__(
        self,
        registry: RegistryService,
        engine: AttestationEngine,
        store_manager: EnterpriseDataStoreManager,
        publish_snapshot_fn: Callable[[], dict[str, Any]],
        scan_lock: threading.Lock,
    ) -> None:
        self.registry = registry
        self.engine = engine
        self.store_manager = store_manager
        self.publish_snapshot_fn = publish_snapshot_fn
        self.scan_lock = scan_lock

        # Configuration
        self.running: bool = False
        self.include_code_dirs: bool = True
        self.auto_revoke_deleted: bool = True
        self.micro_publish_delta_threshold: int = 15
        self.micro_publish_interval_sec: float = 4.0
        self.pause_between_passes_sec: float = 2.0
        self.throttle_ms_per_file: float = 3.5  # Smooth visual ticker speed while sweeping

        # Configurable scan targets (Drives, Directories, Cloud Lakes, Warehouses)
        self.targets: list[dict[str, Any]] = [
            {
                "id": "target-d-drive",
                "path_or_uri": "D:\\",
                "label": "🖴 D:\\ — Entire D: Drive (Unbounded Recursive Sweep)",
                "kind": "pc_drive",
                "enabled": True,
            },
            {
                "id": "target-user-home",
                "path_or_uri": "C:\\Users\\chuck",
                "label": "📁 C:\\Users\\chuck — User Profile Root (Unbounded Recursive Sweep)",
                "kind": "pc_dir",
                "enabled": True,
            },
            {
                "id": "target-c-drive",
                "path_or_uri": "C:\\",
                "label": "🖴 C:\\ — Entire C: Drive (Full System Data Sweep)",
                "kind": "pc_drive",
                "enabled": False,
            },
            {
                "id": "target-aws-s3",
                "path_or_uri": "s3://contoso-ai-datalake-prod/rag-corpus",
                "label": "☁️ AWS S3 — s3://contoso-ai-datalake-prod/rag-corpus",
                "kind": "cloud_store",
                "enabled": True,
            },
            {
                "id": "target-azure-adls",
                "path_or_uri": "azblob://contosodatalake.blob.core.windows.net/enterprise-knowledge",
                "label": "☁️ Azure ADLS Gen2 — azblob://contosodatalake.../enterprise-knowledge",
                "kind": "cloud_store",
                "enabled": True,
            },
            {
                "id": "target-gcp-gcs",
                "path_or_uri": "gs://contoso-vertex-lake-us/curated-zones",
                "label": "☁️ GCP Cloud Storage — gs://contoso-vertex-lake-us/curated-zones",
                "kind": "cloud_store",
                "enabled": True,
            },
            {
                "id": "target-snowflake",
                "path_or_uri": "snowflake://contoso.us-east-1.snowflakecomputing.com/FINANCE_PROD/PUBLIC",
                "label": "☁️ Snowflake — FINANCE_PROD/PUBLIC Warehouse",
                "kind": "warehouse",
                "enabled": True,
            },
            {
                "id": "target-bigquery",
                "path_or_uri": "bigquery://contoso-gcp-analytics/enterprise_mart",
                "label": "☁️ Google BigQuery — enterprise_mart Dataset",
                "kind": "warehouse",
                "enabled": True,
            },
            {
                "id": "target-postgres",
                "path_or_uri": "postgres://estate-db:5432/estate",
                "label": "☁️ PostgreSQL — Operational Database (postgres://estate-db:5432/estate)",
                "kind": "warehouse",
                "enabled": True,
            },
        ]

        # In-Memory Registry Watermark Index: locator -> WatermarkEntry
        self.watermark_index: dict[str, WatermarkEntry] = {}

        # Live Rolling Telemetry & Ticker Feed
        self.status_label: str = "PAUSED (READY)"
        self.current_target: str = "Idle"
        self.current_file: str = "Click '▶ Start Continuous Enterprise Scanner' to begin zero-limit delta sweep"
        self.current_action: str = "IDLE"
        self.files_swept: int = 0
        self.unchanged_skipped: int = 0
        self.deltas_attested: int = 0
        self.deleted_revoked: int = 0
        self.micro_snapshots_published: int = 0
        self.last_snapshot_seq: int | None = None
        self.pass_number: int = 0
        self.scan_rate_files_per_sec: float = 0.0
        self._rate_window: deque[tuple[float, int]] = deque(maxlen=40)
        self.ticker_feed: deque[dict[str, Any]] = deque(maxlen=45)
        self._pending_deltas_since_publish: int = 0
        self._last_publish_ts: float = time.monotonic()

    def seed_watermarks_from_registry(self) -> int:
        """Load existing active Registry records into the in-memory watermark index at startup."""
        try:
            records = self.registry.list_records(current_only=True)
            for r in records:
                if r.get("status") in ("revoked", "expired"):
                    continue
                loc = r["locator"]
                stmt = r.get("statement", {})
                subj_meta = (stmt.get("predicate") or {}).get("subject_metadata") or {}
                sz = int(subj_meta.get("size_bytes") or 0)
                self.watermark_index[loc] = WatermarkEntry(
                    locator=loc,
                    size_bytes=sz,
                    mtime_ns=None,
                    etag=f'"{r["content_sha256"][:32]}"',
                    content_sha256=r["content_sha256"],
                    tier=r["tier"],
                )
            return len(self.watermark_index)
        except Exception:
            return 0

    def _record_step_rate(self, count: int = 1) -> None:
        now_m = time.monotonic()
        self._rate_window.append((now_m, count))
        while len(self._rate_window) > 1 and (now_m - self._rate_window[0][0]) > 4.0:
            self._rate_window.popleft()
        if len(self._rate_window) >= 2:
            dt = max(0.05, self._rate_window[-1][0] - self._rate_window[0][0])
            total = sum(c for _, c in self._rate_window)
            self.scan_rate_files_per_sec = round(total / dt, 1)

    def _push_ticker(
        self,
        kind: str,
        display_path: str,
        detail: str,
        tier: str | None = None,
        sha256: str | None = None,
    ) -> None:
        now_str = datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]
        self.current_file = display_path
        self.current_action = kind.upper()
        self.ticker_feed.appendleft(
            {
                "timestamp": now_str,
                "kind": kind,  # 'delta' | 'skip' | 'snapshot' | 'revoke'
                "path": display_path,
                "detail": detail,
                "tier": tier,
                "sha256": (sha256[:12] + "…") if sha256 else None,
            }
        )

    def _maybe_micro_publish(self, force: bool = False) -> None:
        if self._pending_deltas_since_publish <= 0 and not force:
            return
        now_m = time.monotonic()
        should_pub = (
            force
            or self._pending_deltas_since_publish >= self.micro_publish_delta_threshold
            or (now_m - self._last_publish_ts) >= self.micro_publish_interval_sec
        )
        if not should_pub:
            return

        flushed = self._pending_deltas_since_publish
        try:
            with self.scan_lock:
                env = self.publish_snapshot_fn()
            self._pending_deltas_since_publish = 0
            self._last_publish_ts = now_m
            self.micro_snapshots_published += 1
            # Extract sequence number if available
            import base64
            import json

            payload_b64 = env.get("payload", "")
            if payload_b64:
                stmt = json.loads(base64.b64decode(payload_b64).decode("utf-8"))
                seq = (stmt.get("predicate") or {}).get("sequence_number")
                if seq is not None:
                    self.last_snapshot_seq = int(seq)
            self._push_ticker(
                kind="snapshot",
                display_path=f"DSSE Snapshot #{self.last_snapshot_seq or self.micro_snapshots_published}",
                detail=f"Flushed {flushed} delta record(s) → Signed & pushed to Prevalidator in-memory gate",
                tier="Public",
            )
        except Exception:
            pass

    def get_telemetry(self) -> dict[str, Any]:
        """Return live telemetry and flashing ticker feed for the Dashboard UI."""
        return {
            "running": self.running,
            "status_label": self.status_label,
            "current_target": self.current_target,
            "current_file": self.current_file,
            "current_action": self.current_action,
            "files_swept": self.files_swept,
            "unchanged_skipped": self.unchanged_skipped,
            "deltas_attested": self.deltas_attested,
            "deleted_revoked": self.deleted_revoked,
            "micro_snapshots_published": self.micro_snapshots_published,
            "last_snapshot_seq": self.last_snapshot_seq,
            "pass_number": self.pass_number,
            "scan_rate_files_per_sec": self.scan_rate_files_per_sec,
            "watermark_count": len(self.watermark_index),
            "pending_deltas": self._pending_deltas_since_publish,
            "config": {
                "include_code_dirs": self.include_code_dirs,
                "auto_revoke_deleted": self.auto_revoke_deleted,
                "micro_publish_delta_threshold": self.micro_publish_delta_threshold,
                "micro_publish_interval_sec": self.micro_publish_interval_sec,
                "throttle_ms_per_file": self.throttle_ms_per_file,
            },
            "targets": self.targets,
            "ticker_feed": list(self.ticker_feed)[:35],
        }

    def update_config(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Update continuous scanner settings, target list, or running state."""
        if "running" in payload:
            self.running = bool(payload["running"])
            self.status_label = f"SWEEPING (PASS #{max(1, self.pass_number)})" if self.running else "PAUSED"
        if "include_code_dirs" in payload:
            self.include_code_dirs = bool(payload["include_code_dirs"])
        if "auto_revoke_deleted" in payload:
            self.auto_revoke_deleted = bool(payload["auto_revoke_deleted"])
        if "micro_publish_delta_threshold" in payload:
            self.micro_publish_delta_threshold = max(1, min(500, int(payload["micro_publish_delta_threshold"])))
        if "throttle_ms_per_file" in payload:
            self.throttle_ms_per_file = max(0.0, min(100.0, float(payload["throttle_ms_per_file"])))
        if "targets" in payload and isinstance(payload["targets"], list):
            enabled_map = {str(t.get("path_or_uri")): bool(t.get("enabled", True)) for t in payload["targets"]}
            for t in self.targets:
                if t["path_or_uri"] in enabled_map:
                    t["enabled"] = enabled_map[t["path_or_uri"]]
        if payload.get("add_target_uri"):
            new_uri = str(payload["add_target_uri"]).strip()
            if new_uri and not any(t["path_or_uri"].lower() == new_uri.lower() for t in self.targets):
                is_cloud = is_enterprise_store_uri(new_uri)
                if is_cloud:
                    self.store_manager.resolve_matching_store_uri(new_uri)
                self.targets.insert(
                    0,
                    {
                        "id": f"target-custom-{ len(self.targets) + 1 }",
                        "path_or_uri": new_uri,
                        "label": f"{'☁️' if is_cloud else '📁'} {new_uri} (Custom Enterprise Target)",
                        "kind": "cloud_store" if is_cloud else "pc_dir",
                        "enabled": True,
                    },
                )
        if payload.get("focus_only_target"):
            focus_uri = str(payload["focus_only_target"]).strip()
            found = False
            for t in self.targets:
                if t["path_or_uri"].lower() == focus_uri.lower():
                    t["enabled"] = True
                    found = True
                else:
                    t["enabled"] = False
            if not found:
                is_cloud = is_enterprise_store_uri(focus_uri)
                if is_cloud:
                    self.store_manager.resolve_matching_store_uri(focus_uri)
                self.targets.insert(
                    0,
                    {
                        "id": f"target-focus-{len(self.targets) + 1}",
                        "path_or_uri": focus_uri,
                        "label": f"{'☁️' if is_cloud else '📁'} {focus_uri}",
                        "kind": "cloud_store" if is_cloud else "pc_dir",
                        "enabled": True,
                    },
                )
            self.running = True
            self.status_label = f"SWEEPING ({focus_uri})"

        if payload.get("reset_watermarks"):
            self.watermark_index.clear()
            self._push_ticker(
                kind="snapshot",
                display_path="WATERMARK INDEX RESET",
                detail="Cleared in-memory mtime/ETag watermarks — next pass will deep-verify all files",
            )
        return self.get_telemetry()

    async def run_forever(self) -> None:
        """Main background async loop for the continuous delta crawler."""
        await asyncio.to_thread(self.seed_watermarks_from_registry)
        while True:
            if not self.running:
                self.scan_rate_files_per_sec = 0.0
                await asyncio.sleep(0.4)
                continue

            self.pass_number += 1
            self.status_label = f"SWEEPING (PASS #{self.pass_number})"
            enabled_targets = [t for t in self.targets if t.get("enabled")]
            if not enabled_targets:
                self.status_label = "IDLE (NO TARGETS ENABLED)"
                await asyncio.sleep(1.0)
                continue

            for target in enabled_targets:
                if not self.running:
                    break
                target_uri = target["path_or_uri"]
                self.current_target = target_uri
                try:
                    if is_enterprise_store_uri(target_uri):
                        await self._sweep_enterprise_store_target(target_uri)
                    else:
                        await self._sweep_pc_filesystem_target(target_uri)
                except Exception:
                    continue

            # Flush any remaining deltas at the end of a pass
            if self._pending_deltas_since_publish > 0:
                await asyncio.to_thread(self._maybe_micro_publish, True)

            if self.running:
                self.status_label = f"COMPLETED PASS #{self.pass_number} — MONITORING FOR DELTAS"
                await asyncio.sleep(self.pause_between_passes_sec)

    async def _sweep_pc_filesystem_target(self, raw_path: str) -> None:
        """Sweep a local drive (`C:\\`, `D:\\`) or directory with Pass 1 mtime/size filter + Pass 2 delta attestation."""
        try:
            root_dir, locator_base = resolve_pc_directory_path(raw_path)
        except FileNotFoundError:
            return

        seen_locators: set[str] = set()
        prefix_with_slash = locator_base.rstrip("/") + "/"

        for fpath, rel_posix in iter_scannable_files_unbounded(root_dir, include_code_dirs=self.include_code_dirs):
            if not self.running:
                return

            locator = f"{locator_base.rstrip('/')}/{rel_posix}"
            seen_locators.add(locator)
            win_display = f"{raw_path.rstrip('\\')}\\{rel_posix.replace('/', '\\')}"

            try:
                st = fpath.stat()
                size_bytes = st.st_size
                mtime_ns = st.st_mtime_ns
            except OSError:
                continue

            self.files_swept += 1
            self._record_step_rate(1)

            # PASS 1: Fast mtime_ns + size_bytes Watermark Filter (0 file bytes read!)
            wm = self.watermark_index.get(locator)
            if wm is not None and wm.size_bytes == size_bytes and wm.mtime_ns == mtime_ns:
                self.unchanged_skipped += 1
                self._push_ticker(
                    kind="skip",
                    display_path=win_display,
                    detail=f"mtime+size match ({size_bytes:,} B) • 0 bytes read",
                    tier=wm.tier,
                    sha256=wm.content_sha256,
                )
                if self.throttle_ms_per_file > 0:
                    await asyncio.sleep(self.throttle_ms_per_file / 1000.0)
                continue

            # PASS 2: Delta Detected (New file or mtime/size changed) -> Deep Hash, Chunk & Presidio Scan
            def _attest_one() -> dict[str, Any]:
                with self.scan_lock:
                    return self.engine.attest_file(
                        file_path=fpath,
                        owner="continuous-crawler@contoso.com",
                        locator_override=locator,
                        environment="production",
                    )

            try:
                res = await asyncio.to_thread(_attest_one)
            except Exception:
                continue

            rec = res.get("record")
            action = res.get("action", "issued")
            if rec:
                tier = rec["tier"]
                sha = rec["content_sha256"]
                self.watermark_index[locator] = WatermarkEntry(
                    locator=locator,
                    size_bytes=size_bytes,
                    mtime_ns=mtime_ns,
                    etag=f'"{sha[:32]}"',
                    content_sha256=sha,
                    tier=tier,
                )
                if action == "unchanged":
                    # Content SHA-256 matched existing Registry record; now mtime_ns is locked into watermark_index!
                    self.unchanged_skipped += 1
                    self._push_ticker(
                        kind="skip",
                        display_path=win_display,
                        detail=f"SHA-256 verified & watermarked ({size_bytes:,} B)",
                        tier=tier,
                        sha256=sha,
                    )
                else:
                    self.deltas_attested += 1
                    self._pending_deltas_since_publish += 1
                    self._push_ticker(
                        kind="delta",
                        display_path=win_display,
                        detail=f"ATTESTED DELTA → {tier} ({size_bytes:,} B)",
                        tier=tier,
                        sha256=sha,
                    )
                    await asyncio.to_thread(self._maybe_micro_publish, False)

            if self.throttle_ms_per_file > 0:
                await asyncio.sleep(self.throttle_ms_per_file / 1000.0)

        # Check for deleted files under this root if we completed a full walk
        if self.running and self.auto_revoke_deleted:
            stale_locs = [
                loc
                for loc in list(self.watermark_index.keys())
                if loc.startswith(prefix_with_slash) and loc not in seen_locators
            ]
            for dead_loc in stale_locs:
                try:
                    with self.scan_lock:
                        self.registry.revoke_record(
                            locator=dead_loc,
                            reason="Continuous Delta Crawler detected file deletion on disk",
                        )
                    self.watermark_index.pop(dead_loc, None)
                    self.deleted_revoked += 1
                    self._pending_deltas_since_publish += 1
                    self._push_ticker(
                        kind="revoke",
                        display_path=dead_loc,
                        detail="FILE DELETED ON DISK → Auto-revoked in Registry",
                        tier="Restricted",
                    )
                except Exception:
                    self.watermark_index.pop(dead_loc, None)

    async def _sweep_enterprise_store_target(self, raw_uri: str) -> None:
        """Sweep a cloud bucket (`s3://`, `azblob://`, `gs://`) or warehouse (`snowflake://`, `bigquery://`, `postgres://`) using Pass 1 ETag/Watermark filter + Pass 2 delta attestation."""
        store_uri = self.store_manager.resolve_matching_store_uri(raw_uri)
        cfg = self.store_manager.stores[store_uri]

        if cfg.store_kind == "database" or store_uri.startswith(("postgres://", "postgresql://")):
            sqlite_db = self.store_manager.estate_dir / "synthetic_estate.db"
            db_url = (
                f"sqlite:///{sqlite_db.as_posix()}"
                if sqlite_db.is_file() and store_uri == "postgres://estate-db:5432/estate"
                else store_uri
            )
            tables = await asyncio.to_thread(
                self.engine.db_scanner.scan_database,
                db_url,
                "postgres://estate-db:5432/estate" if store_uri == "postgres://estate-db:5432/estate" else None,
            )
            for tbl in tables:
                if not self.running:
                    return
                self.files_swept += 1
                self._record_step_rate(1)
                wm = self.watermark_index.get(tbl.locator)
                if wm is not None and wm.content_sha256 == tbl.content_sha256:
                    self.unchanged_skipped += 1
                    self._push_ticker(
                        kind="skip",
                        display_path=tbl.locator,
                        detail=f"Table schema+rows hash unchanged ({tbl.row_count} rows)",
                        tier=wm.tier,
                        sha256=wm.content_sha256,
                    )
                else:
                    res = await asyncio.to_thread(self.store_manager.crawl_and_attest_store, store_uri)
                    for f in res.get("files", []):
                        if f["locator"] == tbl.locator:
                            self.watermark_index[tbl.locator] = WatermarkEntry(
                                locator=tbl.locator,
                                size_bytes=tbl.size_bytes,
                                mtime_ns=None,
                                etag=f'"{tbl.content_sha256[:32]}"',
                                content_sha256=tbl.content_sha256,
                                tier=f["tier"],
                            )
                            self.deltas_attested += 1
                            self._pending_deltas_since_publish += 1
                            self._push_ticker(
                                kind="delta",
                                display_path=tbl.locator,
                                detail=f"ATTESTED DB TABLE → {f['tier']} ({tbl.row_count} rows)",
                                tier=f["tier"],
                                sha256=tbl.content_sha256,
                            )
                    await asyncio.to_thread(self._maybe_micro_publish, False)
                if self.throttle_ms_per_file > 0:
                    await asyncio.sleep(self.throttle_ms_per_file / 1000.0)
            return

        objs = list(self.store_manager.store_objects.get(store_uri, []))
        for obj in objs:
            if not self.running:
                return
            self.files_swept += 1
            self._record_step_rate(1)

            # PASS 1: Fast Cloud ETag + Size Watermark Check
            wm = self.watermark_index.get(obj.locator)
            if wm is not None and wm.etag == obj.etag and wm.size_bytes == obj.size_bytes:
                self.unchanged_skipped += 1
                self._push_ticker(
                    kind="skip",
                    display_path=obj.locator,
                    detail=f"Cloud ETag {obj.etag[:10]}… match • 0 bytes streamed",
                    tier=wm.tier,
                    sha256=wm.content_sha256,
                )
                if self.throttle_ms_per_file > 0:
                    await asyncio.sleep(self.throttle_ms_per_file / 1000.0)
                continue

            # PASS 2: Delta Detected -> Attest cloud object
            def _attest_cloud_obj() -> dict[str, Any]:
                with self.scan_lock:
                    return self.store_manager._attest_single_store_object(obj, cfg)

            res = await asyncio.to_thread(_attest_cloud_obj)
            rec = res.get("record")
            if rec:
                tier = rec["tier"]
                sha = rec["content_sha256"]
                self.watermark_index[obj.locator] = WatermarkEntry(
                    locator=obj.locator,
                    size_bytes=obj.size_bytes,
                    mtime_ns=None,
                    etag=obj.etag,
                    content_sha256=sha,
                    tier=tier,
                )
                self.deltas_attested += 1
                self._pending_deltas_since_publish += 1
                self._push_ticker(
                    kind="delta",
                    display_path=obj.locator,
                    detail=f"ATTESTED CLOUD DELTA ({cfg.provider}) → {tier}",
                    tier=tier,
                    sha256=sha,
                )
                await asyncio.to_thread(self._maybe_micro_publish, False)

            if self.throttle_ms_per_file > 0:
                await asyncio.sleep(self.throttle_ms_per_file / 1000.0)
