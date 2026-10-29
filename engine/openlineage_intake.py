"""OpenLineage event intake for keeping `derived_from` provenance links honest."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class LineageLink:
    """Recorded upstream-to-downstream dataset derivation from an OpenLineage RunEvent."""

    downstream_locator: str
    upstream_locator: str
    run_id: str
    job_name: str
    event_time: str


class OpenLineageIntake:
    """Ingests OpenLineage RunEvents and resolves `derived_from` upstream locators for attested objects."""

    def __init__(self) -> None:
        self._upstream_by_downstream: dict[str, list[dict[str, Any]]] = {}

    @staticmethod
    def dataset_to_locator(namespace: str, name: str) -> str:
        """Convert an OpenLineage `(namespace, name)` pair into a canonical POD locator URI."""
        ns = namespace.rstrip("/")
        clean_name = name.lstrip("/")
        if not ns.startswith(("file://", "s3://", "gs://", "http://", "https://")):
            clean_name = clean_name.replace(".", "/")
        if "://" in ns:
            return f"{ns}/{clean_name}"
        return f"postgres://{ns}/{clean_name}"

    def ingest_event(self, event: dict[str, Any]) -> list[LineageLink]:
        """Process an OpenLineage RunEvent JSON object and record input -> output lineage edges."""
        event_type = event.get("eventType", "COMPLETE").upper()
        if event_type not in ("COMPLETE", "RUNNING", "START"):
            return []

        run_id = event.get("run", {}).get("runId", "unknown-run")
        job_name = event.get("job", {}).get("name", "unknown-job")
        event_time = event.get("eventTime", "")

        inputs = event.get("inputs", [])
        outputs = event.get("outputs", [])
        links: list[LineageLink] = []

        upstream_locators = [
            self.dataset_to_locator(inp["namespace"], inp["name"])
            for inp in inputs
            if "namespace" in inp and "name" in inp
        ]

        for out in outputs:
            if "namespace" not in out or "name" not in out:
                continue
            down_loc = self.dataset_to_locator(out["namespace"], out["name"])
            existing = self._upstream_by_downstream.setdefault(down_loc, [])
            existing_locs = {item["locator"] for item in existing}
            for up_loc in upstream_locators:
                if up_loc not in existing_locs:
                    existing.append(
                        {
                            "locator": up_loc,
                            "record_id": None,
                            "lineage_run_id": run_id,
                        }
                    )
                    existing_locs.add(up_loc)
                links.append(
                    LineageLink(
                        downstream_locator=down_loc,
                        upstream_locator=up_loc,
                        run_id=run_id,
                        job_name=job_name,
                        event_time=event_time,
                    )
                )
        return links

    def get_derived_from(self, locator: str) -> list[dict[str, Any]]:
        """Return upstream `derived_from` entries for a given downstream object locator."""
        return list(self._upstream_by_downstream.get(locator, []))
