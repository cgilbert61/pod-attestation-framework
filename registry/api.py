"""Hardened Registry Lookup and Lifecycle Admin FastAPI Service."""

from __future__ import annotations

import os
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from registry.store import (
    DualApprovalRequiredError,
    FingerprintChangedError,
    RegistryLifecycleError,
    RegistryService,
)


class RaiseTierRequest(BaseModel):
    locator: str
    new_tier: str


class ApprovalEntry(BaseModel):
    approver_id: str
    rationale: str = "Approved tier lowering"


class LowerTierRequest(BaseModel):
    locator: str
    new_tier: str
    approvals: list[ApprovalEntry] = Field(min_length=2)


class RevokeRequest(BaseModel):
    locator: str
    reason: str = "Administrative revocation"


class RenewRequest(BaseModel):
    locator: str
    observed_content_sha256: str
    ttl_days: int | None = None


class ReviewDecisionRequest(BaseModel):
    approver_id: str
    confirmed_tier: str | None = None
    rationale: str = "Confirmed in human review"


class IssueFindingRequest(BaseModel):
    model_config = {"extra": "allow"}
    locator: str
    content_sha256: str
    tier: str
    owner: str


def create_registry_app(registry: RegistryService | None = None) -> FastAPI:
    """Create the hardened Registry FastAPI server (requires X-POD-Admin-Key for all catalog queries and mutations)."""
    app = FastAPI(title="POD Authoritative Registry API", version="0.1.0")
    svc = registry or RegistryService()
    admin_key = os.environ.get("POD_ADMIN_API_KEY", "pod-dev-admin-key")
    control_token = os.environ.get("POD_CONTROL_PLANE_TOKEN", "pod-dev-control-plane-token")

    def require_admin_auth(
        x_pod_admin_key: str | None = Header(default=None),
        x_pod_control_token: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> None:
        token = x_pod_admin_key or x_pod_control_token
        if not token and authorization and authorization.lower().startswith("bearer "):
            token = authorization[7:].strip()
        valid_tokens = {t for t in (admin_key, control_token) if t}
        if not token or token not in valid_tokens:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Registry access denied: valid X-POD-Admin-Key, X-POD-Control-Token, or Bearer token required.",
            )

    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        return RedirectResponse(url="/docs")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "service": "pod-registry"}

    @app.get("/v1/records/lookup", dependencies=[Depends(require_admin_auth)])
    def lookup_record(locator: str = Query(..., description="Canonical object locator URI")) -> dict[str, Any]:
        rec = svc.lookup_by_locator(locator)
        if not rec:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No record found for locator")
        return rec

    @app.get("/v1/records", dependencies=[Depends(require_admin_auth)])
    def list_records(current_only: bool = True) -> dict[str, Any]:
        return {"records": svc.list_records(current_only=current_only)}

    @app.get("/v1/records/expiring", dependencies=[Depends(require_admin_auth)])
    def list_expiring(within_days: int = 30) -> dict[str, Any]:
        return {"records": svc.list_expiring(within_days=within_days)}

    @app.post("/v1/records/issue-finding", dependencies=[Depends(require_admin_auth)])
    def issue_finding(req: IssueFindingRequest) -> dict[str, Any]:
        kwargs = req.model_dump()
        return svc.issue_or_queue_finding(**kwargs)

    @app.post("/v1/records/raise-tier", dependencies=[Depends(require_admin_auth)])
    def raise_tier(req: RaiseTierRequest) -> dict[str, Any]:
        try:
            return svc.raise_tier(locator=req.locator, new_tier=req.new_tier)
        except RegistryLifecycleError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    @app.post("/v1/records/lower-tier", dependencies=[Depends(require_admin_auth)])
    def lower_tier(req: LowerTierRequest) -> dict[str, Any]:
        try:
            approvals = [a.model_dump() for a in req.approvals]
            return svc.lower_tier(locator=req.locator, new_tier=req.new_tier, approvals=approvals)
        except DualApprovalRequiredError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        except RegistryLifecycleError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    @app.post("/v1/records/revoke", dependencies=[Depends(require_admin_auth)])
    def revoke_record(req: RevokeRequest) -> dict[str, Any]:
        try:
            return svc.revoke_record(locator=req.locator, reason=req.reason)
        except RegistryLifecycleError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    @app.post("/v1/records/renew", dependencies=[Depends(require_admin_auth)])
    def renew_record(req: RenewRequest) -> dict[str, Any]:
        try:
            return svc.renew_record(
                locator=req.locator,
                observed_content_sha256=req.observed_content_sha256,
                ttl_days=req.ttl_days,
            )
        except FingerprintChangedError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        except RegistryLifecycleError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    @app.get("/v1/reviews", dependencies=[Depends(require_admin_auth)])
    def list_reviews(status_filter: str | None = Query(default="PENDING_REVIEW", alias="status")) -> dict[str, Any]:
        return {"reviews": svc.list_review_queue(status=status_filter)}

    @app.post("/v1/reviews/{review_id}/approve", dependencies=[Depends(require_admin_auth)])
    def approve_review(review_id: str, req: ReviewDecisionRequest) -> dict[str, Any]:
        try:
            return svc.approve_pending_review(
                review_id=review_id,
                approver_id=req.approver_id,
                confirmed_tier=req.confirmed_tier,
                rationale=req.rationale,
            )
        except RegistryLifecycleError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return app
