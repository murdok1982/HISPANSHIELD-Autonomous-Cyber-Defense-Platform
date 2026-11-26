"""Security posture API: deterministic network, cloud and identity summaries."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from app.core.deps import RequestContext, require_permission
from app.modules.posture import service

router = APIRouter(prefix="/posture", tags=["Security Posture"])


@router.get("/network", summary="Network exposure, lateral movement and segmentation posture")
def network_posture(ctx: RequestContext = Depends(require_permission("asset:read"))) -> dict[str, Any]:
    return service.network_posture(ctx.db, ctx.org.id)


@router.get("/cloud", summary="Cloud asset, storage, identity and vulnerability posture")
def cloud_posture(ctx: RequestContext = Depends(require_permission("asset:read"))) -> dict[str, Any]:
    return service.cloud_posture(ctx.db, ctx.org.id)


@router.get("/identity", summary="Identity, MFA and authentication-abuse posture")
def identity_posture(ctx: RequestContext = Depends(require_permission("asset:read"))) -> dict[str, Any]:
    return service.identity_posture(ctx.db, ctx.org.id)


@router.get("/summary", summary="Aggregated posture score with factor breakdown")
def posture_summary(ctx: RequestContext = Depends(require_permission("asset:read"))) -> dict[str, Any]:
    return service.posture_summary(ctx.db, ctx.org.id)


__all__ = ["router"]
