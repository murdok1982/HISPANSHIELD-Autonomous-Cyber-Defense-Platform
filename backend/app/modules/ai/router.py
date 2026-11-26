"""AI gateway router: providers, models, inference, evaluation, RAG and usage."""

from __future__ import annotations

from fastapi import APIRouter

from app.modules.ai import inference, knowledge, models, operations, providers

router = APIRouter(prefix="/ai", tags=["AI Gateway"])
router.include_router(providers.router)
router.include_router(models.router)
router.include_router(inference.router)
router.include_router(knowledge.router)
router.include_router(operations.router)

__all__ = ["router"]
