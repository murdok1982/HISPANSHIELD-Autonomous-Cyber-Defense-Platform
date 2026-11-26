"""Tenant-scoped knowledge base CRUD and hybrid semantic retrieval."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import func, or_, select

from app.core.deps import RequestContext, require_permission
from app.core.errors import NotFound
from app.core.schemas import Page, paginate
from app.models.ai import KnowledgeDocument
from app.modules.ai.schemas import (
    KnowledgeDocumentCreate,
    KnowledgeDocumentDetail,
    KnowledgeDocumentOut,
    KnowledgeDocumentPatch,
    KnowledgeSearchRequest,
    KnowledgeSearchResponse,
)
from app.services.rag.retrieval import search_knowledge
from app.services.rag.service import (
    delete_document,
    document_view,
    ingest_document,
    replace_document_text,
)

router = APIRouter(prefix="/knowledge", tags=["AI Knowledge"])


def _get_document(ctx: RequestContext, document_id: UUID) -> KnowledgeDocument:
    document = ctx.db.get(KnowledgeDocument, document_id)
    if document is None or document.org_id != ctx.org.id:
        raise NotFound("Knowledge document")
    return document


@router.get("", response_model=Page[KnowledgeDocumentOut], summary="List knowledge documents")
def list_documents(
    ctx: RequestContext = Depends(require_permission("ai:read")),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    q: str | None = Query(default=None, max_length=200),
    kind: str | None = Query(default=None, pattern="^(runbook|playbook|policy|sop|reference|other)$"),
) -> Page[KnowledgeDocumentOut]:
    stmt = (
        select(KnowledgeDocument)
        .where(KnowledgeDocument.org_id == ctx.org.id)
        .order_by(KnowledgeDocument.updated_at.desc(), KnowledgeDocument.title)
    )
    if kind:
        stmt = stmt.where(KnowledgeDocument.kind == kind)
    if q:
        needle = f"%{q.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(KnowledgeDocument.title).like(needle),
                func.lower(KnowledgeDocument.source).like(needle),
            )
        )
    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = list(ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars())
    items = [document_view(ctx.db, document) for document in rows]
    return Page[KnowledgeDocumentOut](**paginate(items, total, page, page_size))


@router.post("", response_model=KnowledgeDocumentOut, status_code=201, summary="Ingest a knowledge document")
def create_document(
    payload: KnowledgeDocumentCreate, ctx: RequestContext = Depends(require_permission("ai:admin"))
) -> KnowledgeDocumentOut:
    document = ingest_document(
        ctx.db,
        ctx.org.id,
        title=payload.title,
        source=payload.source,
        kind=payload.kind,
        version=payload.version,
        text=payload.text,
        metadata=payload.metadata,
        created_by=ctx.actor_id,
    )
    ctx.audit(
        action="ai.knowledge.create",
        resource_type="knowledge_document",
        resource_id=str(document.id),
        payload={"title": document.title, "kind": document.kind, "checksum": document.checksum},
    )
    ctx.db.commit()
    ctx.db.refresh(document)
    return KnowledgeDocumentOut(**document_view(ctx.db, document))


@router.get("/{document_id}", response_model=KnowledgeDocumentDetail, summary="Read a document and its chunks")
def get_document(
    document_id: UUID, ctx: RequestContext = Depends(require_permission("ai:read"))
) -> KnowledgeDocumentDetail:
    document = _get_document(ctx, document_id)
    return KnowledgeDocumentDetail(**document_view(ctx.db, document, include_chunks=True))


@router.patch("/{document_id}", response_model=KnowledgeDocumentOut, summary="Update a knowledge document")
def update_document(
    document_id: UUID,
    payload: KnowledgeDocumentPatch,
    ctx: RequestContext = Depends(require_permission("ai:admin")),
) -> KnowledgeDocumentOut:
    document = _get_document(ctx, document_id)
    changes = payload.model_dump(exclude_unset=True)
    if "title" in changes and changes["title"] is not None:
        document.title = changes["title"].strip()
    if "source" in changes and changes["source"] is not None:
        document.source = changes["source"].strip()
    if "kind" in changes and changes["kind"] is not None:
        document.kind = changes["kind"]
    if "version" in changes and changes["version"] is not None:
        document.version = changes["version"].strip()
    if "metadata" in changes and changes["metadata"] is not None:
        document.metadata_json = changes["metadata"]
    if "text" in changes and changes["text"] is not None and changes["text"] != document.text:
        replace_document_text(ctx.db, document, changes["text"])
    ctx.audit(
        action="ai.knowledge.update",
        resource_type="knowledge_document",
        resource_id=str(document.id),
        payload={"fields": sorted(changes.keys()), "rechunked": "text" in changes and changes["text"] is not None},
    )
    ctx.db.commit()
    ctx.db.refresh(document)
    return KnowledgeDocumentOut(**document_view(ctx.db, document))


@router.delete("/{document_id}", status_code=204, response_class=Response, summary="Delete a document and its chunks")
def delete_knowledge_document(
    document_id: UUID, ctx: RequestContext = Depends(require_permission("ai:admin"))
) -> Response:
    document = _get_document(ctx, document_id)
    ctx.audit(
        action="ai.knowledge.delete",
        resource_type="knowledge_document",
        resource_id=str(document.id),
        payload={"title": document.title, "source": document.source},
    )
    delete_document(ctx.db, document)
    ctx.db.commit()
    return Response(status_code=204)


@router.post("/search", response_model=KnowledgeSearchResponse, summary="Hybrid tenant-scoped knowledge search")
def search(
    payload: KnowledgeSearchRequest, ctx: RequestContext = Depends(require_permission("ai:use"))
) -> KnowledgeSearchResponse:
    allowed = {"runbook", "playbook", "policy", "sop", "reference", "other"}
    kinds = [kind for kind in (payload.kinds or []) if kind in allowed] or None
    result = search_knowledge(ctx.db, ctx.org.id, payload.query, top_k=payload.top_k, kinds=kinds)
    return KnowledgeSearchResponse(**result)


__all__ = ["router"]
