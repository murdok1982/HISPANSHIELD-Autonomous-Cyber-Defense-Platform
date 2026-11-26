"""Integration tests for the AI gateway: providers, routing, inference, evaluation and RAG."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.crypto import decrypt_secret, hash_password
from app.main import app
from app.models.ai import AIInvocation, AIProvider, KnowledgeChunk
from app.models.core import Membership, Organization, User
from app.services.rag.service import ingest_document
from tests.conftest import break_glass, login

ADMIN_EMAIL = "admin@hispanshield.eu"
ADMIN_PASSWORD = "Str0ng-Test-Passw0rd!2026"
ANALYST_PASSWORD = "An4lyst-Test-Passw0rd!2026"


class FakeAIServer:
    """Local HTTP server implementing the Ollama and OpenAI-compatible contracts."""

    def __init__(self) -> None:
        self.models: list[str] = ["llama3.1:8b", "nomic-embed-text"]
        self.chat_responses: list[str] = []
        self.chat_default = "The evidence shows a blocked connection."
        self.fail_chat = False
        self.fail_tags = False
        self.delay_seconds = 0.0
        self.embedding_vector = [0.1, 0.2, 0.3, 0.4]
        self.requests: list[dict[str, Any]] = []
        self.chat_requests: list[dict[str, Any]] = []
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _FakeHandler)
        self._httpd.daemon_threads = True
        self._httpd.owner = self  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}"

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=2)


class _FakeHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        return

    @property
    def owner(self) -> FakeAIServer:
        return self.server.owner  # type: ignore[attr-defined]

    def _read(self) -> dict[str, Any]:
        length = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw) if raw else {}
        except ValueError:
            body = {}
        return body if isinstance(body, dict) else {}

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:  # noqa: N802 - stdlib signature
        owner = self.owner
        owner.requests.append({"method": "GET", "path": self.path, "body": {}})
        if self.path.startswith("/api/tags"):
            if owner.fail_tags:
                self._send(500, {"error": "tags unavailable"})
                return
            self._send(200, {"models": [{"name": name} for name in owner.models]})
            return
        if self.path.startswith("/v1/models"):
            self._send(200, {"data": [{"id": name} for name in owner.models]})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - stdlib signature
        owner = self.owner
        body = self._read()
        owner.requests.append({"method": "POST", "path": self.path, "body": body})
        if owner.delay_seconds:
            import time

            time.sleep(owner.delay_seconds)
        if self.path.startswith("/api/chat"):
            owner.chat_requests.append(body)
            if owner.fail_chat:
                self._send(500, {"error": "model crashed"})
                return
            content = owner.chat_responses.pop(0) if owner.chat_responses else owner.chat_default
            self._send(
                200,
                {
                    "model": body.get("model"),
                    "message": {"role": "assistant", "content": content},
                    "prompt_eval_count": 11,
                    "eval_count": 7,
                    "done": True,
                },
            )
            return
        if self.path.startswith("/api/embeddings"):
            self._send(200, {"embedding": owner.embedding_vector})
            return
        if self.path.startswith("/v1/chat/completions"):
            owner.chat_requests.append(body)
            if owner.fail_chat:
                self._send(500, {"error": "model crashed"})
                return
            content = owner.chat_responses.pop(0) if owner.chat_responses else owner.chat_default
            self._send(
                200,
                {
                    "model": body.get("model"),
                    "choices": [{"message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 13, "completion_tokens": 9},
                },
            )
            return
        if self.path.startswith("/v1/embeddings"):
            inputs = body.get("input") or []
            if isinstance(inputs, str):
                inputs = [inputs]
            self._send(
                200,
                {"data": [{"index": index, "embedding": owner.embedding_vector} for index, _item in enumerate(inputs)]},
            )
            return
        self._send(404, {"error": "not found"})


@pytest.fixture
def fake_ai():
    server = FakeAIServer()
    try:
        yield server
    finally:
        server.stop()


def _create_provider(client: TestClient, base_url: str, *, name: str, kind: str = "ollama", **extra: Any) -> dict:
    payload = {
        "name": name,
        "kind": kind,
        "base_url": base_url,
        "default_model": "llama3.1:8b",
        "is_local": True,
        "enabled": True,
        **extra,
    }
    response = client.post("/api/v1/ai/providers", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def _health(client: TestClient, provider_id: str) -> dict:
    response = client.post(f"/api/v1/ai/providers/{provider_id}/health")
    assert response.status_code == 200, response.text
    return response.json()


def _create_model(client: TestClient, provider_id: str, **extra: Any) -> dict:
    payload = {
        "provider_id": provider_id,
        "name": "llama3.1:8b",
        "display_name": "Llama 3.1 8B",
        "task_tags": ["chat", "embedding", "evaluation", "agent_analysis"],
        "context_window": 8192,
        "max_output_tokens": 1024,
        "status": "available",
        **extra,
    }
    response = client.post("/api/v1/ai/models", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def _create_analyst(db, org_id: str, role: str = "soc_analyst") -> User:
    from uuid import UUID

    user = User(
        email=f"{role}@example.eu",
        full_name=f"{role} tester",
        password_hash=hash_password(ANALYST_PASSWORD),
        status="active",
    )
    db.add(user)
    db.flush()
    db.add(Membership(org_id=UUID(org_id), user_id=user.id, role=role, status="active"))
    db.commit()
    return user


def test_provider_crud_encrypts_key_and_never_returns_it(auth_client, db, org_id, fake_ai):
    provider = _create_provider(auth_client, fake_ai.url, name="Local Ollama", api_key="sk-test-secret-123456")
    assert provider["has_api_key"] is True
    assert "api_key" not in provider
    assert "api_key_encrypted" not in provider
    assert provider["org_id"] == org_id

    stored = db.get(AIProvider, provider["id"])
    assert stored is not None
    assert stored.api_key_encrypted != "sk-test-secret-123456"
    assert decrypt_secret(stored.api_key_encrypted or "") == "sk-test-secret-123456"

    listing = auth_client.get("/api/v1/ai/providers")
    assert listing.status_code == 200
    assert listing.json()["meta"]["total"] == 1

    patched = auth_client.patch(f"/api/v1/ai/providers/{provider['id']}", json={"name": "Renamed", "enabled": False})
    assert patched.status_code == 200
    assert patched.json()["name"] == "Renamed"
    assert patched.json()["enabled"] is False

    deleted = auth_client.delete(f"/api/v1/ai/providers/{provider['id']}")
    assert deleted.status_code == 204
    assert auth_client.get(f"/api/v1/ai/providers/{provider['id']}").status_code == 404


def test_provider_rejects_non_http_scheme(auth_client):
    response = auth_client.post(
        "/api/v1/ai/providers",
        json={"name": "bad", "kind": "ollama", "base_url": "ftp://127.0.0.1:11434"},
    )
    assert response.status_code == 422


def test_provider_health_checks_ollama_and_openai(auth_client, fake_ai):
    ollama = _create_provider(auth_client, fake_ai.url, name="Ollama")
    health = _health(auth_client, ollama["id"])
    assert health["healthy"] is True
    assert health["health_status"] == "healthy"

    openai = _create_provider(auth_client, fake_ai.url, name="vLLM", kind="vllm")
    health = _health(auth_client, openai["id"])
    assert health["healthy"] is True


def test_discovery_upserts_real_model_list(auth_client, fake_ai):
    provider = _create_provider(auth_client, fake_ai.url, name="Ollama")
    response = auth_client.post(f"/api/v1/ai/providers/{provider['id']}/discover")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["discovered"] == 2
    assert {model["name"] for model in body["models"]} == {"llama3.1:8b", "nomic-embed-text"}

    second = auth_client.post(f"/api/v1/ai/providers/{provider['id']}/discover")
    assert second.status_code == 200
    assert second.json()["created"] == 0
    assert second.json()["updated"] == 2

    models = auth_client.get(f"/api/v1/ai/models?provider_id={provider['id']}")
    assert models.status_code == 200
    assert models.json()["meta"]["total"] == 2


def test_completion_returns_503_without_fabricating_output(auth_client, db):
    response = auth_client.post("/api/v1/ai/complete", json={"task": "chat", "prompt": "Summarize the incident"})
    assert response.status_code == 503
    body = response.json()
    assert body["error"]["code"] == "ai_unavailable"
    assert "content" not in body
    assert db.execute(select(AIInvocation)).scalars().all() == []


def test_completion_success_logs_redacted_prompt(auth_client, db, fake_ai):
    provider = _create_provider(auth_client, fake_ai.url, name="Ollama")
    _health(auth_client, provider["id"])
    model = _create_model(auth_client, provider["id"])
    fake_ai.chat_default = "Blocked connection confirmed by firewall telemetry."

    response = auth_client.post(
        "/api/v1/ai/complete",
        json={"task": "chat", "prompt": "Analyze event 42", "model": model["name"]},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["content"] == "Blocked connection confirmed by firewall telemetry."
    assert body["model"] == model["name"]
    assert body["usage"]["prompt_tokens"] == 11
    assert body["parsed"] is None

    secret_prompt = "Use this credential Authorization: Bearer supersecret-token-999 to fetch telemetry"
    second = auth_client.post(
        "/api/v1/ai/complete",
        json={"task": "chat", "prompt": secret_prompt, "model": model["name"]},
    )
    assert second.status_code == 200

    invocations = list(db.execute(select(AIInvocation).order_by(AIInvocation.created_at)).scalars())
    assert len(invocations) == 2
    assert all(invocation.status == "success" for invocation in invocations)
    assert invocations[0].prompt_hash and len(invocations[0].prompt_hash) == 64
    for invocation in invocations:
        assert "supersecret-token-999" not in (invocation.prompt_redacted or "")
    assert "Use this credential" in invocations[1].prompt_redacted


def test_routing_falls_back_to_another_healthy_provider(auth_client, db, fake_ai):
    failing = FakeAIServer()
    failing.fail_chat = True
    try:
        first = _create_provider(auth_client, failing.url, name="A-failing")
        second = _create_provider(auth_client, fake_ai.url, name="B-working")
        _health(auth_client, first["id"])
        _health(auth_client, second["id"])
        _create_model(auth_client, first["id"], task_tags=["chat"])
        _create_model(auth_client, second["id"], task_tags=["chat"])

        response = auth_client.post("/api/v1/ai/complete", json={"task": "chat", "prompt": "hello"})
        assert response.status_code == 200, response.text
        assert response.json()["provider_name"] == "B-working"

        db.expire_all()
        failed_provider = db.get(AIProvider, first["id"])
        assert failed_provider is not None
        assert failed_provider.health_status == "unhealthy"
        statuses = [row.status for row in db.execute(select(AIInvocation)).scalars()]
        assert "error" in statuses and "success" in statuses
    finally:
        failing.stop()


def test_routing_by_task_tag_selects_matching_model(auth_client, fake_ai):
    provider = _create_provider(auth_client, fake_ai.url, name="Ollama")
    _health(auth_client, provider["id"])
    _create_model(auth_client, provider["id"], name="general-model", task_tags=["chat"])
    _create_model(auth_client, provider["id"], name="eval-model", task_tags=["evaluation"])

    response = auth_client.post("/api/v1/ai/complete", json={"task": "evaluation", "prompt": "score this"})
    assert response.status_code == 200
    assert response.json()["model"] == "eval-model"


def test_context_window_limit_is_enforced(auth_client, fake_ai):
    provider = _create_provider(auth_client, fake_ai.url, name="Ollama")
    _health(auth_client, provider["id"])
    model = _create_model(
        auth_client, provider["id"], name="tiny", task_tags=["chat"], context_window=512, max_output_tokens=256
    )
    response = auth_client.post(
        "/api/v1/ai/complete",
        json={"task": "chat", "prompt": "x" * 4000, "model": model["name"], "max_tokens": 256},
    )
    assert response.status_code == 422


def test_structured_output_parse_error_is_returned_not_repaired(auth_client, fake_ai):
    provider = _create_provider(auth_client, fake_ai.url, name="Ollama")
    _health(auth_client, provider["id"])
    model = _create_model(auth_client, provider["id"], task_tags=["chat"])
    fake_ai.chat_default = "this is not json"

    response = auth_client.post(
        "/api/v1/ai/complete",
        json={"task": "chat", "prompt": "return json", "model": model["name"], "expect_json": True},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["content"] == "this is not json"
    assert body["parsed"] is None
    assert body["parse_error"]


def test_embeddings_endpoint_uses_provider(auth_client, fake_ai):
    provider = _create_provider(auth_client, fake_ai.url, name="Ollama")
    _health(auth_client, provider["id"])
    _create_model(auth_client, provider["id"], name="nomic-embed-text", task_tags=["embedding"])

    response = auth_client.post("/api/v1/ai/embeddings", json={"input": ["alpha", "beta"], "model": "nomic-embed-text"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["dimension"] == 4
    assert len(body["embeddings"]) == 2
    assert body["embeddings"][0] == fake_ai.embedding_vector


def test_evaluation_runs_real_cases_and_records_failures(auth_client, fake_ai):
    provider = _create_provider(auth_client, fake_ai.url, name="Ollama")
    _health(auth_client, provider["id"])
    model = _create_model(auth_client, provider["id"])
    fake_ai.chat_responses = [
        '{"verdict": "benign", "confidence": 0.2}',
        "I cannot determine: no evidence found in the supplied material.",
        "plain text without json",
    ]

    response = auth_client.post(
        f"/api/v1/ai/models/{model['id']}/evaluate",
        json={
            "cases": [
                {"name": "json_case", "prompt": "Return JSON", "expect_json": True, "required_keys": ["verdict"]},
                {"name": "refusal_case", "prompt": "No evidence. Conclude.", "should_refuse": True},
                {"name": "failing_case", "prompt": "Return JSON now", "expect_json": True},
            ]
        },
    )
    assert response.status_code == 200, response.text
    summary = response.json()
    assert summary["total"] == 3
    assert summary["passed"] == 2
    assert summary["failed"] == 1
    assert summary["score"] == pytest.approx(0.6667, abs=0.01)
    assert summary["results"][2]["passed"] is False
    assert summary["results"][2]["checks"]["valid_json"] is False

    history = auth_client.get(f"/api/v1/ai/models/{model['id']}/evaluations")
    assert history.status_code == 200
    assert history.json()["latest"]["passed"] == 2


def test_evaluation_without_healthy_provider_is_recorded_as_failure(auth_client, fake_ai):
    provider = _create_provider(auth_client, fake_ai.url, name="Ollama")
    model = _create_model(auth_client, provider["id"])
    response = auth_client.post(
        f"/api/v1/ai/models/{model['id']}/evaluate",
        json={"cases": [{"name": "case", "prompt": "Return JSON", "expect_json": True}]},
    )
    assert response.status_code == 200, response.text
    summary = response.json()
    assert summary["passed"] == 0
    assert summary["results"][0]["status"] == "error"


def test_usage_and_health_endpoints(auth_client, fake_ai):
    provider = _create_provider(auth_client, fake_ai.url, name="Ollama")
    _health(auth_client, provider["id"])
    model = _create_model(auth_client, provider["id"], task_tags=["chat"])
    auth_client.post("/api/v1/ai/complete", json={"task": "chat", "prompt": "hello", "model": model["name"]})

    usage = auth_client.get("/api/v1/ai/usage")
    assert usage.status_code == 200
    body = usage.json()
    assert body["totals"]["count"] == 1
    assert body["by_task"]["chat"]["count"] == 1
    assert body["by_model"][model["name"]]["success"] == 1
    assert body["by_status"]["success"] == 1

    health = auth_client.get("/api/v1/ai/health")
    assert health.status_code == 200
    assert health.json()["ai_available"] is True
    assert health.json()["providers_healthy"] == 1


def test_provider_discovery_failure_marks_provider_unhealthy(auth_client, db, fake_ai):
    provider = _create_provider(auth_client, fake_ai.url, name="Ollama")
    fake_ai.fail_tags = True
    response = auth_client.post(f"/api/v1/ai/providers/{provider['id']}/discover")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "ai_discovery_failed"
    db.expire_all()
    stored = db.get(AIProvider, provider["id"])
    assert stored is not None
    assert stored.health_status == "unhealthy"


def test_ai_admin_denied_for_soc_analyst(auth_client, db, org_id, fake_ai):
    _create_analyst(db, org_id, role="soc_analyst")
    with TestClient(app) as analyst_client:
        login(analyst_client, "soc_analyst@example.eu", ANALYST_PASSWORD)
        denied = analyst_client.post(
            "/api/v1/ai/providers",
            json={"name": "denied", "kind": "ollama", "base_url": fake_ai.url},
        )
        assert denied.status_code == 403
        readable = analyst_client.get("/api/v1/ai/providers")
        assert readable.status_code == 200


def test_cross_tenant_provider_is_not_visible(auth_client, fake_ai):
    created_org = auth_client.post(
        "/api/v1/organizations",
        json={"name": "Second Organisation", "slug": "second-org"},
    )
    assert created_org.status_code == 201, created_org.text
    second_org_id = created_org.json()["id"]

    with break_glass(auth_client, second_org_id):
        foreign = _create_provider(auth_client, fake_ai.url, name="Foreign Ollama")

    response = auth_client.get(f"/api/v1/ai/providers/{foreign['id']}")
    assert response.status_code == 404


def test_rag_document_lifecycle_and_citations(auth_client, db):
    text = (
        "Credential compromise runbook. Isolate the affected identity and revoke active sessions. "
        "Preserve authentication logs and verify MFA enrollment. Escalate to the incident commander."
    )
    created = auth_client.post(
        "/api/v1/ai/knowledge",
        json={
            "title": "Credential compromise runbook",
            "source": "sop/identity.md",
            "kind": "runbook",
            "version": "2",
            "text": text,
            "metadata": {"owner": "soc"},
        },
    )
    assert created.status_code == 201, created.text
    document = created.json()
    assert document["chunk_count"] >= 1
    assert document["checksum"]

    search = auth_client.post(
        "/api/v1/ai/knowledge/search", json={"query": "credential compromise revoke sessions", "top_k": 3}
    )
    assert search.status_code == 200, search.text
    body = search.json()
    assert body["count"] >= 1
    assert body["results"][0]["document_id"] == document["id"]
    citation = body["citations"][0]
    assert set(citation) == {"document_id", "title", "source", "chunk_id", "snippet", "score"}
    assert citation["source"] == "sop/identity.md"

    detail = auth_client.get(f"/api/v1/ai/knowledge/{document['id']}")
    assert detail.status_code == 200
    assert detail.json()["chunks"][0]["embedding_dimension"] == 384

    updated = auth_client.patch(
        f"/api/v1/ai/knowledge/{document['id']}",
        json={"text": "Updated runbook. Rotate credentials and review conditional access policies."},
    )
    assert updated.status_code == 200
    assert updated.json()["checksum"] != document["checksum"]

    chunk_count = len(
        db.execute(select(KnowledgeChunk).where(KnowledgeChunk.document_id == document["id"])).scalars().all()
    )
    assert chunk_count >= 1
    deleted = auth_client.delete(f"/api/v1/ai/knowledge/{document['id']}")
    assert deleted.status_code == 204
    db.expire_all()
    assert db.execute(select(KnowledgeChunk).where(KnowledgeChunk.document_id == document["id"])).scalars().all() == []


def test_rag_search_is_tenant_isolated(auth_client, db, org_id):
    second_org = Organization(slug="rag-other", name="RAG Other", status="active")
    db.add(second_org)
    db.commit()
    ingest_document(
        db,
        second_org.id,
        title="Other tenant secret runbook",
        source="other/secret.md",
        kind="runbook",
        version="1",
        text="Confidential containment procedure for the other tenant only.",
    )
    db.commit()

    response = auth_client.post(
        "/api/v1/ai/knowledge/search", json={"query": "confidential containment procedure", "top_k": 5}
    )
    assert response.status_code == 200
    assert response.json()["count"] == 0
    assert response.json()["citations"] == []


def test_knowledge_search_top_k_validation(auth_client):
    response = auth_client.post("/api/v1/ai/knowledge/search", json={"query": "anything", "top_k": 11})
    assert response.status_code == 422


def test_ai_model_registry_validation(auth_client, fake_ai):
    provider = _create_provider(auth_client, fake_ai.url, name="Ollama")
    response = auth_client.post(
        "/api/v1/ai/models",
        json={
            "provider_id": provider["id"],
            "name": "invalid",
            "context_window": 1000,
            "max_output_tokens": 2000,
        },
    )
    assert response.status_code == 422


def test_model_registry_crud(auth_client, fake_ai):
    provider = _create_provider(auth_client, fake_ai.url, name="Ollama")
    model = _create_model(auth_client, provider["id"])
    fetched = auth_client.get(f"/api/v1/ai/models/{model['id']}")
    assert fetched.status_code == 200
    assert fetched.json()["provider_name"] == "Ollama"

    patched = auth_client.patch(
        f"/api/v1/ai/models/{model['id']}", json={"task_tags": ["chat"], "status": "deprecated"}
    )
    assert patched.status_code == 200
    assert patched.json()["task_tags"] == ["chat"]
    assert patched.json()["status"] == "deprecated"

    deleted = auth_client.delete(f"/api/v1/ai/models/{model['id']}")
    assert deleted.status_code == 204


def test_invocation_never_persists_api_key(auth_client, db, fake_ai):
    provider = _create_provider(auth_client, fake_ai.url, name="Ollama", api_key="sk-super-secret-key")
    _health(auth_client, provider["id"])
    _create_model(auth_client, provider["id"], task_tags=["chat"])
    auth_client.post("/api/v1/ai/complete", json={"task": "chat", "prompt": "hello"})
    serialized = json.dumps([row.prompt_redacted for row in db.execute(select(AIInvocation)).scalars()])
    assert "sk-super-secret-key" not in serialized
    stored = db.get(AIProvider, provider["id"])
    assert stored is not None
    assert stored.api_key_encrypted != "sk-super-secret-key"


def test_provider_list_scope_filters(auth_client, fake_ai):
    _create_provider(auth_client, fake_ai.url, name="Org provider")
    _create_provider(auth_client, fake_ai.url, name="Platform provider", scope="platform")
    org_scope = auth_client.get("/api/v1/ai/providers?scope=organization")
    platform_scope = auth_client.get("/api/v1/ai/providers?scope=platform")
    assert org_scope.status_code == 200
    assert platform_scope.status_code == 200
    assert org_scope.json()["meta"]["total"] == 1
    assert platform_scope.json()["meta"]["total"] == 1
    assert platform_scope.json()["items"][0]["org_id"] is None


def test_platform_provider_cannot_be_managed_by_analyst(auth_client, db, org_id, fake_ai):
    platform_provider = _create_provider(auth_client, fake_ai.url, name="Platform", scope="platform")
    _create_analyst(db, org_id, role="soc_manager")
    with TestClient(app) as manager_client:
        login(manager_client, "soc_manager@example.eu", ANALYST_PASSWORD)
        response = manager_client.patch(f"/api/v1/ai/providers/{platform_provider['id']}", json={"enabled": False})
        assert response.status_code == 403


def test_model_metadata_never_invented_on_create(auth_client, fake_ai):
    provider = _create_provider(auth_client, fake_ai.url, name="Ollama")
    model = _create_model(auth_client, provider["id"], name="explicit-model", task_tags=["chat"])
    assert model["name"] == "explicit-model"
    assert model["evaluation"] == {}


def test_usage_filters_by_window(auth_client):
    response = auth_client.get("/api/v1/ai/usage?days=90")
    assert response.status_code == 200
    assert response.json()["invocations"] == 0


def test_max_tokens_above_model_limit_is_rejected(auth_client, fake_ai):
    provider = _create_provider(auth_client, fake_ai.url, name="Ollama")
    _health(auth_client, provider["id"])
    model = _create_model(auth_client, provider["id"], max_output_tokens=128)
    response = auth_client.post(
        "/api/v1/ai/complete",
        json={"task": "chat", "prompt": "hello", "model": model["name"], "max_tokens": 4096},
    )
    assert response.status_code == 422
    assert response.json()["error"]["details"][0]["field"] == "max_tokens"
