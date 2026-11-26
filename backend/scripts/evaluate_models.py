"""Run the real, deterministic model-evaluation rubric against a registered model.

No score is produced without an actual provider completion. Example:
    cd backend && PYTHONPATH=. python scripts/evaluate_models.py --model llama3.1:8b --org-slug my-org
    cd backend && PYTHONPATH=. python scripts/evaluate_models.py --model-id <uuid> --cases cases.json
"""

from __future__ import annotations

import argparse
import json
import sys
from uuid import UUID

from sqlalchemy import or_, select

from app.core.db import SessionLocal
from app.core.errors import ServiceUnavailable
from app.models.ai import AIModel, AIProvider
from app.models.core import Organization
from app.modules.ai.evaluation import evaluate_model_cases
from app.modules.ai.schemas import EvaluateRequest, EvaluationCase


def _load_cases(path: str | None) -> list[EvaluationCase] | None:
    if not path:
        return None
    with open(path, encoding="utf-8") as handle:
        payload = json.load(handle)
    if isinstance(payload, dict):
        payload = payload.get("cases", [])
    if not isinstance(payload, list):
        raise SystemExit("cases file must contain a JSON list or {'cases': [...]}")
    return [EvaluationCase(**item) for item in payload]


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate a registered AI model with the deterministic rubric")
    parser.add_argument("--model", default=None, help="Model name as registered")
    parser.add_argument("--model-id", default=None, help="Model UUID")
    parser.add_argument("--org-slug", default=None, help="Organization whose invocation ledger is used")
    parser.add_argument("--cases", default=None, help="Optional JSON file with custom evaluation cases")
    args = parser.parse_args()

    if not args.model and not args.model_id:
        print("Provide --model or --model-id", file=sys.stderr)
        return 2

    with SessionLocal() as db:
        stmt = select(AIModel, AIProvider).join(AIProvider, AIProvider.id == AIModel.provider_id)
        if args.model_id:
            try:
                model_id = UUID(args.model_id)
            except ValueError:
                print("Invalid --model-id", file=sys.stderr)
                return 2
            stmt = stmt.where(AIModel.id == model_id)
        else:
            stmt = stmt.where(AIModel.name == args.model)
        row = db.execute(stmt).first()
        if row is None:
            print("Model not found", file=sys.stderr)
            return 1
        model, provider = row

        if args.org_slug:
            organization = db.execute(
                select(Organization).where(Organization.slug == args.org_slug, Organization.deleted_at.is_(None))
            ).scalar_one_or_none()
        else:
            organization = db.execute(
                select(Organization)
                .where(
                    Organization.deleted_at.is_(None),
                    or_(provider.org_id.is_(None), Organization.id == provider.org_id),
                )
                .order_by(Organization.name)
                .limit(1)
            ).scalar_one_or_none()
        if organization is None:
            print("No organization available to record the evaluation", file=sys.stderr)
            return 1
        if provider.org_id is not None and provider.org_id != organization.id:
            print("The model provider belongs to a different organization", file=sys.stderr)
            return 1
        if provider.health_status != "healthy":
            print(
                f"Provider '{provider.name}' is not healthy (status={provider.health_status}); "
                "run a provider health check first",
                file=sys.stderr,
            )
            return 1

        try:
            cases = _load_cases(args.cases)
        except (OSError, ValueError) as exc:
            print(f"Unable to load cases: {exc}", file=sys.stderr)
            return 2

        try:
            summary = evaluate_model_cases(db, organization.id, model, provider, EvaluateRequest(cases=cases))
        except ServiceUnavailable as exc:
            db.commit()
            print(f"Evaluation could not run: {exc}", file=sys.stderr)
            return 1
        db.commit()

        print(f"Model: {summary['model']} (provider={summary['provider']})")
        print(f"Score: {summary['passed']}/{summary['total']} ({summary['score']:.2%})")
        for result in summary["results"]:
            status = "PASS" if result["passed"] else "FAIL"
            print(f"  [{status}] {result['name']} status={result['status']}")
            if result.get("error"):
                print(f"         error: {result['error']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
