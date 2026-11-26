"""Built-in framework catalogue integrity and seed idempotency tests."""

from __future__ import annotations

import json

import pytest
from sqlalchemy import func, select

from app.core.errors import ValidationFailure
from app.models.compliance import ComplianceControl, ComplianceFramework
from app.modules.compliance.schemas import ALLOWED_CHECK_TYPES
from app.modules.compliance.service import (
    framework_checksum,
    load_builtin_documents,
    parse_framework_document,
    seed_builtin_frameworks,
)

REQUIRED_CODES = {
    "NIS2",
    "CRA",
    "GDPR",
    "ENS",
    "ISO27001:2022",
    "ISO27002:2022",
    "IEC62443-3-3",
    "ETSI EN 303 645",
}


def _minimal_yaml(control_id: str = "T-1", check_type: str = "mfa_enforced") -> str:
    return f"""
code: TEST-FW
name: Test framework
version: "1.0"
jurisdiction: EU
authority: Test authority
effective_date: 2026-01-01
source_url: https://example.eu/test
status: published
description: Minimal framework used by tests.
controls:
  - control_id: {control_id}
    title: Test control
    description: Test control description.
    category: testing
    weight: 3
    references:
      - "Test reference"
    evidence_requirements:
      - key: evidence_one
        title: Evidence one
        description: Evidence description.
    technical_checks:
      - key: check_one
        title: Check one
        type: {check_type}
        params:
          min_ratio: 1.0
        description: Check description.
"""


def test_builtin_documents_are_complete_and_versioned() -> None:
    documents = load_builtin_documents()
    codes = {document.code for document in documents}
    assert len(documents) == 10
    assert REQUIRED_CODES.issubset(codes)
    for document in documents:
        assert document.version
        assert document.name
        assert document.jurisdiction
        assert document.status == "published"
        assert document.source_url and document.source_url.startswith("https://")
        assert len(document.controls) > 0


def test_every_control_has_checks_and_evidence() -> None:
    documents = load_builtin_documents()
    total_controls = 0
    total_checks = 0
    for document in documents:
        assert len(document.controls) >= 6
        for control in document.controls:
            total_controls += 1
            assert control.evidence_requirements, f"{document.code}/{control.control_id} lacks evidence"
            assert control.technical_checks, f"{document.code}/{control.control_id} lacks technical checks"
            assert 1 <= control.weight <= 5
            for check in control.technical_checks:
                total_checks += 1
                assert check.type in ALLOWED_CHECK_TYPES
    assert total_controls >= 90
    assert total_checks >= 90


def test_checksum_is_stable_and_changes_with_content() -> None:
    document, _ = parse_framework_document(_minimal_yaml(), "yaml")
    first = framework_checksum(document)
    second = framework_checksum(document)
    assert first == second
    assert len(first) == 64

    changed = _minimal_yaml().replace("Test control", "Different control")
    altered_document, _ = parse_framework_document(changed, "yaml")
    assert framework_checksum(altered_document) != first


def test_json_and_yaml_documents_hash_identically() -> None:
    document, _ = parse_framework_document(_minimal_yaml(), "yaml")
    payload = json.dumps(document.model_dump(mode="json"))
    json_document, detected = parse_framework_document(payload, "auto")
    assert detected == "json"
    assert framework_checksum(json_document) == framework_checksum(document)


def test_duplicate_control_ids_are_rejected() -> None:
    duplicated = _minimal_yaml().replace(
        "  - control_id: T-1",
        "  - control_id: T-1\n    title: Duplicate\n    description: Duplicate control.\n    category: testing\n"
        "  - control_id: T-1",
    )
    with pytest.raises(ValidationFailure):
        parse_framework_document(duplicated, "yaml")


def test_unknown_technical_check_type_is_rejected() -> None:
    with pytest.raises(ValidationFailure) as excinfo:
        parse_framework_document(_minimal_yaml(check_type="run_arbitrary_sql"), "yaml")
    assert any("technical check" in detail["message"].lower() for detail in excinfo.value.details)


def test_invalid_source_url_is_rejected() -> None:
    bad = _minimal_yaml().replace("https://example.eu/test", "file:///etc/passwd")
    with pytest.raises(ValidationFailure):
        parse_framework_document(bad, "yaml")


def test_iso27002_controls_map_to_existing_iso27001_controls() -> None:
    documents = {document.code: document for document in load_builtin_documents()}
    iso27001 = documents["ISO27001:2022"]
    iso27002 = documents["ISO27002:2022"]
    parent_ids = {control.control_id for control in iso27001.controls}
    for control in iso27002.controls:
        target = control.mapping.get("iso27001")
        assert target, f"{control.control_id} has no ISO 27001 mapping"
        assert target in parent_ids, f"{control.control_id} maps to unknown {target}"


def test_seed_is_idempotent(db) -> None:
    first = seed_builtin_frameworks(db)
    assert first["created"] == 10
    assert first["skipped"] == 0

    second = seed_builtin_frameworks(db)
    assert second["created"] == 0
    assert second["skipped"] == 10

    frameworks = db.execute(select(func.count()).select_from(ComplianceFramework)).scalar_one()
    controls = db.execute(select(func.count()).select_from(ComplianceControl)).scalar_one()
    assert frameworks == 10
    assert controls >= 90


def test_seed_publishes_required_codes_and_controls(db) -> None:
    seed_builtin_frameworks(db)
    rows = list(db.execute(select(ComplianceFramework)).scalars())
    codes = {row.code for row in rows}
    assert REQUIRED_CODES.issubset(codes)
    for framework in rows:
        assert framework.status == "published"
        assert framework.published_at is not None
        assert framework.is_builtin is True
        assert framework.source_url
        count = db.execute(
            select(func.count()).select_from(ComplianceControl).where(ComplianceControl.framework_id == framework.id)
        ).scalar_one()
        assert count > 0
