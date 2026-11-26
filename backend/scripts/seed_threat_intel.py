"""Idempotent threat-intelligence catalogue seed.

Seeds:

* Global threat actors with real MITRE ATT&CK group identifiers and techniques.
* Per-organization feed definitions for public, authoritative sources. Feeds are
  created **disabled** because activating them is an explicit operator decision
  (TAXII feeds require CISA AIS credentials; the ATT&CK CTI bundle is large).

Run from ``backend/``::

    PYTHONPATH=. /tmp/opencode/hs-venv/bin/python scripts/seed_threat_intel.py
    PYTHONPATH=. /tmp/opencode/hs-venv/bin/python scripts/seed_threat_intel.py --org-slug acme
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from sqlalchemy import select  # noqa: E402

from app.core.db import SessionLocal, utcnow  # noqa: E402
from app.models.core import Organization  # noqa: E402
from app.models.ti import ThreatActor, TIFeed  # noqa: E402

ACTORS: list[dict[str, Any]] = [
    {
        "name": "APT28",
        "aliases": ["Fancy Bear", "Sofacy", "Forest Blizzard", "STRONTIUM"],
        "mitre_id": "G0007",
        "description": (
            "Russian GRU-linked espionage group targeting governments, militaries and critical infrastructure."
        ),
        "sophistication": "advanced",
        "motivation": "espionage",
        "country": "RU",
        "techniques": ["T1566", "T1190", "T1078", "T1059", "T1003", "T1021", "T1071", "T1486"],
    },
    {
        "name": "APT29",
        "aliases": ["Cozy Bear", "Midnight Blizzard", "Nobelium", "The Dukes"],
        "mitre_id": "G0016",
        "description": "Russian SVR-linked group known for supply-chain compromise and cloud identity abuse.",
        "sophistication": "advanced",
        "motivation": "espionage",
        "country": "RU",
        "techniques": ["T1195", "T1078", "T1550", "T1098", "T1071", "T1102", "T1560"],
    },
    {
        "name": "Lazarus Group",
        "aliases": ["Hidden Cobra", "ZINC", "Diamond Sleet"],
        "mitre_id": "G0032",
        "description": "North Korean state-sponsored group conducting financial theft and disruptive operations.",
        "sophistication": "advanced",
        "motivation": "financial",
        "country": "KP",
        "techniques": ["T1566", "T1204", "T1055", "T1070", "T1486", "T1490", "T1005"],
    },
    {
        "name": "Sandworm Team",
        "aliases": ["Voodoo Bear", "APT44", "Seashell Blizzard"],
        "mitre_id": "G0034",
        "description": (
            "Russian GRU unit responsible for destructive attacks on Ukrainian and European critical infrastructure."
        ),
        "sophistication": "advanced",
        "motivation": "destruction",
        "country": "RU",
        "techniques": ["T1190", "T1133", "T1059", "T1485", "T1489", "T1490", "T0831", "T0855"],
    },
    {
        "name": "APT41",
        "aliases": ["Wicked Panda", "Brass Typhoon", "Double Dragon"],
        "mitre_id": "G0096",
        "description": "Chinese state-linked group blending espionage with financially motivated intrusions.",
        "sophistication": "advanced",
        "motivation": "espionage",
        "country": "CN",
        "techniques": ["T1190", "T1505", "T1059", "T1078", "T1021", "T1560", "T1105"],
    },
    {
        "name": "FIN7",
        "aliases": ["Carbanak", "Carbon Spider"],
        "mitre_id": "G0046",
        "description": "Financially motivated criminal group targeting point-of-sale and hospitality systems.",
        "sophistication": "advanced",
        "motivation": "financial",
        "country": None,
        "techniques": ["T1566", "T1204", "T1055", "T1056", "T1005", "T1074"],
    },
    {
        "name": "Wizard Spider",
        "aliases": ["Grim Spider", "UNC1878"],
        "mitre_id": "G0102",
        "description": "Ransomware operator behind Ryuk and Conti, specialising in big-game hunting.",
        "sophistication": "advanced",
        "motivation": "financial",
        "country": None,
        "techniques": ["T1566", "T1078", "T1059", "T1003", "T1021", "T1486", "T1490"],
    },
    {
        "name": "Volt Typhoon",
        "aliases": ["Vanguard Panda", "BRONZE SILHOUETTE"],
        "mitre_id": "G1017",
        "description": "Chinese group pre-positioning in critical infrastructure networks for potential disruption.",
        "sophistication": "advanced",
        "motivation": "espionage",
        "country": "CN",
        "techniques": ["T1190", "T1078", "T1133", "T1552", "T1070", "T1021", "T1090"],
    },
    {
        "name": "Scattered Spider",
        "aliases": ["Octo Tempest", "Muddled Libra", "UNC3944"],
        "mitre_id": "G1015",
        "description": "English-speaking intrusion set using social engineering and identity provider abuse.",
        "sophistication": "intermediate",
        "motivation": "financial",
        "country": None,
        "techniques": ["T1566", "T1621", "T1078", "T1556", "T1098", "T1486"],
    },
    {
        "name": "MuddyWater",
        "aliases": ["Mango Sandstorm", "Static Kitten", "Seedworm"],
        "mitre_id": "G0069",
        "description": "Iranian MOIS-affiliated group targeting government and telecom networks.",
        "sophistication": "intermediate",
        "motivation": "espionage",
        "country": "IR",
        "techniques": ["T1566", "T1204", "T1059", "T1218", "T1071", "T1105"],
    },
    {
        "name": "Turla",
        "aliases": ["Snake", "Venomous Bear", "Secret Blizzard"],
        "mitre_id": "G0010",
        "description": "Russian FSB-linked group known for stealthy long-term espionage implants.",
        "sophistication": "advanced",
        "motivation": "espionage",
        "country": "RU",
        "techniques": ["T1133", "T1014", "T1542", "T1071", "T1572", "T1090"],
    },
    {
        "name": "Kimsuky",
        "aliases": ["Emerald Sleet", "Velvet Chollima", "Black Banshee"],
        "mitre_id": "G0094",
        "description": "North Korean group focused on intelligence collection against policy and research targets.",
        "sophistication": "intermediate",
        "motivation": "espionage",
        "country": "KP",
        "techniques": ["T1566", "T1598", "T1204", "T1059", "T1114", "T1552"],
    },
]

FEEDS: list[dict[str, Any]] = [
    {
        "name": "CISA AIS — TAXII 2.1",
        "kind": "taxii",
        "schedule_minutes": 240,
        "config": {
            "url": "https://taxii.ais.cisa.gov/taxii2",
            "auth_type": "basic",
            "verify_tls": True,
        },
        "enabled": False,
    },
    {
        "name": "MITRE ATT&CK CTI — STIX 2.1",
        "kind": "stix",
        "schedule_minutes": 1440,
        "config": {
            "url": ("https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"),
            "verify_tls": True,
        },
        "enabled": False,
    },
]


def seed_actors(db, *, dry_run: bool) -> tuple[int, int]:  # type: ignore[no-untyped-def]
    created = 0
    updated = 0
    for entry in ACTORS:
        existing = db.execute(
            select(ThreatActor).where(ThreatActor.org_id.is_(None), ThreatActor.name == entry["name"])
        ).scalar_one_or_none()
        if existing is None:
            if not dry_run:
                db.add(
                    ThreatActor(
                        org_id=None,
                        name=entry["name"],
                        aliases=list(entry["aliases"]),
                        mitre_id=entry["mitre_id"],
                        description=entry["description"],
                        sophistication=entry["sophistication"],
                        motivation=entry["motivation"],
                        country=entry["country"],
                        techniques=list(entry["techniques"]),
                        stix={},
                    )
                )
            created += 1
            continue
        changed = False
        for field in ("aliases", "mitre_id", "description", "sophistication", "motivation", "country", "techniques"):
            value = entry[field]
            if getattr(existing, field) != value:
                if not dry_run:
                    setattr(existing, field, list(value) if isinstance(value, list) else value)
                changed = True
        if changed:
            updated += 1
    return created, updated


def seed_feeds(db, org: Organization, *, dry_run: bool) -> tuple[int, int]:  # type: ignore[no-untyped-def]
    created = 0
    updated = 0
    for entry in FEEDS:
        existing = db.execute(
            select(TIFeed).where(TIFeed.org_id == org.id, TIFeed.name == entry["name"])
        ).scalar_one_or_none()
        config = {**entry["config"]}
        if existing is None:
            if not dry_run:
                db.add(
                    TIFeed(
                        org_id=org.id,
                        name=entry["name"],
                        kind=entry["kind"],
                        enabled=entry["enabled"],
                        schedule_minutes=entry["schedule_minutes"],
                        status="idle",
                        config=config,
                    )
                )
            created += 1
            continue
        changed = False
        if existing.kind != entry["kind"]:
            if not dry_run:
                existing.kind = entry["kind"]
            changed = True
        if existing.schedule_minutes != entry["schedule_minutes"]:
            if not dry_run:
                existing.schedule_minutes = entry["schedule_minutes"]
            changed = True
        # Never overwrite an operator-provided URL or credentials; only fill gaps.
        merged_config = dict(existing.config or {})
        for key, value in config.items():
            if not merged_config.get(key):
                merged_config[key] = value
                changed = True
        if changed and not dry_run:
            existing.config = merged_config
        if changed:
            updated += 1
    return created, updated


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed the HISPANSHIELD threat-intelligence catalogue")
    parser.add_argument("--org-slug", help="Only seed feeds for this organization slug")
    parser.add_argument("--dry-run", action="store_true", help="Report changes without writing them")
    args = parser.parse_args()

    with SessionLocal() as db:
        if args.org_slug:
            organizations = list(
                db.execute(
                    select(Organization).where(Organization.slug == args.org_slug, Organization.deleted_at.is_(None))
                ).scalars()
            )
        else:
            organizations = list(db.execute(select(Organization).where(Organization.deleted_at.is_(None))).scalars())
        if args.org_slug and not organizations:
            print(f"Organization not found: {args.org_slug}")
            return 2

        actor_created, actor_updated = seed_actors(db, dry_run=args.dry_run)
        feed_created = 0
        feed_updated = 0
        for org in organizations:
            created, updated = seed_feeds(db, org, dry_run=args.dry_run)
            feed_created += created
            feed_updated += updated
        if not args.dry_run:
            db.commit()

    prefix = "[dry-run] " if args.dry_run else ""
    print(
        f"{prefix}actors: {actor_created} created, {actor_updated} updated | "
        f"feeds: {feed_created} created, {feed_updated} updated for {len(organizations)} organization(s) "
        f"at {utcnow().isoformat()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
