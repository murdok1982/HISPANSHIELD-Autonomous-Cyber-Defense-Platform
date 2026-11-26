"""ingest replay protection and dual-control discovery authorization

Revision ID: 0008_ingest_replay_scope
Revises: 0007_edge_fingerprint_scope

VULN-010: HMAC v2 replays are stopped by consuming single-use nonces
(``ingest_nonces``) and by a per-organization unique dedupe index on
``security_events``. Duplicated rows created before the constraint are removed
(keeping the oldest id) so the unique index can be built on live data.

VULN-011: attack-surface discovery requires an approved, unexpired and
unrevoked ``discovery_authorizations`` record. Jobs reference it explicitly.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0008_ingest_replay_scope"
down_revision = "0007_edge_fingerprint_scope"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- VULN-010: single-use nonces -------------------------------------
    op.create_table(
        "ingest_nonces",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "source_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("ingest_sources.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("nonce", sa.String(length=128), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("source_id", "nonce", name="uq_ingest_nonces_source_nonce"),
    )
    op.create_index("ix_ingest_nonces_org_id", "ingest_nonces", ["org_id"])
    op.create_index("ix_ingest_nonces_received", "ingest_nonces", ["received_at"])

    # --- VULN-010: persistent dedupe -------------------------------------
    op.execute(
        sa.text(
            """
            DELETE FROM security_events duplicate USING security_events keeper
            WHERE duplicate.org_id = keeper.org_id
              AND duplicate.dedupe_key = keeper.dedupe_key
              AND duplicate.dedupe_key IS NOT NULL
              AND duplicate.id > keeper.id
            """
        )
    )
    op.drop_index("ix_events_dedupe", table_name="security_events")
    op.create_index(
        "uq_events_org_dedupe",
        "security_events",
        ["org_id", "dedupe_key"],
        unique=True,
        postgresql_where=sa.text("dedupe_key IS NOT NULL"),
    )

    # --- VULN-011: discovery authorization -------------------------------
    op.create_table(
        "discovery_authorizations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column(
            "cidrs",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "ports",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("max_hosts", sa.Integer(), nullable=False, server_default=sa.text("256")),
        sa.Column(
            "approved_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "revoked_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_discovery_auth_org_id", "discovery_authorizations", ["org_id"])
    op.create_index("ix_discovery_auth_org_created", "discovery_authorizations", ["org_id", "created_at"])

    op.add_column(
        "discovery_jobs",
        sa.Column("authorization_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_discovery_jobs_authorization_id",
        "discovery_jobs",
        "discovery_authorizations",
        ["authorization_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_discovery_jobs_authorization_id", "discovery_jobs", ["authorization_id"])


def downgrade() -> None:
    op.drop_index("ix_discovery_jobs_authorization_id", table_name="discovery_jobs")
    op.drop_constraint("fk_discovery_jobs_authorization_id", "discovery_jobs", type_="foreignkey")
    op.drop_column("discovery_jobs", "authorization_id")
    op.drop_index("ix_discovery_auth_org_created", table_name="discovery_authorizations")
    op.drop_index("ix_discovery_auth_org_id", table_name="discovery_authorizations")
    op.drop_table("discovery_authorizations")

    op.drop_index("uq_events_org_dedupe", table_name="security_events")
    op.create_index("ix_events_dedupe", "security_events", ["org_id", "dedupe_key"], unique=False)

    op.drop_index("ix_ingest_nonces_received", table_name="ingest_nonces")
    op.drop_index("ix_ingest_nonces_org_id", table_name="ingest_nonces")
    op.drop_table("ingest_nonces")
