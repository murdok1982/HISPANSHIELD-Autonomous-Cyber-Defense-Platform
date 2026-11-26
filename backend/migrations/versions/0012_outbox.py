"""transactional outbox and notification idempotency

Revision ID: 0012_outbox
Revises: 0011_audit_hmac
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0012_outbox"
down_revision = "0011_audit_hmac"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("notifications", sa.Column("source_event_id", sa.String(length=80), nullable=True))
    op.create_index("ix_notifications_source_event_id", "notifications", ["source_event_id"])
    op.create_table(
        "outbox_events",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("event_type", sa.String(length=80), nullable=False),
        sa.Column("aggregate_type", sa.String(length=60), nullable=False),
        sa.Column("aggregate_id", sa.String(length=80), nullable=True),
        sa.Column(
            "payload",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("dedupe_key", sa.String(length=160), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="8"),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("locked_by", sa.String(length=80), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_outbox_org_status_available", "outbox_events", ["org_id", "status", "available_at"])
    op.create_index(
        "uq_outbox_org_dedupe",
        "outbox_events",
        ["org_id", "dedupe_key"],
        unique=True,
        postgresql_where=sa.text("dedupe_key IS NOT NULL"),
    )
    op.create_index("ix_outbox_processing_lease", "outbox_events", ["status", "locked_until"])


def downgrade() -> None:
    op.drop_index("ix_outbox_processing_lease", table_name="outbox_events")
    op.drop_index("uq_outbox_org_dedupe", table_name="outbox_events")
    op.drop_index("ix_outbox_org_status_available", table_name="outbox_events")
    op.drop_table("outbox_events")
    op.drop_index("ix_notifications_source_event_id", table_name="notifications")
    op.drop_column("notifications", "source_event_id")
