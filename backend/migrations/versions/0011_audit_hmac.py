"""keyed audit hashes (v3) and signed checkpoints

Revision ID: 0011_audit_hmac
Revises: 0010_break_glass_dual_control

The audit chain keeps verifying historical v1/v2 records. New records written
after ``HS_AUDIT_HMAC_KEY`` is configured use HMAC-SHA256 with a key that is not
stored in PostgreSQL, and record the key id so keys can be rotated without
invalidating old segments.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0011_audit_hmac"
down_revision = "0010_break_glass_dual_control"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("audit_records", sa.Column("hash_version", sa.Integer(), nullable=True))
    op.add_column("audit_records", sa.Column("key_id", sa.String(length=40), nullable=True))
    op.create_table(
        "audit_checkpoints",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("head_hash", sa.String(length=64), nullable=False),
        sa.Column("record_count", sa.Integer(), nullable=False),
        sa.Column("key_id", sa.String(length=40), nullable=False),
        sa.Column("signature", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_audit_checkpoints_org_id", "audit_checkpoints", ["org_id"])
    op.create_index("ix_audit_checkpoints_org_created", "audit_checkpoints", ["org_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_audit_checkpoints_org_created", table_name="audit_checkpoints")
    op.drop_index("ix_audit_checkpoints_org_id", table_name="audit_checkpoints")
    op.drop_table("audit_checkpoints")
    op.drop_column("audit_records", "key_id")
    op.drop_column("audit_records", "hash_version")
