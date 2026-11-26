"""time-boxed break-glass grants for platform administrators

Revision ID: 0005_break_glass
Revises: 0004_approval_single_use
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0005_break_glass"
down_revision = "0004_approval_single_use"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "break_glass_grants",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("reason", sa.String(length=1000), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_index("ix_break_glass_user_org", "break_glass_grants", ["user_id", "org_id", "expires_at"])


def downgrade() -> None:
    op.drop_index("ix_break_glass_user_org", table_name="break_glass_grants")
    op.drop_table("break_glass_grants")
