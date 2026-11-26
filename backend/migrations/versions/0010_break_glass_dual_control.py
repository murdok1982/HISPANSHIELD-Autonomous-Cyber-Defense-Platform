"""dual control for platform break-glass grants

Revision ID: 0010_break_glass_dual_control
Revises: 0009_recovery_codes
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0010_break_glass_dual_control"
down_revision = "0009_recovery_codes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "break_glass_grants",
        sa.Column("status", sa.String(length=20), nullable=False, server_default="approved"),
    )
    op.add_column(
        "break_glass_grants",
        sa.Column("approved_by", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.add_column(
        "break_glass_grants",
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_break_glass_approved_by", "break_glass_grants", "users", ["approved_by"], ["id"]
    )
    op.execute("UPDATE break_glass_grants SET approved_by = user_id, approved_at = created_at WHERE status = 'approved'")


def downgrade() -> None:
    op.drop_constraint("fk_break_glass_approved_by", "break_glass_grants", type_="foreignkey")
    op.drop_column("break_glass_grants", "approved_at")
    op.drop_column("break_glass_grants", "approved_by")
    op.drop_column("break_glass_grants", "status")
