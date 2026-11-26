"""single-use approvals

Revision ID: 0004_approval_single_use
Revises: 0003_audit_truncate
"""

from alembic import op
import sqlalchemy as sa

revision = "0004_approval_single_use"
down_revision = "0003_audit_truncate"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("approvals", sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("approvals", "consumed_at")
