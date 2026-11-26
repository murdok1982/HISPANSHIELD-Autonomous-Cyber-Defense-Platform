"""asset soft delete (deleted_at) instead of physical deletion

Revision ID: 0016_asset_soft_delete
Revises: 0015_outbox_notify
"""

import sqlalchemy as sa
from alembic import op

revision = "0016_asset_soft_delete"
down_revision = "0015_outbox_notify"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("assets", sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_assets_deleted_at", "assets", ["deleted_at"])


def downgrade() -> None:
    op.drop_index("ix_assets_deleted_at", table_name="assets")
    op.drop_column("assets", "deleted_at")
