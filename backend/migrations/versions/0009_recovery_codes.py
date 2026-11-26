"""hashed one-time MFA recovery codes

Revision ID: 0009_recovery_codes
Revises: 0008_ingest_replay_scope
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0009_recovery_codes"
down_revision = "0008_ingest_replay_scope"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("recovery_codes", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
    )


def downgrade() -> None:
    op.drop_column("users", "recovery_codes")
