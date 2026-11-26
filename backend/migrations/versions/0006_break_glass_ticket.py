"""break-glass change ticket

Revision ID: 0006_break_glass_ticket
Revises: 0005_break_glass
"""

from alembic import op
import sqlalchemy as sa

revision = "0006_break_glass_ticket"
down_revision = "0005_break_glass"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("break_glass_grants", sa.Column("ticket", sa.String(length=80), nullable=True))
    op.execute("UPDATE break_glass_grants SET ticket = 'legacy-migration' WHERE ticket IS NULL")
    op.alter_column("break_glass_grants", "ticket", nullable=False)


def downgrade() -> None:
    op.drop_column("break_glass_grants", "ticket")
