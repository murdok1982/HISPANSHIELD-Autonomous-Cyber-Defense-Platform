"""scope edge gateway fingerprints per organization

Revision ID: 0007_edge_fingerprint_scope
Revises: 0006_break_glass_ticket

A global unique fingerprint lets one tenant enumerate or deliberately collide
gateways of another tenant (VULN-028). Uniqueness is now enforced per
organization while the plain index keeps gateway lookups fast.
"""

from alembic import op
import sqlalchemy as sa

revision = "0007_edge_fingerprint_scope"
down_revision = "0006_break_glass_ticket"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_index("ix_edge_gateways_fingerprint", table_name="edge_gateways")
    op.create_index("ix_edge_gateways_fingerprint", "edge_gateways", ["fingerprint"], unique=False)
    op.create_unique_constraint("uq_edge_gateways_org_fingerprint", "edge_gateways", ["org_id", "fingerprint"])


def downgrade() -> None:
    op.drop_constraint("uq_edge_gateways_org_fingerprint", "edge_gateways", type_="unique")
    op.drop_index("ix_edge_gateways_fingerprint", table_name="edge_gateways")
    op.create_index("ix_edge_gateways_fingerprint", "edge_gateways", ["fingerprint"], unique=True)
