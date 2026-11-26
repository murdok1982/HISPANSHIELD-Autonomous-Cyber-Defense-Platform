"""block TRUNCATE on the audit trail

Revision ID: 0003_audit_truncate
Revises: 0002_hardening
"""

from alembic import op

revision = "0003_audit_truncate"
down_revision = "0002_hardening"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TRIGGER audit_records_no_truncate
        BEFORE TRUNCATE ON audit_records
        FOR EACH STATEMENT EXECUTE FUNCTION hispanshield_block_audit_mutation();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_records_no_truncate ON audit_records;")
