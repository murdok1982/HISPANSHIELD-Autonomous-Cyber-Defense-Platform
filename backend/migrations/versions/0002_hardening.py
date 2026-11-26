"""audit append-only trigger and event full-text index

Revision ID: 0002_hardening
Revises: 83825cd958ca
"""

from __future__ import annotations

from alembic import op

revision = "0002_hardening"
down_revision = "83825cd958ca"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION hispanshield_block_audit_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'audit_records is append-only';
        END;
        $$;
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_records_append_only
        BEFORE UPDATE OR DELETE ON audit_records
        FOR EACH ROW EXECUTE FUNCTION hispanshield_block_audit_mutation();
        """
    )
    # Full-text search over normalized security events. Uses the immutable
    # 'simple' configuration so no locale-dependent stemming surprises occur.
    op.execute(
        """
        CREATE INDEX ix_events_fts ON security_events
        USING GIN (
            to_tsvector(
                'simple',
                coalesce(message, '') || ' ' ||
                coalesce(host_name, '') || ' ' ||
                coalesce(user_name, '') || ' ' ||
                coalesce(src_ip, '') || ' ' ||
                coalesce(dst_ip, '') || ' ' ||
                coalesce(domain, '')
            )
        );
        """
    )
    op.execute("CREATE INDEX ix_events_org_received ON security_events (org_id, received_at DESC);")
    op.execute("CREATE INDEX ix_incidents_ref ON incidents (ref);")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_incidents_ref;")
    op.execute("DROP INDEX IF EXISTS ix_events_org_received;")
    op.execute("DROP INDEX IF EXISTS ix_events_fts;")
    op.execute("DROP TRIGGER IF EXISTS audit_records_append_only ON audit_records;")
    op.execute("DROP FUNCTION IF EXISTS hispanshield_block_audit_mutation();")
