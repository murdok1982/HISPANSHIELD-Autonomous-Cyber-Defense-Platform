"""outbox LISTEN/NOTIFY signal (polling remains the safety net)

Revision ID: 0015_outbox_notify
Revises: 0014_invitations

PostgreSQL delivers ``pg_notify`` payloads only after the producing transaction
commits, so a consumer can never observe an event that was rolled back. The
notification is a latency optimisation: the dispatcher still polls and reclaims
expired leases, therefore a lost notification cannot lose an event.
"""

from alembic import op

revision = "0015_outbox_notify"
down_revision = "0014_invitations"
branch_labels = None
depends_on = None

CHANNEL = "hispanshield_outbox"


def upgrade() -> None:
    op.execute(
        f"""
        CREATE OR REPLACE FUNCTION hispanshield_notify_outbox()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            PERFORM pg_notify('{CHANNEL}', NEW.id::text);
            RETURN NEW;
        END;
        $$;
        """
    )
    op.execute(
        """
        CREATE TRIGGER outbox_events_notify
        AFTER INSERT ON outbox_events
        FOR EACH ROW
        EXECUTE FUNCTION hispanshield_notify_outbox();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS outbox_events_notify ON outbox_events")
    op.execute("DROP FUNCTION IF EXISTS hispanshield_notify_outbox()")
