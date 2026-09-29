"""DNS record ops: retry backoff and supersession (#1232).

Two nullable columns, no backfill.

* ``dns_record_op.next_attempt_at`` — when a failed op may ship again.
  Retries used to go out on every heartbeat, so a ~2.5 minute daemon outage
  used all five attempts.
* ``dns_record_op.superseded_by`` — the newer op for the same RRset that
  made this one obsolete (state ``superseded``). Every op carries the whole
  desired RRset (#773), so retrying an older op after a newer one applied
  would revert the newer change.

Ops already stuck ``in_flight`` on an existing install are not touched here:
the first long-poll after the upgrade finds them unacknowledged for longer
than the timeout and returns them to ``pending``.

Revision ID: d8e1b5a26c47
Revises: e6b2d94f1a37
Create Date: 2026-09-29
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "d8e1b5a26c47"
down_revision = "e6b2d94f1a37"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "dns_record_op", sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "dns_record_op", sa.Column("superseded_by", postgresql.UUID(as_uuid=True), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("dns_record_op", "superseded_by")
    op.drop_column("dns_record_op", "next_attempt_at")
