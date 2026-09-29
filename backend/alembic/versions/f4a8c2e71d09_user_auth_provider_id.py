"""User.auth_provider_id: external accounts belong to a provider, not a type (#1235).

External logins were matched on ``(auth_source, external_id)``, where
``auth_source`` is the provider TYPE (``ldap``, ``oidc``, ...). With two
providers of one type, the second could sign in as the first one's users.
This adds the provider reference the match is now keyed on.

Backfill, best effort and never guessing:

* RADIUS / TACACS+ accounts carry their provider in the external id
  (``<provider id>:<username>``), so they are attributed exactly.
* An LDAP / OIDC / SAML account is attributed when exactly one provider of
  its type exists. With two or more there is no way to tell which one it
  came from, so it stays NULL and the next login through either is refused
  until an administrator links it (``POST /users/{id}/link-provider``).

A plain index rather than a unique one: an install that already holds two
rows with one provider and one external id must still be able to upgrade.

Revision ID: f4a8c2e71d09
Revises: e6b2d94f1a37
Create Date: 2026-09-29
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "f4a8c2e71d09"
down_revision = "e6b2d94f1a37"
branch_labels = None
depends_on = None


# RADIUS / TACACS+: the provider id is the external id's prefix.
BACKFILL_BY_PREFIX = """
    UPDATE "user" u
       SET auth_provider_id = p.id
      FROM auth_provider p
     WHERE u.auth_provider_id IS NULL
       AND u.auth_source IN ('radius', 'tacacs')
       AND p.type = u.auth_source
       AND u.external_id LIKE p.id::text || ':%'
"""

# Every other external type: only when exactly one provider of the type
# exists, so the account cannot have come from another one.
BACKFILL_SOLE_PROVIDER = """
    UPDATE "user" u
       SET auth_provider_id = p.id
      FROM auth_provider p
     WHERE u.auth_provider_id IS NULL
       AND u.auth_source <> 'local'
       AND u.external_id IS NOT NULL
       AND p.type = u.auth_source
       AND (SELECT count(*) FROM auth_provider q WHERE q.type = u.auth_source) = 1
"""


def upgrade() -> None:
    op.add_column(
        "user",
        sa.Column("auth_provider_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_user_auth_provider_id_auth_provider",
        "user",
        "auth_provider",
        ["auth_provider_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_user_auth_provider_id", "user", ["auth_provider_id"])

    op.execute(BACKFILL_BY_PREFIX)
    op.execute(BACKFILL_SOLE_PROVIDER)


def downgrade() -> None:
    op.drop_index("ix_user_auth_provider_id", table_name="user")
    op.drop_constraint("fk_user_auth_provider_id_auth_provider", "user", type_="foreignkey")
    op.drop_column("user", "auth_provider_id")
