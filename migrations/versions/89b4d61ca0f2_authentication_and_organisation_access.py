"""add verified accounts, refresh sessions and organisation access

Revision ID: 89b4d61ca0f2
Revises: 308dc1bfd99c
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "89b4d61ca0f2"
down_revision: Union[str, Sequence[str], None] = "308dc1bfd99c"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
  op.add_column(
    "users",
    sa.Column(
      "email_verified",
      sa.Boolean(),
      server_default=sa.false(),
      nullable=False,
    ),
  )

  op.execute(
    "UPDATE memberships SET role = 'worker' WHERE role IN ('member', 'viewer')"
  )
  op.drop_constraint("ck_memberships_role", "memberships", type_="check")
  op.create_check_constraint(
    "ck_memberships_role",
    "memberships",
    "role IN ('owner', 'admin', 'worker')",
  )

  op.create_table(
    "refresh_sessions",
    sa.Column("id", sa.Uuid(), nullable=False),
    sa.Column("family_id", sa.Uuid(), nullable=False),
    sa.Column("user_id", sa.Uuid(), nullable=False),
    sa.Column("token_hash", sa.String(length=64), nullable=False),
    sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("replaced_by_id", sa.Uuid(), nullable=True),
    sa.Column(
      "created_at",
      sa.DateTime(timezone=True),
      server_default=sa.text("now()"),
      nullable=False,
    ),
    sa.ForeignKeyConstraint(
      ["replaced_by_id"],
      ["refresh_sessions.id"],
    ),
    sa.ForeignKeyConstraint(
      ["user_id"],
      ["users.id"],
      ondelete="CASCADE",
    ),
    sa.PrimaryKeyConstraint("id"),
    sa.UniqueConstraint("token_hash"),
  )
  op.create_index("ix_refresh_sessions_family_id", "refresh_sessions", ["family_id"])
  op.create_index("ix_refresh_sessions_user_id", "refresh_sessions", ["user_id"])

  op.create_table(
    "organisation_invitations",
    sa.Column("id", sa.Uuid(), nullable=False),
    sa.Column("organisation_id", sa.Uuid(), nullable=False),
    sa.Column("invited_by_user_id", sa.Uuid(), nullable=False),
    sa.Column("email", sa.String(length=320), nullable=False),
    sa.Column("role", sa.String(length=20), nullable=False),
    sa.Column("token_hash", sa.String(length=64), nullable=False),
    sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column(
      "created_at",
      sa.DateTime(timezone=True),
      server_default=sa.text("now()"),
      nullable=False,
    ),
    sa.CheckConstraint(
      "role IN ('admin', 'worker')",
      name="ck_organisation_invitations_role",
    ),
    sa.ForeignKeyConstraint(
      ["invited_by_user_id"],
      ["users.id"],
      ondelete="CASCADE",
    ),
    sa.ForeignKeyConstraint(
      ["organisation_id"],
      ["organisations.id"],
      ondelete="CASCADE",
    ),
    sa.PrimaryKeyConstraint("id"),
    sa.UniqueConstraint("token_hash"),
  )
  op.create_index(
    "ix_organisation_invitations_email",
    "organisation_invitations",
    ["email"],
  )
  op.create_index(
    "ix_organisation_invitations_organisation_id",
    "organisation_invitations",
    ["organisation_id"],
  )

  op.create_table(
    "platform_bootstrap",
    sa.Column("key", sa.String(length=32), nullable=False),
    sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint("key = 'platform'", name="ck_platform_bootstrap_singleton"),
    sa.PrimaryKeyConstraint("key"),
  )
  op.bulk_insert(
    sa.table("platform_bootstrap", sa.column("key", sa.String())),
    [{"key": "platform"}],
  )


def downgrade() -> None:
  op.drop_table("platform_bootstrap")
  op.drop_index(
    "ix_organisation_invitations_organisation_id",
    table_name="organisation_invitations",
  )
  op.drop_index(
    "ix_organisation_invitations_email",
    table_name="organisation_invitations",
  )
  op.drop_table("organisation_invitations")
  op.drop_index("ix_refresh_sessions_user_id", table_name="refresh_sessions")
  op.drop_index("ix_refresh_sessions_family_id", table_name="refresh_sessions")
  op.drop_table("refresh_sessions")
  op.drop_constraint("ck_memberships_role", "memberships", type_="check")
  op.create_check_constraint(
    "ck_memberships_role",
    "memberships",
    "role IN ('owner', 'admin', 'member', 'viewer')",
  )
  op.drop_column("users", "email_verified")
