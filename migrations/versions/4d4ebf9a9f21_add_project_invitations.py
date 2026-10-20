"""Add project proposal and worker invitation flow.

Revision ID: 4d4ebf9a9f21
Revises: dd2a7e584c31
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "4d4ebf9a9f21"
down_revision: Union[str, Sequence[str], None] = "dd2a7e584c31"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
  op.create_table(
    "project_invitations",
    sa.Column("id", sa.Uuid(), nullable=False),
    sa.Column("organisation_id", sa.Uuid(), nullable=False),
    sa.Column("project_id", sa.Uuid(), nullable=True),
    sa.Column("accepted_project_id", sa.Uuid(), nullable=True),
    sa.Column("invited_by_user_id", sa.Uuid(), nullable=False),
    sa.Column("invitee_user_id", sa.Uuid(), nullable=False),
    sa.Column("role", sa.String(length=20), nullable=False),
    sa.Column("proposed_project_name", sa.String(length=120), nullable=True),
    sa.Column(
      "proposed_project_description",
      sa.String(length=4000),
      nullable=True,
    ),
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
      """
      (role = 'manager'
        AND project_id IS NULL
        AND proposed_project_name IS NOT NULL)
      OR
      (role = 'worker'
        AND project_id IS NOT NULL
        AND proposed_project_name IS NULL
        AND proposed_project_description IS NULL)
      """,
      name="ck_project_invitations_role_target",
    ),
    sa.CheckConstraint(
      """
      (accepted_at IS NULL AND accepted_project_id IS NULL)
      OR
      (accepted_at IS NOT NULL AND accepted_project_id IS NOT NULL)
      """,
      name="ck_project_invitations_acceptance_state",
    ),
    sa.ForeignKeyConstraint(
      ["organisation_id"],
      ["organisations.id"],
      name="fk_project_invitations_organisation",
      ondelete="CASCADE",
    ),
    sa.ForeignKeyConstraint(
      ["organisation_id", "invitee_user_id"],
      ["memberships.organisation_id", "memberships.user_id"],
      name="fk_project_invitations_organisation_invitee",
      ondelete="CASCADE",
    ),
    sa.ForeignKeyConstraint(
      ["project_id", "organisation_id"],
      ["projects.id", "projects.organisation_id"],
      name="fk_project_invitations_project_organisation",
      ondelete="CASCADE",
    ),
    sa.ForeignKeyConstraint(
      ["accepted_project_id", "organisation_id"],
      ["projects.id", "projects.organisation_id"],
      name="fk_project_invitations_accepted_project_organisation",
      ondelete="CASCADE",
    ),
    sa.ForeignKeyConstraint(
      ["invited_by_user_id"],
      ["users.id"],
      name="fk_project_invitations_inviter",
      ondelete="CASCADE",
    ),
    sa.PrimaryKeyConstraint("id"),
    sa.UniqueConstraint("token_hash"),
  )
  op.create_index(
    "ix_project_invitations_organisation_id",
    "project_invitations",
    ["organisation_id"],
  )
  op.create_index(
    "ix_project_invitations_project_id",
    "project_invitations",
    ["project_id"],
  )
  op.create_index(
    "ix_project_invitations_invitee_user_id",
    "project_invitations",
    ["invitee_user_id"],
  )


def downgrade() -> None:
  op.drop_index(
    "ix_project_invitations_invitee_user_id",
    table_name="project_invitations",
  )
  op.drop_index(
    "ix_project_invitations_project_id",
    table_name="project_invitations",
  )
  op.drop_index(
    "ix_project_invitations_organisation_id",
    table_name="project_invitations",
  )
  op.drop_table("project_invitations")
