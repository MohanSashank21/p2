"""Store project invitation recipients by email.

Revision ID: 2f6a9c1d8e43
Revises: f18b76e4a2c9
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "2f6a9c1d8e43"
down_revision: Union[str, Sequence[str], None] = "f18b76e4a2c9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
  op.add_column(
    "project_invitations",
    sa.Column("invitee_email", sa.String(length=320), nullable=True),
  )
  op.execute(
    """
    UPDATE project_invitations AS invitation
    SET invitee_email = lower(users.email)
    FROM users
    WHERE users.id = invitation.invitee_user_id
    """,
  )
  op.alter_column(
    "project_invitations",
    "invitee_email",
    existing_type=sa.String(length=320),
    nullable=False,
  )
  op.drop_constraint(
    "fk_project_invitations_organisation_invitee",
    "project_invitations",
    type_="foreignkey",
  )
  op.drop_index(
    "ix_project_invitations_invitee_user_id",
    table_name="project_invitations",
  )
  op.drop_column("project_invitations", "invitee_user_id")
  op.create_index(
    "ix_project_invitations_invitee_email",
    "project_invitations",
    ["invitee_email"],
  )


def downgrade() -> None:
  op.add_column(
    "project_invitations",
    sa.Column("invitee_user_id", sa.Uuid(), nullable=True),
  )
  op.execute(
    """
    UPDATE project_invitations AS invitation
    SET invitee_user_id = users.id
    FROM users
    WHERE lower(users.email) = lower(invitation.invitee_email)
    """,
  )
  op.execute(
    """
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1
        FROM project_invitations
        WHERE invitee_user_id IS NULL
      ) THEN
        RAISE EXCEPTION
          'Cannot downgrade project invitation emails: an invitee email has no matching user';
      END IF;
    END
    $$;
    """,
  )
  op.alter_column(
    "project_invitations",
    "invitee_user_id",
    existing_type=sa.Uuid(),
    nullable=False,
  )
  op.create_index(
    "ix_project_invitations_invitee_user_id",
    "project_invitations",
    ["invitee_user_id"],
  )
  op.create_foreign_key(
    "fk_project_invitations_organisation_invitee",
    "project_invitations",
    "memberships",
    ["organisation_id", "invitee_user_id"],
    ["organisation_id", "user_id"],
    ondelete="CASCADE",
  )
  op.drop_index(
    "ix_project_invitations_invitee_email",
    table_name="project_invitations",
  )
  op.drop_column("project_invitations", "invitee_email")
