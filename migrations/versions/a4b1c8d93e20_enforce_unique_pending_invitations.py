"""Enforce one pending invitation per target.

Revision ID: a4b1c8d93e20
Revises: 2f6a9c1d8e43
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "a4b1c8d93e20"
down_revision: Union[str, Sequence[str], None] = "2f6a9c1d8e43"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
  op.execute(
    """
    WITH ranked AS (
      SELECT
        id,
        row_number() OVER (
          PARTITION BY organisation_id, lower(email)
          ORDER BY created_at DESC, id DESC
        ) AS position
      FROM organisation_invitations
      WHERE accepted_at IS NULL
    )
    DELETE FROM organisation_invitations AS invitation
    USING ranked
    WHERE invitation.id = ranked.id AND ranked.position > 1;
    """,
  )
  op.execute(
    """
    WITH ranked AS (
      SELECT
        id,
        row_number() OVER (
          PARTITION BY organisation_id, proposed_project_name
          ORDER BY created_at DESC, id DESC
        ) AS position
      FROM project_invitations
      WHERE role = 'manager' AND accepted_at IS NULL
    )
    DELETE FROM project_invitations AS invitation
    USING ranked
    WHERE invitation.id = ranked.id AND ranked.position > 1;
    """,
  )
  op.execute(
    """
    WITH ranked AS (
      SELECT
        id,
        row_number() OVER (
          PARTITION BY project_id, lower(invitee_email)
          ORDER BY created_at DESC, id DESC
        ) AS position
      FROM project_invitations
      WHERE role = 'worker' AND accepted_at IS NULL
    )
    DELETE FROM project_invitations AS invitation
    USING ranked
    WHERE invitation.id = ranked.id AND ranked.position > 1;
    """,
  )
  op.create_index(
    "uq_organisation_invitations_pending_target",
    "organisation_invitations",
    ["organisation_id", sa.text("lower(email)")],
    unique=True,
    postgresql_where=sa.text("accepted_at IS NULL"),
  )
  op.create_index(
    "uq_project_invitations_pending_manager",
    "project_invitations",
    ["organisation_id", "proposed_project_name"],
    unique=True,
    postgresql_where=sa.text(
      "role = 'manager' AND accepted_at IS NULL",
    ),
  )
  op.create_index(
    "uq_project_invitations_pending_worker",
    "project_invitations",
    ["project_id", sa.text("lower(invitee_email)")],
    unique=True,
    postgresql_where=sa.text(
      "role = 'worker' AND accepted_at IS NULL",
    ),
  )


def downgrade() -> None:
  op.drop_index(
    "uq_project_invitations_pending_worker",
    table_name="project_invitations",
  )
  op.drop_index(
    "uq_project_invitations_pending_manager",
    table_name="project_invitations",
  )
  op.drop_index(
    "uq_organisation_invitations_pending_target",
    table_name="organisation_invitations",
  )
