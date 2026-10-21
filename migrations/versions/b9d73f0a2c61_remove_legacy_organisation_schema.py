"""Remove inactive organization and invitation schema.

Revision ID: b9d73f0a2c61
Revises: c18f34d9a207
"""

from typing import Sequence, Union

from alembic import op


revision: str = "b9d73f0a2c61"
down_revision: Union[str, Sequence[str], None] = "c18f34d9a207"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
  op.execute(
    """
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM organisations)
        OR EXISTS (SELECT 1 FROM memberships)
        OR EXISTS (SELECT 1 FROM organisation_invitations)
        OR EXISTS (SELECT 1 FROM project_invitations)
        OR EXISTS (SELECT 1 FROM email_outbox)
      THEN
        RAISE EXCEPTION
          'Cannot remove legacy organization schema while organization or invitation records remain';
      END IF;
    END
    $$;
    """,
  )

  op.execute("DROP TRIGGER trg_memberships_require_owner ON memberships")
  op.execute("DROP TRIGGER trg_organisations_require_owner ON organisations")
  op.execute("DROP FUNCTION enforce_organisation_owner_membership()")

  op.drop_table("email_outbox")
  op.drop_table("project_invitations")
  op.drop_table("organisation_invitations")
  op.drop_table("memberships")

  op.drop_constraint(
    "projects_organisation_id_fkey",
    "projects",
    type_="foreignkey",
  )
  op.drop_index("ix_projects_organisation_id", table_name="projects")
  op.drop_constraint(
    "uq_projects_id_organisation",
    "projects",
    type_="unique",
  )
  op.drop_column("projects", "organisation_id")
  op.drop_column("project_memberships", "organisation_id")
  op.drop_table("organisations")


def downgrade() -> None:
  raise RuntimeError(
    "This migration is irreversible: organization and invitation schema "
    "and data were intentionally removed.",
  )
