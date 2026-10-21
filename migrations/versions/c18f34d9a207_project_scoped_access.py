"""Make project memberships the access boundary.

Revision ID: c18f34d9a207
Revises: da84b63c105e
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c18f34d9a207"
down_revision: Union[str, Sequence[str], None] = "da84b63c105e"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
  op.execute(
    """
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1
        FROM project_memberships
        WHERE role NOT IN ('manager', 'worker')
      ) THEN
        RAISE EXCEPTION
          'Cannot migrate project roles: an unrecognized role exists';
      END IF;
    END
    $$;
    """,
  )

  op.drop_constraint(
    "ck_project_memberships_role",
    "project_memberships",
    type_="check",
  )
  op.drop_constraint(
    "fk_project_memberships_project_organisation",
    "project_memberships",
    type_="foreignkey",
  )
  op.drop_constraint(
    "fk_project_memberships_organisation_user",
    "project_memberships",
    type_="foreignkey",
  )
  op.drop_constraint(
    "uq_projects_organisation_name",
    "projects",
    type_="unique",
  )

  op.execute(
    """
    UPDATE project_memberships
    SET role = CASE role
      WHEN 'manager' THEN 'owner'
      WHEN 'worker' THEN 'member'
    END
    """,
  )
  op.execute(
    """
    UPDATE project_memberships AS membership
    SET role = 'owner'
    FROM projects AS project
    JOIN organisations AS organisation
      ON organisation.id = project.organisation_id
    WHERE membership.project_id = project.id
      AND membership.user_id = organisation.owner_user_id
      AND membership.role = 'member'
      AND NOT EXISTS (
        SELECT 1
        FROM project_memberships AS owner_membership
        WHERE owner_membership.project_id = project.id
          AND owner_membership.role = 'owner'
      )
    """,
  )
  op.execute(
    """
    INSERT INTO project_memberships
      (id, project_id, organisation_id, user_id, role, created_at)
    SELECT
      gen_random_uuid(),
      project.id,
      project.organisation_id,
      organisation.owner_user_id,
      'owner',
      now()
    FROM projects AS project
    JOIN organisations AS organisation
      ON organisation.id = project.organisation_id
    WHERE NOT EXISTS (
      SELECT 1
      FROM project_memberships AS membership
      WHERE membership.project_id = project.id
        AND membership.role = 'owner'
    )
    """,
  )

  op.alter_column(
    "projects",
    "organisation_id",
    existing_type=sa.Uuid(),
    nullable=True,
  )
  op.alter_column(
    "project_memberships",
    "organisation_id",
    existing_type=sa.Uuid(),
    nullable=True,
  )
  op.create_check_constraint(
    "ck_project_memberships_role",
    "project_memberships",
    "role IN ('owner', 'member')",
  )
  op.create_foreign_key(
    "fk_project_memberships_project",
    "project_memberships",
    "projects",
    ["project_id"],
    ["id"],
    ondelete="CASCADE",
  )
  op.drop_constraint(
    "environments_project_id_fkey",
    "environments",
    type_="foreignkey",
  )
  op.create_foreign_key(
    "fk_environments_project_id_projects",
    "environments",
    "projects",
    ["project_id"],
    ["id"],
    ondelete="CASCADE",
  )


def downgrade() -> None:
  op.execute(
    """
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1
        FROM projects
        WHERE organisation_id IS NULL
      ) OR EXISTS (
        SELECT 1
        FROM project_memberships
        WHERE organisation_id IS NULL
      ) THEN
        RAISE EXCEPTION
          'Cannot downgrade project access: projects or memberships created after the project-scoped migration no longer have organization assignments';
      END IF;
    END
    $$;
    """,
  )
  op.drop_constraint(
    "fk_environments_project_id_projects",
    "environments",
    type_="foreignkey",
  )
  op.drop_constraint(
    "fk_project_memberships_project",
    "project_memberships",
    type_="foreignkey",
  )
  op.drop_constraint(
    "ck_project_memberships_role",
    "project_memberships",
    type_="check",
  )
  op.execute(
    """
    UPDATE project_memberships
    SET role = CASE role
      WHEN 'owner' THEN 'manager'
      WHEN 'member' THEN 'worker'
    END
    """,
  )
  op.alter_column(
    "project_memberships",
    "organisation_id",
    existing_type=sa.Uuid(),
    nullable=False,
  )
  op.create_foreign_key(
    "fk_project_memberships_project_organisation",
    "project_memberships",
    "projects",
    ["project_id", "organisation_id"],
    ["id", "organisation_id"],
    ondelete="CASCADE",
  )
  op.create_foreign_key(
    "fk_project_memberships_organisation_user",
    "project_memberships",
    "memberships",
    ["organisation_id", "user_id"],
    ["organisation_id", "user_id"],
    ondelete="CASCADE",
  )
  op.create_check_constraint(
    "ck_project_memberships_role",
    "project_memberships",
    "role IN ('manager', 'worker')",
  )
  op.create_unique_constraint(
    "uq_projects_organisation_name",
    "projects",
    ["organisation_id", "name"],
  )
  op.drop_constraint(
    "fk_environments_project_id_projects",
    "environments",
    type_="foreignkey",
  )
  op.create_foreign_key(
    "environments_project_id_fkey",
    "environments",
    "projects",
    ["project_id"],
    ["id"],
  )
  op.alter_column(
    "projects",
    "organisation_id",
    existing_type=sa.Uuid(),
    nullable=False,
  )
