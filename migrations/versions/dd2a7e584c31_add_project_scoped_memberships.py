"""Add project-scoped manager and worker memberships.

Revision ID: dd2a7e584c31
Revises: c72f4f27b613
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "dd2a7e584c31"
down_revision: Union[str, Sequence[str], None] = "c72f4f27b613"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
  op.create_unique_constraint(
    "uq_projects_id_organisation",
    "projects",
    ["id", "organisation_id"],
  )
  op.create_table(
    "project_memberships",
    sa.Column("id", sa.Uuid(), nullable=False),
    sa.Column("project_id", sa.Uuid(), nullable=False),
    sa.Column("organisation_id", sa.Uuid(), nullable=False),
    sa.Column("user_id", sa.Uuid(), nullable=False),
    sa.Column("role", sa.String(length=20), nullable=False),
    sa.Column(
      "created_at",
      sa.DateTime(timezone=True),
      server_default=sa.text("now()"),
      nullable=False,
    ),
    sa.CheckConstraint(
      "role IN ('manager', 'worker')",
      name="ck_project_memberships_role",
    ),
    sa.ForeignKeyConstraint(
      ["project_id", "organisation_id"],
      ["projects.id", "projects.organisation_id"],
      name="fk_project_memberships_project_organisation",
      ondelete="CASCADE",
    ),
    sa.ForeignKeyConstraint(
      ["organisation_id", "user_id"],
      ["memberships.organisation_id", "memberships.user_id"],
      name="fk_project_memberships_organisation_user",
      ondelete="CASCADE",
    ),
    sa.ForeignKeyConstraint(
      ["user_id"],
      ["users.id"],
      name="fk_project_memberships_user",
      ondelete="CASCADE",
    ),
    sa.PrimaryKeyConstraint("id"),
    sa.UniqueConstraint(
      "project_id",
      "user_id",
      name="uq_project_memberships_project_user",
    ),
  )
  op.create_index(
    "ix_project_memberships_project_id",
    "project_memberships",
    ["project_id"],
  )
  op.create_index(
    "ix_project_memberships_user_id",
    "project_memberships",
    ["user_id"],
  )


def downgrade() -> None:
  op.drop_index(
    "ix_project_memberships_user_id",
    table_name="project_memberships",
  )
  op.drop_index(
    "ix_project_memberships_project_id",
    table_name="project_memberships",
  )
  op.drop_table("project_memberships")
  op.drop_constraint(
    "uq_projects_id_organisation",
    "projects",
    type_="unique",
  )
