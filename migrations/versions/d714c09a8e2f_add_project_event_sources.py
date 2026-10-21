"""Add project-scoped event sources and received events.

Revision ID: d714c09a8e2f
Revises: b9d73f0a2c61
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "d714c09a8e2f"
down_revision: Union[str, Sequence[str], None] = "b9d73f0a2c61"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
  op.create_table(
    "incident_sources",
    sa.Column("id", sa.Uuid(), nullable=False),
    sa.Column("project_id", sa.Uuid(), nullable=False),
    sa.Column("environment_id", sa.Uuid(), nullable=True),
    sa.Column("name", sa.String(length=120), nullable=False),
    sa.Column(
      "source_type",
      sa.String(length=40),
      server_default="generic_webhook",
      nullable=False,
    ),
    sa.Column("credential_hash", sa.String(length=64), nullable=False),
    sa.Column(
      "enabled",
      sa.Boolean(),
      server_default=sa.true(),
      nullable=False,
    ),
    sa.Column(
      "created_at",
      sa.DateTime(timezone=True),
      server_default=sa.func.now(),
      nullable=False,
    ),
    sa.ForeignKeyConstraint(
      ["environment_id"],
      ["environments.id"],
      name="fk_incident_sources_environment_id_environments",
      ondelete="SET NULL",
    ),
    sa.ForeignKeyConstraint(
      ["project_id"],
      ["projects.id"],
      name="fk_incident_sources_project_id_projects",
      ondelete="CASCADE",
    ),
    sa.PrimaryKeyConstraint("id", name="pk_incident_sources"),
    sa.UniqueConstraint(
      "project_id",
      "name",
      name="uq_incident_sources_project_name",
    ),
  )
  op.create_index(
    "ix_incident_sources_project_id",
    "incident_sources",
    ["project_id"],
  )
  op.create_index(
    "ix_incident_sources_environment_id",
    "incident_sources",
    ["environment_id"],
  )
  op.create_table(
    "source_events",
    sa.Column("id", sa.Uuid(), nullable=False),
    sa.Column("source_id", sa.Uuid(), nullable=False),
    sa.Column("project_id", sa.Uuid(), nullable=False),
    sa.Column("environment_id", sa.Uuid(), nullable=True),
    sa.Column("external_event_id", sa.String(length=255), nullable=True),
    sa.Column("event_type", sa.String(length=64), nullable=False),
    sa.Column("title", sa.String(length=255), nullable=False),
    sa.Column("description", sa.Text(), nullable=True),
    sa.Column("severity", sa.String(length=16), nullable=False),
    sa.Column("original_payload", sa.JSON(), nullable=False),
    sa.Column(
      "received_at",
      sa.DateTime(timezone=True),
      server_default=sa.func.now(),
      nullable=False,
    ),
    sa.CheckConstraint(
      "severity IN ('low', 'medium', 'high', 'critical')",
      name="ck_source_events_severity",
    ),
    sa.ForeignKeyConstraint(
      ["environment_id"],
      ["environments.id"],
      name="fk_source_events_environment_id_environments",
      ondelete="SET NULL",
    ),
    sa.ForeignKeyConstraint(
      ["project_id"],
      ["projects.id"],
      name="fk_source_events_project_id_projects",
      ondelete="CASCADE",
    ),
    sa.ForeignKeyConstraint(
      ["source_id"],
      ["incident_sources.id"],
      name="fk_source_events_source_id_incident_sources",
      ondelete="CASCADE",
    ),
    sa.PrimaryKeyConstraint("id", name="pk_source_events"),
    sa.UniqueConstraint(
      "source_id",
      "external_event_id",
      name="uq_source_events_source_external_id",
    ),
  )
  op.create_index("ix_source_events_source_id", "source_events", ["source_id"])
  op.create_index("ix_source_events_project_id", "source_events", ["project_id"])
  op.create_index(
    "ix_source_events_environment_id",
    "source_events",
    ["environment_id"],
  )


def downgrade() -> None:
  op.drop_index("ix_source_events_environment_id", table_name="source_events")
  op.drop_index("ix_source_events_project_id", table_name="source_events")
  op.drop_index("ix_source_events_source_id", table_name="source_events")
  op.drop_table("source_events")
  op.drop_index(
    "ix_incident_sources_environment_id",
    table_name="incident_sources",
  )
  op.drop_index("ix_incident_sources_project_id", table_name="incident_sources")
  op.drop_table("incident_sources")
