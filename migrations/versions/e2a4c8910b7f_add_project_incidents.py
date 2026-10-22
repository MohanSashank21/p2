"""Add project-scoped incidents and persisted evidence.

Revision ID: e2a4c8910b7f
Revises: d714c09a8e2f
"""

from typing import Sequence, Union
import uuid

from alembic import op
import sqlalchemy as sa


revision: str = "e2a4c8910b7f"
down_revision: Union[str, Sequence[str], None] = "d714c09a8e2f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
  op.create_table(
    "incidents",
    sa.Column("id", sa.Uuid(), nullable=False),
    sa.Column("project_id", sa.Uuid(), nullable=False),
    sa.Column("environment_id", sa.Uuid(), nullable=True),
    sa.Column("source_event_id", sa.Uuid(), nullable=True),
    sa.Column("reported_by_user_id", sa.Uuid(), nullable=True),
    sa.Column("source_type", sa.String(length=40), nullable=False),
    sa.Column("incident_type", sa.String(length=64), nullable=False),
    sa.Column("title", sa.String(length=255), nullable=False),
    sa.Column("description", sa.Text(), nullable=True),
    sa.Column("severity", sa.String(length=16), nullable=False),
    sa.Column(
      "status",
      sa.String(length=20),
      server_default="open",
      nullable=False,
    ),
    sa.Column(
      "created_at",
      sa.DateTime(timezone=True),
      server_default=sa.func.now(),
      nullable=False,
    ),
    sa.Column(
      "updated_at",
      sa.DateTime(timezone=True),
      server_default=sa.func.now(),
      nullable=False,
    ),
    sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint(
      "source_type IN ('manual', 'generic_webhook')",
      name="ck_incidents_source_type",
    ),
    sa.CheckConstraint(
      "severity IN ('low', 'medium', 'high', 'critical')",
      name="ck_incidents_severity",
    ),
    sa.CheckConstraint(
      "status IN ('open', 'acknowledged', 'resolved')",
      name="ck_incidents_status",
    ),
    sa.ForeignKeyConstraint(
      ["environment_id"],
      ["environments.id"],
      name="fk_incidents_environment_id_environments",
      ondelete="SET NULL",
    ),
    sa.ForeignKeyConstraint(
      ["project_id"],
      ["projects.id"],
      name="fk_incidents_project_id_projects",
      ondelete="CASCADE",
    ),
    sa.ForeignKeyConstraint(
      ["reported_by_user_id"],
      ["users.id"],
      name="fk_incidents_reported_by_user_id_users",
      ondelete="SET NULL",
    ),
    sa.ForeignKeyConstraint(
      ["source_event_id"],
      ["source_events.id"],
      name="fk_incidents_source_event_id_source_events",
      ondelete="SET NULL",
    ),
    sa.PrimaryKeyConstraint("id", name="pk_incidents"),
    sa.UniqueConstraint(
      "source_event_id",
      name="uq_incidents_source_event_id",
    ),
  )
  op.create_index("ix_incidents_project_id", "incidents", ["project_id"])
  op.create_index("ix_incidents_environment_id", "incidents", ["environment_id"])
  op.create_index(
    "ix_incidents_reported_by_user_id",
    "incidents",
    ["reported_by_user_id"],
  )
  op.create_table(
    "incident_evidence",
    sa.Column("id", sa.Uuid(), nullable=False),
    sa.Column("incident_id", sa.Uuid(), nullable=False),
    sa.Column("source_event_id", sa.Uuid(), nullable=True),
    sa.Column("evidence_type", sa.String(length=32), nullable=False),
    sa.Column("original_content", sa.JSON(), nullable=False),
    sa.Column("normalized_content", sa.JSON(), nullable=False),
    sa.Column(
      "created_at",
      sa.DateTime(timezone=True),
      server_default=sa.func.now(),
      nullable=False,
    ),
    sa.CheckConstraint(
      "evidence_type IN ('manual_report', 'webhook_payload')",
      name="ck_incident_evidence_type",
    ),
    sa.ForeignKeyConstraint(
      ["incident_id"],
      ["incidents.id"],
      name="fk_incident_evidence_incident_id_incidents",
      ondelete="CASCADE",
    ),
    sa.ForeignKeyConstraint(
      ["source_event_id"],
      ["source_events.id"],
      name="fk_incident_evidence_source_event_id_source_events",
      ondelete="SET NULL",
    ),
    sa.PrimaryKeyConstraint("id", name="pk_incident_evidence"),
    sa.UniqueConstraint(
      "source_event_id",
      name="uq_incident_evidence_source_event_id",
    ),
  )
  op.create_index(
    "ix_incident_evidence_incident_id",
    "incident_evidence",
    ["incident_id"],
  )

  source_events = sa.table(
    "source_events",
    sa.column("id", sa.Uuid()),
    sa.column("project_id", sa.Uuid()),
    sa.column("environment_id", sa.Uuid()),
    sa.column("event_type", sa.String()),
    sa.column("title", sa.String()),
    sa.column("description", sa.Text()),
    sa.column("severity", sa.String()),
    sa.column("original_payload", sa.JSON()),
    sa.column("received_at", sa.DateTime(timezone=True)),
  )
  incidents = sa.table(
    "incidents",
    sa.column("id", sa.Uuid()),
    sa.column("project_id", sa.Uuid()),
    sa.column("environment_id", sa.Uuid()),
    sa.column("source_event_id", sa.Uuid()),
    sa.column("source_type", sa.String()),
    sa.column("incident_type", sa.String()),
    sa.column("title", sa.String()),
    sa.column("description", sa.Text()),
    sa.column("severity", sa.String()),
    sa.column("status", sa.String()),
    sa.column("created_at", sa.DateTime(timezone=True)),
    sa.column("updated_at", sa.DateTime(timezone=True)),
  )
  evidence = sa.table(
    "incident_evidence",
    sa.column("id", sa.Uuid()),
    sa.column("incident_id", sa.Uuid()),
    sa.column("source_event_id", sa.Uuid()),
    sa.column("evidence_type", sa.String()),
    sa.column("original_content", sa.JSON()),
    sa.column("normalized_content", sa.JSON()),
    sa.column("created_at", sa.DateTime(timezone=True)),
  )
  connection = op.get_bind()
  existing_events = connection.execute(sa.select(source_events)).mappings()
  for source_event in existing_events:
    incident_id = uuid.uuid4()
    created_at = source_event["received_at"]
    connection.execute(
      incidents.insert().values(
        id=incident_id,
        project_id=source_event["project_id"],
        environment_id=source_event["environment_id"],
        source_event_id=source_event["id"],
        source_type="generic_webhook",
        incident_type=source_event["event_type"],
        title=source_event["title"],
        description=source_event["description"],
        severity=source_event["severity"],
        status="open",
        created_at=created_at,
        updated_at=created_at,
      ),
    )
    connection.execute(
      evidence.insert().values(
        id=uuid.uuid4(),
        incident_id=incident_id,
        source_event_id=source_event["id"],
        evidence_type="webhook_payload",
        original_content=source_event["original_payload"],
        normalized_content={
          "event_type": source_event["event_type"],
          "title": source_event["title"],
          "description": source_event["description"],
          "severity": source_event["severity"],
        },
        created_at=created_at,
      ),
    )


def downgrade() -> None:
  op.drop_index(
    "ix_incident_evidence_incident_id",
    table_name="incident_evidence",
  )
  op.drop_table("incident_evidence")
  op.drop_index("ix_incidents_reported_by_user_id", table_name="incidents")
  op.drop_index("ix_incidents_environment_id", table_name="incidents")
  op.drop_index("ix_incidents_project_id", table_name="incidents")
  op.drop_table("incidents")
