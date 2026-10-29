"""Add GitHub App installations, repository links, and webhook events.

Revision ID: e91a3c5d7b42
Revises: c4d2a7b91e63
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "e91a3c5d7b42"
down_revision: Union[str, Sequence[str], None] = "c4d2a7b91e63"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
  op.create_table(
    "github_installations",
    sa.Column("id", sa.Uuid(), nullable=False),
    sa.Column("project_id", sa.Uuid(), nullable=False),
    sa.Column("installation_id", sa.BigInteger(), nullable=False),
    sa.Column("account_id", sa.BigInteger(), nullable=True),
    sa.Column("account_login", sa.String(length=255), nullable=False),
    sa.Column(
      "status",
      sa.String(length=16),
      server_default="active",
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
    sa.CheckConstraint(
      "status IN ('active', 'disconnected')",
      name="ck_github_installations_status",
    ),
    sa.ForeignKeyConstraint(
      ["project_id"],
      ["projects.id"],
      name="fk_github_installations_project_id_projects",
      ondelete="CASCADE",
    ),
    sa.PrimaryKeyConstraint("id", name="pk_github_installations"),
    sa.UniqueConstraint(
      "project_id",
      "installation_id",
      name="uq_github_installations_project_installation",
    ),
  )
  op.create_index(
    "ix_github_installations_project_id",
    "github_installations",
    ["project_id"],
  )
  op.create_table(
    "github_repositories",
    sa.Column("id", sa.Uuid(), nullable=False),
    sa.Column("project_id", sa.Uuid(), nullable=False),
    sa.Column("installation_id", sa.Uuid(), nullable=False),
    sa.Column("github_repo_id", sa.BigInteger(), nullable=False),
    sa.Column("full_name", sa.String(length=512), nullable=False),
    sa.Column("owner", sa.String(length=255), nullable=False),
    sa.Column("default_branch", sa.String(length=255), nullable=True),
    sa.Column("html_url", sa.Text(), nullable=False),
    sa.Column(
      "status",
      sa.String(length=16),
      server_default="active",
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
    sa.CheckConstraint(
      "status IN ('active', 'disconnected')",
      name="ck_github_repositories_status",
    ),
    sa.ForeignKeyConstraint(
      ["installation_id"],
      ["github_installations.id"],
      name="fk_github_repositories_installation_id_github_installations",
      ondelete="CASCADE",
    ),
    sa.ForeignKeyConstraint(
      ["project_id"],
      ["projects.id"],
      name="fk_github_repositories_project_id_projects",
      ondelete="CASCADE",
    ),
    sa.PrimaryKeyConstraint("id", name="pk_github_repositories"),
    sa.UniqueConstraint(
      "project_id",
      "github_repo_id",
      name="uq_github_repositories_project_repo",
    ),
  )
  op.create_index(
    "ix_github_repositories_project_id",
    "github_repositories",
    ["project_id"],
  )
  op.create_index(
    "ix_github_repositories_installation_id",
    "github_repositories",
    ["installation_id"],
  )
  op.create_table(
    "github_webhook_events",
    sa.Column("id", sa.Uuid(), nullable=False),
    sa.Column("project_id", sa.Uuid(), nullable=False),
    sa.Column("github_repository_id", sa.Uuid(), nullable=False),
    sa.Column("delivery_id", sa.String(length=255), nullable=False),
    sa.Column("event_name", sa.String(length=64), nullable=False),
    sa.Column("action", sa.String(length=64), nullable=True),
    sa.Column("payload", sa.JSON(), nullable=False),
    sa.Column(
      "received_at",
      sa.DateTime(timezone=True),
      server_default=sa.func.now(),
      nullable=False,
    ),
    sa.ForeignKeyConstraint(
      ["github_repository_id"],
      ["github_repositories.id"],
      name="fk_webhook_events_repository_id",
      ondelete="CASCADE",
    ),
    sa.ForeignKeyConstraint(
      ["project_id"],
      ["projects.id"],
      name="fk_github_webhook_events_project_id_projects",
      ondelete="CASCADE",
    ),
    sa.PrimaryKeyConstraint("id", name="pk_github_webhook_events"),
    sa.UniqueConstraint(
      "project_id",
      "delivery_id",
      name="uq_github_webhook_events_project_delivery",
    ),
  )
  op.create_index(
    "ix_github_webhook_events_project_id",
    "github_webhook_events",
    ["project_id"],
  )
  op.create_index(
    "ix_github_webhook_events_github_repository_id",
    "github_webhook_events",
    ["github_repository_id"],
  )
  op.drop_constraint("ck_incident_evidence_type", "incident_evidence", type_="check")
  op.create_check_constraint(
    "ck_incident_evidence_type",
    "incident_evidence",
    "evidence_type IN ('manual_report', 'webhook_payload', "
    "'alertmanager_notification', 'grafana_notification', 'loki_logs', "
    "'github_context')",
  )


def downgrade() -> None:
  connection = op.get_bind()
  events = sa.table(
    "github_webhook_events",
    sa.column("id", sa.Uuid()),
  )
  repositories = sa.table(
    "github_repositories",
    sa.column("id", sa.Uuid()),
  )
  installations = sa.table(
    "github_installations",
    sa.column("id", sa.Uuid()),
  )
  if any(
    connection.scalar(sa.select(sa.func.count()).select_from(table))
    for table in (events, repositories, installations)
  ):
    raise RuntimeError(
      "Cannot downgrade while GitHub integration records exist",
    )

  op.drop_constraint("ck_incident_evidence_type", "incident_evidence", type_="check")
  op.create_check_constraint(
    "ck_incident_evidence_type",
    "incident_evidence",
    "evidence_type IN ('manual_report', 'webhook_payload', "
    "'alertmanager_notification', 'grafana_notification', 'loki_logs')",
  )
  op.drop_index(
    "ix_github_webhook_events_github_repository_id",
    table_name="github_webhook_events",
  )
  op.drop_index(
    "ix_github_webhook_events_project_id",
    table_name="github_webhook_events",
  )
  op.drop_table("github_webhook_events")
  op.drop_index(
    "ix_github_repositories_installation_id",
    table_name="github_repositories",
  )
  op.drop_index(
    "ix_github_repositories_project_id",
    table_name="github_repositories",
  )
  op.drop_table("github_repositories")
  op.drop_index(
    "ix_github_installations_project_id",
    table_name="github_installations",
  )
  op.drop_table("github_installations")
