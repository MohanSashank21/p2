"""Add durable GitHub workflow event processing and incident correlation.

Revision ID: a6f1c9d4e820
Revises: 5e7a9c1d3f20
"""

from collections import defaultdict
import re
import uuid
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "a6f1c9d4e820"
down_revision: Union[str, Sequence[str], None] = "5e7a9c1d3f20"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_COMMIT_SHA = re.compile(r"^[0-9a-fA-F]{40,64}$")


def _backfill_github_correlations() -> None:
  if op.get_context().as_sql:
    op.execute(
      """
      WITH candidate_identifiers AS (
        SELECT
          i.project_id,
          r.id AS github_repository_id,
          'workflow_run' AS identifier_type,
          e.normalized_content->'workflow_run'->>'id' AS identifier_value,
          e.incident_id
        FROM incident_evidence AS e
        JOIN incidents AS i ON i.id = e.incident_id
        JOIN github_repositories AS r
          ON r.project_id = i.project_id
          AND r.github_repo_id::text = e.normalized_content->>'repository_id'
        WHERE e.evidence_type = 'github_context'
          AND e.normalized_content->'workflow_run'->>'id'
            ~ '^[1-9][0-9]{0,31}$'
        UNION ALL
        SELECT
          i.project_id,
          r.id AS github_repository_id,
          'commit' AS identifier_type,
          lower(e.normalized_content->'commit'->>'sha') AS identifier_value,
          e.incident_id
        FROM incident_evidence AS e
        JOIN incidents AS i ON i.id = e.incident_id
        JOIN github_repositories AS r
          ON r.project_id = i.project_id
          AND r.github_repo_id::text = e.normalized_content->>'repository_id'
        WHERE e.evidence_type = 'github_context'
          AND e.normalized_content->'commit'->>'sha'
            ~ '^[0-9a-fA-F]{40,64}$'
      ),
      unique_identifiers AS (
        SELECT
          project_id,
          github_repository_id,
          identifier_type,
          identifier_value,
          MIN(incident_id::text)::uuid AS incident_id
        FROM candidate_identifiers
        GROUP BY
          project_id,
          github_repository_id,
          identifier_type,
          identifier_value
        HAVING COUNT(DISTINCT incident_id) = 1
      )
      INSERT INTO github_incident_correlations (
        id,
        project_id,
        github_repository_id,
        identifier_type,
        identifier_value,
        incident_id
      )
      SELECT
        gen_random_uuid(),
        project_id,
        github_repository_id,
        identifier_type,
        identifier_value,
        incident_id
      FROM unique_identifiers
      ON CONFLICT (
        project_id,
        github_repository_id,
        identifier_type,
        identifier_value
      ) DO NOTHING
      """,
    )
    return

  connection = op.get_bind()
  evidence = sa.table(
    "incident_evidence",
    sa.column("incident_id", sa.Uuid()),
    sa.column("evidence_type", sa.String()),
    sa.column("normalized_content", sa.JSON()),
  )
  incidents = sa.table(
    "incidents",
    sa.column("id", sa.Uuid()),
    sa.column("project_id", sa.Uuid()),
  )
  repositories = sa.table(
    "github_repositories",
    sa.column("id", sa.Uuid()),
    sa.column("project_id", sa.Uuid()),
    sa.column("github_repo_id", sa.BigInteger()),
  )
  correlations = sa.table(
    "github_incident_correlations",
    sa.column("id", sa.Uuid()),
    sa.column("project_id", sa.Uuid()),
    sa.column("github_repository_id", sa.Uuid()),
    sa.column("identifier_type", sa.String()),
    sa.column("identifier_value", sa.String()),
    sa.column("incident_id", sa.Uuid()),
  )

  repository_ids = {
    (row.project_id, row.github_repo_id): row.id
    for row in connection.execute(
      sa.select(
        repositories.c.id,
        repositories.c.project_id,
        repositories.c.github_repo_id,
      ),
    )
  }
  evidence_rows = connection.execute(
    sa.select(
      evidence.c.incident_id,
      incidents.c.project_id,
      evidence.c.normalized_content,
    )
    .select_from(
      evidence.join(incidents, evidence.c.incident_id == incidents.c.id),
    )
    .where(evidence.c.evidence_type == "github_context"),
  )
  incident_candidates: dict[
    tuple[uuid.UUID, uuid.UUID, str, str],
    set[uuid.UUID],
  ] = defaultdict(set)
  for row in evidence_rows:
    normalized = row.normalized_content
    if not isinstance(normalized, dict):
      continue
    repository_id = normalized.get("repository_id")
    if not isinstance(repository_id, int) or isinstance(repository_id, bool):
      continue
    github_repository_id = repository_ids.get((row.project_id, repository_id))
    if github_repository_id is None:
      continue

    workflow_run = normalized.get("workflow_run")
    workflow_run = workflow_run if isinstance(workflow_run, dict) else {}
    run_id = workflow_run.get("id")
    if isinstance(run_id, int) and not isinstance(run_id, bool) and run_id > 0:
      incident_candidates[
        (row.project_id, github_repository_id, "workflow_run", str(run_id))
      ].add(row.incident_id)

    commit = normalized.get("commit")
    commit = commit if isinstance(commit, dict) else {}
    sha = commit.get("sha")
    if isinstance(sha, str) and _COMMIT_SHA.fullmatch(sha):
      incident_candidates[
        (row.project_id, github_repository_id, "commit", sha.lower())
      ].add(row.incident_id)

  unique_records = [
    {
      "id": uuid.uuid4(),
      "project_id": key[0],
      "github_repository_id": key[1],
      "identifier_type": key[2],
      "identifier_value": key[3],
      "incident_id": next(iter(candidate_ids)),
    }
    for key, candidate_ids in incident_candidates.items()
    if len(candidate_ids) == 1
  ]
  for start in range(0, len(unique_records), 500):
    connection.execute(
      sa.insert(correlations),
      unique_records[start:start + 500],
    )


def upgrade() -> None:
  op.add_column(
    "github_webhook_events",
    sa.Column(
      "processing_status",
      sa.String(length=16),
      server_default="processed",
      nullable=False,
    ),
  )
  op.add_column(
    "github_webhook_events",
    sa.Column("attempt_count", sa.Integer(), server_default="0", nullable=False),
  )
  op.add_column(
    "github_webhook_events",
    sa.Column("available_at", sa.DateTime(timezone=True), nullable=True),
  )
  op.add_column(
    "github_webhook_events",
    sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
  )
  op.add_column(
    "github_webhook_events",
    sa.Column("last_failure_code", sa.String(length=64), nullable=True),
  )
  op.add_column(
    "github_webhook_events",
    sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
  )
  op.add_column(
    "github_webhook_events",
    sa.Column("workflow_run_id", sa.String(length=32), nullable=True),
  )
  op.add_column(
    "github_webhook_events",
    sa.Column("commit_sha", sa.String(length=64), nullable=True),
  )
  op.add_column(
    "github_webhook_events",
    sa.Column("incident_id", sa.Uuid(), nullable=True),
  )
  with op.batch_alter_table("github_webhook_events") as batch_op:
    batch_op.create_foreign_key(
      "fk_github_webhook_events_incident_id_incidents",
      "incidents",
      ["incident_id"],
      ["id"],
      ondelete="SET NULL",
    )
    batch_op.create_check_constraint(
      "ck_github_webhook_events_processing_status",
      "processing_status IN ('pending', 'processing', 'retry', 'processed', 'failed')",
    )
    batch_op.create_check_constraint(
      "ck_github_webhook_events_attempt_count",
      "attempt_count >= 0",
    )
  op.create_index(
    "ix_github_webhook_events_processing_status",
    "github_webhook_events",
    ["processing_status"],
  )
  op.create_index(
    "ix_github_webhook_events_incident_id",
    "github_webhook_events",
    ["incident_id"],
  )

  op.create_table(
    "github_incident_correlations",
    sa.Column("id", sa.Uuid(), nullable=False),
    sa.Column("project_id", sa.Uuid(), nullable=False),
    sa.Column("github_repository_id", sa.Uuid(), nullable=False),
    sa.Column("identifier_type", sa.String(length=16), nullable=False),
    sa.Column("identifier_value", sa.String(length=128), nullable=False),
    sa.Column("incident_id", sa.Uuid(), nullable=False),
    sa.Column(
      "created_at",
      sa.DateTime(timezone=True),
      server_default=sa.func.now(),
      nullable=False,
    ),
    sa.CheckConstraint(
      "identifier_type IN ('workflow_run', 'commit')",
      name="ck_github_incident_correlations_identifier_type",
    ),
    sa.CheckConstraint(
      "length(identifier_value) > 0",
      name="ck_github_incident_correlations_identifier_value",
    ),
    sa.ForeignKeyConstraint(
      ["project_id"],
      ["projects.id"],
      name="fk_github_incident_correlations_project_id_projects",
      ondelete="CASCADE",
    ),
    sa.ForeignKeyConstraint(
      ["github_repository_id"],
      ["github_repositories.id"],
      name="fk_github_incident_correlations_github_repository_id",
      ondelete="CASCADE",
    ),
    sa.ForeignKeyConstraint(
      ["incident_id"],
      ["incidents.id"],
      name="fk_github_incident_correlations_incident_id_incidents",
      ondelete="CASCADE",
    ),
    sa.PrimaryKeyConstraint("id", name="pk_github_incident_correlations"),
    sa.UniqueConstraint(
      "project_id",
      "github_repository_id",
      "identifier_type",
      "identifier_value",
      name="uq_github_incident_correlations_identifier",
    ),
  )
  op.create_index(
    "ix_github_incident_correlations_project_id",
    "github_incident_correlations",
    ["project_id"],
  )
  op.create_index(
    "ix_github_incident_correlations_github_repository_id",
    "github_incident_correlations",
    ["github_repository_id"],
  )
  op.create_index(
    "ix_github_incident_correlations_incident_id",
    "github_incident_correlations",
    ["incident_id"],
  )
  _backfill_github_correlations()

  with op.batch_alter_table("incidents") as batch_op:
    batch_op.drop_constraint("ck_incidents_source_type", type_="check")
    batch_op.create_check_constraint(
      "ck_incidents_source_type",
      "source_type IN ('manual', 'generic_webhook', 'alertmanager', 'grafana', 'github')",
    )
  with op.batch_alter_table("incident_evidence") as batch_op:
    batch_op.drop_constraint("ck_incident_evidence_type", type_="check")
    batch_op.create_check_constraint(
      "ck_incident_evidence_type",
      "evidence_type IN ('manual_report', 'webhook_payload', "
      "'alertmanager_notification', 'grafana_notification', 'loki_logs', "
      "'github_context', 'trace_spans', 'docker_investigation', "
      "'prometheus_metrics', 'github_workflow_event')",
    )

  with op.batch_alter_table("github_webhook_events") as batch_op:
    batch_op.alter_column(
      "processing_status",
      server_default="pending",
      existing_type=sa.String(length=16),
      existing_nullable=False,
    )


def downgrade() -> None:
  connection = op.get_bind()
  events = sa.table(
    "github_webhook_events",
    sa.column("incident_id", sa.Uuid()),
    sa.column("processing_status", sa.String()),
    sa.column("workflow_run_id", sa.String()),
    sa.column("commit_sha", sa.String()),
    sa.column("processed_at", sa.DateTime(timezone=True)),
  )
  incidents = sa.table(
    "incidents",
    sa.column("source_type", sa.String()),
  )
  evidence = sa.table(
    "incident_evidence",
    sa.column("evidence_type", sa.String()),
  )
  if (
    connection.scalar(
      sa.select(sa.func.count()).select_from(events).where(
        sa.or_(
          events.c.incident_id.is_not(None),
          events.c.processing_status != "processed",
          events.c.workflow_run_id.is_not(None),
          events.c.commit_sha.is_not(None),
          events.c.processed_at.is_not(None),
        ),
      ),
    )
    or connection.scalar(
      sa.select(sa.func.count()).select_from(incidents).where(
        incidents.c.source_type == "github",
      ),
    )
    or connection.scalar(
      sa.select(sa.func.count()).select_from(evidence).where(
        evidence.c.evidence_type == "github_workflow_event",
      ),
    )
  ):
    raise RuntimeError(
      "Cannot downgrade while GitHub workflow incidents or processing state exist",
    )

  with op.batch_alter_table("incident_evidence") as batch_op:
    batch_op.drop_constraint("ck_incident_evidence_type", type_="check")
    batch_op.create_check_constraint(
      "ck_incident_evidence_type",
      "evidence_type IN ('manual_report', 'webhook_payload', "
      "'alertmanager_notification', 'grafana_notification', 'loki_logs', "
      "'github_context', 'trace_spans', 'docker_investigation', "
      "'prometheus_metrics')",
    )
  with op.batch_alter_table("incidents") as batch_op:
    batch_op.drop_constraint("ck_incidents_source_type", type_="check")
    batch_op.create_check_constraint(
      "ck_incidents_source_type",
      "source_type IN ('manual', 'generic_webhook', 'alertmanager', 'grafana')",
    )

  op.drop_index(
    "ix_github_incident_correlations_incident_id",
    table_name="github_incident_correlations",
  )
  op.drop_index(
    "ix_github_incident_correlations_github_repository_id",
    table_name="github_incident_correlations",
  )
  op.drop_index(
    "ix_github_incident_correlations_project_id",
    table_name="github_incident_correlations",
  )
  op.drop_table("github_incident_correlations")
  op.drop_index(
    "ix_github_webhook_events_incident_id",
    table_name="github_webhook_events",
  )
  op.drop_index(
    "ix_github_webhook_events_processing_status",
    table_name="github_webhook_events",
  )
  with op.batch_alter_table("github_webhook_events") as batch_op:
    batch_op.drop_constraint(
      "ck_github_webhook_events_attempt_count",
      type_="check",
    )
    batch_op.drop_constraint(
      "ck_github_webhook_events_processing_status",
      type_="check",
    )
    batch_op.drop_constraint(
      "fk_github_webhook_events_incident_id_incidents",
      type_="foreignkey",
    )
  for column in (
    "incident_id",
    "commit_sha",
    "workflow_run_id",
    "processed_at",
    "last_failure_code",
    "lease_expires_at",
    "available_at",
    "attempt_count",
    "processing_status",
  ):
    op.drop_column("github_webhook_events", column)
