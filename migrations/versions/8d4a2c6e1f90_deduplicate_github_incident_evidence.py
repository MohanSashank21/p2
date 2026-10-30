"""Deduplicate GitHub investigation evidence per incident and event.

Revision ID: 8d4a2c6e1f90
Revises: 7c3e91a4b620
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "8d4a2c6e1f90"
down_revision: Union[str, Sequence[str], None] = "7c3e91a4b620"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
  op.create_index(
    "uq_incident_evidence_github_context_event",
    "incident_evidence",
    ["incident_id", "query_hash"],
    unique=True,
    postgresql_where=sa.text(
      "evidence_type = 'github_context' AND query_hash IS NOT NULL",
    ),
    sqlite_where=sa.text(
      "evidence_type = 'github_context' AND query_hash IS NOT NULL",
    ),
  )


def downgrade() -> None:
  op.drop_index(
    "uq_incident_evidence_github_context_event",
    table_name="incident_evidence",
  )
