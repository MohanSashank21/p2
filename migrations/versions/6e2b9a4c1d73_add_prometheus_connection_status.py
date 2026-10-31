"""Add Prometheus source connection status.

Revision ID: 6e2b9a4c1d73
Revises: 4a8d1c6f2b90
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "6e2b9a4c1d73"
down_revision: Union[str, Sequence[str], None] = "4a8d1c6f2b90"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
  op.add_column(
    "incident_sources",
    sa.Column(
      "prometheus_connection_status",
      sa.String(length=16),
      server_default="not_checked",
      nullable=False,
    ),
  )
  op.add_column(
    "incident_sources",
    sa.Column(
      "prometheus_last_checked_at",
      sa.DateTime(timezone=True),
      nullable=True,
    ),
  )
  op.create_check_constraint(
    "ck_incident_sources_prometheus_connection_status",
    "incident_sources",
    "prometheus_connection_status IN ('not_checked', 'connected', 'unavailable')",
  )


def downgrade() -> None:
  op.drop_constraint(
    "ck_incident_sources_prometheus_connection_status",
    "incident_sources",
    type_="check",
  )
  op.drop_column("incident_sources", "prometheus_last_checked_at")
  op.drop_column("incident_sources", "prometheus_connection_status")
