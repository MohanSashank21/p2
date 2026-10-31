"""Add encrypted Prometheus source authentication.

Revision ID: 4a8d1c6f2b90
Revises: c9f5a1b3d7e2
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "4a8d1c6f2b90"
down_revision: Union[str, Sequence[str], None] = "c9f5a1b3d7e2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
  op.add_column(
    "incident_sources",
    sa.Column("prometheus_auth_type", sa.String(length=16), nullable=True),
  )
  op.add_column(
    "incident_sources",
    sa.Column("prometheus_auth_ciphertext", sa.Text(), nullable=True),
  )


def downgrade() -> None:
  op.drop_column("incident_sources", "prometheus_auth_ciphertext")
  op.drop_column("incident_sources", "prometheus_auth_type")
