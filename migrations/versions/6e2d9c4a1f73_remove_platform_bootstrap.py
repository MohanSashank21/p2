"""Remove one-time platform organization bootstrap state.

Revision ID: 6e2d9c4a1f73
Revises: 7ac1e0b45d92
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "6e2d9c4a1f73"
down_revision: Union[str, Sequence[str], None] = "7ac1e0b45d92"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
  op.drop_table("platform_bootstrap")


def downgrade() -> None:
  op.create_table(
    "platform_bootstrap",
    sa.Column("key", sa.String(length=32), nullable=False),
    sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint("key = 'platform'", name="ck_platform_bootstrap_singleton"),
    sa.PrimaryKeyConstraint("key"),
  )
  op.execute(
    """
    INSERT INTO platform_bootstrap (key, completed_at)
    VALUES ('platform', CURRENT_TIMESTAMP)
    """,
  )
