"""Enforce globally unique, normalized organization names.

Revision ID: f18b76e4a2c9
Revises: 6e2d9c4a1f73
"""

from typing import Sequence, Union

from alembic import op


revision: str = "f18b76e4a2c9"
down_revision: Union[str, Sequence[str], None] = "6e2d9c4a1f73"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
  op.execute(
    """
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1
        FROM organisations
        GROUP BY lower(btrim(name))
        HAVING count(*) > 1
      ) THEN
        RAISE EXCEPTION
          'Cannot enforce unique organization names: duplicate names remain after trimming whitespace and ignoring case';
      END IF;
    END
    $$;
    """,
  )
  op.execute(
    """
    CREATE UNIQUE INDEX uq_organisations_name_normalized
    ON organisations (lower(btrim(name)))
    """,
  )


def downgrade() -> None:
  op.drop_index(
    "uq_organisations_name_normalized",
    table_name="organisations",
  )
