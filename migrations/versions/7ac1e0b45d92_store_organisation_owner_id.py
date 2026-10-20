"""Store the organization owner identifier on the organization row.

Revision ID: 7ac1e0b45d92
Revises: 4d4ebf9a9f21
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "7ac1e0b45d92"
down_revision: Union[str, Sequence[str], None] = "4d4ebf9a9f21"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
  op.add_column(
    "organisations",
    sa.Column("owner_user_id", sa.Uuid(), nullable=True),
  )
  op.execute(
    """
    UPDATE organisations AS organisation
    SET owner_user_id = membership.user_id
    FROM memberships AS membership
    WHERE membership.organisation_id = organisation.id
      AND membership.role = 'owner'
    """,
  )
  op.alter_column(
    "organisations",
    "owner_user_id",
    existing_type=sa.Uuid(),
    nullable=False,
  )
  op.create_foreign_key(
    "fk_organisations_owner_user",
    "organisations",
    "users",
    ["owner_user_id"],
    ["id"],
  )
  op.create_index(
    "ix_organisations_owner_user_id",
    "organisations",
    ["owner_user_id"],
  )

  op.execute(
    """
    CREATE OR REPLACE FUNCTION enforce_organisation_owner_membership()
    RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    DECLARE
      affected_organisation_ids uuid[];
      organisation_id_to_check uuid;
      declared_owner_user_id uuid;
      membership_owner_user_id uuid;
    BEGIN
      IF TG_TABLE_NAME = 'organisations' THEN
        IF TG_OP = 'DELETE' THEN
          RETURN OLD;
        END IF;
        affected_organisation_ids := ARRAY[NEW.id];
      ELSIF TG_OP = 'INSERT' THEN
        affected_organisation_ids := ARRAY[NEW.organisation_id];
      ELSIF TG_OP = 'DELETE' THEN
        affected_organisation_ids := ARRAY[OLD.organisation_id];
      ELSE
        affected_organisation_ids := ARRAY[
          OLD.organisation_id,
          NEW.organisation_id
        ];
      END IF;

      FOREACH organisation_id_to_check IN ARRAY affected_organisation_ids
      LOOP
        SELECT owner_user_id
        INTO declared_owner_user_id
        FROM organisations
        WHERE id = organisation_id_to_check;

        IF FOUND THEN
          SELECT user_id
          INTO membership_owner_user_id
          FROM memberships
          WHERE organisation_id = organisation_id_to_check
            AND role = 'owner';

          IF membership_owner_user_id IS NULL
            OR membership_owner_user_id IS DISTINCT FROM declared_owner_user_id
          THEN
            RAISE EXCEPTION
              'Organization % must have one owner membership matching owner_user_id',
              organisation_id_to_check
              USING ERRCODE = '23514',
                    CONSTRAINT = 'ck_organisations_owner_matches_membership';
          END IF;
        END IF;
      END LOOP;

      RETURN NULL;
    END
    $$;
    """,
  )


def downgrade() -> None:
  op.execute(
    """
    CREATE OR REPLACE FUNCTION enforce_organisation_owner_membership()
    RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    DECLARE
      affected_organisation_ids uuid[];
      organisation_id_to_check uuid;
    BEGIN
      IF TG_TABLE_NAME = 'organisations' THEN
        IF TG_OP = 'DELETE' THEN
          RETURN OLD;
        END IF;
        affected_organisation_ids := ARRAY[NEW.id];
      ELSIF TG_OP = 'INSERT' THEN
        affected_organisation_ids := ARRAY[NEW.organisation_id];
      ELSIF TG_OP = 'DELETE' THEN
        affected_organisation_ids := ARRAY[OLD.organisation_id];
      ELSE
        affected_organisation_ids := ARRAY[
          OLD.organisation_id,
          NEW.organisation_id
        ];
      END IF;

      FOREACH organisation_id_to_check IN ARRAY affected_organisation_ids
      LOOP
        IF EXISTS (
          SELECT 1
          FROM organisations
          WHERE id = organisation_id_to_check
        ) AND NOT EXISTS (
          SELECT 1
          FROM memberships
          WHERE organisation_id = organisation_id_to_check
            AND role = 'owner'
        ) THEN
          RAISE EXCEPTION
            'Organization % must have exactly one owner membership',
            organisation_id_to_check
            USING ERRCODE = '23514',
                  CONSTRAINT = 'ck_organisations_require_owner';
        END IF;
      END LOOP;

      RETURN NULL;
    END
    $$;
    """,
  )
  op.drop_index(
    "ix_organisations_owner_user_id",
    table_name="organisations",
  )
  op.drop_constraint(
    "fk_organisations_owner_user",
    "organisations",
    type_="foreignkey",
  )
  op.drop_column("organisations", "owner_user_id")
