"""Enforce OWNER/MEMBER organization roles and ownership invariants.

Revision ID: c72f4f27b613
Revises: 89b4d61ca0f2
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c72f4f27b613"
down_revision: Union[str, Sequence[str], None] = "89b4d61ca0f2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
  op.execute(
    """
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1
        FROM organisations AS organisation
        WHERE (
          SELECT count(*)
          FROM memberships AS membership
          WHERE membership.organisation_id = organisation.id
            AND membership.role = 'owner'
        ) <> 1
      ) THEN
        RAISE EXCEPTION
          'Cannot enforce organization ownership: every existing organization must have exactly one owner membership';
      END IF;
    END
    $$;
    """,
  )

  op.drop_constraint("ck_memberships_role", "memberships", type_="check")
  op.execute(
    "UPDATE memberships SET role = 'member' WHERE role IN ('admin', 'worker')",
  )
  op.create_check_constraint(
    "ck_memberships_role",
    "memberships",
    "role IN ('owner', 'member')",
  )
  op.create_index(
    "uq_memberships_single_owner_per_organisation",
    "memberships",
    ["organisation_id"],
    unique=True,
    postgresql_where=sa.text("role = 'owner'"),
  )

  op.drop_constraint(
    "ck_organisation_invitations_role",
    "organisation_invitations",
    type_="check",
  )
  op.execute(
    "UPDATE organisation_invitations SET role = 'member' WHERE role IN ('admin', 'worker')",
  )
  op.create_check_constraint(
    "ck_organisation_invitations_role",
    "organisation_invitations",
    "role = 'member'",
  )

  op.execute(
    """
    CREATE FUNCTION enforce_organisation_owner_membership()
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
  op.execute(
    """
    CREATE CONSTRAINT TRIGGER trg_organisations_require_owner
    AFTER INSERT OR UPDATE ON organisations
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    EXECUTE FUNCTION enforce_organisation_owner_membership();
    """,
  )
  op.execute(
    """
    CREATE CONSTRAINT TRIGGER trg_memberships_require_owner
    AFTER INSERT OR UPDATE OR DELETE ON memberships
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    EXECUTE FUNCTION enforce_organisation_owner_membership();
    """,
  )


def downgrade() -> None:
  op.execute(
    "DROP TRIGGER trg_memberships_require_owner ON memberships",
  )
  op.execute(
    "DROP TRIGGER trg_organisations_require_owner ON organisations",
  )
  op.execute("DROP FUNCTION enforce_organisation_owner_membership()")
  op.drop_index(
    "uq_memberships_single_owner_per_organisation",
    table_name="memberships",
  )

  op.drop_constraint("ck_organisation_invitations_role", "organisation_invitations", type_="check")
  op.execute(
    "UPDATE organisation_invitations SET role = 'worker' WHERE role = 'member'",
  )
  op.create_check_constraint(
    "ck_organisation_invitations_role",
    "organisation_invitations",
    "role IN ('admin', 'worker')",
  )

  op.drop_constraint("ck_memberships_role", "memberships", type_="check")
  op.execute(
    "UPDATE memberships SET role = 'worker' WHERE role = 'member'",
  )
  op.create_check_constraint(
    "ck_memberships_role",
    "memberships",
    "role IN ('owner', 'admin', 'worker')",
  )
