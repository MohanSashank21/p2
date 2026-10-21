"""Add durable invitation email outbox.

Revision ID: da84b63c105e
Revises: a4b1c8d93e20
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "da84b63c105e"
down_revision: Union[str, Sequence[str], None] = "a4b1c8d93e20"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
  op.create_table(
    "email_outbox",
    sa.Column("id", sa.Uuid(), nullable=False),
    sa.Column("invitation_type", sa.String(length=20), nullable=False),
    sa.Column("invitation_id", sa.Uuid(), nullable=False),
    sa.Column("recipient", sa.String(length=320), nullable=False),
    sa.Column("subject", sa.String(length=998), nullable=False),
    sa.Column("body_template", sa.Text(), nullable=False),
    sa.Column("accept_path", sa.String(length=120), nullable=False),
    sa.Column("target_scope", sa.String(length=40), nullable=False),
    sa.Column("target_key", sa.String(length=500), nullable=False),
    sa.Column(
      "status",
      sa.String(length=20),
      server_default="queued",
      nullable=False,
    ),
    sa.Column(
      "attempts",
      sa.Integer(),
      server_default="0",
      nullable=False,
    ),
    sa.Column(
      "available_at",
      sa.DateTime(timezone=True),
      server_default=sa.text("now()"),
      nullable=False,
    ),
    sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("last_error", sa.String(length=1000), nullable=True),
    sa.Column(
      "created_at",
      sa.DateTime(timezone=True),
      server_default=sa.text("now()"),
      nullable=False,
    ),
    sa.CheckConstraint(
      "status IN ('queued', 'sent', 'failed', 'superseded')",
      name="ck_email_outbox_status",
    ),
    sa.CheckConstraint(
      "invitation_type IN ('organisation', 'project')",
      name="ck_email_outbox_invitation_type",
    ),
    sa.PrimaryKeyConstraint("id"),
  )
  op.create_index(
    "ix_email_outbox_due",
    "email_outbox",
    ["status", "available_at"],
  )


def downgrade() -> None:
  op.drop_index("ix_email_outbox_due", table_name="email_outbox")
  op.drop_table("email_outbox")
