from __future__ import annotations

import uuid
from datetime import datetime
from sqlalchemy import DateTime, Index, String, Uuid, func
from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base

class Organisation(Base):
  __tablename__ = "organisations"

  id: Mapped[uuid.UUID] = mapped_column(
    Uuid(as_uuid=True),
    primary_key=True,
    default=uuid.uuid4,
  )
  name: Mapped[str] = mapped_column(
    String(120),
    nullable=False,
  )
  __table_args__ = (
    Index(
      "uq_organisations_name_normalized",
      func.lower(func.btrim(name)),
      unique=True,
    ),
  )
  owner_user_id: Mapped[uuid.UUID] = mapped_column(
    Uuid(as_uuid=True),
    ForeignKey("users.id"),
    nullable=False,
    index=True,
  )

  created_at: Mapped[datetime] = mapped_column(
    DateTime(timezone=True),
    server_default=func.now(),
    nullable=False,
  )
