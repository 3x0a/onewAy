from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.client import Client
    from app.models.module import Module


class ClientModule(Base):
    __tablename__ = "client_modules"

    client_uuid: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("clients.uuid", ondelete="CASCADE"),
        primary_key=True,
    )
    module_uuid: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("modules.uuid", ondelete="CASCADE"),
        primary_key=True,
    )

    installed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    client: Mapped[Client] = relationship(back_populates="module_links")
    module: Mapped[Module] = relationship(back_populates="client_links")
