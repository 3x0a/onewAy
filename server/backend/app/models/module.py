from uuid import UUID, uuid4

from sqlalchemy import String, Text
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.client_module import ClientModule


class Module(Base):
    __tablename__ = "modules"

    uuid: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    name: Mapped[str] = mapped_column(
        String(255), unique=True, index=True, nullable=False
    )
    description: Mapped[str | None] = mapped_column(String(500), nullable=True)
    version: Mapped[str] = mapped_column(String(255), nullable=False)
    windows: Mapped[str | None] = mapped_column(Text, nullable=True)
    mac: Mapped[str | None] = mapped_column(Text, nullable=True)
    linux: Mapped[str | None] = mapped_column(Text, nullable=True)

    client_links: Mapped[list[ClientModule]] = relationship(
        back_populates="module",
        cascade="all, delete-orphan",
    )
