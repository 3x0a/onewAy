from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.client_module import ClientModule
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.utils import Platform


def _enum_values(enum_cls: type[Platform]) -> list[str]:
    return [item.value for item in enum_cls]


PLATFORM_ENUM = Enum(
    Platform,
    name="platform",
    values_callable=_enum_values,
)


class Client(Base):
    __tablename__ = "clients"
    uuid: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    username: Mapped[str] = mapped_column(
        String(255), unique=True, index=True, nullable=False
    )
    hashed_password: Mapped[str] = mapped_column(String, nullable=False)
    blocked: Mapped[bool] = mapped_column(default=False, nullable=False)
    ip_address: Mapped[str | None] = mapped_column(INET, nullable=True)
    hostname: Mapped[str | None] = mapped_column(Text, nullable=True)
    platform: Mapped[Platform] = mapped_column(PLATFORM_ENUM, nullable=False)
    version: Mapped[str] = mapped_column(String(225), nullable=False)
    alive: Mapped[bool] = mapped_column(default=False, nullable=False)
    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    owner_uuid: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("users.uuid", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    module_links: Mapped[list[ClientModule]] = relationship(
        back_populates="client",
        cascade="all, delete-orphan",
    )

    refresh_tokens: Mapped[list[RefreshToken]] = relationship(
        back_populates="client",
        cascade="all, delete-orphan",
    )

    owner: Mapped[User] = relationship(back_populates="owned_clients")
