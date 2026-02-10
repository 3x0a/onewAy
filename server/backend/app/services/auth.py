import enum
import uuid
from datetime import UTC, datetime, timedelta
from typing import Protocol

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import WebSocket
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped

from app.exceptions import InvalidTokenError
from app.models.client import Client
from app.models.user import User
from app.settings import settings


class Authenticatable(Protocol):
    """Protocol for auth-capable models with username and hashed password."""
    username: Mapped[str]
    hashed_password: Mapped[str]


_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """Hash a plaintext password using Argon2."""
    return _hasher.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    """Return True if a plaintext password matches the stored hash."""
    try:
        _hasher.verify(hashed, password)
        return True
    except VerifyMismatchError:
        return False


class TokenType(enum.StrEnum):
    """Supported token-purpose discriminator values."""
    CLIENT = "client"
    USER = "user"
    REFRESH = "refresh"  # Should only be used by clients
    WEBSOCKET = "websocket"


def create_access_token(sub: uuid.UUID, token_type: TokenType) -> str:
    """Create a signed access token with expiration and type."""
    expire = datetime.now(UTC) + timedelta(
        minutes=settings.security.access_token_expire_minutes
    )
    payload = {
        "sub": str(sub),
        "exp": expire,
        "type": token_type.value,
    }
    return jwt.encode(
        payload, settings.security.secret_key, algorithm=settings.security.algorithm
    )


def create_refresh_token(client_uuid: uuid.UUID) -> str:
    """Create a signed refresh token for a client."""
    expire = datetime.now(UTC) + timedelta(
        days=settings.security.refresh_token_expire_days
    )
    payload = {
        "sub": str(client_uuid),
        "exp": expire,
        "type": "refresh",
    }
    return jwt.encode(
        payload, settings.security.secret_key, algorithm=settings.security.algorithm
    )


def create_ws_token(client_uuid: uuid.UUID) -> str:
    """Create a signed websocket token for a client."""
    expire = datetime.now(UTC) + timedelta(
        minutes=settings.security.access_token_expire_minutes
    )
    payload = {
        "sub": str(client_uuid),
        "exp": expire,
        "type": TokenType.WEBSOCKET.value,
    }
    return jwt.encode(
        payload, settings.security.secret_key, algorithm=settings.security.algorithm
    )


def verify_ws_token(token: str) -> uuid.UUID:
    """Validate a websocket token and return the client UUID."""
    try:
        payload = jwt.decode(
            token,
            settings.security.secret_key,
            algorithms=[settings.security.algorithm],
        )
    except JWTError as exc:
        raise InvalidTokenError() from exc

    token_type = payload.get("type")
    if token_type != TokenType.WEBSOCKET.value:
        raise InvalidTokenError()

    sub = payload.get("sub")
    if not sub:
        raise InvalidTokenError()

    try:
        return uuid.UUID(sub)
    except ValueError as exc:
        raise InvalidTokenError() from exc


async def _authenticate[T: Authenticatable](
    model: type[T], username: str, password: str, db: AsyncSession
) -> T | None:
    """Look up an entity by username and verify its password."""
    result = await db.execute(select(model).where(model.username == username))
    entity = result.scalar_one_or_none()

    if entity is None or not verify_password(password, entity.hashed_password):
        return None

    return entity


async def authenticate_client(
    username: str, password: str, db: AsyncSession
) -> Client | None:
    """Authenticate a client account by username and password."""
    return await _authenticate(Client, username, password, db)


async def authenticate_user(
    username: str, password: str, db: AsyncSession
) -> User | None:
    """Authenticate a user account by username and password."""
    return await _authenticate(User, username, password, db)


def extract_ws_token(websocket: WebSocket) -> str | None:
    """Extract a websocket token from the Authorization header."""
    auth_header = websocket.headers.get("authorization")
    if not auth_header:
        return None

    scheme, sep, credentials = auth_header.partition(" ")
    if sep and scheme.lower() == "bearer":
        token = credentials.strip()
        return token or None

    token = auth_header.strip()
    return token or None
