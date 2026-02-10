import uuid
from collections.abc import AsyncGenerator

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import AsyncSessionLocal
from app.exceptions import (
    ClientNotFoundError,
    ClientTokenRequiredError,
    InvalidTokenError,
    UserNotFoundError,
    UserTokenRequiredError,
)
from app.models.client import Client
from app.models.user import User
from app.services.auth import TokenType
from app.settings import settings

security = HTTPBearer(auto_error=False)


async def get_db() -> AsyncGenerator[AsyncSession]:
    """Yield a database session for request-scoped dependencies."""
    async with AsyncSessionLocal() as session:
        yield session


async def verify_token(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> dict:
    """Validate an access token from headers or cookies and return its payload."""
    token = credentials.credentials if credentials else None
    if not token:
        token = request.cookies.get("access_token")
    if not token:
        raise InvalidTokenError()

    try:
        payload = jwt.decode(
            token,
            settings.security.secret_key,
            algorithms=[settings.security.algorithm],
        )
    except JWTError as exc:
        raise InvalidTokenError() from exc

    sub = payload.get("sub")
    if not sub:
        raise InvalidTokenError()
    try:
        sub = uuid.UUID(sub)
    except ValueError as exc:
        raise InvalidTokenError() from exc

    try:
        token_type = TokenType(payload["type"])
    except (KeyError, ValueError) as exc:
        raise InvalidTokenError(sub) from exc

    if token_type in [TokenType.REFRESH, TokenType.WEBSOCKET]:
        raise InvalidTokenError(sub)

    return {
        "sub": sub,
        "type": token_type,
        "exp": payload.get("exp"),
    }


async def get_current_client(
    token: dict = Depends(verify_token), db: AsyncSession = Depends(get_db)
) -> Client:
    """Return the authenticated client from a verified client access token."""
    if token["type"] != TokenType.CLIENT:
        raise ClientTokenRequiredError(token["sub"])

    result = await db.execute(select(Client).where(Client.uuid == token["sub"]))
    client = result.scalars().one_or_none()
    if not client:
        raise ClientNotFoundError()

    return client


async def get_current_user(
    token: dict = Depends(verify_token), db: AsyncSession = Depends(get_db)
) -> User:
    """Return the authenticated user from a verified user access token."""
    if token["type"] != TokenType.USER:
        raise UserTokenRequiredError(token["sub"])

    result = await db.execute(select(User).where(User.uuid == token["sub"]))
    user = result.scalars().one_or_none()
    if not user:
        raise UserNotFoundError()

    return user
