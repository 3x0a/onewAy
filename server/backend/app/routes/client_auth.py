from fastapi import APIRouter, Depends, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_current_client, get_db
from app.exceptions import InvalidCredentialsError
from app.schemas.client_auth import *
from app.services.auth import (
    TokenType,
    authenticate_client,
    create_access_token,
    create_refresh_token,
    create_ws_token,
)
from app.settings import settings

router = APIRouter(prefix="/client/auth", tags=["client", "auth"])


@router.post("/login", response_model=ClientAuthLoginResponse)
async def client_auth_login(
    credentials: ClientAuthLoginRequest,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """Authenticate a client and issue access/refresh tokens."""
    client = await authenticate_client(credentials.username, credentials.password, db)
    if not client:
        raise InvalidCredentialsError("client", credentials.username)

    access_token = create_access_token(client.uuid, TokenType.CLIENT)
    refresh_token = create_refresh_token(client.uuid)

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=settings.security.refresh_token_expire_days * 24 * 60 * 60,
    )

    return ClientAuthLoginResponse(access_token=access_token)


@router.get("/ws-token", response_model=ClientAuthWsTokenResponse)
async def client_auth_ws_token(client=Depends(get_current_client)):
    """Issue a short-lived websocket token for the authenticated client."""
    return ClientAuthWsTokenResponse(token=create_ws_token(client.uuid))
