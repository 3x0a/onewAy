from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db
from app.exceptions import InvalidCredentialsError
from app.schemas.user_auth import *
from app.services.auth import TokenType, authenticate_user, create_access_token
from app.settings import settings

router = APIRouter(prefix="/user/auth", tags=["user", "auth"])


@router.post("/login", response_model=UserAuthLoginResponse)
async def user_auth_login(
    credentials: UserAuthLoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """Authenticate a user and set the access token cookie."""
    user = await authenticate_user(credentials.username, credentials.password, db)
    if not user:
        raise InvalidCredentialsError("user", credentials.username)

    access_token = create_access_token(user.uuid, TokenType.USER)

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="lax",
        max_age=settings.security.access_token_expire_minutes * 60,
        path="/",
    )

    return UserAuthLoginResponse(access_token=access_token)
