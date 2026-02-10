from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.exceptions import DatabaseError, ResourceNotFoundError
from app.models.client import Client
from app.schemas.general import BasicTaskResponse


async def get_client(client_username: str, db: AsyncSession) -> Client:
    """Fetch a client by username or raise a not-found error."""
    try:
        result = await db.execute(
            select(Client).where(Client.username == client_username)
        )
        client = result.scalars().one_or_none()
    except SQLAlchemyError as e:
        raise DatabaseError(str(e)) from e

    if not client:
        raise ResourceNotFoundError("Client not found")

    return client


async def update_client_block_status(
    client_username: str, block: bool, db: AsyncSession
) -> BasicTaskResponse:
    """Set a client's blocked status and persist the change."""
    try:
        result = await db.execute(
            select(Client).where(Client.username == client_username)
        )
        client = result.scalars().one_or_none()
    except SQLAlchemyError as e:
        raise DatabaseError(str(e)) from e

    if not client:
        raise ValueError(f"Client '{client_username}' not found")

    client.blocked = block

    try:
        await db.commit()
    except SQLAlchemyError as e:
        await db.rollback()
        raise DatabaseError(f"DB error blocking client: {e!s}") from e

    return BasicTaskResponse()
