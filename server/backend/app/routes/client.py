import json

from fastapi import APIRouter, WebSocket
from sqlalchemy import select
from starlette.websockets import WebSocketDisconnect

from app.db.session import AsyncSessionLocal
from app.exceptions import InvalidTokenError, WebsocketMessageInvalidDataType
from app.logger import get_logger
from app.models.client import Client
from app.services.auth import extract_ws_token, verify_ws_token
from app.services.websocket_manager import WebsocketManager, handle_message
from app.services.websocket_message import Error, WebsocketMessage

router = APIRouter(prefix="/client", tags=["client"])
ws_manager = WebsocketManager()
log = get_logger()


@router.websocket("/ws")
async def client_ws(websocket: WebSocket):
    """Handle authenticated client websocket connections and messages."""
    token = extract_ws_token(websocket)
    if not token:
        await websocket.close(code=1008)
        return

    try:
        client_uuid = verify_ws_token(token)
    except InvalidTokenError:
        await websocket.close(code=1008)
        log.warning("Failed to verify websocket token")
        return

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Client).where(Client.uuid == client_uuid))
        client = result.scalars().one_or_none()
        if not client:
            await websocket.close(code=1008)
            log.warning(
                f"Websocket auth failed: client with uuid {client_uuid} not found"
            )
            return

    await ws_manager.connect(client_uuid, websocket)
    log.debug(f"Websocket connected: {client_uuid}")
    try:
        while True:
            raw = await websocket.receive_text()

            try:
                data = json.loads(raw)
                if not isinstance(data, dict):
                    raise WebsocketMessageInvalidDataType()

                msg = WebsocketMessage.from_json(data)

            except (
                json.JSONDecodeError,
                ValueError,
                WebsocketMessageInvalidDataType,
            ) as e:
                match e:
                    case json.JSONDecodeError():
                        message = "Invalid JSON"
                    case ValueError():
                        message = e.args[0]
                    case WebsocketMessageInvalidDataType():
                        message = e.msg

                await websocket.send_json(Error(message).to_json())
                continue

            await handle_message(client_uuid, websocket, msg)

    except WebSocketDisconnect:
        ws_manager.disconnect(client_uuid)


# - [ ] /client/update-info
# - [ ] /client/sync-modules

