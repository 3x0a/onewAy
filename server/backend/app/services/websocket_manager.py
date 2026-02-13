from uuid import UUID

from starlette.websockets import WebSocket

from app.logger import get_logger
from app.services.websocket_message import (
    Error,
    Ping,
    Pong,
    StartModule,
    Stdout,
    WebsocketMessage,
)

log = get_logger()


class WebsocketManager:
    """Track active client websockets and send payloads by client UUID."""

    def __init__(self):
        self.connections: dict[UUID, WebSocket] = {}

    async def connect(self, key: UUID, websocket: WebSocket):
        await websocket.accept()
        self.connections[key] = websocket

    def disconnect(self, key: UUID):
        self.connections.pop(key)

    async def send(self, key: UUID, payload: dict):
        ws = self.connections.get(key)
        if ws:
            await ws.send_json(payload)
        else:
            log.warning("No websocket found for key %s", key)


async def handle_message(
    client_uuid: UUID, websocket: WebSocket, msg: WebsocketMessage
) -> None:
    """Handle a parsed websocket message from a client."""
    match msg:
        case Error():
            log.error("Received error message from %s: %s", client_uuid, msg.message)

        case Ping():
            log.info("Received ping from %s, sending pong", client_uuid)
            await websocket.send_json(Pong().to_json())

        case Pong():
            log.debug("Received pong from %s", client_uuid)

        case StartModule():
            pass

        case Stdout():
            pass

        case _:
            log.warning("Unknown message type %s", msg)
            await websocket.send_json(
                {"type": "error", "message": "Unknown message type"}
            )


websocket_manager = WebsocketManager()
