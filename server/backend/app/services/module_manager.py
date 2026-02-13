from uuid import UUID, uuid4

from app.exceptions import NoWebsocketManagerSetError
from app.services.websocket_manager import WebsocketManager
from app.services.websocket_message import StartModule


class ModuleManager:
    _ws_manager: WebsocketManager | None = None

    def __init__(self):
        self.state: dict[UUID, dict[UUID, str]] = {}

    @property
    def ws_manager(self) -> WebsocketManager:
        ws_manager = self._ws_manager
        if ws_manager is None:
            raise NoWebsocketManagerSetError()
        return ws_manager

    def set_ws_manager(self, ws_manager: WebsocketManager) -> None:
        self._ws_manager = ws_manager

    async def run_module(self, module_name: str, client_uuid: UUID) -> UUID:
        msg = StartModule(module_name=module_name)
        await self.ws_manager.send(client_uuid, msg.to_json())

        job_id = uuid4()
        self.state[job_id] = {client_uuid: module_name}
        return job_id

    def get_jobs_by_client(self, client_uuid: UUID) -> list[UUID]:
        return [
            job_id for job_id, job_meta in self.state.items() if client_uuid in job_meta
        ]


module_manager = ModuleManager()
