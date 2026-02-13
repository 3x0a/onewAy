from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.models.client import Client
from app.utils import Platform


class UserMeResponse(BaseModel):
    username: str


class UserAllClientsResponse(BaseModel):
    all_clients: list[str]


class UserQueryClientBasicInfoResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    username: str
    ip_address: str | None
    hostname: str | None
    platform: Platform
    alive: bool


class UserRegisterClientRequest(BaseModel):
    username: str
    password: str
    platform: Platform


class RefreshTokenBasicInfo(BaseModel):
    uuid: UUID
    expires_at: datetime
    created_at: datetime
    revoked: bool


class UserQueryClientAllInfoResponse(UserQueryClientBasicInfoResponse):
    uuid: UUID
    blocked: bool
    version: str
    last_seen: datetime | None
    owner_uuid: UUID
    installed_modules: list[str]
    refresh_tokens: list[RefreshTokenBasicInfo]


class UserQueryClientInstalledModulesResponse(BaseModel):
    installed_modules: list[str]


class UserModifyClientInstallModuleRequest(BaseModel):
    module_name: str


class UserRunModuleRequest(BaseModel):
    client_username: str

