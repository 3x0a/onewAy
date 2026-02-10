from pydantic import BaseModel


class ClientAuthLoginRequest(BaseModel):
    username: str
    password: str


class ClientAuthLoginResponse(BaseModel):
    access_token: str


class ClientAuthWsTokenResponse(BaseModel):
    token: str
