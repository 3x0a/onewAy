from pydantic import BaseModel


class UserAuthLoginRequest(BaseModel):
    username: str
    password: str


class UserAuthLoginResponse(BaseModel):
    access_token: str
