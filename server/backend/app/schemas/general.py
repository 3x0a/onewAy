from pydantic import BaseModel


class BasicTaskResponse(BaseModel):
    result: str = "success"
