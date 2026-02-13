from typing import Literal
from uuid import UUID

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.logger import get_logger

log = get_logger()


class AppError(Exception):
    def __init__(self, msg: str):
        self.msg = msg
        super().__init__(msg)


class AppHTTPError(AppError):
    status_code: int = 500
    detail = "Internal server error"
    msg = "Internal server error"

    def __init__(
        self,
        msg: str | None = None,
        *,
        status_code: int | None = None,
        detail: str | None = None,
    ):
        if status_code is not None:
            self.status_code = status_code
        if detail is not None:
            self.detail = detail

        msg = msg or self.msg
        self.msg = msg
        super().__init__(msg)


class AppWebsocketError(AppError):
    msg = "Internal websocket error"

    def __init__(self, msg: str | None = None):
        msg = msg or self.msg
        self.msg = msg
        super().__init__(msg)


class InvalidTokenError(AppHTTPError):
    status_code = 401
    detail = "Invalid token"

    def __init__(self, uuid: UUID | None = None):
        msg = f"Invalid token for user {uuid}" if uuid else None
        super().__init__(msg=msg)


class UserTokenRequiredError(AppHTTPError):
    status_code = 403
    detail = "Forbidden"

    def __init__(self, uuid: UUID):
        super().__init__(msg=f"Forbidden for user {uuid}")


class ClientTokenRequiredError(AppHTTPError):
    status_code = 403
    detail = "Forbidden"

    def __init__(self, uuid: UUID):
        super().__init__(msg=f"Forbidden for client {uuid}")


class InvalidCredentialsError(AppHTTPError):
    status_code = 401
    detail = "Invalid credentials"

    def __init__(self, mtype: Literal["client", "user"], username: str):
        super().__init__(
            msg=f"Invalid credentials for {mtype}. Username provided was {username}"
        )


class DatabaseError(AppHTTPError):
    detail = "Database error"

    def __init__(self, msg: str):
        super().__init__(msg=msg, detail=self.detail)


class ResourceNotFoundError(AppHTTPError):
    status_code = 404

    def __init__(self, msg):
        super().__init__(detail=msg, msg=msg)


class ClientNotFoundError(AppHTTPError):
    status_code = 404
    detail = "Client not found"

    def __init__(self):
        super().__init__(msg=self.detail, detail=self.detail)


class UserNotFoundError(AppHTTPError):
    status_code = 404
    detail = "User not found"

    def __init__(self):
        super().__init__(msg=self.detail, detail=self.detail)


class InvalidPathError(AppHTTPError):
    status_code = 400
    detail = "The provided path is invalid"

    def __init__(self):
        super().__init__(msg=self.detail, detail=self.detail)


class NoFilesProvidedError(AppHTTPError):
    status_code = 400
    detail = "No files provided"

    def __init__(self):
        super().__init__(msg=self.detail, detail=self.detail)


class ConfigYAMLError(AppHTTPError):
    status_code = 400

    def __init__(self, msg):
        super().__init__(msg=msg, detail=msg)


class NoLocalModulesError(AppHTTPError):
    status_code = 400
    detail = "No local modules could be found"

    def __init__(self):
        super().__init__(msg=self.detail, detail=self.detail)


class ModuleAlreadyExistsError(AppHTTPError):
    status_code = 409
    detail = "Module with the same name already exists"

    def __init__(self):
        super().__init__(msg=self.detail, detail=self.detail)


class NoConfigFoundError(AppHTTPError):
    status_code = 400
    detail = "The directory requested does not contain a config.yaml file"

    def __init__(self):
        super().__init__(msg=self.detail, detail=self.detail)


class VersionConflictError(AppHTTPError):
    status_code = 409

    def __init__(self, msg: str):
        super().__init__(msg=msg, detail=msg)


class ClientNotAliveError(AppHTTPError):
    status_code = 400
    detail = "The requested client is not alive"

    def __init__(self):
        super().__init__(msg=self.detail, detail=self.detail)


class WebsocketMessageInvalidDataType(AppWebsocketError):
    def __init__(self):
        super().__init__("Invalid websocket message data type")


class MissingRequiredFieldError(Exception):
    def __init__(self, field: str):
        self.msg = f"Missing required field {field}"
        super().__init__(self.msg)


class CorruptedFieldError(Exception):
    def __init__(self, field: str):
        self.msg = f"Corrupted field {field}"
        super().__init__(self.msg)


class NoWebsocketManagerSetError(Exception):
    def __init__(self):
        self.msg = "No Websocket Manager is set for Module Manager"
        super().__init__(self.msg)


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppHTTPError)
    async def app_error_handler(req: Request, exc: AppHTTPError):
        if exc.status_code >= 500:
            log.error(f"({req.url.path}) {exc.msg or exc.detail}", exc_info=True)
        else:
            log.warning(f"({req.url.path}) {exc.msg or exc.detail}")

        return JSONResponse(
            status_code=exc.status_code,
            content={"status_code": exc.status_code, "detail": exc.detail},
        )

    @app.exception_handler(AppWebsocketError)
    async def websocket_error_handler(req: Request, exc: AppWebsocketError):
        log.error(f"Websocket error: {exc.msg}")

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(req: Request, exc: RequestValidationError):
        log.warning(f"({req.url.path}) Validation error: {exc.errors()}")
        return JSONResponse(
            status_code=422,
            content={"status_code": 422, "detail": "Validation error"},
        )

    @app.exception_handler(Exception)
    async def unhandled_error_handler(req: Request, exc: Exception):
        log.error(f"({req.url.path}) Unhandled exception: {exc}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"status_code": 500, "detail": "Internal server error"},
        )
