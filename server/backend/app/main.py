import re
from contextlib import asynccontextmanager

from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from app.db.base import Base
from app.db.session import engine
from app.exceptions import register_exception_handlers
from app.logger import get_logger
from app.routes import client, client_auth, user, user_auth
from app.services.module_manager import module_manager
from app.services.websocket_manager import websocket_manager
from app.settings import settings

log = get_logger()


@asynccontextmanager
async def lifespan(_: FastAPI):
    if settings.testing.testing:
        log.info(f"{'=' * 10} TESTING MODE {'=' * 10}")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    module_manager.set_ws_manager(websocket_manager)

    try:
        yield
    finally:
        if settings.testing.testing:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.drop_all)


app = FastAPI(lifespan=lifespan)

allow_origins = [settings.app.frontend_url]
localhost_re = re.compile(r"^https?://localhost(?::\d{1,5})?$")
loopback_re = re.compile(r"^https?://127.0.0.1(?::\d{1,5})?$")
if localhost_re.match(settings.app.frontend_url):
    allow_origins.append(settings.app.frontend_url.replace("localhost", "127.0.0.1", 1))

if loopback_re.match(settings.app.frontend_url):
    allow_origins.append(settings.app.frontend_url.replace("127.0.0.1", "localhost", 1))

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

register_exception_handlers(app)

app.include_router(client_auth.router)
app.include_router(client.router)
app.include_router(user_auth.router)
app.include_router(user.router)


@app.get("/")
async def root():
    return {"message": "onewAy"}
