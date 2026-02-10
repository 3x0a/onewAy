import uvicorn

from app.settings import settings

if __name__ == "__main__":
    if settings.security.ssl:
        uvicorn.run(
            "app.main:app",
            host=settings.app.host,
            port=settings.app.port,
            ssl_certfile=settings.security.ssl_certfile,
            ssl_keyfile=settings.security.ssl_keyfile,
        )
    else:
        uvicorn.run("app.main:app", host=settings.app.host, port=settings.app.port)
