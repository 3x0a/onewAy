import logging

from app.settings import settings


def get_logger() -> logging.Logger:
    logger = logging.getLogger("uvicorn")
    if settings.app.debug and logger.level != logging.DEBUG:
        logger.setLevel(logging.DEBUG)

    return logger
