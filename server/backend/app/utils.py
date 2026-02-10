import enum
from pathlib import Path

from app.logger import get_logger
from app.settings import settings

log = get_logger()


class Platform(enum.StrEnum):
    """All supported platforms."""

    WINDOWS = "windows"
    MAC = "mac"
    LINUX = "linux"


def resolve_root(path: str) -> str:
    """Resolve a path relative to the project root."""

    root = Path(__file__).resolve().parents[3]
    resolved = path.replace("[ROOT]", str(root))
    return str(Path(resolved))


def get_local_modules_from_dir() -> list[str] | None:
    """Return local module directory names from the configured modules path."""
    module_dir = Path(settings.paths.modules_path)
    module_names = []

    try:
        for child in module_dir.iterdir():
            if child.is_dir():
                module_names.append(child.parts[-1])

        return module_names if module_names else None
    except OSError:
        log.error("Unable to get module names from modules directory")
        return None
