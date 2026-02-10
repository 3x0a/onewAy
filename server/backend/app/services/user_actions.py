from typing import Any

from app.exceptions import CorruptedFieldError, MissingRequiredFieldError
from app.logger import get_logger

log = get_logger()


class ModuleFromConfig:
    """Validated module metadata parsed from a module config.yaml file."""
    name: str
    description: str | None
    version: str
    windows: str | None
    mac: str | None
    linux: str | None

    @classmethod
    def from_yaml_data(
        cls, data: dict[str, Any], error_on_unknown_binary_field: bool = False
    ) -> ModuleFromConfig:
        """Build a validated module config object from parsed YAML data."""
        name = data.get("name")
        description = data.get("description")
        version = data.get("version")
        binaries = data.get("binaries")

        if not name:
            raise MissingRequiredFieldError("name")
        if not version:
            raise MissingRequiredFieldError("version")
        if not binaries:
            raise MissingRequiredFieldError("binaries")

        if not isinstance(name, str):
            raise CorruptedFieldError("name")
        if description is not None and not isinstance(description, str):
            raise CorruptedFieldError("description")
        if not isinstance(version, str):
            raise CorruptedFieldError("version")
        if not isinstance(binaries, dict):
            raise CorruptedFieldError("binaries")

        instance = cls()
        instance.name = name
        instance.description = description
        instance.version = version
        instance.windows = None
        instance.mac = None
        instance.linux = None

        for key, value in binaries.items():
            if key == "windows":
                if not isinstance(value, str) or not value.strip():
                    raise CorruptedFieldError("binaries.windows")
                instance.windows = value
            elif key == "mac":
                if not isinstance(value, str) or not value.strip():
                    raise CorruptedFieldError("binaries.mac")
                instance.mac = value
            elif key == "linux":
                if not isinstance(value, str) or not value.strip():
                    raise CorruptedFieldError("binaries.linux")
                instance.linux = value
            else:
                if error_on_unknown_binary_field:
                    raise CorruptedFieldError(f"binaries.{key}")
                log.warning("Unknown key '%s' found in config.yaml", key)

        if not instance.windows and not instance.mac and not instance.linux:
            log.warning("No valid binary values found in config file")

        return instance
