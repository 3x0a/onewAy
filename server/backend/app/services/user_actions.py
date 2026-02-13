import shutil
from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import Any

import yaml
from fastapi import UploadFile
from yaml.error import YAMLError

from app.exceptions import (
    ConfigYAMLError,
    CorruptedFieldError,
    InvalidPathError,
    MissingRequiredFieldError,
    NoFilesProvidedError,
)
from app.logger import get_logger

log = get_logger()


@dataclass
class ModuleUploadData:
    """Uploaded module files and validated config metadata."""

    uploaded_files: list[tuple[PurePath, bytes]]
    config_path: PurePath
    config_data: ModuleFromConfig


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


def parse_module_config_payload(
    config_payload: bytes, *, error_on_unknown_binary_field: bool = True
) -> ModuleFromConfig:
    """Parse and validate a config.yaml payload into a ModuleFromConfig."""
    try:
        config = yaml.safe_load(config_payload.decode())
        if not isinstance(config, dict):
            raise ConfigYAMLError("Invalid config.yaml structure")
        return ModuleFromConfig.from_yaml_data(
            config,
            error_on_unknown_binary_field=error_on_unknown_binary_field,
        )
    except YAMLError as e:
        raise ConfigYAMLError("Invalid config.yaml") from e
    except ConfigYAMLError as e:
        raise e
    except (MissingRequiredFieldError, CorruptedFieldError) as e:
        raise ConfigYAMLError(str(e)) from e


async def parse_module_upload(
    files: list[UploadFile], *, error_on_unknown_binary_field: bool = True
) -> ModuleUploadData:
    """Collect uploaded files and return validated config data for a module upload."""
    if not files:
        raise NoFilesProvidedError()

    uploaded_files: list[tuple[PurePath, bytes]] = []
    config_payload: bytes | None = None
    config_path: PurePath | None = None

    for upload in files:
        if not upload.filename:
            continue
        normalized_name = upload.filename.replace("\\", "/")
        file_path = PurePath(normalized_name)
        payload = await upload.read()
        uploaded_files.append((file_path, payload))
        if file_path.name == "config.yaml":
            config_payload = payload
            config_path = file_path

    if not config_payload or not config_path:
        raise ConfigYAMLError("config.yaml not found")

    config_data = parse_module_config_payload(
        config_payload,
        error_on_unknown_binary_field=error_on_unknown_binary_field,
    )
    return ModuleUploadData(
        uploaded_files=uploaded_files,
        config_path=config_path,
        config_data=config_data,
    )


def materialize_module_upload(
    upload_data: ModuleUploadData, module_dir: Path, *, replace_existing: bool = False
) -> None:
    """Write uploaded module files to disk with path traversal protection."""
    root_dir = upload_data.config_path.parent

    if replace_existing and module_dir.exists():
        shutil.rmtree(module_dir, ignore_errors=True)

    try:
        module_dir.mkdir(parents=True, exist_ok=False)
        base_resolved = module_dir.resolve()

        for file_path, payload in upload_data.uploaded_files:
            try:
                relative_path = file_path.relative_to(root_dir)
            except ValueError:
                continue

            relative_fs_path = Path(*relative_path.parts)
            if not relative_fs_path.parts:
                continue

            dest_path = (module_dir / relative_fs_path).resolve()
            if base_resolved not in dest_path.parents and dest_path != base_resolved:
                raise InvalidPathError()

            dest_path.parent.mkdir(parents=True, exist_ok=True)
            dest_path.write_bytes(payload)
    except InvalidPathError:
        shutil.rmtree(module_dir, ignore_errors=True)
        raise
    except Exception as e:
        shutil.rmtree(module_dir, ignore_errors=True)
        log.error(
            "Failed to write uploaded module files for %r", upload_data.config_data.name
        )
        raise ConfigYAMLError("Failed to save uploaded module files") from e
