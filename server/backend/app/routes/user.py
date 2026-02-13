import shutil
from pathlib import Path

import yaml
from fastapi import APIRouter, Depends, File, Response, UploadFile
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from yaml.error import YAMLError

import app.services.client_actions as client_actions
from app.dependencies import get_current_user, get_db
from app.exceptions import (
    ClientNotAliveError,
    ClientNotFoundError,
    ConfigYAMLError,
    CorruptedFieldError,
    DatabaseError,
    InvalidPathError,
    MissingRequiredFieldError,
    ModuleAlreadyExistsError,
    NoConfigFoundError,
    NoLocalModulesError,
    ResourceNotFoundError,
    VersionConflictError,
)
from app.logger import get_logger
from app.models.client import Client
from app.models.client_module import ClientModule
from app.models.module import Module
from app.models.refresh_token import RefreshToken
from app.schemas.general import BasicTaskResponse
from app.schemas.user import *
from app.schemas.user import RefreshTokenBasicInfo
from app.services.auth import hash_password
from app.services.module_manager import module_manager
from app.services.user_actions import (
    ModuleFromConfig,
    materialize_module_upload,
    parse_module_upload,
)
from app.settings import settings
from app.utils import get_local_modules_from_dir

router = APIRouter(prefix="/user", tags=["user"])
log = get_logger()


@router.get("/me", response_model=UserMeResponse)
async def user_me(user=Depends(get_current_user)):
    """Return the current user's username."""
    return UserMeResponse(username=user.username)


@router.get("/all-clients", response_model=UserAllClientsResponse)
async def user_all_clients(
    _=Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    """Return all client usernames visible to the current user."""
    try:
        client_usernames = await db.scalars(select(Client.username))
        result = client_usernames.all()
        return UserAllClientsResponse(all_clients=list(result))
    except SQLAlchemyError as e:
        raise DatabaseError(str(e)) from e


@router.get(
    "/query/{client_username}/basic-info",
    response_model=UserQueryClientBasicInfoResponse,
)
async def user_query_client_basic_info(
    client_username: str,
    _=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return basic metadata about a single client by username."""
    client = await client_actions.get_client(client_username, db)

    return UserQueryClientBasicInfoResponse(
        username=client.username,
        ip_address=str(client.ip_address),
        hostname=client.hostname,
        platform=client.platform,
        alive=client.alive,
    )


@router.post("/register-client", response_model=BasicTaskResponse)
async def user_register_client(
    client_info: UserRegisterClientRequest,
    _=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Register a new client."""
    new_client = Client(
        username=client_info.username,
        hashed_password=hash_password(client_info.password),
        platform=client_info.platform,
        version="0.1.0",
    )
    db.add(new_client)

    try:
        await db.commit()
    except SQLAlchemyError as e:
        await db.rollback()
        raise DatabaseError(f"DB error registering client: {e!s}") from e

    return BasicTaskResponse()


@router.get(
    "/query/{client_username}/all-info",
    response_model=UserQueryClientAllInfoResponse,
)
async def user_query_client_all_info(
    client_username: str,
    _=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return full metadata and tokens for a single client by username."""
    result = await db.execute(
        select(Client)
        .options(
            selectinload(Client.module_links).selectinload(ClientModule.module),
            selectinload(Client.refresh_tokens),
        )
        .where(Client.username == client_username)
    )
    client = result.scalar_one_or_none()

    if not client:
        raise ClientNotFoundError()

    installed_modules = [
        link.module.name for link in client.module_links if link.module is not None
    ]
    refresh_tokens = [
        RefreshTokenBasicInfo(
            uuid=token.uuid,
            expires_at=token.expires_at,
            created_at=token.created_at,
            revoked=token.revoked,
        )
        for token in client.refresh_tokens
    ]

    return UserQueryClientAllInfoResponse(
        username=client.username,
        ip_address=str(client.ip_address) if client.ip_address else None,
        hostname=client.hostname,
        platform=client.platform,
        alive=client.alive,
        uuid=client.uuid,
        blocked=client.blocked,
        version=client.version,
        last_seen=client.last_seen,
        owner_uuid=client.owner_uuid,
        installed_modules=installed_modules,
        refresh_tokens=refresh_tokens,
    )


@router.get(
    "/revoke-refresh-token/{refresh_token_uuid}", response_model=BasicTaskResponse
)
async def user_revoke_refresh_token(
    refresh_token_uuid: UUID,
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Revoke a refresh token owned by the current user's client."""
    try:
        result = await db.execute(
            select(RefreshToken)
            .join(Client)
            .where(
                RefreshToken.uuid == refresh_token_uuid,
                Client.owner_uuid == user.uuid,
            )
        )
        token = result.scalars().one_or_none()
    except SQLAlchemyError as e:
        raise DatabaseError(str(e)) from e

    if not token:
        raise ResourceNotFoundError("Refresh token not found")

    if not token.revoked:
        token.revoked = True
        try:
            await db.commit()
        except SQLAlchemyError as e:
            await db.rollback()
            raise DatabaseError(f"DB error revoking refresh token: {e!s}") from e

    return BasicTaskResponse()


@router.get("/logout", response_model=BasicTaskResponse)
async def user_logout(
    response: Response,
    _=Depends(get_current_user),
):
    """Clear the access token cookie for the current user."""
    response.delete_cookie(key="access_token", path="/")
    return BasicTaskResponse()


@router.get(
    "/query/{client_username}/installed-modules",
    response_model=UserQueryClientInstalledModulesResponse,
)
async def user_query_client_installed_modules(
    client_username: str,
    _=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return installed module names for a client by username."""
    try:
        client_result = await db.execute(
            select(Client).where(Client.username == client_username)
        )
        client = client_result.scalars().one_or_none()
        if not client:
            raise ResourceNotFoundError("Client not found")

        result = await db.execute(
            select(Module)
            .join(ClientModule, ClientModule.module_uuid == Module.uuid)
            .join(Client, Client.uuid == ClientModule.client_uuid)
            .where(Client.username == client_username)
        )
        modules = result.scalars().all()
        return UserQueryClientInstalledModulesResponse(
            installed_modules=list([mod.name for mod in modules])
        )
    except SQLAlchemyError as e:
        raise DatabaseError(str(e)) from e


@router.post("/modify/{client_username}/block", response_model=BasicTaskResponse)
async def user_modify_client_block(
    client_username: str,
    _=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Block a client by username."""
    try:
        return await client_actions.update_client_block_status(
            client_username, True, db
        )
    except ValueError as e:
        raise ResourceNotFoundError(str(e)) from e


@router.post("/modify/{client_username}/unblock", response_model=BasicTaskResponse)
async def user_modify_client_unblock(
    client_username: str,
    _=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Unblock a client by username."""
    try:
        return await client_actions.update_client_block_status(
            client_username, False, db
        )
    except ValueError as e:
        raise ResourceNotFoundError(str(e)) from e


@router.post(
    "/modify/{client_username}/install-module", response_model=BasicTaskResponse
)
async def user_modify_client_install_module(
    client_username: str,
    module_info: UserModifyClientInstallModuleRequest,
    _=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Install a module on a client."""
    try:
        result = await db.execute(
            select(Module).where(Module.name == module_info.module_name)
        )
        module = result.scalars().one_or_none()
    except SQLAlchemyError as e:
        raise DatabaseError(str(e)) from e

    if not module:
        raise ResourceNotFoundError("Module not found")

    client = await client_actions.get_client(client_username, db)
    client_module = ClientModule(client_uuid=client.uuid, module_uuid=module.uuid)
    db.add(client_module)

    try:
        await db.commit()
    except SQLAlchemyError as e:
        await db.rollback()
        raise DatabaseError(f"DB error installing module: {e!s}") from e

    return BasicTaskResponse()


@router.post("/modules/upload", response_model=BasicTaskResponse)
async def user_upload_modules(
    files: list[UploadFile] = File(...),
    _=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Upload a directory containing a module."""
    upload_data = await parse_module_upload(files, error_on_unknown_binary_field=True)
    config_data = upload_data.config_data

    try:
        result = await db.execute(select(Module).where(Module.name == config_data.name))
        existing = result.scalars().one_or_none()
    except SQLAlchemyError as e:
        raise DatabaseError(str(e)) from e

    if existing:
        raise ModuleAlreadyExistsError()

    module_root = Path(settings.paths.modules_path)
    module_dir = module_root / config_data.name
    if module_dir.exists():
        raise ModuleAlreadyExistsError()
    module_root.mkdir(parents=True, exist_ok=True)

    materialize_module_upload(upload_data, module_dir)

    module = Module(
        name=config_data.name,
        description=config_data.description,
        version=config_data.version,
        windows=config_data.windows,
        mac=config_data.mac,
        linux=config_data.linux,
    )
    db.add(module)

    try:
        await db.commit()
    except SQLAlchemyError as e:
        await db.rollback()
        shutil.rmtree(module_dir, ignore_errors=True)
        raise DatabaseError(f"DB error creating module: {e!s}") from e

    return BasicTaskResponse()


@router.post("/modules/install", response_model=BasicTaskResponse)
async def user_modules_install(
    module_name: str, _=Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    """Install a local module directory into the database."""
    local_modules = get_local_modules_from_dir()
    if not local_modules:
        raise NoLocalModulesError()

    target_mod: str | None = None
    for mod in local_modules:
        if mod == module_name:
            target_mod = mod

    if not target_mod:
        raise ResourceNotFoundError(f"Could not find local module {module_name}")

    try:
        result = await db.execute(select(Module).where(Module.name == module_name))
        module = result.scalar_one_or_none()
    except SQLAlchemyError as e:
        raise DatabaseError("DB error looking for modules") from e

    if module:
        raise ModuleAlreadyExistsError()

    new_mod_path = Path(settings.paths.modules_path) / module_name
    config_found = False
    for node in new_mod_path.iterdir():
        if node.name == "config.yaml":
            config_found = True

    if not config_found:
        raise NoConfigFoundError()

    try:
        with open(new_mod_path / "config.yaml") as f:
            data = yaml.safe_load(f)
    except (FileNotFoundError, PermissionError, OSError) as e:
        raise ConfigYAMLError("Failed to read config.yaml") from e
    except YAMLError as e:
        raise ConfigYAMLError("Failed to parse config.yaml") from e

    if not isinstance(data, dict):
        raise ConfigYAMLError("Failed to parse config.yaml")

    try:
        module_data = ModuleFromConfig.from_yaml_data(data)
    except (MissingRequiredFieldError, CorruptedFieldError) as e:
        raise ConfigYAMLError(str(e)) from e

    new_module = Module(
        name=module_data.name,
        description=module_data.description,
        version=module_data.version,
        windows=module_data.windows,
        mac=module_data.mac,
        linux=module_data.linux,
    )
    try:
        db.add(new_module)
        await db.commit()
        await db.refresh(new_module)
    except SQLAlchemyError as e:
        await db.rollback()
        raise DatabaseError(f"Unable to save new module {module_name} in the DB") from e

    return BasicTaskResponse()


@router.post("/modules/update-local", response_model=BasicTaskResponse)
async def user_modules_update_local(
    module_name: str, _=Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    """Update an existing module record from its local config.yaml."""
    result = await db.execute(select(Module).where(Module.name == module_name))
    db_mod = result.scalar_one_or_none()
    if not db_mod:
        raise ResourceNotFoundError(
            f"Unable to find local module {module_name} in the db"
        )

    local_modules = get_local_modules_from_dir()
    if not local_modules:
        raise NoLocalModulesError()

    target_mod: str | None = None
    for mod in local_modules:
        if mod == module_name:
            target_mod = mod

    if not target_mod:
        raise ResourceNotFoundError(f"Unable to find local module {module_name}")

    target_dir = Path(settings.paths.modules_path) / target_mod
    if not target_dir.is_dir():
        raise InvalidPathError()

    mod_config: ModuleFromConfig | None = None
    for node in target_dir.iterdir():
        if node.is_file() and str(node.name) == "config.yaml":
            try:
                with open(node) as f:
                    mod_config = ModuleFromConfig.from_yaml_data(yaml.safe_load(f))
            except yaml.YAMLError as e:
                raise ConfigYAMLError("Failed to parse config.yaml") from e
            except (MissingRequiredFieldError, CorruptedFieldError) as e:
                raise e

    if not mod_config:
        raise NoConfigFoundError()

    if mod_config.version == db_mod.version:
        raise VersionConflictError("Local module is up to date")

    db_mod.description = mod_config.description
    db_mod.version = mod_config.version
    db_mod.windows = mod_config.windows
    db_mod.mac = mod_config.mac
    db_mod.linux = mod_config.linux

    try:
        await db.commit()
    except SQLAlchemyError as e:
        await db.rollback()
        raise DatabaseError(
            f"Unable to save changes for {module_name} to the DB"
        ) from e

    return BasicTaskResponse()


@router.post("/modules/update-remote", response_model=BasicTaskResponse)
async def user_modules_update_remote(
    files: list[UploadFile] = File(...),
    _=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Upload a remote module package and upsert it when the version changes."""
    upload_data = await parse_module_upload(files, error_on_unknown_binary_field=True)
    config_data = upload_data.config_data

    try:
        result = await db.execute(select(Module).where(Module.name == config_data.name))
        existing = result.scalars().one_or_none()
    except SQLAlchemyError as e:
        raise DatabaseError(str(e)) from e

    if existing and existing.version == config_data.version:
        raise VersionConflictError("Remote module is up to date")

    module_root = Path(settings.paths.modules_path)
    module_dir = module_root / config_data.name
    module_root.mkdir(parents=True, exist_ok=True)
    materialize_module_upload(upload_data, module_dir, replace_existing=True)

    if existing:
        existing.description = config_data.description
        existing.version = config_data.version
        existing.windows = config_data.windows
        existing.mac = config_data.mac
        existing.linux = config_data.linux
    else:
        module = Module(
            name=config_data.name,
            description=config_data.description,
            version=config_data.version,
            windows=config_data.windows,
            mac=config_data.mac,
            linux=config_data.linux,
        )
        db.add(module)

    try:
        await db.commit()
    except SQLAlchemyError as e:
        await db.rollback()
        raise DatabaseError(
            f"Unable to save changes for {config_data.name} to the DB"
        ) from e

    return BasicTaskResponse()


@router.post("/run/{module_name}", response_model=BasicTaskResponse)
async def user_run_module(
    module_name: str,
    run_info: UserRunModuleRequest,
    _=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Client).where(Client.username == run_info.client_username)
    )
    client = result.scalar_one_or_none()
    if not client:
        raise ClientNotFoundError()
    if not client.alive:
        raise ClientNotAliveError()

    await module_manager.run_module(module_name, client.uuid)
    return BasicTaskResponse()


# - [X] /user/modules/install
# - [X] /user/modules/update-local
# - [X] /user/modules/update-remote
# - [ ] /user/run/{module_name}
# - [ ] /user/stop/{module_name}
# - [ ] /user/metasploit/modules
# - [ ] /user/modify/{client_username}/update
# - [ ] /user/metasploit/info/{metasploit_mod_name}
# - [ ] /user/metasploit/advanced-info/{metasploit_mod_name}
# - [ ] /user/metasploit/run/{metasploit_mod_name}
# - [ ] /user/metasploit/stop/{metasploit_mod_name}
