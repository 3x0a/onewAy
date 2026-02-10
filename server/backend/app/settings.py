from pathlib import Path

from pydantic import BaseModel, DirectoryPath, Field, FilePath, model_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    TomlConfigSettingsSource,
)

from app.utils import resolve_root

CONFIG_FILE = "config.toml"


class AppSettings(BaseModel):
    debug: bool = False
    host: str = "0.0.0.0"
    port: int = 8000
    frontend_url: str = "https://localhost:5173"


class SecuritySettings(BaseModel):
    ssl: bool = True
    ssl_certfile: FilePath = Path.home() / ".onewAy" / "onewAy.crt"
    ssl_keyfile: FilePath = Path.home() / ".onewAy" / "onewAy.key"
    secret_key: str
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7


class DatabaseSettings(BaseModel):
    database_url: str


class PathsSettings(BaseModel):
    modules_path: DirectoryPath = Path(resolve_root("[ROOT]")) / "modules"
    metasploit_mod_info_path: FilePath = (
        Path(resolve_root("[ROOT]"))
        / "server"
        / "backend"
        / "metasploit_mod_options.json"
    )


class TestingSettings(BaseModel):
    testing: bool = False
    database_url: str | None = None
    secret_key: str | None = None


class Settings(BaseSettings):
    app: AppSettings = Field(default_factory=AppSettings)
    security: SecuritySettings
    database: DatabaseSettings
    paths: PathsSettings = Field(default_factory=PathsSettings)
    testing: TestingSettings = Field(default_factory=TestingSettings)

    model_config = SettingsConfigDict(toml_file=CONFIG_FILE, extra="ignore")

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            file_secret_settings,
            TomlConfigSettingsSource(settings_cls),
        )

    @model_validator(mode="after")
    def inject_testing_settings(self) -> Settings:
        if self.testing.testing:
            if not self.testing.database_url:
                raise ValueError("You must provide a separate testing database URL")

            if not self.testing.secret_key:
                raise ValueError("You must provide a separate testing secret key")

            self.database.database_url = self.testing.database_url
            self.security.secret_key = self.testing.secret_key

        return self

    @model_validator(mode="after")
    def remove_trailing_slash(self) -> Settings:
        self.app.frontend_url = self.app.frontend_url.rstrip("/")
        return self


# noinspection PyArgumentList
settings = Settings()
