from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[2]
BACKEND = Path(__file__).resolve().parents[1]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(str(ROOT / ".env"), str(BACKEND / ".env"), ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = f"sqlite:///{ROOT / 'artifacts' / 'ethoscan.db'}"
    redis_url: str = "redis://localhost:6379/0"
    ethoscan_mode: str = "local"
    ethoscan_artifacts_dir: str = str(ROOT / "artifacts")
    ethoscan_allow_mock: bool = True
    ethoscan_api_host: str = "0.0.0.0"
    ethoscan_api_port: int = 8000

    @property
    def artifacts_path(self) -> Path:
        path = Path(self.ethoscan_artifacts_dir).resolve()
        path.mkdir(parents=True, exist_ok=True)
        return path


@lru_cache
def get_settings() -> Settings:
    return Settings()
