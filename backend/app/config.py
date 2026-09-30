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
    ethoscan_force_mock: bool = False
    ethoscan_api_host: str = "127.0.0.1"
    ethoscan_api_port: int = 8000
    ethoscan_api_key: str = ""
    ethoscan_cors_origins: str = "http://localhost:3000"
    ethoscan_allowlist: str = ""
    ethoscan_worker_enabled: bool = True
    ethoscan_worker_concurrency: int = 1
    ethoscan_worker_poll_interval: float = 0.5
    ethoscan_log_level: str = "INFO"
    ethoscan_log_format: str = "text"

    @property
    def artifacts_path(self) -> Path:
        path = Path(self.ethoscan_artifacts_dir).resolve()
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def cors_origins(self) -> list[str]:
        """Origens permitidas no CORS (CSV em ETHOSCAN_CORS_ORIGINS)."""
        origins = [item.strip() for item in self.ethoscan_cors_origins.split(",") if item.strip()]
        return origins or ["http://localhost:3000"]

    @property
    def allowlist_targets(self) -> list[str]:
        """Allowlist global (CSV em ETHOSCAN_ALLOWLIST). Vazia = sem restrição extra."""
        return [item.strip() for item in self.ethoscan_allowlist.split(",") if item.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
