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
    ethoscan_api_host: str = "127.0.0.1"
    ethoscan_api_port: int = 8000

    # Auth — ver README "Segurança do próprio Ethoscan"
    ethoscan_api_key: str = ""
    ethoscan_disable_auth: bool = False
    # Utilizador local (desktop/lab) — password apenas como hash bcrypt
    ethoscan_local_username: str = ""
    ethoscan_local_password_hash: str = ""
    # TTL dos tokens de sessão emitidos por POST /api/auth/login (horas)
    ethoscan_session_ttl_hours: int = 12

    # CORS — origem da UI (não usar *)
    ethoscan_cors_origins: str = "http://localhost:3000"

    # Fila Redis
    ethoscan_queue_key: str = "ethoscan:jobs"
    ethoscan_cancel_prefix: str = "ethoscan:cancel:"

    @property
    def artifacts_path(self) -> Path:
        path = Path(self.ethoscan_artifacts_dir).resolve()
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.ethoscan_cors_origins.split(",") if o.strip()]

    @property
    def local_user_configured(self) -> bool:
        return bool(
            self.ethoscan_local_username.strip()
            and self.ethoscan_local_password_hash.strip()
        )

    @property
    def auth_enabled(self) -> bool:
        """Auth obrigatória se houver API key ou utilizador local (salvo DISABLE_AUTH)."""
        if self.ethoscan_disable_auth:
            return False
        return bool(self.ethoscan_api_key.strip()) or self.local_user_configured


@lru_cache
def get_settings() -> Settings:
    return Settings()
