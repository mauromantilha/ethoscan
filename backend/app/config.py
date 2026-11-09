import socket
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[2]
BACKEND = Path(__file__).resolve().parents[1]

# Placeholders conhecidos — rejeitados fora de mode=local e avisados em local.
WEAK_API_KEYS = frozenset(
    {
        "change-me-local",
        "change-me",
        "changeme",
        "your-api-key",
        "secret",
        "password",
    }
)


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
    # Fail-closed: sem tools reais o job falha; mock é opt-in explícito (dev/lab).
    ethoscan_allow_mock: bool = False
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
    # Incrementar invalida todas as sessões emitidas (Redis e fallback memória).
    ethoscan_session_epoch: int = 1
    # Rate limit de login por IP (memória do processo; Caddy pode reforçar).
    ethoscan_login_max_attempts: int = 5
    ethoscan_login_window_seconds: int = 60
    # Credenciais em argv ficam visíveis em `ps`; BloodHound só corre se habilitado.
    ethoscan_allow_creds_in_argv: bool = False

    # CORS — origem da UI (não usar *)
    ethoscan_cors_origins: str = "http://localhost:3000"

    # Fila Redis
    ethoscan_queue_key: str = "ethoscan:jobs"
    # Lista de processamento por worker (ack/requeue após crash).
    ethoscan_processing_prefix: str = "ethoscan:processing:"
    # ID estável do worker para recuperar jobs órfãos. Vazio = hostname.
    ethoscan_worker_id: str = ""
    ethoscan_worker_heartbeat_key: str = "ethoscan:worker:heartbeat"
    ethoscan_worker_heartbeat_ttl_seconds: int = 30
    ethoscan_cancel_prefix: str = "ethoscan:cancel:"
    # Segredo para assinar webhooks (HMAC-SHA256). Vazio = sem assinatura.
    ethoscan_callback_secret: str = ""
    ethoscan_callback_prefix: str = "ethoscan:callback:"
    # Sessões de login (login local). No Redis elas sobrevivem a restart da API;
    # sem Redis há fallback em memória do processo.
    ethoscan_session_prefix: str = "ethoscan:session:"
    # Chaves de serviço extras (CSV) — ex.: uma dedicada por integração (n8n),
    # revogável sem trocar a master key nem o login local.
    ethoscan_service_keys: str = ""

    # Logs — ETHOSCAN_LOG_FORMAT=json para logs estruturados (app/logging_conf.py)
    ethoscan_log_level: str = "INFO"
    ethoscan_log_format: str = "text"

    # Allowlist global de alvos (CSV) — vazio = sem restrição adicional além do escopo
    # do engagement. Ex.: ETHOSCAN_ALLOWLIST=lab.exemplo.com,10.10.0.0/24
    ethoscan_allowlist: str = ""

    @property
    def artifacts_path(self) -> Path:
        path = Path(self.ethoscan_artifacts_dir).resolve()
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.ethoscan_cors_origins.split(",") if o.strip()]

    @property
    def allowlist_targets(self) -> list[str]:
        """Allowlist global (CSV em ETHOSCAN_ALLOWLIST). Vazia = sem restrição extra."""
        return [item.strip() for item in self.ethoscan_allowlist.split(",") if item.strip()]

    @property
    def local_user_configured(self) -> bool:
        return bool(
            self.ethoscan_local_username.strip()
            and self.ethoscan_local_password_hash.strip()
        )

    @property
    def service_keys(self) -> list[str]:
        """Chaves de serviço (CSV), sem entradas vazias."""
        return [key.strip() for key in self.ethoscan_service_keys.split(",") if key.strip()]

    @property
    def worker_id(self) -> str:
        return self.ethoscan_worker_id.strip() or socket.gethostname()

    @property
    def processing_key(self) -> str:
        return f"{self.ethoscan_processing_prefix}{self.worker_id}"

    @property
    def weak_credentials(self) -> list[str]:
        """Credenciais default/fracas configuradas (master key e service keys)."""
        candidates = [self.ethoscan_api_key.strip(), *self.service_keys]
        return [value for value in candidates if value.lower() in WEAK_API_KEYS]

    @property
    def auth_enabled(self) -> bool:
        """Auth obrigatória se houver API key, service key ou utilizador local.

        ``ETHOSCAN_DISABLE_AUTH=true`` continua a ser o escape explícito para lab.
        """
        if self.ethoscan_disable_auth:
            return False
        return (
            bool(self.ethoscan_api_key.strip())
            or bool(self.service_keys)
            or self.local_user_configured
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
