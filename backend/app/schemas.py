from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.models import Intensity, JobStatus, Severity


class EngagementCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    scope_targets: list[str] = Field(min_length=1)
    intensity: Intensity = Intensity.safe
    roe_acknowledged: bool = False
    roe_text: str | None = None
    notes: str | None = None
    selected_tools: list[str] = Field(default_factory=list)

    @field_validator("scope_targets")
    @classmethod
    def clean_targets(cls, value: list[str]) -> list[str]:
        cleaned = [t.strip() for t in value if t and t.strip()]
        if not cleaned:
            raise ValueError("Informe ao menos um alvo no escopo")
        return cleaned

    @field_validator("selected_tools")
    @classmethod
    def clean_tools(cls, value: list[str]) -> list[str]:
        return [t.strip().lower() for t in (value or []) if t and t.strip()]


class EngagementOut(BaseModel):
    id: int
    name: str
    scope_targets: list[str]
    intensity: Intensity
    roe_acknowledged: bool
    roe_text: str | None
    notes: str | None
    selected_tools: list[str] = Field(default_factory=list)
    created_at: datetime

    model_config = {"from_attributes": True}

    @field_validator("selected_tools", mode="before")
    @classmethod
    def coerce_selected(cls, value: list[str] | None) -> list[str]:
        return list(value or [])


class JobStartRequest(BaseModel):
    """Body opcional ao iniciar job — sobrescreve selected_tools do engagement."""

    selected_tools: list[str] | None = None

    @field_validator("selected_tools")
    @classmethod
    def clean_tools(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        return [t.strip().lower() for t in value if t and t.strip()]


class JobOut(BaseModel):
    id: int
    engagement_id: int
    status: JobStatus
    phase: str
    current_tool: str | None
    progress: int
    error: str | None
    report_path: str | None
    report_pdf_path: str | None = None
    selected_tools: list[str] = Field(default_factory=list)
    tool_runs: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None

    model_config = {"from_attributes": True}

    @field_validator("selected_tools", mode="before")
    @classmethod
    def coerce_selected(cls, value: list[str] | None) -> list[str]:
        return list(value or [])


class FindingOut(BaseModel):
    id: int
    engagement_id: int
    job_id: int | None
    title: str
    severity: Severity
    target: str
    tool: str
    category: str
    description: str
    evidence: str | None
    cve: str | None
    cwe: str | None
    remediation: str | None
    fingerprint: str
    mocked: bool = False
    created_at: datetime

    model_config = {"from_attributes": True}


class JobStartResponse(BaseModel):
    job: JobOut
    message: str


class HistoryItemOut(BaseModel):
    """Resumo de jobs passados para a área Histórico (Desktop/API)."""

    job_id: int
    engagement_id: int
    engagement_name: str
    status: JobStatus
    phase: str
    progress: int
    intensity: Intensity
    selected_tools: list[str] = Field(default_factory=list)
    findings_count: int = 0
    has_html_report: bool = False
    has_pdf_report: bool = False
    error: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None

    @field_validator("selected_tools", mode="before")
    @classmethod
    def coerce_selected(cls, value: list[str] | None) -> list[str]:
        return list(value or [])


class AuditEventOut(BaseModel):
    """Evento da trilha de auditoria (GET /api/audit)."""

    id: int
    engagement_id: int | None = None
    actor: str
    action: str
    detail: dict[str, Any]
    created_at: datetime

    model_config = {"from_attributes": True}


class IntegrationScanRequest(BaseModel):
    """Entrada da API de integração (`POST /api/integrations/n8n/scan`)."""

    name: str = Field(min_length=2, max_length=200)
    targets: list[str] = Field(min_length=1)
    intensity: Intensity = Intensity.safe
    roe_acknowledged: bool = False
    selected_tools: list[str] | None = None
    # Referência do sistema chamador (rastreabilidade no nome/notes do engagement)
    external_ref: str | None = Field(default=None, max_length=120)
    # Webhook opcional chamado quando o job termina (http/https)
    callback_url: str | None = Field(default=None, max_length=500)

    @field_validator("targets")
    @classmethod
    def clean_targets(cls, value: list[str]) -> list[str]:
        cleaned = [t.strip() for t in value if t and t.strip()]
        if not cleaned:
            raise ValueError("Informe ao menos um alvo em targets")
        return cleaned


class IntegrationScanResponse(BaseModel):
    engagement_id: int
    job_id: int
    status: JobStatus
    phase: str
    callback_registered: bool = False
    status_url: str
    findings_url: str
    report_html_url: str
    report_pdf_url: str
    audit_url: str
    message: str


class IntegrationJobStatus(BaseModel):
    """Status compacto para polling de automação."""

    job_id: int
    engagement_id: int
    status: JobStatus
    phase: str
    progress: int
    current_tool: str | None = None
    error: str | None = None
    selected_tools: list[str] = Field(default_factory=list)
    findings_count: int = 0
    has_report: bool = False
    has_report_pdf: bool = False
    callback_registered: bool = False
    poll_after_seconds: int = 0
    status_url: str
    findings_url: str
    report_html_url: str
    report_pdf_url: str
    audit_url: str
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None


class IntegrationManifest(BaseModel):
    """Contrato autodescritivo para o lado da automação (n8n)."""

    name: str
    version: str
    auth_header: str
    auth_hint: str
    endpoints: dict[str, str]
    terminal_statuses: list[str]
    example_scan_body: dict[str, Any]
    example_callback_payload: dict[str, Any]
    notes: list[str]


class HealthOut(BaseModel):
    status: str
    mode: str
    mock_allowed: bool
    auth_enabled: bool
    local_login_available: bool = False
    redis_ok: bool
    worker_hint: str
    tools: dict[str, Any]
    phases: dict[str, str]


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class LoginResponse(BaseModel):
    token: str
    token_type: str = "api_key"
    username: str
    expires_at: datetime
    message: str = "Sessão criada. Use o token no header X-API-Key."


class LabToolOut(BaseModel):
    name: str
    binary: str
    available: bool


class LabInventoryOut(BaseModel):
    tools: list[LabToolOut]
    phases: dict[str, str]
    pipeline_tools: dict[str, Any]
    note: str = (
        "Inventário por existência no PATH deste processo — não executa scans."
    )


class ToolCatalogEntryOut(BaseModel):
    id: str
    display_name: str
    category: str
    phase: str | None = None
    binary: str
    available: bool
    runnable: bool
    launchable: bool = False
    intensity_min: str = "safe"
    description: str
    default_args_hint: str = ""
    ethics_note: str | None = None
    will_mock: bool = False
    mode: str = "unavailable"
    role: str = "inventário"
    status: str


class ToolCatalogOut(BaseModel):
    tools: list[ToolCatalogEntryOut]
    default_pipeline: list[str]
    note: str = (
        "Catálogo completo: instalado ≠ executável. "
        "Executável = adapter no pipeline (RoE + allowlist). "
        "Só GUI = lançamento manual. Inventário = PATH apenas (RF/SET/utils). "
        "Vazio = pipeline clássico F1–F4. Sem exploits Metasploit nem RF automatizado."
    )


class LaunchToolResponse(BaseModel):
    tool: str
    launched: bool
    binary: str | None = None
    message: str
