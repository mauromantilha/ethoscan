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
    status: str


class ToolCatalogOut(BaseModel):
    tools: list[ToolCatalogEntryOut]
    default_pipeline: list[str]
    note: str = (
        "Selecione tools runnable para o job. Lista vazia = pipeline clássico F1–F4. "
        "Burp Suite: só lançamento GUI; use ZAP para scan automatizado. "
        "Metasploit: apenas auxiliary/scanner. Wireless permanece inventário."
    )


class LaunchToolResponse(BaseModel):
    tool: str
    launched: bool
    binary: str | None = None
    message: str
