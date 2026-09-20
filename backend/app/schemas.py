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

    @field_validator("scope_targets")
    @classmethod
    def clean_targets(cls, value: list[str]) -> list[str]:
        cleaned = [t.strip() for t in value if t and t.strip()]
        if not cleaned:
            raise ValueError("Informe ao menos um alvo no escopo")
        return cleaned


class EngagementOut(BaseModel):
    id: int
    name: str
    scope_targets: list[str]
    intensity: Intensity
    roe_acknowledged: bool
    roe_text: str | None
    notes: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class JobOut(BaseModel):
    id: int
    engagement_id: int
    status: JobStatus
    phase: str
    current_tool: str | None
    progress: int
    error: str | None
    report_path: str | None
    tool_runs: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None

    model_config = {"from_attributes": True}


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
