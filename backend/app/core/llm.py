"""Cliente LLM consultivo do Ethoscan (API OpenAI-compatível via env).

Papel: analista assistente (aikido) — triagem de achados, correlação e
chat sobre o job. **Advisory-only por design**: o modelo analisa e sugere,
nunca executa scans nem recebe credenciais.

Dados enviados ao provedor (data minimization):
- metadados do job (estado, intensidade, tools, resumo de tool_runs);
- findings: título, severidade, tool, alvo, descrição e evidência TRUNCADAS.
Artefactos brutos (pcaps, outputs completos) e segredos não saem do host.

Configuração (.env):
    ETHOSCAN_LLM_BASE_URL=http://host.docker.internal:11434/v1   # Ollama
    ETHOSCAN_LLM_MODEL=llama3.1:8b
    ETHOSCAN_LLM_API_KEY=              # vazio para Ollama/LM Studio local

Qualquer endpoint OpenAI-compatível serve: OpenAI, Groq, Together,
vLLM, LiteLLM, Neon AI Gateway...
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from app.config import get_settings

# Papel do assistente — fixo, não controlável pelo usuário final via prompt.
SYSTEM_PROMPT = """Você é o analista assistente do Ethoscan, uma plataforma de pentest ÉTICO.
Suas funções: (1) triar findings como real / false_positive / inconclusive / informational,
(2) correlacionar achados em cadeias de ataque plausíveis, (3) sugerir próximos passos
de teste MANUAL. Regras absolutas:
- Você NUNCA executa, dispara ou orquestra scans; apenas recomenda com justificativa.
- Os alvos estão autorizados por RoE (Rules of Engagement) do engagement; não sugira
  ataques fora do escopo informado, engenharia social ou bypass de WAF sem autorização.
- NUNCA sugira bypass/evasão de WAF/CDN (obfuscação de payloads, headers falsos, etc.)
  e não use a expressão "bypass de WAF". Se a cobertura for bloqueada por WAF/Cloudflare,
  o caminho correto é coordenação: liberar o IP do scanner (allowlist), apontar para
  origin/staging com autorização do dono, ou testar com sessão autenticada fornecida
  pelo dono. Chame isso de "acesso autorizado ao origin".
- Achados atrás de CDN/WAF (ex.: Cloudflare challenge) frequentemente medem a EDGE,
  não a aplicação real — sinalize isso na triagem.
- Outputs de scanner têm falsos positivos comuns (assinaturas Nikto, warnings do sqlmap,
  placeholders); seja cético e peça validação manual quando a evidência for fraca.
- Responda em português do Brasil, técnico e direto. Não invente informações que não
  estejam no contexto fornecido."""

_MAX_FINDINGS_IN_CONTEXT = 60
_MAX_DESCRIPTION_CHARS = 400
_MAX_EVIDENCE_CHARS = 300


class LLMNotConfigured(RuntimeError):
    """LLM não configurado — a feature fica desligada até o .env definir endpoint/modelo."""


class LLMRequestError(RuntimeError):
    """Falha de rede/HTTP ao falar com o provedor do LLM."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


def llm_enabled() -> bool:
    settings = get_settings()
    return bool(settings.ethoscan_llm_base_url.strip() and settings.ethoscan_llm_model.strip())


def chat(messages: list[dict[str, str]], *, json_mode: bool = False) -> str:
    """Uma rodada de chat contra o endpoint OpenAI-compatível configurado.

    ``json_mode`` pede JSON estrito (response_format json_object) — provedores
    sem suporte recebem a instrução equivalente no prompt e o parser do nosso
    lado tolera cercas de código.
    """
    settings = get_settings()
    base = settings.ethoscan_llm_base_url.strip().rstrip("/")
    model = settings.ethoscan_llm_model.strip()
    if not base or not model:
        raise LLMNotConfigured(
            "LLM não configurado: defina ETHOSCAN_LLM_BASE_URL e ETHOSCAN_LLM_MODEL no .env"
        )

    payload: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": 0.2,
        "max_tokens": settings.ethoscan_llm_max_tokens,
    }
    if json_mode:
        payload["response_format"] = {"type": "json_object"}

    headers = {"Content-Type": "application/json"}
    api_key = settings.ethoscan_llm_api_key.strip()
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    try:
        with httpx.Client(timeout=settings.ethoscan_llm_timeout_seconds) as http:
            response = http.post(f"{base}/chat/completions", json=payload, headers=headers)
    except httpx.HTTPError as exc:
        raise LLMRequestError(f"Provedor LLM indisponível ({base}): {exc}") from exc

    if response.status_code != 200:
        detail = response.text[:300]
        raise LLMRequestError(
            f"Provedor LLM respondeu HTTP {response.status_code}: {detail}",
            status=response.status_code,
        )
    try:
        content = response.json()["choices"][0]["message"]["content"]
    except (KeyError, IndexError, ValueError) as exc:
        raise LLMRequestError(f"Resposta inesperada do provedor LLM: {response.text[:300]}") from exc
    if not isinstance(content, str) or not content.strip():
        raise LLMRequestError("Provedor LLM devolveu resposta vazia")
    return content


def parse_json_object(text: str) -> dict[str, Any]:
    """Extrai o primeiro objeto JSON de uma resposta (tolera ```json fences```)."""
    cleaned = re.sub(r"```(?:json)?\s*|\s*```", "", text.strip())
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start < 0 or end <= start:
        raise LLMRequestError("Resposta do LLM não contém JSON válido")
    try:
        data = json.loads(cleaned[start : end + 1])
    except json.JSONDecodeError as exc:
        raise LLMRequestError(f"JSON inválido na resposta do LLM: {exc}") from exc
    if not isinstance(data, dict):
        raise LLMRequestError("Resposta do LLM não é um objeto JSON")
    return data


def job_context_payload(engagement: Any, job: Any, findings: list[Any]) -> dict[str, Any]:
    """Contexto compacto do job para o LLM (data minimization)."""
    tool_runs = {}
    for tool, run in (job.tool_runs or {}).items():
        tool_runs[str(tool)] = {
            "ok": bool((run or {}).get("ok")),
            "mocked": bool((run or {}).get("mocked")),
            "error": str((run or {}).get("error") or "")[:200],
        }

    findings_payload = []
    for f in findings[:_MAX_FINDINGS_IN_CONTEXT]:
        findings_payload.append(
            {
                "finding_id": f.id,
                "title": (f.title or "")[:200],
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "target": (f.target or "")[:200],
                "tool": f.tool,
                "mocked": bool(f.mocked),
                "cve": f.cve,
                "cwe": f.cwe,
                "description": (f.description or "")[:_MAX_DESCRIPTION_CHARS],
                "evidence": (f.evidence or "")[:_MAX_EVIDENCE_CHARS],
            }
        )

    return {
        "engagement": {
            "name": engagement.name,
            "scope_targets": engagement.scope_targets,
            "intensity": getattr(engagement.intensity, "value", engagement.intensity),
            "selected_tools": engagement.selected_tools,
        },
        "job": {
            "id": job.id,
            "status": getattr(job.status, "value", job.status),
            "phase": job.phase,
            "error": (job.error or "")[:300],
            "selected_tools": job.selected_tools,
        },
        "tool_runs": tool_runs,
        "findings": findings_payload,
        "findings_omitidos_no_contexto": max(0, len(findings) - _MAX_FINDINGS_IN_CONTEXT),
    }


ANALYSIS_INSTRUCTIONS = """Analise o job e responda APENAS com um objeto JSON (sem texto fora do JSON)
neste formato exato:
{
  "summary": "resumo executivo curto do que o job realmente provou (2-4 frases)",
  "triage": [
    {"finding_id": 123, "verdict": "real|false_positive|inconclusive|informational",
     "confidence": 0.0, "reasoning": "porquê, citando a evidência"}
  ],
  "correlations": ["cadeias de ataque plausíveis ligando 2+ achados, se houver"],
  "next_steps": ["próximos passos de teste MANUAL, priorizados, dentro do escopo/RoE"],
  "limitations": ["limitações de cobertura: WAF/CDN, tools que falharam, alvos que não resolveram"]
}
Regras: triage só para findings de severidade >= low (info/metadados ficam fora ou entram como
"informational"); confidence entre 0.0 e 1.0; não invente findings; next_steps nunca incluem
execução automatizada não autorizada."""

ASSISTANT_INSTRUCTIONS = (
    "Responda à pergunta do usuário sobre o job em anexo. Use apenas o contexto fornecido; "
    "se algo não estiver no contexto, diga isso. Máximo 300 palavras. Advisory-only: se a "
    "ação pedida envolver executar scans, explique o risco e indique como fazer manualmente "
    "via Ethoscan."
)
