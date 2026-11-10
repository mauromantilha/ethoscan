#!/usr/bin/env bash
# Doutor de instalação do Ethoscan: verifica uma instalação do zero e diz
# exatamente o que falta para a ferramenta funcionar.
#
# Uso: ./scripts/check-install.sh
#
# Verifica (nesta ordem):
#   1. Docker + compose        — obrigatório para os scanners
#   2. .env                    — credenciais, Dockerfile e LLM
#   3. Stack (api/worker/redis)
#   4. Tools no container      — sem Dockerfile.kali/.tools, nenhum scan real
#   5. Assistente LLM          — precisa de ETHOSCAN_LLM_* configurado
#   6. Desktop instalado
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

OK="✔"; BAD="✗"; WARN="!"
RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
pass() { echo "${GREEN}${OK}${RESET} $1"; }
fail() { echo "${RED}${BAD}${RESET} $1"; FAILED=1; }
warn() { echo "${YELLOW}${WARN}${RESET} $1"; }
section() { echo; echo "${BOLD}== $1${RESET}"; }
hint()    { echo "    $1"; }

FAILED=0

section "1. Docker (obrigatório para os scanners)"
if ! command -v docker >/dev/null 2>&1; then
  fail "Docker não encontrado."
  hint "Instale: https://docs.docker.com/engine/install/ (ou no Ubuntu: sudo apt install docker.io docker-compose-plugin)"
  hint "Depois libere sem sudo: sudo usermod -aG docker \$USER (reinicie a sessão)."
elif ! docker info >/dev/null 2>&1; then
  warn "Docker instalado, mas sem permissão/daemon — neste shell use sudo:"
  hint "sudo docker compose up -d --build"
else
  pass "Docker respondendo."
fi

section "2. Configuração (.env)"
if [[ ! -f .env ]]; then
  fail ".env não existe."
  hint "cp .env.example .env  && edite credenciais (login local e/ou ETHOSCAN_API_KEY)"
else
  pass ".env presente."
  get_env() { grep -m1 "^$1=" .env 2>/dev/null | cut -d= -f2-; }

  DOCKERFILE=$(get_env ETHOSCAN_DOCKERFILE)
  if [[ -z "$DOCKERFILE" || "$DOCKERFILE" == "Dockerfile" ]]; then
    fail "ETHOSCAN_DOCKERFILE não define uma imagem com scanners."
    hint "A imagem slim padrão NÃO TEM NENHUMA tool — /health mostra tudo indisponível."
    hint "Edite o .env:  ETHOSCAN_DOCKERFILE=Dockerfile.kali   (catálogo completo;"
    hint "      imagem grande, build de 10–30 min — recomendado/primordial)"
    hint "    ou:  ETHOSCAN_DOCKERFILE=Dockerfile.tools   (pipeline clássico, mais leve)"
    hint "Depois:  sudo docker compose up -d --build api worker"
  else
    pass "Imagem com scanners: $DOCKERFILE"
  fi

  if [[ -z "${ETHOSCAN_LLM_MODEL:-}" ]]; then
    LLM_MODEL=$(get_env ETHOSCAN_LLM_MODEL); else LLM_MODEL="${ETHOSCAN_LLM_MODEL}"; fi
  LLM_URL=$(get_env ETHOSCAN_LLM_BASE_URL)
  if [[ -z "$LLM_MODEL" || -z "$LLM_URL" ]]; then
    warn "Assistente LLM desconfigurado (aba Assistente fica inativa)."
    hint "Inclua no .env (qualquer endpoint OpenAI-compatível):"
    hint "  ETHOSCAN_LLM_BASE_URL=https://api.mistral.ai/v1   (ou OpenAI/Groq/OpenRouter/Ollama)"
    hint "  ETHOSCAN_LLM_MODEL=mistral-small-latest"
    hint "  ETHOSCAN_LLM_API_KEY=<sua key>"
    hint "Detalhes: docs/llm-assistant.md"
  else
    pass "Assistente LLM configurado ($LLM_MODEL)."
  fi
fi

section "3. Stack (API + worker + Redis)"
HEALTH=""
if command -v curl >/dev/null 2>&1; then
  HEALTH=$(curl -fsS -m 5 http://127.0.0.1:8000/health 2>/dev/null || true)
fi
if [[ -z "$HEALTH" ]]; then
  fail "API não responde em http://127.0.0.1:8000."
  hint "sudo docker compose up -d --build"
else
  pass "API no ar."
  if command -v python3 >/dev/null 2>&1; then
    read -r REDIS_OK WORKER_OK TOOLS_OK TOOLS_TOTAL LLM_OK <<<"$(printf '%s' "$HEALTH" | python3 -c "
import json, sys
d = json.load(sys.stdin)
tools = d.get('tools', {})
print(int(d.get('redis_ok', False)), int(d.get('worker_ok', False)),
      sum(1 for t in tools.values() if t.get('available')),
      len(tools), int(d.get('llm_enabled', False)))
")"
    if [[ "$REDIS_OK" == "1" ]]; then pass "Redis ok."; else fail "Redis down — a fila de jobs não funciona."; fi
    if [[ "$WORKER_OK" == "1" ]]; then pass "Worker ok."; else fail "Worker sem heartbeat — nenhum job roda."; fi

    section "4. Scanners no container"
    if [[ "$TOOLS_TOTAL" -eq 0 ]]; then
      fail "API não reporta nenhuma tool."
      hint "A imagem atual é a slim — construa com scanners (primordial):"
      hint "  .env: ETHOSCAN_DOCKERFILE=Dockerfile.kali"
      hint "  sudo docker compose up -d --build api worker"
    elif [[ "$TOOLS_OK" -eq 0 ]]; then
      fail "0 de $TOOLS_TOTAL tools disponíveis — a imagem não tem scanners instalados."
      hint "Defina ETHOSCAN_DOCKERFILE=Dockerfile.kali (ou Dockerfile.tools) e rebuild:"
      hint "  sudo docker compose up -d --build api worker"
    else
      pass "$TOOLS_OK de $TOOLS_TOTAL tools disponíveis."
    fi

    section "5. Assistente LLM (aikido)"
    if [[ "$LLM_OK" == "1" ]]; then
      pass "llm_enabled: true — triagem/chat ativos (teste: aba Assistente > Testar API)."
    else
      warn "llm_enabled: false — o assistente responde 503 até configurar ETHOSCAN_LLM_*."
      hint "Inclua BASE_URL/MODEL(/KEY) no .env e:  sudo docker compose up -d --build api worker"
    fi
  fi
fi

section "6. Desktop"
if dpkg -l ethoscan >/dev/null 2>&1; then
  VER=$(dpkg -l ethoscan | awk '/^ii/{print $3}')
  pass "Desktop instalado (v$VER)."
else
  warn "Desktop não instalado (opcional)."
  hint "Baixe o .deb em https://github.com/mauromantilha/ethoscan/releases"
  hint "ou gere localmente: cd desktop && npm run dist:linux"
fi

echo
if [[ "$FAILED" -eq 1 ]]; then
  echo "${RED}Instalação incompleta${RESET} — corrija os itens marcados com ${BAD} acima."
  exit 1
else
  echo "${GREEN}Instalação OK${RESET} — Ethoscan pronto. Abra a app ou acesse http://127.0.0.1:8000."
fi
