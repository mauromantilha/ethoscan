# Ethoscan

Orquestrador local de **pentest ético** (CLI + API + dashboard + worker).

- Pipeline **F0–F6** (gate RoE/escopo/tools → recon → enum → web → vuln → correlação → relatório)
- Escopo allowlist + RoE obrigatório + audit log
- Adapters: Nmap, WhatWeb, Gobuster, sslscan, Nuclei
- Worker dedicado via **Redis** (a API não bloqueia em scans longos)
- Intensidade padrão recomendada: **`safe`**
- Auth mínima por API key + CORS restrito à UI

## Ambientes de execução

### 1. Host Kali Linux (caminho oficial para scans reais)

Ver checklist completo em [docs/kali-setup.md](docs/kali-setup.md).

Binários mínimos: `nmap`, `whatweb`, `gobuster`, `sslscan`, `nuclei` (+ wordlist para Gobuster).

```bash
ETHOSCAN_ALLOW_MOCK=false
```

- Tool no PATH → scan **real** (`mocked=false`)
- Tool em falta + mock off → **falha** no gate F0
- Tool em falta + `ETHOSCAN_ALLOW_MOCK=true` → **mock** (`mocked=true` em findings/jobs)

### 2. Dev sem tools / Docker (mock permitido)

```bash
ETHOSCAN_ALLOW_MOCK=true
```

O mock não gera tráfego real de scan; serve para exercitar API, UI, pipeline e relatórios.

### 3. Intensidade (`safe` / `standard` / `aggressive`)

| Modo | Uso |
|------|-----|
| **`safe`** (padrão) | Assessment ético conservador |
| `standard` | Lab próprio, RoE explícito |
| `aggressive` | Apenas lab controlado |

## Arquitetura (API + worker)

```
UI / CLI  →  API (FastAPI)  →  Redis queue  →  Worker (python -m app.worker)
                                ↑ cancel flags
```

- A API **enfileira** jobs; o **worker** executa o pipeline fora do processo HTTP
- Cancelamento: `POST /api/jobs/{id}/cancel` (CLI/UI) — pending cancela já; running observa o flag entre fases/tools
- Limite single-node: 1 worker ≈ 1 job de cada vez; a API permanece responsiva

## F0 — gate explícito

`F0` valida RoE, escopo allowlist e disponibilidade das tools (política de mock) **antes** de F1–F6. Progresso e `tool_runs` ficam visíveis na API/UI.

## Subir local (sem Docker)

```bash
cp .env.example .env
# Lab sem auth: ETHOSCAN_DISABLE_AUTH=true
# Ou defina ETHOSCAN_API_KEY=... e a mesma key em NEXT_PUBLIC_API_KEY / ETHOSCAN_API_KEY (CLI)

# Redis (obrigatório para a fila)
docker run -d --name ethoscan-redis -p 6379:6379 redis:7-alpine

# API
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

# Worker (outro terminal)
cd backend && source .venv/bin/activate
python -m app.worker

# Dashboard (outro terminal)
cd frontend && npm install && npm run dev
```

- API: http://localhost:8000/docs  
- UI: http://localhost:3000  
- Health (público): http://localhost:8000/health  

### Com Docker

```bash
docker compose up --build
# sobe postgres + redis + api + worker + web
```

## CLI

```bash
cd backend && source .venv/bin/activate
export ETHOSCAN_API_KEY=change-me-local   # se auth ativa

python cli.py health
python cli.py create -n "Lab" -t scanme.nmap.org --ack
python cli.py run 1
python cli.py findings -e 1
python cli.py report 1 --out report.html
python cli.py cancel 1
```

## Relatórios

- Path em disco: `job.report_path`
- Download: `GET /api/jobs/{id}/report` (UI botão / CLI `report`)

## Migrações

SQLite local continua a funcionar. Alembic cobre evolução de schema (`backend/alembic/`).

```bash
cd backend && alembic upgrade head
```

`init_db()` faz `create_all` + `upgrade head` (best-effort) e garante colunas novas em SQLite.

## Testes smoke (sem Kali)

```bash
./scripts/smoke.sh
# ou: cd backend && ETHOSCAN_DISABLE_AUTH=true pytest tests/test_smoke.py -q
```

Cobertura: RoE negado, alvo inválido, create→run (mock)→findings→report, cancel, auth.

## Aceitação Kali (manual)

Ver [docs/kali-acceptance.md](docs/kali-acceptance.md).

## Segurança do próprio Ethoscan

**Default seguro**

- Defina `ETHOSCAN_API_KEY` (header `X-API-Key` na API; CLI via env; UI via `NEXT_PUBLIC_API_KEY`)
- CORS apenas para `ETHOSCAN_CORS_ORIGINS` (default `http://localhost:3000`) — **não** usa `*`
- Bind diário: `127.0.0.1`

**Lab local sem auth**

```bash
ETHOSCAN_DISABLE_AUTH=true
```

Só é aceitável em lab isolado. Sem key e sem `DISABLE_AUTH` em `mode=local`, a API arranca mas regista aviso. Fora de `local`, falta de key é erro de configuração.

**Checklist — não publicar casualmente na LAN**

- [ ] Porta **8000** (API)
- [ ] Porta **3000** (dashboard)
- [ ] Porta **5432** (Postgres do compose)
- [ ] Porta **6379** (Redis)

No compose, Postgres usa credenciais de exemplo `ethoscan`/`ethoscan` — só lab local.

## Ética e responsabilidade

- Use **somente** em alvos autorizados, projetos próprios ou labs com permissão explícita
- A responsabilidade pelo escopo, RoE e impacto é do **operador**
- Controles Purple (RoE + allowlist) não são enfraquecidos por estas alterações

## O que nunca commitar

- [ ] `.env`
- [ ] `artifacts/`
- [ ] Relatórios reais / credenciais / evidências de alvos
- [ ] Ficheiros `*:Zone.Identifier`
