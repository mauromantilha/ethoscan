# Ethoscan

Orquestrador local de **pentest ético** (CLI + API + dashboard).

- Pipeline **F0–F6** (autorização → recon → enum → web → vuln → correlação → relatório)
- Escopo allowlist + RoE obrigatório + audit log
- **API autenticada** (`X-API-Key`, fail-closed) + allowlist global opcional + CORS restrito
- **Worker persistente** no banco: jobs sobrevivem a restart, cancelamento cooperativo e recuperação de jobs órfãos
- Falha de uma tool não derruba o pipeline (`tool_error` explícito no relatório)
- Adapters: Nmap, WhatWeb, Gobuster, sslscan, Nuclei
- No host sem tools Kali: **modo mock** (`ETHOSCAN_ALLOW_MOCK=true`, `ETHOSCAN_FORCE_MOCK` para forçar)
- Deploy na Kali Purple fica para o final (mesmo código)

## Subir local (sem Docker)

Neste host o default é **SQLite** (não precisa Postgres).

```bash
cd ethoscan                # raiz do repositório
cp .env.example .env

# 1) gere a API key (obrigatória: sem ela /api/* responde 503)
KEY=$(openssl rand -hex 32)
sed -i "s|^ETHOSCAN_API_KEY=.*|ETHOSCAN_API_KEY=$KEY|" .env
sed -i "s|^NEXT_PUBLIC_API_KEY=.*|NEXT_PUBLIC_API_KEY=$KEY|" .env

# 2) API
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000

# 3) Dashboard (outro terminal) — o Next lê env do próprio diretório
cd ethoscan/frontend
cp .env.local.example .env.local   # e cole a mesma NEXT_PUBLIC_API_KEY
npm install
npm run dev
```

- API: http://localhost:8000/docs (use **Authorize**/header `X-API-Key`)  
- UI: http://localhost:3000  
- `--reload` ajuda a editar código, mas reinicia a API e interrompe jobs em execução.

> **Banco e diretório de execução:** o caminho do SQLite é relativo ao CWD. Rodando `uvicorn` de
> `backend/`, o banco fica em `backend/ethoscan.db`; rodando da raiz, em `./ethoscan.db` — os dados
> "desaparecem" se você trocar de diretório. Use caminho absoluto em `DATABASE_URL` para fixar.
>
> **Python:** requer 3.12 ou 3.13 (`requires-python = ">=3.12,<3.14"`; os pins atuais não têm wheel
> para 3.14).

### Com Docker (quando tiver permissão no socket)

```bash
# Ajuste DATABASE_URL no .env para Postgres, defina ETHOSCAN_API_KEY e:
docker compose up --build
```

- API e UI ficam publicadas em `127.0.0.1` (não expostas na rede local).
- O serviço `api` roda **sem `--reload`** (reload mataria jobs em execução): depois de mudar código, use `docker compose up --build api`.
- `NEXT_PUBLIC_*` é embutido no bundle no **build**: ao trocar a chave, use `docker compose build web && docker compose up -d web`.
- O serviço `redis` está reservado para um broker externo; o worker atual consome jobs do banco.

Deploy na Kali Purple fica para o final (mesmo código + tools nativas).

## Execução e robustez

| Mecanismo | Como funciona |
|---|---|
| Worker | `app/core/worker.py`: poller no banco (`ETHOSCAN_WORKER_ENABLED`, `ETHOSCAN_WORKER_CONCURRENCY`, `ETHOSCAN_WORKER_POLL_INTERVAL`). Jobs nascem `pending` e são reivindicados com `UPDATE ... WHERE status='pending'` — seguro com vários processos e resistente a restart. |
| Watchdog | No startup, jobs `running` de uma instância anterior viram `failed` com motivo (audit `job_orphaned`) e nunca ficam presos. |
| Cancelamento | `POST /api/jobs/{id}/cancel` marca `cancelled` na hora; o pipeline para no próximo checkpoint (entre fases/tools) e registra `job_cancel_stopped`. Não há SIGKILL de subprocesso em execução. |
| Falha de tool | Exit code é checado; timeout/exceção vira `tool_error` no relatório e o job segue para as próximas fases (`ok`/`exit_code` também ficam no audit). |
| Mock explícito | O relatório ganha banner de aviso quando qualquer tool rodou em modo mock. |

## API

| Endpoint | Descrição |
|---|---|
| `GET /health` | Público: modo, mock forçado, worker e tools disponíveis. |
| `GET/POST /api/engagements`, `GET /api/engagements/{id}` | Engagements (escopo validado + allowlist global). |
| `POST /api/engagements/{id}/jobs` | Enfileira o pipeline (requer RoE). |
| `GET /api/jobs`, `GET /api/jobs/{id}` | Estado dos jobs. |
| `POST /api/jobs/{id}/cancel` | Cancela job pendente/em execução. |
| `GET /api/jobs/{id}/report` | Relatório HTML (inline; `?download=1` baixa). |
| `GET /api/findings` | Achados paginados (`limit`, `offset`, `severity`, `engagement_id`, `job_id`; total em `X-Total-Count`). |
| `GET /api/audit` | Trilha de auditoria paginada (`engagement_id`, `job_id`, `action`). |

Todos os `/api/*` exigem o header `X-API-Key`.

## Segurança

| Controle | Como funciona |
|---|---|
| `ETHOSCAN_API_KEY` | Todo `/api/*` exige o header `X-API-Key`; **sem chave configurada a API responde 503** (fail-closed). Comparação timing-safe. |
| CORS | Somente as origens de `ETHOSCAN_CORS_ORIGINS` (default `http://localhost:3000`). |
| Bind | Default `ETHOSCAN_API_HOST=127.0.0.1` e portas publicadas só em loopback no Docker. |
| Escopo | `validate_scope` rejeita TLD, nome de label único (exceto `localhost`) e sufixos públicos (`co.uk`, `com.br`, ...); aceita IP/CIDR com contenção. |
| `ETHOSCAN_ALLOWLIST` | Allowlist global (CSV) revalidada na criação do engagement **e** antes de cada execução de tool. Vazia = sem restrição extra. |
| RoE | `roe_acknowledged=true` é obrigatório na criação e reconferido no pipeline (403). |

> A `NEXT_PUBLIC_API_KEY` do dashboard vai no bundle do navegador: aceitável para uso local/single-user. Para multiusuário, troque por autenticação real (Sprint futuro).

## CLI

```bash
cd backend && source .venv/bin/activate
export ETHOSCAN_API_KEY=<mesma chave do .env>

python cli.py health
python cli.py create -n "Lab" -t scanme.nmap.org --ack
python cli.py run 1
python cli.py findings -e 1
python cli.py audit -e 1
python cli.py cancel 3
# ou: python cli.py health --api-key <chave>
```

## Qualidade (testes, lint, tipos, smoke)

```bash
cd backend && source .venv/bin/activate
pip install -r requirements-dev.txt

ruff check .          # lint + imports
mypy                  # tipagem estática (app, cli, scripts, tests)
pytest                # 78 testes (unit + API + E2E mock)
pytest --cov=app      # com cobertura
python scripts/smoke_e2e.py   # smoke E2E offline (47 checks, sem pytest)
```

Os testes e o smoke rodam em **sandbox**: banco/artefatos temporários, mock forçado e allowlist
própria — nunca tocam o banco do ambiente. O mesmo conjunto roda na CI
(`.github/workflows/ci.yml`) junto com `tsc`, `next build` e `npm audit`.

## Banco de dados e migrações (Alembic)

O app cria o schema com `create_all` no startup (dev) e o Alembic versiona a evolução:

```bash
cd backend
alembic upgrade head                        # cria o schema (ou reconcilia banco já existente)
alembic stamp head                          # alternativa manual em banco criado por create_all
alembic revision --autogenerate -m "descrição"   # nova migração a partir dos models
alembic upgrade head --sql                  # revisar o SQL sem executar
```

A baseline (`migrations/versions/*_baseline.py`) é **reconciliável**: se o banco já tiver o schema
(criado pelo `create_all` das versões anteriores), ela não recria nada e apenas marca a revisão —
`alembic upgrade head` funciona tanto em banco novo quanto em banco existente. O `autogenerate`
não acusa drift em nenhum dos casos. Em SQLite o env usa `render_as_batch` para permitir `ALTER TABLE`.

## Logs

`ETHOSCAN_LOG_LEVEL` (default `INFO`) e `ETHOSCAN_LOG_FORMAT`:

```bash
ETHOSCAN_LOG_FORMAT=json ETHOSCAN_LOG_LEVEL=DEBUG uvicorn app.main:app
# {"ts": "...", "level": "INFO", "logger": "app.core.worker", "message": "job reivindicado", "job_id": 3}
```

Eventos logados: job reivindicado/concluído/falhou/cancelado, fase iniciada (DEBUG), timeout/falha
de tool (WARNING) e jobs órfãos recuperados no startup (WARNING).

## Notas éticas

Use **somente** em alvos autorizados. O modo padrão é descoberta/detecção; mock não gera tráfego real de scan.
