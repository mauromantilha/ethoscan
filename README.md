# Ethoscan

Orquestrador local de **pentest ético** (CLI + API + dashboard + desktop + worker).

> Versão **0.5.2** — mudanças/migração em [CHANGELOG.md](CHANGELOG.md); publicação em
> [docs/release-checklist.md](docs/release-checklist.md).

- Pipeline **F0–F6** (gate RoE/escopo/tools → recon → enum → web → vuln → correlação → relatório)
- Escopo allowlist + RoE obrigatório + audit log
- Catálogo de tools pré-configuradas (selecionáveis); adapters: Nmap, WhatWeb, Gobuster, sslscan, Nuclei, Nikto, Masscan, ZAP; Metasploit **só aux/scanner**; Burp **só lançamento GUI**
- **Assistente LLM** (aikido): tria findings (real/falso positivo), correlaciona achados e
  conversa sobre o job — advisory-only, qualquer API OpenAI-compatível ([docs/llm-assistant.md](docs/llm-assistant.md))
- **Descoberta passiva de IP de origem**: antes/durante cada job contra domínios atrás
  de CDN — subdomínios comuns, MX e Certificate Transparency; candidatos listados no
  relatório para validação manual no RoE
- Relatório HTML + **PDF** imprimível (`GET /api/jobs/{id}/report.pdf`)
- Worker dedicado via **Redis** (a API não bloqueia em scans longos)
- Shell **Electron** opcional (`desktop/`) para Kali/Windows — client fino da API
- Intensidade padrão recomendada: **`safe`**
- Auth por API key + login local com 2FA TOTP + CORS restrito à UI web

## Instalação do zero (5 passos)

```bash
# 1. Clone
git clone https://github.com/mauromantilha/ethoscan && cd ethoscan

# 2. Configure (credenciais, imagem Docker e LLM)
cp .env.example .env && nano .env

# 3. Docker + Docker Compose são OBRIGATÓRIOS: os scanners rodam em container.
#    No .env, escolha a imagem com as ferramentas — SEM isso, nenhum scan real roda:
#      ETHOSCAN_DOCKERFILE=Dockerfile.kali   <- RECOMENDADO: catálogo completo
#         (Metasploit, ZAP, NetExec, Nuclei...; imagem grande, build 10–30 min)
#      ETHOSCAN_DOCKERFILE=Dockerfile.tools  <- pipeline clássico, mais leve
sudo docker compose up -d --build api worker

# 4. Assistente LLM: inclua no .env um endpoint OpenAI-compatível
#      ETHOSCAN_LLM_BASE_URL=https://api.mistral.ai/v1   (ou OpenAI/Groq/OpenRouter/Ollama)
#      ETHOSCAN_LLM_MODEL=mistral-small-latest
#      ETHOSCAN_LLM_API_KEY=<sua key>
#    Sem isso a aba Assistente fica inativa (o resto funciona).

# 5. Verifique a instalação (diz exatamente o que falta, se faltar algo):
./scripts/check-install.sh
```

Desktop Electron: baixe o `.deb` em
[Releases](https://github.com/mauromantilha/ethoscan/releases) e instale com
`sudo apt install ./ethoscan_<versão>_amd64.deb`. A API precisa estar no ar
(`docker compose up -d`) antes de abrir o app.

> Perdido no fluxo de chamadas (API → Redis → worker → orchestrator → adapters)? Ver
> [docs/architecture.md](docs/architecture.md) — diagramas de sequência e mapa de arquivos por camada.
>
> Retomando o projeto (agente ou humano)? Ver **[docs/handoff.md](docs/handoff.md)** — memória de estado
> (o que está mergeado, decisões, armadilhas e pendências) e
> [docs/remote-access.md](docs/remote-access.md) — deploy fora do localhost e integração com n8n.

## Ambientes de execução

### 1. Host Kali Linux (caminho oficial para scans reais)

Ver checklist completo em [docs/kali-setup.md](docs/kali-setup.md).

Binários mínimos (pipeline clássico): `nmap`, `whatweb`, `gobuster`, `sslscan`, `nuclei` (+ wordlist para Gobuster).

Opcionais (selecionáveis no catálogo): `nikto`, `masscan`, `unicornscan`, `zap`, `sqlmap`,
`hydra` (standard+), `john` (hashes offline), `netexec`/`nxc`, `bloodhound-python` (standard+),
`msfconsole` (apenas auxiliary/scanner). GUI: `burpsuite`, `wireshark`, `fern-wifi-cracker`.
Inventário (visível, sem job): RF (`wifite`, `kismet`, `aircrack-ng`), `bettercap`, `arpwatch`,
`setoolkit`, `tcpdump`, `netcat`.

```bash
ETHOSCAN_ALLOW_MOCK=false
```

- Tool no PATH → scan **real** (`mocked=false`)
- Tool em falta + mock off → **falha** no gate F0 (apenas para as tools **selecionadas**)
- Tool em falta + `ETHOSCAN_ALLOW_MOCK=true` → **mock** (`mocked=true` em findings/jobs)
- `selected_tools` omitido/`null` → pipeline clássico F1–F4; lista vazia explícita,
  tool GUI/inventário ou tool incompatível com a intensidade → **400** (sem fallback silencioso)

### Ética / limites

- Sem scans sem RoE + escopo allowlist (gate F0).
- Metasploit: **nunca** auto-executa exploits/payloads; só resource scripts `auxiliary/scanner`.
- Burp Community: GUI — use **OWASP ZAP** no pipeline para relatório automatizado.
- Wireless (wifite, etc.): inventário PATH apenas.

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
UI / CLI / Desktop  →  API (FastAPI)  →  Redis queue  →  Worker (python -m app.worker)
                                          ↑ cancel flags
```

- A API **enfileira** jobs; o **worker** executa o pipeline fora do processo HTTP
- Cancelamento: `POST /api/jobs/{id}/cancel` (CLI/UI) — o status no **DB** é a fonte de verdade;
  running observa o status/flag entre fases/tools (Redis é best-effort)
- Worker usa lista de processamento + **ack**: job não fica perdido se o worker cair; no restart,
  jobs órfãos do mesmo `ETHOSCAN_WORKER_ID` voltam à fila. `/health` expõe `worker_ok` (heartbeat)
- Limite single-node: 1 worker ≈ 1 job de cada vez; a API permanece responsiva.
  Para múltiplos workers, cada réplica precisa de um `ETHOSCAN_WORKER_ID` único.

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

# Desktop Electron (opcional; outro terminal — requer API + worker + Redis já a correr)
cd desktop && npm install && npm start
```

- API: http://localhost:8000/docs  
- UI: http://localhost:3000  
- Health (público): http://localhost:8000/health  
- Desktop: app nativa que fala com a mesma API (`127.0.0.1:8000` por omissão)

### Desktop Electron (MVP)

Shell local mínimo (Kali/Windows) para configurar a API, ver `/health`, escolher tools do catálogo, criar engagement (RoE obrigatório), arrancar/cancelar jobs F0–F6, listar achados e descarregar HTML/PDF. **Não** substitui o scanner — só chama a API existente (RoE/allowlist/auth intactos).

Pré-requisitos: API + Redis + worker já a correr (ver passos acima). Uso ético apenas; preferir bind localhost.

```bash
cd desktop
npm install
npm start
```

Na UI desktop: ecrã de **login** (utilizador + palavra-passe + URL base, default `http://127.0.0.1:8000`) quando o login local ou a API key estiverem configurados. Alternativa avançada: `X-API-Key`. As chamadas saem do processo principal do Electron (sem alterar CORS da API). A API tem de estar a correr antes de abrir o desktop.

#### Empacotar / releases

Instaladores via [electron-builder](https://www.electron.build/) (`AppImage` + `.deb` no Linux; portable + NSIS no Windows):

```bash
cd desktop
npm install
npm run dist:linux   # → desktop/release/*.AppImage, *.deb
npm run dist:win     # → desktop/release/*.exe (preferir Windows / CI)
```

**GitHub Release:** push de uma tag `v*` (ex. `v0.4.0`) dispara [`.github/workflows/desktop-release.yml`](.github/workflows/desktop-release.yml), que constrói Linux + Windows, valida o `.deb` em Debian 12 e Ubuntu 24.04, gera `SHA256SUMS.txt` e anexa os artefactos ao release. A app empacotada (NSIS / AppImage) verifica atualizações nos Releases via electron-updater — ver [desktop/README.md](desktop/README.md).

**Debian/Ubuntu:** instale com `sudo apt install ./ethoscan_<versão>_amd64.deb` (não use `dpkg -i`) ou `./scripts/install-deb.sh`. Guia completo, atualização e repositório APT em [docs/desktop-linux.md](docs/desktop-linux.md). Se instalou a 0.3.0 e a app não abre, veja o troubleshooting de `chrome-sandbox` nesse guia.

Repositório APT assinado (GitHub Pages): `https://mauromantilha.github.io/ethoscan` — instalação com `apt install ethoscan` e upgrades com `apt upgrade`.
### Com Docker

```bash
cp .env.example .env      # defina ETHOSCAN_API_KEY forte e/ou ETHOSCAN_LOCAL_* (login local)
docker compose up -d --build
# sobe postgres + redis (dedicado) + api + worker + web
```

**Tools dentro do Docker (opcional):** a imagem padrão (`python:3.12-slim`) **não** traz
scanners — por isso `/health` mostra tudo `indisponível`. Há duas variantes:

```bash
# .env — pipeline clássico + opcionais Debian (imagem menor)
ETHOSCAN_DOCKERFILE=Dockerfile.tools

# .env — catálogo completo em Kali rolling (imagem grande, build demorado)
ETHOSCAN_DOCKERFILE=Dockerfile.kali

# depois, em qualquer dos casos:
docker compose up -d --build api worker
```

- `Dockerfile.tools` (Debian trixie): `nmap`, `whatweb`, `gobuster`, `sslscan`, `nuclei`,
  `nikto` (`non-free`), `masscan`, `sqlmap`, `hydra`, `john` + wordlist do Gobuster.
- `Dockerfile.kali` (Kali rolling): o catálogo completo, incluindo **Metasploit, ZAP,
  NetExec, BloodHound.py e unicornscan**, mais as ferramentas de **inventário**
  (`tcpdump`, `netcat`, `aircrack-ng`, `kismet`, `wifite`, `bettercap`, `arpwatch`, SET).
  Usa Python 3.13 no venv do backend. As de inventário continuam **não executáveis em
  jobs** (RF/SET/MITM são manuais e exigem hardware/interface próprios).

Sem tools, `ETHOSCAN_ALLOW_MOCK=true` permite testar o fluxo (findings marcados como mock).
Se o Nuclei não tiver templates: `docker compose exec worker nuclei -update-templates`.
O caminho oficial para scans reais continua a ser um host/VM Kali
([docs/kali-setup.md](docs/kali-setup.md)).

O compose base é **lab local** (`ETHOSCAN_MODE=local`) e o mock é **opt-in**
(`ETHOSCAN_ALLOW_MOCK=false` por default). Para expor fora do host, use o override
remoto, que define `ETHOSCAN_MODE=remote`, exige `ETHOSCAN_API_KEY` e desliga mock:

```bash
cp deploy/Caddyfile.example deploy/Caddyfile   # ajuste domínio/e-mail
docker compose -f docker-compose.yml -f docker-compose.remote.yml up -d --build
```

Exposição de cada serviço (configurável no `.env`):

| Serviço | Porta no host | Observação |
|---|---|---|
| `api` | `${API_BIND}:${API_PORT}` — default `127.0.0.1:8000` | `API_BIND=0.0.0.0` publica na rede local (auth continua obrigatória) |
| `web` | `${WEB_BIND}:${WEB_PORT}` — default `127.0.0.1:3000` | a UI embute `NEXT_PUBLIC_API_KEY` no bundle JS: exponha só se aceitar esse risco |
| `worker` | nenhuma | consome a fila e executa o pipeline |
| `redis` | **nenhuma** | Redis **dedicado** do Ethoscan (`ethoscan_redis`, com AOF) na rede interna do compose |
| `postgres` | `127.0.0.1:${POSTGRES_PORT:-15432}` | loopback + porta alternativa para não colidir com outros stacks |

- **Desktop em outra máquina:** no login, troque "URL base da API" para `http://<IP-do-host>:8000`
  (ex.: `http://192.168.0.7:8000`) e entre com o utilizador local (`mauromantilha` + senha + 2FA) — não precisa da master key.
  O desktop fala com a API pelo processo principal (Node), então **CORS não se aplica**.
- **UI web na rede:** `WEB_BIND=0.0.0.0` no `.env` + `docker compose build web`
  (os `NEXT_PUBLIC_*` são embutidos no bundle **no build**; se o navegador acessar por IP, ajuste
  `NEXT_PUBLIC_API_URL` para esse IP e inclua a origem em `ETHOSCAN_CORS_ORIGINS`).
- **Dados:** Postgres no volume `ethoscan_pg`; relatórios HTML/PDF em `./artifacts/` no host.
- **Hardening Docker:** `api` corre non-root (UID 1000); `worker` corre root com apenas
  `NET_RAW`/`NET_ADMIN`/`DAC_OVERRIDE`; `artifacts-init` ajusta o dono de `./artifacts` e
  `no-new-privileges` está ativo.
- **Mudou código?** `docker compose up -d --build api worker` (sem `--reload`: reload mataria jobs em execução).
- **Logs:** `docker compose logs -f api worker` (`ETHOSCAN_LOG_FORMAT=json` no `.env` para logs estruturados).
- **Parar:** `docker compose down` (use `down -v` para apagar também os volumes/dados).

## CLI

```bash
cd backend && source .venv/bin/activate
export ETHOSCAN_API_KEY="<a-mesma-key-forte-da-API>"   # se auth ativa

python cli.py health
python cli.py create -n "Lab" -t scanme.nmap.org --ack
python cli.py run 1
python cli.py findings -e 1
python cli.py report 1 --out report.html
python cli.py cancel 1
```

## Relatórios

- Path em disco: `job.report_path` (HTML) e `job.report_pdf_path` (PDF)
- Download HTML: `GET /api/jobs/{id}/report`
- Download PDF: `GET /api/jobs/{id}/report.pdf` (`application/pdf`, imprimível)
- Relatórios mostram o status final (`completed`), a coluna **Modo** (`real`/`MOCK`) e um
  aviso quando há achados mock. Reexecuções mantêm os findings visíveis em cada job
  (associação `job_findings`), sem duplicar no engagement.
- Catálogo: `GET /api/tools` — `selected_tools` no create/start (omitir/`null` = pipeline
  clássico; lista vazia, GUI/inventário ou incompatível com a intensidade = 400)

## Tema da UI

A dashboard web e o desktop suportam **light/dark/system**. O web e o desktop aplicam o
tema antes do primeiro paint e persistem a escolha em `localStorage`; o default é seguir
`prefers-color-scheme`. Relatórios HTML/PDF permanecem claros para impressão.

## Auditoria e logs

- `GET /api/audit` — trilha de auditoria paginada, com filtros `engagement_id`, `job_id` e
  `action`; total no header `X-Total-Count`.
- `GET /api/findings` — aceita `limit` (1–500), `offset` e `severity`; total em `X-Total-Count`.
  O filtro `job_id` usa a associação `job_findings` (o campo `job_id` do finding é o
  primeiro job que o encontrou; o mesmo finding pode aparecer em reexecuções).
- `tool_ran` registra `ok`, `exit_code` e `error` de cada execução; falha/timeout de tool vira
  achado `tool_error` no relatório **sem derrubar o job** (as demais fases continuam).
- A auditoria registra `actor` (master-key/service-key/session/user) e `client_ip` nas ações da
  API; `job_queued` só é gravado depois de o job entrar na fila.
- Logs estruturados: `ETHOSCAN_LOG_LEVEL` (default `INFO`) e `ETHOSCAN_LOG_FORMAT=json` gera uma
  linha JSON por evento (`job_id`, `tool`, `exit_code`, `phase`...).

```bash
ETHOSCAN_LOG_FORMAT=json uvicorn app.main:app     # API
ETHOSCAN_LOG_FORMAT=json python -m app.worker     # worker
```

## Migrações

SQLite local continua a funcionar. Alembic cobre evolução de schema (`backend/alembic/`).

```bash
cd backend && alembic upgrade head
```

`init_db()` faz `create_all` + `upgrade head` e **falha explicitamente** se a migração
Alembic falhar: API/worker não sobem com schema desatualizado. Faça backup da DB antes de
aplicar migrações em produção.

## Testes smoke (sem Kali)

```bash
cd backend
pip install -r requirements-dev.txt   # pytest, pytest-cov, ruff, pip-audit
cd ..
./scripts/smoke.sh
# ou: cd backend && ETHOSCAN_DISABLE_AUTH=true pytest -q
# lint: cd backend && ruff check .
```

Cobertura: RoE negado, alvo inválido, create→run (mock)→findings→report HTML/PDF, selected_tools,
catálogo, cancel, auth, falha de tool (`tool_error`) e auditoria/paginação (`/api/audit`).

## Aceitação Kali (manual)

Ver [docs/kali-acceptance.md](docs/kali-acceptance.md).

## Segurança do próprio Ethoscan

**Default seguro**

- Defina `ETHOSCAN_API_KEY` forte (`openssl rand -hex 32`; header `X-API-Key` na API;
  CLI via env; UI via `NEXT_PUBLIC_API_KEY`). Chaves default/fracas (`change-me-local`, etc.)
  são **rejeitadas** fora de `mode=local`.
- `ETHOSCAN_SERVICE_KEYS` (CSV) também **ativa auth**; use uma chave dedicada por integração
  (n8n) e revogue sem trocar a master key.
- Opcional (desktop/lab): `ETHOSCAN_LOCAL_USERNAME` + `ETHOSCAN_LOCAL_PASSWORD_HASH` (bcrypt).
  Login: `POST /api/auth/login` → token de sessão para usar como `X-API-Key` (não devolve a master key).
  Gerar hash: `python3 -c "import bcrypt; print(bcrypt.hashpw(b'YOUR_PASSWORD', bcrypt.gensalt()).decode())"`
- **2FA opcional (TOTP/authenticator app):** `ETHOSCAN_LOCAL_TOTP_SECRET` (base32) +
  `ETHOSCAN_LOCAL_TOTP_ISSUER`; o login passa a exigir `totp_code` de 6 dígitos.
  Gerar segredo: `python3 -c "import pyotp; print(pyotp.random_base32())"`.
  O `/health` expõe `local_login_2fa` e o desktop mostra o campo **Código 2FA**.
  Sem códigos de recuperação: para repor, remova/altere `ETHOSCAN_LOCAL_TOTP_SECRET`
  no `.env` e reinicie a API.
- CORS apenas para `ETHOSCAN_CORS_ORIGINS` (default `http://localhost:3000`) — **não** usa `*`
- Bind diário: `127.0.0.1`
- Mock default **desligado** (`ETHOSCAN_ALLOW_MOCK=false`); ative apenas em dev/lab.
- `ETHOSCAN_ALLOWLIST` (CSV de hosts/IPs/CIDRs): restringe **globalmente** o que pode ser escaneado
  (revalidado na criação e na execução); vazio = sem restrição extra. O escopo recusa TLD/single-label
  (`com`, `io`) e sufixos públicos (`co.uk`, `com.br`).
- Sessões do login local ficam no **Redis** (sobrevivem a restart da API); sem Redis há fallback em
  memória do processo. `ETHOSCAN_SESSION_EPOCH` invalida todas as sessões ao ser incrementado.
- Login local tem rate limit por IP (`ETHOSCAN_LOGIN_MAX_ATTEMPTS`/`..._WINDOW_SECONDS`) e
  auditoria de sucesso/falha; username inválido também executa bcrypt (timing).
- Webhooks de conclusão são revalidados contra SSRF (DNS + IP público) e assinados com HMAC
  quando `ETHOSCAN_CALLBACK_SECRET` está definido (`X-Ethoscan-Signature` + timestamp).
- Subprocessos recebem ambiente mínimo (sem `ETHOSCAN_API_KEY`/DB URL); credenciais em argv do
  BloodHound ficam desativadas por default (`ETHOSCAN_ALLOW_CREDS_IN_ARGV=false`).

**Lab local sem auth**

```bash
ETHOSCAN_DISABLE_AUTH=true
```

Só é aceitável em lab isolado. Sem key, service keys ou utilizador local e sem
`DISABLE_AUTH` em `mode=local`, a API arranca mas regista aviso. Fora de `local`
(`remote`/`production`), falta de auth **impede o arranque** e `ETHOSCAN_DISABLE_AUTH=true`
é rejeitado.

**Smoke desktop (login local)**

1. Defina `ETHOSCAN_LOCAL_USERNAME` e `ETHOSCAN_LOCAL_PASSWORD_HASH` (hash bcrypt; ver `.env.example`)
2. Opcional: `ETHOSCAN_LOCAL_TOTP_SECRET` (authenticator app) e `ETHOSCAN_LOCAL_TOTP_ISSUER`
3. `ETHOSCAN_DISABLE_AUTH=false` (e opcionalmente uma `ETHOSCAN_API_KEY` para CLI)
4. Suba Redis + API + worker
5. `cd desktop && npm start` → entre com utilizador/palavra-passe (e código 2FA, se ativo)
6. Confirme pipeline tools, inventário Kali (`/api/lab/tools`) e fases F0–F6; crie um engagement com RoE

**Checklist — não publicar casualmente na LAN**

- [ ] Porta **8000** (API)
- [ ] Porta **3000** (dashboard web)
- [ ] App desktop Electron (só cliente local; ainda depende da API em 8000)
- [ ] Porta **5432** (Postgres do compose)
- [ ] Porta **6379** (Redis)

No compose, Postgres usa credenciais de exemplo `ethoscan`/`ethoscan` — só lab local.

## Ética e responsabilidade

- Use **somente** em alvos autorizados, projetos próprios ou labs com permissão explícita
- A responsabilidade pelo escopo, RoE e impacto é do **operador**
- Controles éticos (RoE + allowlist) não são enfraquecidos por estas alterações

## O que nunca commitar

- [ ] `.env`
- [ ] `artifacts/`
- [ ] Relatórios reais / credenciais / evidências de alvos
- [ ] Ficheiros `*:Zone.Identifier`
