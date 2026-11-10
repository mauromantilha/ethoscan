# Handoff — memória de estado do projeto

> Documento operacional para **retomar o trabalho** (agente ou humano) sem reler a conversa toda.
> Atualize ao mudar o estado. **Nunca coloque segredos aqui**: valores vivem no `.env` (gitignored).

## Onde o projeto está (2026-11-10)

- **0.4.0 em preparação** — login local com 2FA TOTP (`ETHOSCAN_LOCAL_TOTP_SECRET`), campo
  **Código 2FA** no desktop; inclui as correções de instalação da 0.3.1
  (`chrome-sandbox` 4755, wrapper do AppImage, updater `.deb` via `apt`).
- `main` = `48f66c6` (release 0.3.0) + working tree 0.4.0.
- **Release 0.3.0 publicado** (tag `v0.3.0`, GitHub Release com AppImage/`.deb`/`.exe`/
  `SHA256SUMS.txt`); teste Debian 12 passou.
- **Repositório APT publicado** em <https://mauromantilha.github.io/ethoscan> (branch
  `gh-pages`, chave GPG `F14D 7665 D743 07E3 33F6 CD65 35C1 D6BE 8BC7 72DD`).
- Suíte: **141 passed** (`cd backend && .venv/bin/pytest -q`; também validado em Python 3.13).
  CI: `.github/workflows/smoke.yml`
  roda ruff, pytest com cobertura mínima de 70%, build do frontend, package do desktop e shellcheck
  em cada PR/push.
- Stack Docker definido no compose: `api` (`:8000`), `worker`, `redis` (rede interna, AOF,
  sem porta no host), `postgres` (loopback `:15432`), `web` (loopback `:3000`). Subir com
  `docker compose up -d --build`; no host deste setup não estava a correr.
- `ETHOSCAN_DOCKERFILE=Dockerfile.tools` inclui nmap/whatweb/gobuster/sslscan/nuclei +
  opcionais Debian no container; `Dockerfile.kali` inclui o catálogo completo (Metasploit,
  ZAP, NetExec, BloodHound.py, unicornscan) e venv Python 3.13. O default `Dockerfile` é
  slim (tools vêm do host Kali).
- Ambiente **limpo**: 0 engagements/jobs; sessões de teste revogadas no Redis.
- `.env`: auth ligada (`ETHOSCAN_DISABLE_AUTH=false`), utilizador local `mauromantilha` com
  hash bcrypt + 2FA TOTP; `API_BIND`/`ETHOSCAN_ALLOWLIST`/`ETHOSCAN_SERVICE_KEYS` conforme o
  host. Segredos **não** versionados (`.env` é gitignored, modo 0600).

## Entregue nos últimos PRs

### #12 — API de integração para n8n + deploy Docker fora do localhost

`/api/integrations/n8n` (`X-API-Key` obrigatório):

| Endpoint | Função |
|---|---|
| `GET /manifest` | contrato autodescritivo (endpoints, auth, exemplos) |
| `POST /scan` | cria engagement **e** enfileira o job em 1 chamada (`targets`, `intensity`, `selected_tools`, `external_ref`, `callback_url`) → `engagement_id`, `job_id`, URLs |
| `GET /jobs/{id}` | status compacto (`status`, `phase`, `progress`, `findings_count`, `has_report`, `callback_registered`, `poll_after_seconds`) |

- **Webhook de conclusão**: worker faz `POST` no `callback_url` em completed/failed/cancelled —
  best-effort, timeout 5s, sem retry; audit `callback_sent`/`callback_failed`.
- **`ETHOSCAN_SERVICE_KEYS`** (CSV): chave dedicada por integração, aceita no `X-API-Key` junto da master
  key e do token de login — revogável sem afetar desktop/web.
- Deploy: `docker-compose.remote.yml` + `deploy/Caddyfile.example` (TLS, rate limit, log JSON, `X-Forwarded-For`
  **sobrescrito** p/ não permitir IP forjado no audit), `backend/.dockerignore` (o `.venv` de 243 MB saiu da imagem).
- Docs: `docs/remote-access.md` (receita nó-a-nó do n8n + 5 caminhos de conectividade: LAN, Tailscale,
  túnel SSH reverso/autossh, Cloudflare Tunnel, Caddy+port-forward).

### #13 — hardening de escopo/allowlist + sessões no Redis

- `validate_scope` agora **recusa TLD/single-label** (`com`, `io`) e sufixos públicos (`co.uk`, `com.br`);
  `localhost` segue liberado para lab.
- **`ETHOSCAN_ALLOWLIST`** (CSV de hosts/IPs/CIDRs): vazio = sem restrição extra; **403** na criação
  (`/api/engagements` e `/api/integrations/n8n/scan`) e **revalidada no gate F0 do worker**.
- Entrada inválida na allowlist → API **não sobe** (fail-fast no lifespan com `Configuração inválida: ...`).
- **Sessões de login no Redis** (`ethoscan:session:`, TTL `ETHOSCAN_SESSION_TTL_HOURS`, default 12h):
  sobrevivem a restart da API; sem Redis há fallback em memória do processo.

## Decisões de design que não são óbvias

- **Auth fail-closed**: `ETHOSCAN_SERVICE_KEYS` também ativa auth. Fora de `mode=local`
  (`remote`/`production`), falta de auth ou chave default (`change-me-local`, etc.) **impede
  o arranque**. Em `local`, auth desligada só gera aviso. Mock default é `false`.
- **Seleção de tools**: omitir/`null` = pipeline clássico; lista vazia explícita, tool
  GUI/inventário ou tool incompatível com a intensidade → **400** (sem fallback silencioso).
- **Dedupe**: `job_findings` (N:N) + `UNIQUE(engagement_id, fingerprint)`. O relatório de
  cada job consulta a associação, então reexecutar um scan não zera o relatório seguinte.
- **Nuclei**: `safe` mantém `high,critical`; a intrusividade é controlada por tags/rate-limit.
- **Allowlist type-aware**: IP só casa com IP/rede; hostname só com hostname/subdomínio;
  rede usa `subnet_of`. URLs com porta/path/query/fragment são rejeitadas no escopo.
- **Cancelamento**: o DB é a fonte de verdade (`job.status=cancelled`); Redis é best-effort.
- **Worker**: lista de processamento por `ETHOSCAN_WORKER_ID`, ack após cada job, heartbeat em
  `/health` (`worker_ok`) e requeue de órfãos no restart. `stop_grace_period` de 10m no compose.
- **`init_db` fail-fast**: migração Alembic falhada impede API/worker de subir.
- **Webhooks**: `external_ref` é idempotente (unique em `engagements`); callback é revalidado
  contra SSRF no envio e assinado com HMAC se `ETHOSCAN_CALLBACK_SECRET` existir.
- **Auth**: rate limit de login por IP, bcrypt dummy para username inválido, auditoria de
  sucesso/falha e `ETHOSCAN_SESSION_EPOCH` para invalidar sessões.
- **Segredos**: Hydra redige password; BloodHound exige `ETHOSCAN_ALLOW_CREDS_IN_ARGV=true`
  (default false); subprocessos usam ambiente mínimo.
- **Docker/desktop**: API non-root, worker root com caps mínimas, `artifacts-init`; token do
  desktop cifrado com `safeStorage` (fallback 0600); updater pode ser desativado com
  `ETHOSCAN_DISABLE_UPDATER=1`.
- **UI**: web e desktop têm tema `system/light/dark` (persistido, sem flash); desktop usa CSP
  estrito sem estilos inline; banner de mock e confirmação antes de scan/cancelamento.
- **Debian**: pacote `ethoscan_<versão>_amd64.deb` (nome Debian `ethoscan`, dependências GTK/NSS/
  ALSA/etc., ícone e desktop entry). Instalação recomendada: `sudo apt install ./ethoscan_*.deb`
  ou `scripts/install-deb.sh`. Release gera `SHA256SUMS.txt` e testa instalação em Debian 12.
- **APT repo**: `.github/workflows/apt-repo.yml` publica `gh-pages` assinado com GPG
  (`APT_GPG_PRIVATE_KEY`/`APT_GPG_PASSPHRASE`), disparado após `desktop-release` ou manual;
  instruções em `docs/desktop-linux.md`.
- **Allowlist precisa existir no `api` E no `worker`** — quem roda o gate F0 é o worker. Depois de editar
  o `.env`: `docker compose up -d api worker`.
- **Master key ≠ token de sessão** para automação: use master key ou `ETHOSCAN_SERVICE_KEYS` (o token de
  login agora persiste no Redis, mas continua sendo credencial de pessoa).
- **`WEB_BIND` fica em loopback**: a UI web embute `NEXT_PUBLIC_API_KEY` no bundle JS.
- `_is_covered` (authz) **descarta entradas inválidas** de escopo/allowlist para que um TLD não amplie
  autorização por casamento de sufixo.
- Worker é **single job por vez** e usa lista de processamento + ack/heartbeat. Para escala,
  cada réplica precisa de um `ETHOSCAN_WORKER_ID` único; o compose usa `worker-1` por default,
  então `--scale worker=3` exige override por réplica.
- A API **não tem rate limit** próprio — usar o proxy (Caddy/Cloudflare).

## Como subir e validar

```bash
cd /home/mksbr/projetos/ethoscan
docker compose up -d --build api worker   # código mudou
curl -s localhost:8000/health             # {"status":"ok",...}
cd backend && .venv/bin/pytest -q          # 126 passed
# integração (manifest descreve tudo):
curl -s -H "X-API-Key: $KEY" localhost:8000/api/integrations/n8n/manifest | head -40
```

## Pendências (ordem sugerida)

1. **Implementar o n8n do lado cliente** — o Ethoscan está pronto; use `GET /manifest` + a receita de
   `docs/remote-access.md`. Webhook testado de ponta a ponta (payload real recebido).
2. **Conectividade Ethoscan (NAT) ↔ VM OCI** — escolher um caminho no doc: Tailscale (mais simples),
   túnel SSH reverso (autossh/systemd), Cloudflare Tunnel ou Caddy + port-forward. Inbound direto **não** funciona.
3. **Popular `ETHOSCAN_ALLOWLIST`** (api + worker) antes de expor a API.
4. `ETHOSCAN_API_KEY` própria para produção + `docker compose build web` (a UI embute a key).
5. Rate limit no proxy e revisão do `/api/audit` periodicamente.

## Armadilhas já pagas nesta sessão (não repetir)

- Compose antigo publicava `5432`/`6379` no host → colisão com outros stacks; agora loopback/interno.
- Testes que trocam env precisam de `get_settings.cache_clear()` (settings é cacheado).
- Fakes de settings em teste: qualquer campo novo lido em `credential_accepted` quebra o fake (já ocorreu com
  `ethoscan_session_prefix`).
- Rotas clássicas: o start de scan é `POST /api/engagements/{id}/jobs` (não `/api/jobs/scan`) e a resposta é
  `{"job": {...}, "message": ...}`.
- Ao testar com `curl` em shell: `$(...)` dentro de `echo "..."` com `\"` mascara o header e produz um
  **401 fantasma** — use comandos separados.
