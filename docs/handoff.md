# Handoff — memória de estado do projeto

> Documento operacional para **retomar o trabalho** (agente ou humano) sem reler a conversa toda.
> Atualize ao mudar o estado. **Nunca coloque segredos aqui**: valores vivem no `.env` (gitignored).

## Onde o projeto está (2026-09-30)

- `main` = `f1095a8` — PRs **#12** (integração n8n + deploy) e **#13** (allowlist + sessões) mergeados;
  #11 antes deles; #10 ficou **fechado** (foi retomado em partes no #12/#13).
- Suíte: **67 passed** (`cd backend && .venv/bin/pytest -q`). CI: `.github/workflows/smoke.yml`
  (pytest + `scripts/smoke.sh`) roda em cada PR/push.
- Stack Docker no host do Ethoscan (LAN `192.168.0.7`) **rodando**: `api` (rede `:8000`, `--proxy-headers`),
  `worker`, `redis` (rede interna, AOF, sem porta no host), `postgres` (loopback `:15432`), `web` (loopback `:3000`).
- Ambiente **limpo**: 0 engagements/jobs; sessões de teste revogadas no Redis.
- `.env`: auth ligada (`ETHOSCAN_DISABLE_AUTH=false`), `API_BIND=0.0.0.0`, `ETHOSCAN_ALLOWLIST=` (**vazio** =
  sem restrição), `ETHOSCAN_SERVICE_KEYS` com chave do n8n. Segredos **não** versionados.

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

- **Allowlist precisa existir no `api` E no `worker`** — quem roda o gate F0 é o worker. Depois de editar
  o `.env`: `docker compose up -d api worker`.
- **Master key ≠ token de sessão** para automação: use master key ou `ETHOSCAN_SERVICE_KEYS` (o token de
  login agora persiste no Redis, mas continua sendo credencial de pessoa).
- **`WEB_BIND` fica em loopback**: a UI web embute `NEXT_PUBLIC_API_KEY` no bundle JS.
- `_is_covered` (authz) **descarta entradas inválidas** de escopo/allowlist para que um TLD não amplie
  autorização por casamento de sufixo.
- Worker é **single job por vez**; para escala: `docker compose up -d --scale worker=3`.
- A API **não tem rate limit** próprio — usar o proxy (Caddy/Cloudflare).

## Como subir e validar

```bash
cd /home/mksbr/projetos/ethoscan
docker compose up -d --build api worker   # código mudou
curl -s localhost:8000/health             # {"status":"ok",...}
cd backend && .venv/bin/pytest -q          # 67 passed
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
