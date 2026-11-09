# Changelog

## [0.3.0] — 2026-11-09

Revisão de segurança, confiabilidade, UI e empacotamento Debian.

### Segurança / auth

- Auth fail-closed: fora de `ETHOSCAN_MODE=local`, a API não sobe sem auth; chaves
  default/fracas são rejeitadas.
- `ETHOSCAN_SERVICE_KEYS` também ativa auth.
- Login local com rate limit por IP, bcrypt dummy para username inválido e auditoria de
  sucesso/falha.
- `ETHOSCAN_SESSION_EPOCH` invalida todas as sessões; tokens do desktop cifrados com
  `safeStorage` (fallback `0600`).
- Webhooks com validação anti-SSRF no envio e assinatura HMAC opcional
  (`ETHOSCAN_CALLBACK_SECRET`).
- `external_ref` idempotente na API de integração.
- Auditoria com `actor` e `client_ip`; `job_queued` só após enqueue.
- Subprocessos usam ambiente mínimo; Hydra redige passwords; BloodHound não usa argv por
  default (`ETHOSCAN_ALLOW_CREDS_IN_ARGV=false`).
- Docker: API non-root, worker root com caps mínimas (`NET_RAW`, `NET_ADMIN`,
  `DAC_OVERRIDE`), `artifacts-init`, `no-new-privileges`.

### Escopo / scans / relatórios

- Allowlist type-aware: IP, CIDR e hostname não se misturam por sufixo; CIDR usa `subnet_of`.
- URLs com porta/path/query/fragment são rejeitadas no escopo (evita ampliação silenciosa).
- IPv6 corrigido nos adapters (`target_host`/`target_url`, brackets em URLs).
- Seleção de tools: omitir/`null` = pipeline clássico; lista vazia, GUI/inventário ou tool
  incompatível com a intensidade = **400**.
- Nuclei em `safe` mantém `high`/`critical`; intrusividade por tags/rate-limit.
- Dedupe entre jobs com `job_findings` + `UNIQUE(engagement_id, fingerprint)`; relatórios de
  reexecuções mantêm os findings.
- Relatórios mostram `completed`, `finished_at` e badge/aviso **MOCK**.
- Cancelamento usa o DB como fonte de verdade; funciona mesmo com Redis indisponível.
- Worker com lista de processamento por `ETHOSCAN_WORKER_ID`, ack, heartbeat e requeue de
  órfãos; `/health` expõe `worker_ok`.
- `init_db` fail-fast quando Alembic falha.

### UI

- Tema **system/light/dark** no web e desktop, persistido e sem flash.
- Desktop com CSP estrito, sem estilos inline.
- Banner de mock, confirmação antes de scan/cancelamento, filtros de findings, detalhes de
  evidência/remediação e tratamento de erros no polling.

### Empacotamento

- `.deb` Debian/Ubuntu apt-ready: pacote `ethoscan`, dependências GTK/NSS/ALSA/etc., ícone,
  desktop entry e `Exec=/opt/Ethoscan/ethoscan`.
- Instalação recomendada: `sudo apt install ./ethoscan_0.3.0_amd64.deb` ou
  `scripts/install-deb.sh`.
- Release gera `SHA256SUMS.txt` e testa instalação em Debian 12.
- Workflow opcional de repositório APT assinado (GitHub Pages + GPG).
- CI com ruff, pytest/cobertura, build do frontend, packaging Debian e shellcheck.

### Breaking changes / migração

- `selected_tools: []` explícito deixa de significar pipeline clássico; omita o campo ou
  envie `null` para o comportamento antigo.
- URLs de escopo com porta/path/query/fragment passam a ser rejeitadas.
- `ETHOSCAN_ALLOW_MOCK` passa a default `false`.
- Fora de `mode=local`, auth passa a ser obrigatória (API não sobe sem chave/utilizador/serviço).
- Sessões antigas são invalidadas pelo novo prefixo de epoch.
- Migrações Alembic `0003_job_findings` e `0004_hardening` (backup da DB antes de aplicar).
- Contrato da integração n8n atualizado para **1.1**.

### Validação

- `126 passed`, cobertura `77.11%`.
- `ruff check` limpo.
- Frontend build e desktop packaging validados.
- Migrações 0003/0004 validadas em SQLite antigo.

### Limitações conhecidas

- Migrações em Postgres e build Docker/Caddy não foram executados neste ambiente.
- Updater do desktop continua sem code signing; pode ser desativado com
  `ETHOSCAN_DISABLE_UPDATER=1`.
- `npm audit` do desktop ainda reporta vulnerabilidades em dependências de build/dev
  (`electron-builder@25`, `tar`, `node-gyp`).
- A master key embutida em `NEXT_PUBLIC_API_KEY` continua um risco; mantenha a UI web em
  loopback ou use uma chave dedicada.
