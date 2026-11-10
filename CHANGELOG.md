# Changelog

## [0.5.1] — 2026-11-10

Descoberta **passiva** do IP de origem (atrás de CDN/WAF) antes de um job.

### Descoberta de IP de origem

- `app/core/ipdiscovery.py`: técnicas somente passivas — resolução A/AAAA +
  classificação Cloudflare (faixas oficiais com refresh best-effort + snapshot),
  sondagem DNS de ~25 subdomínios comuns (mail, cpanel, origin, dev, staging...),
  registros MX (via `dig`, quando disponível) e Certificate Transparency (crt.sh).
  **Nenhum pacote é enviado aos IPs candidatos.**
- `POST /api/discover-ip`: descoberta sob demanda (máx. 10 alvos, escopo validado
  contra a allowlist, auditada como `ip_discovery`).
- **F0 automático**: todo job contra domínio atrás da Cloudflare roda a descoberta
  e registra os candidatos em `tool_runs._coverage.origin_ip`; o relatório
  (Cobertura/limitações) lista os candidatos com a fonte e o lembrete de validação
  manual (Host/SNI, dentro do RoE).
- Filtro de falsos positivos: MX de SaaS de e-mail (Zoho, Google, Microsoft,
  Proton, SES...) **não** é candidato — testado contra corretorsync.com (Zoho).
- Desktop: botão **"Descobrir IP de origem (passivo)"** na aba Novo, com os
  resultados renderizados antes de criar o engagement.
- 9 testes novos (DNS/crt.sh/filtro mockados); suíte **165 passed**, ruff limpo.

## [0.5.0] — 2026-11-10

Analista assistente LLM ("aikido"): triagem de findings, correlação e chat sobre o job —
**advisory-only** (o modelo nunca executa scans). Qualquer endpoint OpenAI-compatível.

### Assistente LLM

- `POST /api/jobs/{id}/analyze`: tria cada finding como `real` / `false_positive` /
  `inconclusive` / `informational` com confiança e justificativa, correlaciona achados em
  cadeias plausíveis, sugere próximos passos MANUAIS e lista limitações de cobertura
  (WAF/CDN, tools que falharam).
- `POST /api/jobs/{id}/assistant`: chat sobre o job com histórico limitado (20 msgs,
  papéis user/assistant validados).
- `/health` expõe `llm_enabled`; sem `ETHOSCAN_LLM_BASE_URL`+`ETHOSCAN_LLM_MODEL` os
  endpoints respondem 503 e nada é enviado a terceiros.
- Data minimization: ao provedor vão apenas metadados do job e findings TRUNCADOS
  (título, severidade, tool, alvo, descrição 400 chars, evidência 300 chars, máx. 60
  findings). Artefactos brutos, outputs completos e credenciais não saem do host.
- System prompt fixo: ceticismo com falsos positivos de scanner, awareness de edge
  Cloudflare/CDN, proibição de sugerir ações fora do RoE; respostas em pt-BR.
- Auditoria: `llm_analyze` / `llm_assistant` com modelo e contagens (pergunta truncada).
- Desktop: aba **Assistente** — seletor de job, botão "Analisar achados" com triagem
  renderizada e chat com bolhas de conversa.
- `POST /api/llm/test` + botão **Testar API** no desktop: ping ao provedor com modelo,
  latência e resposta; falha do provedor volta no corpo (`ok: false` + detail).
- `.env`/`.env.example` com menu de provedores OpenAI-compatíveis (OpenAI, Groq free
  tier, OpenRouter `:free`, Cloudflare Workers AI, Ollama local); docs/llm-assistant.md.
- **Instalação limpa**: `scripts/check-install.sh` (doutor de instalação) verifica Docker,
  `.env`, imagem com scanners, stack, LLM e desktop — e diz exatamente o que falta
  instalar/configurar; README ganha quickstart "Instalação do zero (5 passos)".
- Desktop: health mostra `llm: on/off`; sem nenhum scanner no container, o painel
  orienta a construir `Dockerfile.kali` (primordial para scans reais).
- 14 testes novos (provedor mockado via httpx; nenhum teste fala com LLM real);
  conftest limpa as vars ETHOSCAN_LLM_* para a suíte ser hermética.

## [0.4.0] — 2026-11-10

Login local com 2FA (TOTP/authenticator app) e correções de instalação do desktop.

### Autenticação

- 2FA TOTP opcional no login local: `ETHOSCAN_LOCAL_TOTP_SECRET` (base32) +
  `ETHOSCAN_LOCAL_TOTP_ISSUER`; `POST /api/auth/login` aceita `totp_code`.
- `/health` expõe `local_login_2fa`; o desktop mostra o campo **Código 2FA** quando ativo.
- Segredo TOTP inválido impede a API de subir (fail-fast); verificação com janela de ±30s
  para tolerar desvio de relógio.
- Dependência `pyotp==2.9.0`.

### Relatórios / cobertura

- F0 regista a resolução DNS de cada alvo em `tool_runs._coverage`; o relatório passa a
  mostrar **Cobertura / limitações** quando o alvo não resolve ou uma tool falha.
- WhatWeb, sslscan e nmap deixam de criar findings genéricos quando não há output/ligação;
  passam a falha de tool com o motivo. Gobuster guarda o `stderr` no artefacto.
- `tool_runs.command` mostra até 16 argumentos (inclui o alvo; antes cortava em 8).
- Tool errors (`category=tool_error`) ficam separados dos achados de segurança no relatório.
- Cobertura deduplica tool_error + tool_run do mesmo tool/alvo e avisa quando
  Cloudflare/WAF é detetado (ferramentas HTTP veem challenge/edge).

### Correções de adapters (multi-target)

- SQLMap: não marca `high` por causa da frase "no dynamic nor injectable" no output;
  só confirma injeção com um injection point/parameter positivo. URL sem query string é
  omitida com aviso de cobertura.
- Nikto: artefacto por alvo (evita contaminação entre alvos) e parser ignora metadados
  (`Target Port`, etc.), baixa observações Cloudflare/uncommon headers para `info` e
  classifica headers ausentes/XSS de forma mais conservadora.
- NetExec sem output e Hydra sem ligação deixam de gerar "concluído" falso; viram falha.
- SSLScan com certificado ilegível/protocolos indisponíveis deixa de gerar "TLS concluído".
- Artefactos por alvo em nmap, whatweb, gobuster, nuclei, nikto, sqlmap, hydra, netexec,
  zap e metasploit (evita overwrite no último alvo).
- Nuclei: timeout `standard` 420s → 600s (atrás de WAF/CDN o scan legítimo era cortado
  no 2º alvo) e `aggressive` 600s → 900s.
- Suíte: **140 passed** em Python 3.12 e 3.13.

### Docker

- `backend/Dockerfile.tools` + `ETHOSCAN_DOCKERFILE=Dockerfile.tools`: inclui no container
  nmap, whatweb, gobuster, sslscan, nuclei, nikto, masscan, sqlmap, hydra, john e a wordlist
  do Gobuster. O default `Dockerfile` continua slim (tools vêm do host Kali).
- `backend/Dockerfile.kali` + `ETHOSCAN_DOCKERFILE=Dockerfile.kali`: Kali rolling com o
  catálogo completo (Metasploit, ZAP, NetExec, BloodHound.py, unicornscan), ferramentas de
  inventário (tcpdump, netcat, aircrack-ng, kismet, wifite, bettercap, arpwatch, SET) e venv
  Python 3.13 para o backend. Imagem grande e build demorado; inventário continua fora dos jobs.
- **Fix EPERM no exec de binários com file capabilities** (ex.: `/usr/lib/nmap/nmap` no Kali
  pede `cap_net_bind_service`, fora do bounding set do worker → `exit 126`): os Dockerfiles
  passam a remover file capabilities da imagem (o worker é root com `NET_RAW`/`NET_ADMIN`).
- `env_file` com `format: raw` no compose preserva o hash bcrypt (o `$` não é interpolado).

### Lab de inventário (rede real do host)

- `docker-compose.lab.yml` (override opcional): serviço `lab` com a imagem Kali em
  `network_mode: host` — tcpdump, arpwatch, netcat, bettercap, aircrack-ng e setoolkit
  enxergam a LAN física (antes confinados à bridge do compose). Não sobe no `up -d` normal.
- `scripts/lab-tools.sh`: atalhos `up`/`down`/`ps`/`shell`/`run` + 23 tools com atalho
  direto; detecta sudo automaticamente; capturas persistem em `./artifacts`.
- Wi-Fi (kismet/wifite/airodump) continua exigindo host/VM Kali com rádio monitor mode
  (descomente `privileged: true` no override se o rádio aparecer como `wlan0` no host).

### Desktop / empacotamento

- Inclui as correções da 0.3.1: `chrome-sandbox` 4755 no `.deb` (Ubuntu 23.10+/26.04),
  wrapper `--no-sandbox` no AppImage e updater `.deb` via `apt`.
- Instalações existentes: `sudo chmod 4755 /opt/Ethoscan/chrome-sandbox` (ou reinstalar o `.deb`).

## [0.3.1] — 2026-11-10

Correção de instalação/arranque do desktop em Ubuntu 23.10+ (AppArmor).

### Desktop / empacotamento

- `.deb`: o `postinst` passa a marcar `/opt/Ethoscan/chrome-sandbox` como `root:root 4755`
  (SUID). O template do electron-builder deixava 0755 quando `unshare --user true` passava;
  em Ubuntu 23.10+/26.04 com `kernel.apparmor_restrict_unprivileged_userns=1` esse teste
  passa, mas o Chromium não consegue criar o user namespace com UID map e aborta com
  *"The SUID sandbox helper binary was found, but is not configured correctly"*.
- Instalações existentes: `sudo chmod 4755 /opt/Ethoscan/chrome-sandbox` (ou reinstalar o `.deb`).
- AppImage: wrapper adiciona `--no-sandbox` apenas quando `$APPIMAGE` está definido (o
  AppImage não consegue usar SUID); documentados `libfuse2`/`libfuse2t64`.
- Updater: no `.deb` a app verifica a versão mas não tenta instalar sem root; mostra o
  comando `sudo apt update && sudo apt install --only-upgrade ethoscan`.
- CI: valida o modo 4755 do `chrome-sandbox` após instalar o `.deb`.

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
- Repositório APT assinado publicado em <https://mauromantilha.github.io/ethoscan>
  (GitHub Pages + GPG); instalação/upgrade via `apt`.
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
