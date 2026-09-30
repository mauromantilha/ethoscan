# Acesso remoto (n8n, automações, desktop em outra máquina)

A API do Ethoscan é a única superfície que precisa ser alcançável por automações. **Ela executa
varreduras de rede**: trate o acesso como privilegiado (TLS + chave forte + restrição por IP/VPN).

## Resumo das decisões

| Onde está o n8n | Caminho recomendado |
|---|---|
| Mesma rede local (LAN) | direto: `http://<IP-do-host>:8000` + `API_BIND=0.0.0.0` (já é o padrão no `.env` deste host) |
| Outra rede / internet | **VPN (Tailscale/WireGuard)** — nada exposto publicamente · ou **Cloudflare Tunnel** · ou **proxy TLS (Caddy)** — ver abaixo |
| Precisa de TLS com domínio próprio | `docker-compose.remote.yml` + `deploy/Caddyfile.example` |

> Nunca publique a porta `8000` direto na internet sem TLS: a `X-API-Key` viajaria em claro e a API
> dispara scans.

## Autenticação: use a **master key**, não o login

- `X-API-Key: <ETHOSCAN_API_KEY>` — key estática, sem expiração, comparação timing-safe. **É o que o n8n deve usar.**
- O login local (`POST /api/auth/login`) devolve um **token de sessão em memória**, com TTL de
  `ETHOSCAN_SESSION_TTL_HOURS` (default 12h) e **perdido quando a API reinicia** — serve para o
  desktop (humano), não para automação desassistida.
- Sem key válida: **401**. Com header ausente e auth desligada (`ETHOSCAN_DISABLE_AUTH=true`): sem restrição — não use isso com a API exposta.

## API de conexão pronta para automação (n8n)

Endpoints dedicados (veja também `/docs`), todos exigindo `X-API-Key`:

| Endpoint | Uso |
|---|---|
| `GET /api/integrations/n8n/manifest` | contrato **autodescritivo** (endpoints, auth, exemplos) — o n8n pode ler na 1ª execução |
| `POST /api/integrations/n8n/scan` | cria o engagement **e** enfileira o job em **1 chamada** (aceita `callback_url`) |
| `GET /api/integrations/n8n/jobs/{job_id}` | status compacto: `status`, `phase`, `progress`, `findings_count`, `has_report`, `poll_after_seconds` + URLs |

```bash
KEY=$ETHOSCAN_API_KEY        # ou uma chave dedicada em ETHOSCAN_SERVICE_KEYS
curl -sS -X POST https://ethoscan.seudominio.com/api/integrations/n8n/scan \
  -H "X-API-Key: $KEY" -H 'Content-Type: application/json' -d '{
    "name": "scan-n8n-01",
    "targets": ["scanme.nmap.org"],
    "intensity": "safe",
    "roe_acknowledged": true,
    "selected_tools": ["nmap", "nuclei"],
    "external_ref": "n8n-exec-1234",
    "callback_url": "https://n8n.seudominio.com/webhook/ethoscan"
  }'
# → {"engagement_id":7,"job_id":12,"status":"pending","callback_registered":true,
#    "status_url":"/api/integrations/n8n/jobs/12",
#    "findings_url":"/api/findings?job_id=12&limit=200",
#    "report_html_url":"/api/jobs/12/report","report_pdf_url":"/api/jobs/12/report.pdf","audit_url":"..."}
```

**Com `callback_url`** o worker faz um `POST` (timeout 5s, uma tentativa, best-effort) quando o job
termina — sem polling:

```json
{"job_id":12,"engagement_id":7,"status":"completed","phase":"F6","progress":100,"error":null,
 "findings_count":9,"report_path":"/app/artifacts/...","report_pdf_path":"/app/artifacts/...",
 "finished_at":"2026-10-01T03:52:51.238377+00:00"}
```

O envio fica registrado no audit como `callback_sent` / `callback_failed`. Sem callback, faça
polling do `status_url` respeitando `poll_after_seconds`.

**Chave dedicada para o n8n** (revogável sem trocar a master key nem o login do desktop):

```bash
# .env da API
ETHOSCAN_SERVICE_KEYS=<chave-do-n8n>[,<outra>]
```

**Limitar o que pode ser escaneado** (mesmo que a chave vaze) — a allowlist vale para a API e para
o worker, na criação e na execução:

```bash
# .env da API **e** do worker (docker compose up -d api worker)
ETHOSCAN_ALLOWLIST=lab.exemplo.com,10.10.0.0/24
```

Entradas precisam ser host FQDN, IP ou CIDR: um TLD/sufixo público (`com`, `co.uk`) na allowlist
derruba a API no boot com `Configuração inválida: ... entradas inválidas` (fail-fast, de propósito).
Vazio = sem restrição adicional além do escopo do engagement.

## Fluxo de integração (endpoints clássicos, verificado neste host)


```bash
API=https://ethoscan.seudominio.com          # ou http://192.168.0.7:8000 na LAN
KEY=$ETHOSCAN_API_KEY                        # master key (guardada em credencial do n8n)

# 1) cria o engagement (escopo + RoE obrigatórios)
curl -sS -X POST "$API/api/engagements" -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{"name":"n8n scan","scope_targets":["scanme.nmap.org"],"intensity":"safe","roe_acknowledged":true}'
# → {"id":7,"scope_targets":["scanme.nmap.org"],...}

# 2) enfileira o pipeline (body opcional: {"selected_tools":["nmap","nuclei"]})
curl -sS -X POST "$API/api/engagements/7/jobs" -H "X-API-Key: $KEY" -H 'Content-Type: application/json' -d '{}'
# → {"job":{"id":12,"status":"pending","phase":"F0",...},"message":"Pipeline enfileirado no worker (F0 gate → F1–F6)"}

# 3) acompanha (não existe webhook: faça polling)
curl -sS "$API/api/jobs/12" -H "X-API-Key: $KEY"
# status: pending|running|completed|failed|cancelled · phase: F0..F6 · progress: 0..100
# quando status=completed → report_path (HTML) e report_pdf_path

# 4) achados e auditoria
curl -sS "$API/api/findings?job_id=12&limit=200" -H "X-API-Key: $KEY"
curl -sS "$API/api/audit?job_id=12&limit=200"    -H "X-API-Key: $KEY"   # tool_ran com ok/exit_code

# 5) relatório (binário)
curl -sS -o relatorio.pdf "$API/api/jobs/12/report.pdf" -H "X-API-Key: $KEY"
```

Erros que o n8n precisa tratar: **401** key inválida · **403** RoE não confirmado (passe
`roe_acknowledged: true`) · **400** escopo/tools inválidos · **404** engagement/job inexistente ·
**503** Redis/worker fora do ar (a API não roda scan in-process).

### Receita no n8n

1. **Credential** → *Header Auth*: nome `X-API-Key`, valor = sua master key (não deixe a key no
   JSON do workflow).
2. **HTTP Request** (POST `…/api/engagements`) → Body JSON com `name`, `scope_targets`,
   `intensity`, `roe_acknowledged: true` → guarde o `id` retornado.
3. **HTTP Request** (POST `…/api/engagements/{{ $json.id }}/jobs`) → Body JSON `{}` → guarde `job.id`.
4. **Wait** (ex.: 30s) → **HTTP Request** (GET `…/api/jobs/{{ $json['job']['id'] }}`) → **IF**
   `status` é `completed`/`failed`/`cancelled`:
   - terminal → segue; senão, volta para o Wait (loop).
5. **HTTP Request** (GET `…/api/findings?job_id=…&limit=200`) → trate/roteie os achados
   (`severity`, `tool`, `target`, `cve`).
6. **HTTP Request** (GET `…/api/jobs/…/report.pdf`) com *Response* → **File** → anexe no e-mail/Slack.

## Opções de conectividade

### 1. LAN (direto) — o que já está rodando neste host

`.env` deste host: `API_BIND=0.0.0.0` → API em `http://192.168.0.7:8000`. Restrinja no firewall do
host ao IP do n8n:

```bash
sudo ufw allow from <IP-DO-N8N> to any port 8000 proto tcp   # só o n8n fala com a API
```

### 2. Tailscale / WireGuard (mais seguro, sem portas públicas)

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up            # autentique na sua tailnet
tailscale ip -4              # ex.: 100.x.y.z
```

Instale o Tailscale também no host do n8n e aponte a URL para `http://100.x.y.z:8000`. Nada é
publicado na internet e o tráfego é criptografado pela VPN.

### 3. Cloudflare Tunnel (TLS sem abrir porta)

```bash
cloudflared tunnel login
cloudflared tunnel create ethoscan
cloudflared tunnel route dns ethoscan ethoscan.seudominio.com
cloudflared tunnel run --url http://127.0.0.1:8000 ethoscan
```

Combine com `API_BIND=127.0.0.1` (só o túnel alcança a API) e proteja com **Cloudflare Access**:
o n8n envia `CF-Access-Client-Id`/`CF-Access-Client-Secret` além da `X-API-Key`.

### 4. Proxy reverso com TLS (Caddy) — já incluído no repo

```bash
cp deploy/Caddyfile.example deploy/Caddyfile   # ajuste domínio + e-mail
docker compose -f docker-compose.yml -f docker-compose.remote.yml up -d
```

O override **fecha a 8000/3000 no host** e publica só o Caddy (80/443, TLS automático) com rate
limit por IP, log JSON e (comentado) allowlist por IP de origem. A API roda com `--proxy-headers`,
então o IP real do n8n aparece nos logs/audit.

### 5. n8n em VM OCI (`mk-server`)

Este host (Ethoscan) está atrás de NAT — o IP da API é privado. A VM OCI tem IP público e saída
livre, então o caminho tem que ser **iniciado de dentro para fora** (VPN/túnel). O worker roda
aqui; só a **API de controle** precisa ser alcançável.

#### 5.1 Tailscale (recomendado)

No host Ethoscan:

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up --hostname ethoscan-host
tailscale ip -4                     # ex.: 100.101.102.103
```

Na VM OCI (`mk-server`):

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up --hostname mk-server
tailscale ping ethoscan-host
curl -fsS http://100.101.102.103:8000/health -H "X-API-Key: $ETHOSCAN_API_KEY"
```

No n8n: *Base URL* `http://100.101.102.103:8000` + credencial Header Auth `X-API-Key`.
Não precisa abrir nada na VCN nem no roteador. Se o n8n roda em **Docker** na VM, o container
precisa de rota para a tailnet: use `network_mode: host` (mais simples) ou suba o túnel de 5.2.

#### 5.2 Túnel SSH reverso (sem instalar agente na VM)

Do host Ethoscan (abre a API no loopback da VM):

```bash
ssh -N -o ServerAliveInterval=30 -o ExitOnForwardFailure=yes \
    -R 8000:127.0.0.1:8000 <usuario>@<IP-PUBLICO-DA-VM>
# na VM:  curl -fsS http://127.0.0.1:8000/health -H "X-API-Key: ..."
# no n8n: http://127.0.0.1:8000   (se o n8n usa network_mode: host)
```

- n8n em container **sem** host networking: faça o bind no IP privado da VM
  (`-R <IP-PRIVADO-DA-VM>:8000:127.0.0.1:8000` + `GatewayPorts clientspecified` no `sshd_config`)
  e restrinja a porta no firewall da VM (VCN/NSG + iptables) ao bridge do Docker.
- Nada é exposto à internet: a 8000 fica no loopback/IP privado da VM.
- Persistência com autossh:

```ini
# /etc/systemd/system/ethoscan-tunnel.service  (no host Ethoscan)
[Unit]
Description=Tunel reverso da API Ethoscan para a VM OCI (n8n)
After=network-online.target docker.service

[Service]
User=<seu-usuario>
Environment=AUTOSSH_GATETIME=0
ExecStart=/usr/bin/autossh -M 0 -N -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
  -o ExitOnForwardFailure=yes -R 8000:127.0.0.1:8000 <usuario>@<IP-PUBLICO-DA-VM>
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

#### 5.3 Cloudflare Tunnel (com domínio na Cloudflare)

No host Ethoscan:

```bash
cloudflared tunnel login && cloudflared tunnel create ethoscan
cloudflared tunnel route dns ethoscan ethoscan.seudominio.com
cloudflared tunnel run --url http://127.0.0.1:8000 ethoscan   # API_BIND=127.0.0.1 basta
```

No n8n: `https://ethoscan.seudominio.com` (+ Service Token do Cloudflare Access, se habilitado).
A VM OCI tem IP de saída fixo → dá para restringir a origem a esse IP.

#### 5.4 Endpoint público (Caddy + DNS + port-forward)

Só se quiser expor de verdade: libere 443 no roteador + DNS do domínio, use o override do Caddy e
restrinja por IP de origem (o IP de saída da VM você descobre com `curl -s https://ifconfig.me` nela):

```bash
cp deploy/Caddyfile.example deploy/Caddyfile     # ajuste domínio/e-mail
# descomente no Caddyfile:  @bloqueado not remote_ip <IP-PUBLICO-DA-VM>
docker compose -f docker-compose.yml -f docker-compose.remote.yml up -d
```

> Em 5.1–5.4, se for expor portas na VM OCI, lembre que as imagens OCI bloqueiam tudo por padrão:
> libere na **VCN/NSG** (Oracle) **e** no firewall do SO (`iptables`/`nftables`).

## Checklist antes de expor

- [ ] `ETHOSCAN_API_KEY` forte e rotacionada (`openssl rand -hex 32`); atualize no `.env` e no
      credential do n8n. A UI web usa `NEXT_PUBLIC_API_KEY` **embutida no bundle** → exige
      `docker compose build web` depois de trocar.
- [ ] `ETHOSCAN_DISABLE_AUTH=false` (nunca exponha com auth desligada).
- [ ] **TLS** ponta a ponta (proxy/túnel): sem ele a key trafega em claro.
- [ ] Restrição por origem: IP allowlist (`ufw` / `remote_ip` no Caddy) ou Cloudflare Access.
- [ ] `ETHOSCAN_ALLOWLIST` (CSV de hosts/IPs/CIDRs) para limitar globalmente **o que** pode ser
      escaneado, mesmo que a chave vaze. Vazio = sem restrição extra.
- [ ] Escopo: `validate_scope` recusa TLD/single-label (`com`, `io`) e sufixos públicos
      (`co.uk`, `com.br`) além de alvos malformados; cada engagement exige RoE.
- [ ] Rate limit no proxy — a API **não** tem rate limit próprio (protege contra força-bruta na key).
- [ ] `WEB_BIND=127.0.0.1` (padrão): a UI embute a master key no JS, não publique sem necessidade.
- [ ] Postgres/Redis **sem** porta pública (já é o padrão do compose).
- [ ] Acompanhar `GET /api/audit` — toda execução fica registrada (`tool_ran` com `ok`/`exit_code`, `job_completed`).
- [ ] Revisar o escopo: cada engagement exige `scope_targets` + `roe_acknowledged=true`; alvos
      malformados e TLD/single-label (`com`, `io`, `co.uk`) são recusados na criação (`validate_scope`)
      e a `ETHOSCAN_ALLOWLIST` é revalidada também na execução (gate F0 do worker).

## Limitações conhecidas

| Limitação | Mitigação hoje | Evolução possível |
|---|---|---|
| Sem rate limit na app | rate limit no Caddy/Cloudflare | middleware (ex.: slowapi) |
| Sem webhook de conclusão nos endpoints clássicos | use a API de integração (`callback_url`) ou polling | — |
| 1 job por vez (single-node) | enfileirar e acompanhar | `docker compose up -d --scale worker=3` |
