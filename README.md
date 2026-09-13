# Ethoscan

Orquestrador local de **pentest ético** (CLI + API + dashboard).

- Pipeline **F0–F6** (autorização → recon → enum → web → vuln → correlação → relatório)
- Escopo allowlist + RoE obrigatório + audit log
- Adapters: Nmap, WhatWeb, Gobuster, sslscan, Nuclei
- Intensidade padrão recomendada: **`safe`** (descoberta/detecção conservadora)

## Ambientes de execução

### 1. Host Kali Linux (caminho oficial para scans reais)

Use **Kali Linux** como host do operador, com as tools nativas no `PATH` (`nmap`, `whatweb`, `gobuster`, `sslscan`, `nuclei`, …).

Nesse cenário:

- Defina `ETHOSCAN_ALLOW_MOCK=false` para exigir tools reais.
- Scans reais só fazem sentido com o binário instalado e no escopo autorizado.

### 2. Dev sem tools / Docker (mock permitido)

Em máquinas sem as tools Kali (ou em containers de desenvolvimento), o **modo mock** é aceitável:

```bash
ETHOSCAN_ALLOW_MOCK=true
```

O mock não gera tráfego real de scan; serve para exercitar API, UI, pipeline e relatórios.

### 3. Intensidade (`safe` / `standard` / `aggressive`)

| Modo | Uso |
|------|-----|
| **`safe`** (padrão e recomendado) | Assessment ético conservador; preferência para o dia a dia. |
| `standard` | Lab próprio, com RoE explícito e necessidade de cobertura um pouco maior. |
| `aggressive` | Apenas lab próprio / ambiente controlado, RoE explícito e consciência do impacto. |

O enum de intensidade permanece; a postura pública do produto é **ética e não agressiva por omissão** — `safe` é o default na API, CLI e UI.

## Subir local (sem Docker)

Neste host o default é **SQLite** (não precisa Postgres).

```bash
cd ~/Projetos/ethoscan
cp .env.example .env

# API — preferir localhost no uso diário em Kali
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

# Dashboard (outro terminal)
cd ~/Projetos/ethoscan/frontend
npm install
npm run dev
```

- API: http://localhost:8000/docs  
- UI: http://localhost:3000  

### Com Docker (quando tiver permissão no socket)

```bash
# Ajuste DATABASE_URL no .env para Postgres e:
docker compose up --build
```

## CLI

```bash
cd backend && source .venv/bin/activate
python cli.py health
python cli.py create -n "Lab" -t scanme.nmap.org --ack
python cli.py run 1
python cli.py findings -e 1
```

## Segurança do próprio Ethoscan

A API atual é **local-first e sem autenticação**. Trate o Ethoscan como ferramenta de operador na sua máquina/lab, não como serviço exposto.

**Preferências de bind**

- Uso diário em Kali: ligue a API a **localhost** (`127.0.0.1`).
- `0.0.0.0` apenas em lab isolado, quando precisar aceder a partir de outra máquina na mesma rede controlada.

**Riscos atuais (código presente)**

- Sem autenticação na API.
- CORS configurado com `allow_origins=["*"]`.
- No `docker-compose.yml`, Postgres usa credenciais locais de exemplo `ethoscan` / `ethoscan` — só para lab local, nunca para produção ou rede partilhada.

**Checklist — não publicar casualmente na LAN**

- [ ] Porta **8000** (API)
- [ ] Porta **3000** (dashboard)
- [ ] Porta **5432** (Postgres do compose)
- [ ] Porta **6379** (Redis do compose)

Auth de API e endurecimento de CORS ficam para iterações futuras; até lá, isole a exposição.

## Ética e responsabilidade

- Use **somente** em alvos autorizados, projetos próprios ou labs com permissão explícita.
- A responsabilidade pelo escopo, RoE e impacto é do **operador**.
- Alvos de exemplo de laboratório (ex.: `scanme.nmap.org`) são aceitáveis quando o dono do serviço os disponibiliza para testes.
- Não use o Ethoscan para reconhecimento ou exploração sem autorização.

## O que nunca commitar

Checklist — estes caminhos/artefactos **não** devem ir para o repositório:

- [ ] `.env` (segredos e configuração local) — já coberto no `.gitignore`
- [ ] `artifacts/` (DB local, outputs de jobs, relatórios) — já coberto no `.gitignore`
- [ ] Relatórios reais de engagements / clientes
- [ ] Credenciais, tokens, chaves, dumps ou evidências de alvos reais
- [ ] Ficheiros `*:Zone.Identifier` (lixo ADS do Windows) — já cobertos no `.gitignore`

Antes de `git add` / push, confirme que nenhum destes caminhos aparece no staging.
