# Ethoscan

Orquestrador local de **pentest ético** (CLI + API + dashboard).

- Pipeline **F0–F6** (autorização → recon → enum → web → vuln → correlação → relatório)
- Escopo allowlist + RoE obrigatório + audit log
- Adapters: Nmap, WhatWeb, Gobuster, sslscan, Nuclei
- No host sem tools Kali: **modo mock** (`ETHOSCAN_ALLOW_MOCK=true`)
- Deploy na Kali Purple fica para o final (mesmo código)

## Subir local (sem Docker)

Neste host o default é **SQLite** (não precisa Postgres).

```bash
cd ~/Projetos/ethoscan
cp .env.example .env

# API
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

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

Deploy na Kali Purple fica para o final (mesmo código + tools nativas).
## CLI

```bash
cd backend && source .venv/bin/activate
python cli.py health
python cli.py create -n "Lab" -t scanme.nmap.org --ack
python cli.py run 1
python cli.py findings -e 1
```

## Notas éticas

Use **somente** em alvos autorizados. O modo padrão é descoberta/detecção; mock não gera tráfego real de scan.
