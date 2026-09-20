# Setup Kali — Ethoscan

Checklist para um host **Kali Linux** stock com packages instalados, de forma a que `/health` e `cli.py health` mostrem `available=true` para as cinco tools.

## Binários mínimos

| Tool | Binário | Pacote Kali (exemplo) | Notas |
|------|---------|------------------------|-------|
| Nmap | `nmap` | `nmap` | Enum de portas/serviços |
| WhatWeb | `whatweb` | `whatweb` | Fingerprint web |
| Gobuster | `gobuster` | `gobuster` | Dir busting |
| sslscan | `sslscan` | `sslscan` | TLS/SSL |
| Nuclei | `nuclei` | `nuclei` (ou binário ProjectDiscovery) | Templates de vuln |

## Tools opcionais (catálogo selecionável)

| Tool | Binário | Pacote / notas | Ethoscan |
|------|---------|----------------|----------|
| Nikto | `nikto` | `nikto` | Adapter runnable (maxtime limitado) |
| Masscan | `masscan` | `masscan` | Rate baixo + portas top |
| Unicornscan | `unicornscan` | `unicornscan` | Enum de portas (como masscan) |
| OWASP ZAP | `zap.sh` / `zap` | `zaproxy` | Scan headless + relatório (alternativa ao Burp) |
| Metasploit | `msfconsole` | `metasploit-framework` | **Só** `auxiliary/scanner` — sem exploits |
| sqlmap | `sqlmap` | `sqlmap` | Defaults seguros; URL allowlisted |
| Hydra | `hydra` | `hydra` | standard+; wordlist curta; host allowlisted |
| John | `john` | `john` | Offline; só com `hashes.txt` nos artefactos |
| NetExec (CME) | `nxc` / `netexec` / `crackmapexec` | `netexec` | Enum SMB apenas |
| BloodHound.py | `bloodhound-python` | `bloodhound.py` | standard+; creds em `ad_creds.env` |
| Burp Suite | `burpsuite` | instalador PortSwigger | **Só GUI** |
| Wireshark | `wireshark` | `wireshark` | **Só GUI** |
| Fern | `fern-wifi-cracker` | `fern-wifi-cracker` | **Só GUI** (sem RF automatizado) |

### Inventário apenas (visível, não selecionável em jobs)

`tcpdump`, `netcat`, `aircrack-ng`, `kismet`, `wifite`, `bettercap`, `arpwatch`, `setoolkit` —
aparecem no catálogo com badge **inventário** (ética/RF/utils). Ethoscan **não** automatiza
ataques RF nem campanhas SET.

```bash
# Opcionais (exemplos)
sudo apt install -y nikto masscan unicornscan zaproxy metasploit-framework \
  sqlmap hydra john netexec wireshark tcpdump aircrack-ng
# Burp CE: instalar à parte e garantir `burpsuite` no PATH
```

> **Ética:** Ethoscan não automatiza exploits Metasploit nem ataques RF (wifite/kismet/aircrack
> permanecem inventário). SET = inventário. RoE + allowlist F0 inalterados.
> **Instalado ≠ executável:** o Desktop lista todas as tools com badges
> Disponível / Executável / Só GUI / Inventário.

### Wordlists (Gobuster)

Gobuster, no adapter atual, usa por omissão:

```text
/usr/share/wordlists/dirb/common.txt
```

No Kali, instale/extraia wordlists se necessário:

```bash
sudo apt update
sudo apt install -y wordlists
# Se common.txt estiver gzipado:
sudo gunzip -k /usr/share/wordlists/dirb/common.txt.gz || true
```

## Instalação rápida das cinco tools

```bash
sudo apt update
sudo apt install -y nmap whatweb gobuster sslscan nuclei wordlists
# Confirmar PATH
command -v nmap whatweb gobuster sslscan nuclei
```

## Checklist “Setup Kali”

- [ ] Kali atualizado (`apt update`)
- [ ] `nmap`, `whatweb`, `gobuster`, `sslscan`, `nuclei` no `PATH`
- [ ] Wordlist Gobuster presente (`/usr/share/wordlists/dirb/common.txt`)
- [ ] `.env` com `ETHOSCAN_ALLOW_MOCK=false` para exigir tools reais
- [ ] Redis a correr (fila do worker)
- [ ] API: `uvicorn app.main:app --host 127.0.0.1 --port 8000`
- [ ] Worker: `python -m app.worker`
- [ ] `curl -s http://127.0.0.1:8000/health | jq .tools` → todos `available: true`
- [ ] `python cli.py health` → mesma matriz
- [ ] (opcional) `GET /api/lab/tools` → inventário Kali alargado (`available` por binário) + fases F0–F6

## Política mock vs real

| Situação | Comportamento |
|----------|----------------|
| Tool no PATH | Scan **real**; findings/jobs com `mocked=false` / mode `real` |
| Tool em falta + `ETHOSCAN_ALLOW_MOCK=true` | **Mock**; findings/jobs marcados `mocked=true` / mode `mock` |
| Tool em falta + `ETHOSCAN_ALLOW_MOCK=false` | **Falha** no gate F0 (ou na execução da tool) |

O `/health` expõe as 5 tools do pipeline: `available`, `will_mock`, `mode`. O inventário alargado (masscan, nikto, netexec, etc.) está em `GET /api/lab/tools` (existência no PATH apenas — sem executar scans). A UI desktop mostra ambos + fases F0–F6.
