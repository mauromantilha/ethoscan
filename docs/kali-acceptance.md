# Runbook de aceitação Kali (manual)

Objetivo: validar Ethoscan num Kali com tools reais, sem regressões nos controlos éticos (RoE/allowlist).

## Pré-requisitos

1. Completar [kali-setup.md](./kali-setup.md)
2. Redis + API + worker a correr
3. `ETHOSCAN_ALLOW_MOCK=false`
4. API key definida (`ETHOSCAN_API_KEY`) ou lab local com `ETHOSCAN_DISABLE_AUTH=true` **explícito**

## Fluxo

```bash
cd backend && source .venv/bin/activate
export ETHOSCAN_API_KEY=...   # se auth ativa
python cli.py health          # 5/5 available=true

python cli.py create -n "Aceitação Kali" -t scanme.nmap.org --ack
python cli.py run 1           # acompanhar F0→F6
python cli.py findings -e 1
python cli.py report 1 --out /tmp/ethoscan-acceptance.html
```

## Critérios

- [ ] F0 passa (RoE + escopo + tools)
- [ ] Fases F1–F6 progridem; `tool_runs` com `mocked=false` para tools usadas
- [ ] Achados com `mocked=false`
- [ ] Relatório HTML descarregável via API/CLI
- [ ] Cancelamento: iniciar job e `python cli.py cancel <id>` → status `cancelled`
- [ ] RoE negado / alvo fora de escopo continuam a ser rejeitados (403/400)

## Limites single-node

- 1 worker = tipicamente 1 job de cada vez (API permanece responsiva)
- Scans longos (nuclei/nmap agressivo) ocupam o worker até terminar ou cancelar
