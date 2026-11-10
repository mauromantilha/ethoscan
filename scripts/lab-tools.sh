#!/usr/bin/env bash
# Lab de inventário Ethoscan: tools de rede (tcpdump, netcat, arpwatch,
# bettercap, aircrack-ng, setoolkit...) rodando na REDE REAL do host.
#
# Uso:
#   ./scripts/lab-tools.sh up                 # build + sobe o container lab
#   ./scripts/lab-tools.sh run <tool> [args]  # ex.: run tcpdump -i eth0 -c 20
#   ./scripts/lab-tools.sh shell              # bash interativo no lab
#   ./scripts/lab-tools.sh ps                 # estado do container
#   ./scripts/lab-tools.sh down               # para e remove o container
#
# Atalhos:
#   ./scripts/lab-tools.sh tcpdump -i eth0 -c 20
#   ./scripts/lab-tools.sh arpwatch -i eth0
#   ./scripts/lab-tools.sh nc -vz exemplo.com 443
#   ./scripts/lab-tools.sh aircrack-ng /artifacts/capture.cap -w /usr/share/wordlists/rockyou.txt
#
# Avisos:
#   - O lab usa network_mode: host: enxerga a LAN física. Use apenas em
#     ambiente que você controla e com alvos dentro do RoE/escopo.
#   - setoolkit/bettercap exigem autorização explícita por escrito.
#   - kismet/wifite/airodump precisam de rádio monitor mode (ver
#     docker-compose.lab.yml: descomente `privileged: true`).
set -euo pipefail

cd "$(dirname "$0")/.."

COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.lab.yml)

# Docker sem sudo? Se o socket não estiver acessível, prefixa sudo.
if ! docker info >/dev/null 2>&1; then
  COMPOSE=(sudo "${COMPOSE[@]}")
fi

TOOL_ALIASES=(tcpdump nc netcat arpwatch bettercap aircrack-ng airodump-ng
  airmon-ng kismet wifite setoolkit nmap whatweb gobuster sslscan nuclei
  nikto masscan sqlmap hydra john nxc msfconsole)

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  echo
  echo "Tools com atalho direto: ${TOOL_ALIASES[*]}"
  exit 1
}

cmd="${1:-}"; shift || true

case "$cmd" in
  up)
    exec "${COMPOSE[@]}" up -d --build lab
    ;;
  down)
    exec "${COMPOSE[@]}" rm -sf lab
    ;;
  ps)
    exec "${COMPOSE[@]}" ps lab
    ;;
  shell)
    exec "${COMPOSE[@]}" exec -it lab bash
    ;;
  run)
    [[ $# -ge 1 ]] || { echo "uso: $0 run <tool> [args...]" >&2; exit 1; }
    exec "${COMPOSE[@]}" exec -it lab "$@"
    ;;
  tcpdump|nc|netcat|arpwatch|bettercap|aircrack-ng|airodump-ng|airmon-ng|\
  kismet|wifite|setoolkit|nmap|whatweb|gobuster|sslscan|nuclei|nikto|\
  masscan|sqlmap|hydra|john|nxc|msfconsole)
    # executa na API real (não interativa) para tools simples
    if [[ $# -eq 0 && "$cmd" =~ ^(setoolkit|bettercap|kismet|wifite)$ ]]; then
      # tools interativas sem args: abre TTY
      exec "${COMPOSE[@]}" exec -it lab "$cmd"
    fi
    exec "${COMPOSE[@]}" exec lab "$cmd" "$@"
    ;;
  ""|-h|--help|help)
    usage
    ;;
  *)
    echo "comando desconhecido: $cmd" >&2
    usage
    ;;
esac
