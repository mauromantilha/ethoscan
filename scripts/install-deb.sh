#!/usr/bin/env bash
# Instala o .deb do Ethoscan via apt (resolve dependências).
# Uso: ./scripts/install-deb.sh [tag|latest]
set -euo pipefail

REPO="${ETHOSCAN_REPO:-mauromantilha/ethoscan}"
VERSION="${1:-latest}"
ARCH="$(dpkg --print-architecture)"

if ! command -v apt-get >/dev/null 2>&1; then
  echo "apt-get não encontrado; este instalador é para Debian/Ubuntu." >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 é necessário para ler a API do GitHub." >&2
  exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "curl é necessário para descarregar o release." >&2
  exit 1
fi

if [[ "$VERSION" == "latest" ]]; then
  API="https://api.github.com/repos/${REPO}/releases/latest"
else
  API="https://api.github.com/repos/${REPO}/releases/tags/${VERSION}"
fi

JSON="$(curl -fsSL "$API")"
mapfile -t ASSETS < <(
  printf '%s' "$JSON" | python3 -c '
import json, sys
data = json.load(sys.stdin)
arch = sys.argv[1]
deb = ""
sums = ""
for asset in data.get("assets", []):
    name = asset.get("name", "")
    if name.startswith("ethoscan_") and name.endswith(f"_{arch}.deb"):
        deb = asset.get("browser_download_url", "")
    if name == "SHA256SUMS.txt":
        sums = asset.get("browser_download_url", "")
print(deb)
print(sums)
' "$ARCH"
)

DEB_URL="${ASSETS[0]:-}"
SUMS_URL="${ASSETS[1]:-}"
if [[ -z "$DEB_URL" ]]; then
  echo "Nenhum ethoscan_*_${ARCH}.deb encontrado no release ${VERSION}." >&2
  exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
DEB_PATH="$TMP/$(basename "$DEB_URL")"
echo "Baixando $DEB_URL"
curl -fL "$DEB_URL" -o "$DEB_PATH"

if [[ -n "$SUMS_URL" ]]; then
  curl -fL "$SUMS_URL" -o "$TMP/SHA256SUMS.txt"
  (cd "$TMP" && grep " $(basename "$DEB_URL")\$" SHA256SUMS.txt | sha256sum -c -)
fi

if [[ "${ETHOSCAN_DRY_RUN:-0}" == "1" ]]; then
  echo "Dry-run: sudo apt install $DEB_PATH"
  exit 0
fi

sudo apt install "$DEB_PATH"
echo "Ethoscan instalado. Abra com: ethoscan"
