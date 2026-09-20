# Ethoscan Desktop

Shell Electron mínimo para disparar assessments éticos via a API Ethoscan.

> **Não** é um scanner standalone. A app só fala com a API local (`/health`, engagements, jobs, findings, relatório). Controles éticos (RoE + allowlist + auth) permanecem no backend.

## Pré-requisitos

- Node.js ≥ 18
- API FastAPI em `http://127.0.0.1:8000` (ou URL configurável)
- Redis + worker (`python -m app.worker`)
- Uso **apenas** em alvos autorizados / lab próprio

## Desenvolvimento (sem empacotar)

```bash
npm install
npm start
```

Na UI: URL base (default `http://127.0.0.1:8000`) e, se a auth estiver ativa, a mesma `X-API-Key` definida em `ETHOSCAN_API_KEY`.

## Empacotar instaladores (local)

Usa [electron-builder](https://www.electron.build/). Os artefactos saem em `desktop/release/`.

```bash
npm install

# Linux: AppImage + .deb
npm run dist:linux

# Windows: portable + NSIS (.exe) — preferir runner Windows / CI
npm run dist:win

# Plataforma atual (targets do package.json)
npm run dist
```

| Script | Resultado típico |
|--------|------------------|
| `dist:linux` | `Ethoscan-0.1.0-linux-x86_64.AppImage`, `Ethoscan-0.1.0-linux-amd64.deb` |
| `dist:win` | `Ethoscan-0.1.0-win-x64.exe` (NSIS), `Ethoscan-0.1.0-win-x64-portable.exe` |

Cross-compilar Windows a partir de Linux não é o caminho suportado; use o workflow de CI ou uma máquina Windows.

## Releases no GitHub

O workflow [`.github/workflows/desktop-release.yml`](../.github/workflows/desktop-release.yml) corre em **push de tags** `v*`:

1. Merge do builder para `main`
2. Criar e publicar a tag, por exemplo:

   ```bash
   git checkout main && git pull
   git tag -a v0.1.0 -m "Ethoscan Desktop v0.1.0"
   git push origin v0.1.0
   ```

3. O CI gera artefactos Linux (ubuntu) e Windows, e anexa-os a um [GitHub Release](https://github.com/mauromantilha/ethoscan/releases) com o mesmo nome da tag

Releases: https://github.com/mauromantilha/ethoscan/releases
