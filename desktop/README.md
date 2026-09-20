# Ethoscan Desktop

Shell Electron mínimo para disparar assessments éticos via a API Ethoscan.

> **Não** é um scanner standalone. A app só fala com a API local (`/health`, `/api/auth/login`, `/api/tools`, inventário, engagements, jobs, findings, relatório HTML/PDF). Controles éticos (RoE + allowlist + auth) permanecem no backend.

Após login: escolha tools no formulário (checkboxes; desativadas se não instaladas/runnable). Burp Suite = *só lançamento GUI*; ZAP e Metasploit (aux/scanner) podem entrar no pipeline. Botões **Descarregar HTML** e **Descarregar PDF**.

## Pré-requisitos

- Node.js ≥ 18
- API FastAPI em `http://127.0.0.1:8000` (ou URL configurável) **já a correr**
- Redis + worker (`python -m app.worker`)
- Uso **apenas** em alvos autorizados / lab próprio

## Login local

1. No `.env` da API, configure utilizador + hash bcrypt (ver `.env.example`):

   ```bash
   ETHOSCAN_DISABLE_AUTH=false
   ETHOSCAN_LOCAL_USERNAME=mauro
   ETHOSCAN_LOCAL_PASSWORD_HASH='...(bcrypt)...'
   # opcional para CLI: ETHOSCAN_API_KEY=...
   ```

   Gerar hash (substitua a password; **não** committe passwords):

   ```bash
   python3 -c "import bcrypt; print(bcrypt.hashpw(b'YOUR_PASSWORD', bcrypt.gensalt()).decode())"
   ```

2. Suba API + Redis + worker.
3. Abra o desktop, indique a URL base, utilizador e palavra-passe → **Entrar**.
4. A sessão (token + username + URL) fica em `ethoscan-desktop.json` no userData; **Sair** limpa o token.
5. Na app: health/pipeline tools, inventário Kali, fases F0–F6, engagements/jobs/findings.

Com `ETHOSCAN_DISABLE_AUTH=true` (lab puro), o desktop pode continuar sem login.

## Desenvolvimento (sem empacotar)

```bash
npm install
npm start
```

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
