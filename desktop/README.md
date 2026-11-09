# Ethoscan Desktop

Shell Electron mínimo para disparar assessments éticos via a API Ethoscan.

> **Não** é um scanner standalone. A app só fala com a API local (`/health`, `/api/auth/login`, `/api/tools`, inventário, engagements, jobs, findings, relatório HTML/PDF). Controles éticos (RoE + allowlist + auth) permanecem no backend.

Após login: escolha tools no formulário (checkboxes; desativadas se não instaladas/runnable). Burp Suite = *só lançamento GUI*; ZAP e Metasploit (aux/scanner) podem entrar no pipeline. Botões **Descarregar HTML** e **Descarregar PDF**.

## Pré-requisitos

- Node.js ≥ 18
- API FastAPI em `http://127.0.0.1:8000` (ou URL configurável) **já a correr**
- Redis + worker (`python -m app.worker`)
- Uso **apenas** em alvos autorizados / lab próprio

## Tema

A UI usa o tema do sistema por default. O botão **Tema** no cabeçalho alterna
**sistema → claro → escuro**; a escolha fica em `localStorage` e é aplicada antes do
primeiro paint (sem flash).

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
   O token é cifrado com `safeStorage` quando o keyring do SO está disponível (fallback:
   ficheiro com permissões `0600`). `config:get` devolve apenas `hasApiKey`, nunca o token.
5. Na app: health/pipeline tools, inventário Kali, fases F0–F6, engagements/jobs/findings.

Com `ETHOSCAN_DISABLE_AUTH=true` (lab puro), o desktop pode continuar sem login.

## Atualizações automáticas

A app empacotada usa [electron-updater](https://www.electron.build/auto-update) com feed nos [GitHub Releases](https://github.com/mauromantilha/ethoscan/releases) do repositório `mauromantilha/ethoscan`.

- Verifica ao **arranque** (mesmo se a API local estiver offline) e de novo ao **conectar / login** (e no botão **Verificar** / **Atualizar**).
- UI em pt-BR: a verificar / disponível / a descarregar / pronta (reiniciar) / atualizado / erro.
- **Windows:** o auto-update aplica-se à instalação **NSIS**. O build **portable** continua a ser gerado, mas **não** atualiza in-place de forma fiável — use o instalador NSIS.
- **Linux:** AppImage pode atualizar; `.deb` tipicamente exige reinstalar o pacote.
- Sem code signing por agora (uso lab/privado). O Windows SmartScreen pode avisar em binários não assinados.
  Para lab/offline, desative o updater com `ETHOSCAN_DISABLE_UPDATER=1` ao arrancar a app.
- Em `npm start` (dev) o updater é no-op e mostra que só funciona na app empacotada.

**Primeira instalação:** descarregue manualmente o instalador do release. Versões seguintes atualizam sozinhas quando online (NSIS/AppImage; `.deb` via `apt`).

## Desenvolvimento (sem empacotar)

```bash
npm install
npm start
```

## Empacotar instaladores (local)

Usa [electron-builder](https://www.electron.build/). Os artefactos saem em `desktop/release/` (inclui `latest.yml` / `latest-linux.yml` graças a `publish.provider=github`).

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
| `dist:linux` | `Ethoscan-0.3.0-x86_64.AppImage`, `ethoscan_0.3.0_amd64.deb` |
| `dist:win` | `Ethoscan-0.3.0-win-x64.exe` (NSIS), `Ethoscan-0.3.0-win-x64-portable.exe` |

No Debian/Ubuntu, instale o `.deb` com `sudo apt install ./ethoscan_0.3.0_amd64.deb`
(ou `./scripts/install-deb.sh`); ver [`docs/desktop-linux.md`](../docs/desktop-linux.md).

Cross-compilar Windows a partir de Linux não é o caminho suportado; use o workflow de CI ou uma máquina Windows.

## Releases no GitHub

O workflow [`.github/workflows/desktop-release.yml`](../.github/workflows/desktop-release.yml) corre em **push de tags** `v*`:

1. Merge do builder para `main`
2. Criar e publicar a tag, por exemplo:

   ```bash
   git checkout main && git pull
   git tag -a v0.3.0 -m "Ethoscan Desktop v0.3.0"
   git push origin v0.3.0
   ```

3. O CI gera artefactos Linux (ubuntu) e Windows (`*.exe`, `latest.yml`, blockmaps), e anexa-os a um [GitHub Release](https://github.com/mauromantilha/ethoscan/releases) com o mesmo nome da tag

Releases: https://github.com/mauromantilha/ethoscan/releases
