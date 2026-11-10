# Release checklist — v0.5.0

> Não publique a tag sem confirmar que o CI e a DB de produção estão prontos.

## Pré-release

- [ ] `git status` limpo e revisão do diff.
- [ ] Backup da DB de produção.
- [ ] `cd backend && .venv/bin/pytest -q --cov=app --cov-fail-under=70`
- [ ] `cd backend && .venv/bin/ruff check .`
- [ ] `cd frontend && npm ci && npm run build`
- [ ] `cd desktop && npm ci && npm run dist:linux`
- [ ] (opcional) `ETHOSCAN_DOCKERFILE=Dockerfile.tools docker compose build api worker` (tools Debian)
- [ ] (opcional) `ETHOSCAN_DOCKERFILE=Dockerfile.kali docker compose build api worker` (catálogo completo Kali)
- [ ] `dpkg-deb -f desktop/release/ethoscan_0.5.0_amd64.deb Package Version Depends`
- [ ] `dpkg-deb --ctrl-tarfile desktop/release/ethoscan_0.5.0_amd64.deb | tar -xO ./postinst | grep -q 'chmod 4755'`
- [ ] Migrações `0003`/`0004` aplicadas em ambiente de staging.
- [ ] `.env` de produção: `ETHOSCAN_API_KEY` forte, `ETHOSCAN_ALLOWLIST` preenchida,
      `ETHOSCAN_ALLOW_MOCK=false`, `ETHOSCAN_MODE=remote`.
- [ ] Login local: `ETHOSCAN_LOCAL_USERNAME` + hash bcrypt + `ETHOSCAN_LOCAL_TOTP_SECRET`;
      testar login com código TOTP válido e rejeição sem/incorreto.

## Publicar

```bash
git add -A
git commit -m "release: v0.5.0"
git tag -a v0.5.0 -m "Ethoscan v0.5.0"
git push origin main
git push origin v0.5.0
```

O push da tag dispara:

1. `.github/workflows/desktop-release.yml` — build Linux/Windows, teste Debian 12,
   `SHA256SUMS.txt` e GitHub Release.
2. `.github/workflows/apt-repo.yml` — (se configurado) publicação do repositório APT
   assinado em `gh-pages`.

## Pós-release

- [ ] Confirmar assets: AppImage, `.deb`, `.exe`, `SHA256SUMS.txt`.
- [ ] Testar `sudo apt install ./ethoscan_0.5.0_amd64.deb` em Debian 12/Ubuntu 24.04+.
- [ ] Confirmar `stat -c '%a %U' /opt/Ethoscan/chrome-sandbox` → `4755 root` e abrir a app.
- [ ] Testar `./scripts/install-deb.sh v0.5.0`.
- [ ] Se APT repo ativo: `apt update && apt install ethoscan` + `apt upgrade`.
- [ ] Validar `/health` (auth, Redis, worker) e um job mock/real.
- [ ] Atualizar `docs/handoff.md` com o hash/tag publicados.

## Rollback

- Manter o `.deb`/AppImage da versão anterior no release.
- Reverter a tag/Release no GitHub se o pacote estiver quebrado.
- Se a migração falhar: restaurar backup da DB antes de subir a versão anterior.
