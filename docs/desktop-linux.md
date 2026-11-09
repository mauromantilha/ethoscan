# Desktop Ethoscan no Linux (Debian/Ubuntu)

O desktop é um cliente Electron da API Ethoscan. O pacote **não** inclui scanners;
API + Redis + worker continuam a correr separadamente.

## Instalação local via apt

Baixe `ethoscan_<versão>_amd64.deb` do GitHub Releases e instale com `apt` (não use
`dpkg -i`, para que as dependências sejam resolvidas):

```bash
sudo apt install ./ethoscan_0.3.0_amd64.deb
ethoscan
```

Ou use o instalador que descarrega o último release e verifica o checksum:

```bash
./scripts/install-deb.sh
# ou uma tag específica:
./scripts/install-deb.sh v0.3.0
```

Requisitos testados: **Debian 12+**, **Ubuntu 22.04/24.04** (amd64). O pacote declara
dependências de GTK, NSS, X11, libsecret, GBM e ALSA.

## Atualização e remoção

```bash
# .deb local:
sudo apt install ./ethoscan_<nova-versão>_amd64.deb

# remover (mantém a configuração em ~/.config/Ethoscan):
sudo apt remove ethoscan
```

O auto-update do `electron-updater` não atualiza `.deb`; use `apt` para atualizar.
AppImage/Windows NSIS mantêm o updater.

## Repositório APT (opcional)

Se o repositório APT assinado estiver publicado (GitHub Pages), use:

```bash
sudo install -m 0644 ethoscan-archive-keyring.gpg \
  /usr/share/keyrings/ethoscan-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/ethoscan-archive-keyring.gpg] \
https://SEU_OWNER.github.io/ethoscan stable main" \
  | sudo tee /etc/apt/sources.list.d/ethoscan.list
sudo apt update
sudo apt install ethoscan
```

Depois:

```bash
sudo apt update && sudo apt install --only-upgrade ethoscan
```

O workflow `.github/workflows/apt-repo.yml` publica o repositório na branch `gh-pages`.
Configure os secrets `APT_GPG_PRIVATE_KEY` e `APT_GPG_PASSPHRASE` e ative GitHub Pages
para a branch `gh-pages`.

Gerar a chave (uma vez, fora do repo):

```bash
gpg --full-generate-key                 # RSA 4096, validade 2y
gpg --list-secret-keys --keyid-format LONG
gpg --armor --export-secret-keys <KEY_ID> > ethoscan-apt-private.asc
gh secret set APT_GPG_PRIVATE_KEY < ethoscan-apt-private.asc
gh secret set APT_GPG_PASSPHRASE
rm ethoscan-apt-private.asc
```

Nunca commite a chave privada. O workflow publica a chave pública como
`ethoscan-archive-keyring.gpg` na raiz do Pages; confirme o fingerprint antes de
adicionar a source.

## Troubleshooting

- **Sandbox do Chromium:** o `postinst` do pacote configura `chrome-sandbox` (SUID quando
  não há user namespaces). Em lab sem sandbox, use `ethoscan --no-sandbox` apenas para teste.
- **Wayland:** se a janela não abrir, tente `--ozone-platform=x11` ou execute numa sessão X11.
- **API offline:** o desktop abre, mas login/health falham até a API em
  `http://127.0.0.1:8000` estar a correr.
- **Dependências:** `sudo apt install -f` corrige dependências pendentes.
- **Configuração:** fica em `~/.config/Ethoscan/ethoscan-desktop.json` (token cifrado com
  `safeStorage` quando o keyring está disponível).
