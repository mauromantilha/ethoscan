# Desktop Ethoscan no Linux (Debian/Ubuntu)

O desktop é um cliente Electron da API Ethoscan. O pacote **não** inclui scanners;
API + Redis + worker continuam a correr separadamente.

## Instalação local via apt

Baixe `ethoscan_<versão>_amd64.deb` do GitHub Releases e instale com `apt` (não use
`dpkg -i`, para que as dependências sejam resolvidas):

```bash
sudo apt install ./ethoscan_0.4.0_amd64.deb
ethoscan
```

Ou use o instalador que descarrega o último release e verifica o checksum:

```bash
./scripts/install-deb.sh
# ou uma tag específica:
./scripts/install-deb.sh v0.4.0
```

Requisitos testados: **Debian 12+**, **Ubuntu 22.04/24.04/26.04** (amd64). O pacote declara
dependências de GTK, NSS, X11, libsecret, GBM e ALSA.

## Atualização e remoção

```bash
# .deb local:
sudo apt install ./ethoscan_<nova-versão>_amd64.deb

# remover (mantém a configuração em ~/.config/Ethoscan):
sudo apt remove ethoscan
```

O auto-update do `electron-updater` não instala `.deb` sem root; a app verifica a versão e
mostra o comando `sudo apt update && sudo apt install --only-upgrade ethoscan` (ou
`sudo apt install ./ethoscan_<nova-versão>_amd64.deb`). AppImage/Windows NSIS mantêm o
updater automático.

## Repositório APT (opcional)

O repositório APT assinado está publicado em GitHub Pages:

```bash
curl -fsSL https://mauromantilha.github.io/ethoscan/ethoscan-archive-keyring.gpg \
  -o /tmp/ethoscan-archive-keyring.gpg
sudo install -m 0644 /tmp/ethoscan-archive-keyring.gpg \
  /usr/share/keyrings/ethoscan-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/ethoscan-archive-keyring.gpg] \
https://mauromantilha.github.io/ethoscan stable main" \
  | sudo tee /etc/apt/sources.list.d/ethoscan.list
sudo apt update
sudo apt install ethoscan
```

Fingerprint da chave: `F14D 7665 D743 07E3 33F6 CD65 35C1 D6BE 8BC7 72DD`.

Depois:

```bash
sudo apt update && sudo apt install --only-upgrade ethoscan
```

O workflow `.github/workflows/apt-repo.yml` publica o repositório na branch `gh-pages`
depois de o workflow `desktop-release` terminar (ou via `workflow_dispatch`). Configure os
secrets `APT_GPG_PRIVATE_KEY` e `APT_GPG_PASSPHRASE` e ative GitHub Pages para a branch
`gh-pages`.

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

- **App não abre / aborta com "The SUID sandbox helper binary was found, but is not
  configured correctly":** o `chrome-sandbox` ficou sem SUID. Corrija com
  `sudo chmod 4755 /opt/Ethoscan/chrome-sandbox` (ou reinstale o `.deb` 0.3.1+). Verifique
  com `stat -c '%a %U' /opt/Ethoscan/chrome-sandbox` — deve mostrar `4755 root`.
  Isto afeta Ubuntu 23.10+ (incluindo 24.04/26.04) com
  `kernel.apparmor_restrict_unprivileged_userns=1`, onde o teste `unshare --user true`
  do postinst antigo passava mas o Chromium continuava sem sandbox utilizável.
- **AppImage não abre (`dlopen(): error loading libfuse.so.2`):** instale o FUSE 2:
  `sudo apt install libfuse2` (Debian 12/Ubuntu 22.04) ou `sudo apt install libfuse2t64`
  (Ubuntu 24.04+). Alternativa sem FUSE:
  `APPIMAGE_EXTRACT_AND_RUN=1 ./Ethoscan-<versão>-x86_64.AppImage`.
- **AppImage aborta com erro de sandbox:** o AppImage é montado sem SUID e, em Ubuntu
  23.10+, o user namespace pode estar bloqueado pelo AppArmor. O AppImage 0.3.1+ já
  deteta `$APPIMAGE` e arranca com `--no-sandbox`; em versões antigas use
  `./Ethoscan-<versão>-x86_64.AppImage --no-sandbox`. Para manter o sandbox ativo,
  prefira o `.deb` (chrome-sandbox SUID).
- **Wayland:** se a janela não abrir, tente `--ozone-platform=x11` ou execute numa sessão X11.
- **API offline:** o desktop abre, mas login/health falham até a API em
  `http://127.0.0.1:8000` estar a correr.
- **Dependências:** `sudo apt install -f` corrige dependências pendentes.
- **Configuração:** fica em `~/.config/Ethoscan/ethoscan-desktop.json` (token cifrado com
  `safeStorage` quando o keyring está disponível).
