#!/bin/bash
# Postinst do pacote Debian do Ethoscan.
#
# O template padrão do electron-builder testa `unshare --user true` e, se passar,
# deixa o chrome-sandbox sem SUID (0755). Em Ubuntu 23.10+ com AppArmor
# (kernel.apparmor_restrict_unprivileged_userns=1) esse teste passa, mas o
# Chromium não consegue criar o user namespace com mapeamento de UID e aborta:
#
#   The SUID sandbox helper binary was found, but is not configured correctly.
#
# O chrome-sandbox é projetado para ser root:root 4755. Usar sempre SUID é o
# comportamento canónico (igual ao google-chrome/chromium) e funciona também
# em Debian/Kali sem depender do estado do AppArmor.

if type update-alternatives 2>/dev/null >&1; then
    # Remove previous link if it doesn't use update-alternatives
    if [ -L '/usr/bin/${executable}' -a -e '/usr/bin/${executable}' -a "`readlink '/usr/bin/${executable}'`" != '/etc/alternatives/${executable}' ]; then
        rm -f '/usr/bin/${executable}'
    fi
    update-alternatives --install '/usr/bin/${executable}' '${executable}' '/opt/${sanitizedProductName}/${executable}' 100 || ln -sf '/opt/${sanitizedProductName}/${executable}' '/usr/bin/${executable}'
else
    ln -sf '/opt/${sanitizedProductName}/${executable}' '/usr/bin/${executable}'
fi

chmod 4755 '/opt/${sanitizedProductName}/chrome-sandbox' || true

if hash update-mime-database 2>/dev/null; then
    update-mime-database /usr/share/mime || true
fi

if hash update-desktop-database 2>/dev/null; then
    update-desktop-database /usr/share/applications || true
fi
