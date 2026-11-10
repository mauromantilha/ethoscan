const fs = require("fs");
const path = require("path");

/**
 * O AppImage é montado via FUSE sem SUID, por isso o chrome-sandbox não pode
 * ser usado. Em Ubuntu 23.10+ o user namespace também pode estar bloqueado
 * pelo AppArmor. Cria um wrapper `ethoscan` que adiciona --no-sandbox apenas
 * quando corre dentro de um AppImage; o .deb instalado continua a usar o
 * sandbox SUID (ver build/after-install.sh).
 */
module.exports = async function afterPack(context) {
  if (context.electronPlatformName !== "linux") return;

  const appOutDir = context.appOutDir;
  const executableName = context.packager.executableName;
  const wrapperPath = path.join(appOutDir, executableName);
  const realBinaryPath = path.join(appOutDir, `${executableName}-bin`);

  if (!fs.existsSync(wrapperPath) || fs.existsSync(realBinaryPath)) return;

  fs.renameSync(wrapperPath, realBinaryPath);

  const wrapper = `#!/bin/sh
# Gerado por build/after-pack.js (electron-builder).
# AppImage: montado sem SUID -> usa --no-sandbox.
# .deb: chrome-sandbox 4755 -> mantém o sandbox do Chromium.
SELF=$(readlink -f "$0")
DIR=$(CDPATH= cd -- "$(dirname -- "$SELF")" && pwd)
if [ -n "$APPIMAGE" ]; then
  exec "$DIR/${executableName}-bin" --no-sandbox "$@"
fi
exec "$DIR/${executableName}-bin" "$@"
`;

  fs.writeFileSync(wrapperPath, wrapper, { mode: 0o755 });
  fs.chmodSync(realBinaryPath, 0o755);
};
