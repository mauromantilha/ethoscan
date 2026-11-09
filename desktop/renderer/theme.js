(function () {
  const KEY = "ethoscan-theme";
  const LABELS = {
    system: "Tema: sistema",
    light: "Tema: claro",
    dark: "Tema: escuro",
  };

  function getMode() {
    const value = localStorage.getItem(KEY);
    return value === "light" || value === "dark" || value === "system" ? value : "system";
  }

  function resolve(mode) {
    if (mode !== "system") return mode;
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  function apply(mode) {
    document.documentElement.dataset.theme = resolve(mode);
    document.documentElement.dataset.themeMode = mode;
    const button = document.getElementById("btnTheme");
    if (button) {
      button.textContent = LABELS[mode];
      button.setAttribute("aria-label", LABELS[mode]);
      button.title = LABELS[mode];
    }
  }

  function cycle() {
    const mode = getMode();
    const next = mode === "system" ? "light" : mode === "light" ? "dark" : "system";
    localStorage.setItem(KEY, next);
    apply(next);
  }

  // Aplica antes do primeiro paint possível (script no <head>).
  apply(getMode());

  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
    if (getMode() === "system") apply("system");
  });

  document.addEventListener("DOMContentLoaded", () => {
    apply(getMode());
    const button = document.getElementById("btnTheme");
    if (button) button.addEventListener("click", cycle);
  });

  window.ethoscanTheme = { apply, cycle, getMode, resolve };
})();
