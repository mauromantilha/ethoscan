"use client";

import { useEffect, useState } from "react";

type ThemeMode = "system" | "light" | "dark";

const STORAGE_KEY = "ethoscan-theme";

function resolveTheme(mode: ThemeMode): "light" | "dark" {
  if (mode !== "system") return mode;
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function applyTheme(mode: ThemeMode): void {
  document.documentElement.dataset.theme = resolveTheme(mode);
  document.documentElement.dataset.themeMode = mode;
}

const LABELS: Record<ThemeMode, string> = {
  system: "Tema: sistema",
  light: "Tema: claro",
  dark: "Tema: escuro",
};

export default function ThemeToggle() {
  const [mode, setMode] = useState<ThemeMode>("system");
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (stored === "light" || stored === "dark" || stored === "system") {
      setMode(stored);
    }
    setMounted(true);
  }, []);

  useEffect(() => {
    if (!mounted) return;
    applyTheme(mode);
    window.localStorage.setItem(STORAGE_KEY, mode);
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => {
      if (mode === "system") applyTheme("system");
    };
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, [mode, mounted]);

  function cycle() {
    setMode((current) => {
      if (current === "system") return "light";
      if (current === "light") return "dark";
      return "system";
    });
  }

  return (
    <button
      type="button"
      className="theme-toggle"
      onClick={cycle}
      aria-label={LABELS[mode]}
      title={LABELS[mode]}
    >
      {mounted ? LABELS[mode] : LABELS.system}
    </button>
  );
}
