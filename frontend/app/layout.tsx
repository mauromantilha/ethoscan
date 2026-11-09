import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Ethoscan",
  description: "Orquestrador local de pentest ético — modo safe recomendado",
};

const THEME_SCRIPT = `(function () {
  try {
    var mode = localStorage.getItem("ethoscan-theme") || "system";
    var dark = mode === "dark" || (mode === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
    document.documentElement.dataset.theme = dark ? "dark" : "light";
    document.documentElement.dataset.themeMode = mode;
  } catch (e) {}
})();`;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="pt-BR" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }} />
      </head>
      <body>{children}</body>
    </html>
  );
}
