import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Ethoscan",
  description: "Orquestrador de pentest ético",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="pt-BR">
      <body>{children}</body>
    </html>
  );
}
