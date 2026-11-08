import "./globals.css";
import type { ReactNode } from "react";

export const metadata = {
  title: "Serrier — Security intelligence",
  description: "Security intelligence for the AI-native era",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="sv">
      <body>{children}</body>
    </html>
  );
}
