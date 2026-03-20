import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "zkDB: Plonky2 Zero-Knowledge Database",
  description: "A production-grade verifiable SQL database prototype powered by Plonky2 FRI-SNARKs. Execute real ZK queries with Poseidon anchors and Blake3 metadata commitments.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600&display=swap"
          rel="stylesheet"
        />
      </head>
      <body>{children}</body>
    </html>
  );
}
