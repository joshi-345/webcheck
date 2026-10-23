import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { Navbar } from "@/components/Navbar";
import { Footer } from "@/components/Footer";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  display: "swap",
});

export const metadata: Metadata = {
  title: "AegisX | Autonomous Attack Surface & Cyber Posture Auditor",
  description:
    "Enterprise-grade passive web security audit platform. Evaluates perimeter headers, cryptographic TLS 1.3 chains, DNSSEC/DMARC/CAA spoofing defense, attack surface leaks, and generates 1-click multi-platform remediation configs.",
  keywords: [
    "cybersecurity scanner",
    "attack surface management",
    "SSL TLS cipher audit",
    "CSP generator",
    "HSTS security",
    "DMARC SPF CAA checker",
    "OWASP vulnerability scanner",
    "AegisX"
  ],
  authors: [{ name: "AegisX Cyber Defense Lab" }],
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={`${inter.variable} h-full antialiased`}>
      <body className="app-shell">
        <Navbar />
        <main className="main-content-area">{children}</main>
        <Footer />
      </body>
    </html>
  );
}
