"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import Image from "next/image";
import { ShieldIcon } from "./Icons";

export function Navbar() {
  const pathname = usePathname();

  const links = [
    { href: "/", label: "Audit Console" },
    { href: "/compare", label: "Domain Compare" },
    { href: "/sandbox", label: "Attack Sandbox" },
    { href: "/tools/remediation", label: "Remediation Workbench" },
    { href: "/compliance", label: "Compliance Controls" },
    { href: "/standards", label: "Security Standards" },
  ];

  return (
    <header className="site-header">
      <div className="header-inner">
        <Link href="/" className="header-brand">
          <div className="brand-icon-box">
            <ShieldIcon size={18} className="text-slate-900" />
          </div>
          <div>
            <div className="brand-name">AegisX</div>
            <div className="brand-tagline">Security Intelligence</div>
          </div>
        </Link>

        <nav className="header-nav">
          {links.map((link) => {
            const isActive = pathname === link.href;
            return (
              <Link
                key={link.href}
                href={link.href}
                className={`nav-link ${isActive ? "active" : ""}`}
              >
                {link.label}
              </Link>
            );
          })}
        </nav>

        <div className="header-right">
          <div className="engine-status-badge">
            <span className="status-dot-emerald" />
            <span>Engine v2.4</span>
          </div>
        </div>
      </div>
    </header>
  );
}
