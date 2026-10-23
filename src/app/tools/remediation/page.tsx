"use client";

import { useState } from "react";
import { CopyIcon, CheckIcon, FileCodeIcon, LockIcon } from "@/components/Icons";

export default function RemediationPage() {
  const [domain, setDomain] = useState("example.com");
  const [platform, setPlatform] = useState<"nginx" | "apache" | "nextjs" | "vercel" | "caddy" | "dns">("nginx");
  const [copied, setCopied] = useState(false);
  const [hstsPreload, setHstsPreload] = useState(true);
  const [strictCsp, setStrictCsp] = useState(true);
  const [blockDotfiles, setBlockDotfiles] = useState(true);

  const cleanHost = domain.replace(/^https?:\/\//, "").replace(/\/.*$/, "") || "example.com";

  const getCode = () => {
    switch (platform) {
      case "nginx":
        return `# ========================================================
# Nginx Hardened Security Directives
# Target Host: ${cleanHost}
# Place within server { ... } block
# ========================================================

# 1. Clickjacking Protection
add_header X-Frame-Options "SAMEORIGIN" always;

# 2. Block MIME-type Confusion
add_header X-Content-Type-Options "nosniff" always;

# 3. HTTP Strict Transport Security
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains${hstsPreload ? "; preload" : ""}" always;

# 4. Content Security Policy
${strictCsp 
  ? `add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; font-src 'self' https: data:; connect-src 'self' https:; frame-ancestors 'self';" always;`
  : `add_header Content-Security-Policy "default-src 'self' https:;" always;`}

# 5. Referrer and Permissions Policies
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;

${blockDotfiles ? `# 6. Deny access to sensitive hidden directories (.git, .env)
location ~ /\\.(?!well-known) {
    deny all;
    return 404;
}` : ""}`;

      case "apache":
        return `# ========================================================
# Apache Hardened Directives (.htaccess / httpd.conf)
# Target Host: ${cleanHost}
# ========================================================
<IfModule mod_headers.c>
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains${hstsPreload ? "; preload" : ""}"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self' https:; img-src 'self' data: https:;"
</IfModule>

${blockDotfiles ? `# Deny hidden dotfiles (.git, .env)
<FilesMatch "^\\.(?!well-known)">
    Order allow,deny
    Deny from all
</FilesMatch>` : ""}`;

      case "nextjs":
        return `// ========================================================
// Next.js (next.config.mjs / next.config.js) Security Headers
// Target Host: ${cleanHost}
// ========================================================
/** @type {import('next').NextConfig} */
const nextConfig = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          { key: 'X-Frame-Options', value: 'SAMEORIGIN' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { 
            key: 'Strict-Transport-Security', 
            value: 'max-age=31536000; includeSubDomains${hstsPreload ? "; preload" : ""}' 
          },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
          {
            key: 'Content-Security-Policy',
            value: "default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:;",
          },
        ],
      },
    ];
  },
};

export default nextConfig;`;

      case "vercel":
        return `{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        { "key": "X-Frame-Options", "value": "SAMEORIGIN" },
        { "key": "X-Content-Type-Options", "value": "nosniff" },
        { "key": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains${hstsPreload ? "; preload" : ""}" },
        { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" },
        { "key": "Permissions-Policy", "value": "camera=(), microphone=(), geolocation=()" }
      ]
    }
  ]
}`;

      case "caddy":
        return `# ========================================================
# Caddyfile Security Directives
# Target Host: ${cleanHost}
# ========================================================
${cleanHost} {
    header {
        X-Frame-Options "SAMEORIGIN"
        X-Content-Type-Options "nosniff"
        Strict-Transport-Security "max-age=31536000; includeSubDomains${hstsPreload ? "; preload" : ""}"
        Referrer-Policy "strict-origin-when-cross-origin"
        Permissions-Policy "camera=(), microphone=(), geolocation=()"
        Content-Security-Policy "default-src 'self' https:;"
    }

    ${blockDotfiles ? `# Hide hidden files
    @hiddenFiles path_regexp (^|/)\\.(?!well-known)
    error @hiddenFiles 404` : ""}
}`;

      case "dns":
        return `; ========================================================
; DNS Zone Records for ${cleanHost}
; Add these TXT and CAA entries to your DNS provider
; ========================================================

; 1. SPF Record (Email Spoofing Prevention)
@   IN  TXT   "v=spf1 include:_spf.google.com ~all"

; 2. DMARC Enforcement Policy Record
_dmarc.${cleanHost}.  IN  TXT   "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc-reports@${cleanHost}"

; 3. CAA Record (Certificate Authority Authorization)
@   IN  CAA   0 issue "letsencrypt.org"
@   IN  CAA   0 issue "digicert.com"
@   IN  CAA   0 iodef "mailto:security@${cleanHost}"`;
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(getCode());
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div style={{ maxWidth: "1000px", margin: "0 auto" }}>
      <div style={{ marginBottom: "2rem" }}>
        <span className="page-category-tag">Configuration Generator</span>
        <h1 style={{ fontSize: "2rem", fontWeight: 800, color: "var(--text-primary)", letterSpacing: "-0.02em", marginBottom: "0.5rem" }}>
          Hardening Blueprint Workbench
        </h1>
        <p style={{ color: "var(--text-secondary)", fontSize: "0.95rem", lineHeight: 1.6 }}>
          Generate battle-tested, production-ready server and DNS configurations tailored to your domain.
        </p>
      </div>

      {/* Domain Customizer */}
      <div style={{ background: "var(--bg-subtle)", border: "1px solid var(--border-light)", borderRadius: "var(--radius-md)", padding: "1.25rem", marginBottom: "1.5rem" }}>
        <div style={{ display: "flex", gap: "1.5rem", flexWrap: "wrap", alignItems: "center" }}>
          <div style={{ flex: 1, minWidth: "260px" }}>
            <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 700, color: "var(--text-secondary)", textTransform: "uppercase", marginBottom: "0.35rem" }}>
              Target Domain Name
            </label>
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="example.com"
              style={{
                width: "100%",
                background: "#ffffff",
                border: "1px solid var(--border-mid)",
                borderRadius: "var(--radius-sm)",
                padding: "0.5rem 0.75rem",
                fontFamily: "var(--font-mono)",
                fontSize: "0.9rem",
                color: "var(--text-primary)",
                outline: "none"
              }}
            />
          </div>

          <div style={{ display: "flex", gap: "1.25rem", flexWrap: "wrap" }}>
            <label style={{ display: "flex", alignItems: "center", gap: "0.45rem", fontSize: "0.85rem", color: "var(--text-primary)", cursor: "pointer" }}>
              <input type="checkbox" checked={hstsPreload} onChange={(e) => setHstsPreload(e.target.checked)} />
              <span>HSTS Preload</span>
            </label>
            <label style={{ display: "flex", alignItems: "center", gap: "0.45rem", fontSize: "0.85rem", color: "var(--text-primary)", cursor: "pointer" }}>
              <input type="checkbox" checked={strictCsp} onChange={(e) => setStrictCsp(e.target.checked)} />
              <span>Strict CSP</span>
            </label>
            <label style={{ display: "flex", alignItems: "center", gap: "0.45rem", fontSize: "0.85rem", color: "var(--text-primary)", cursor: "pointer" }}>
              <input type="checkbox" checked={blockDotfiles} onChange={(e) => setBlockDotfiles(e.target.checked)} />
              <span>Block Dotfiles</span>
            </label>
          </div>
        </div>
      </div>

      {/* Workbench Block */}
      <div className="workbench-container">
        <div className="workbench-bar">
          <div className="platform-selector">
            <button
              type="button"
              className={`platform-tab-btn ${platform === "nginx" ? "active" : ""}`}
              onClick={() => setPlatform("nginx")}
            >
              Nginx
            </button>
            <button
              type="button"
              className={`platform-tab-btn ${platform === "apache" ? "active" : ""}`}
              onClick={() => setPlatform("apache")}
            >
              Apache (.htaccess)
            </button>
            <button
              type="button"
              className={`platform-tab-btn ${platform === "nextjs" ? "active" : ""}`}
              onClick={() => setPlatform("nextjs")}
            >
              Next.js
            </button>
            <button
              type="button"
              className={`platform-tab-btn ${platform === "vercel" ? "active" : ""}`}
              onClick={() => setPlatform("vercel")}
            >
              Vercel
            </button>
            <button
              type="button"
              className={`platform-tab-btn ${platform === "caddy" ? "active" : ""}`}
              onClick={() => setPlatform("caddy")}
            >
              Caddy
            </button>
            <button
              type="button"
              className={`platform-tab-btn ${platform === "dns" ? "active" : ""}`}
              onClick={() => setPlatform("dns")}
            >
              DNS Zone
            </button>
          </div>

          <button
            type="button"
            className="btn-outline"
            onClick={handleCopy}
            style={{ fontSize: "0.78rem" }}
          >
            {copied ? (
              <>
                <CheckIcon size={14} className="text-emerald-600" />
                <span>Copied to Clipboard</span>
              </>
            ) : (
              <>
                <CopyIcon size={14} />
                <span>Copy Blueprint</span>
              </>
            )}
          </button>
        </div>

        <pre className="code-viewer">
          <code>{getCode()}</code>
        </pre>
      </div>

      {/* Integration Tips */}
      <div style={{ marginTop: "2rem", display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
        <div style={{ background: "#ffffff", border: "1px solid var(--border-light)", borderRadius: "var(--radius-md)", padding: "1.25rem" }}>
          <h3 style={{ fontSize: "0.95rem", fontWeight: 700, color: "var(--text-primary)", marginBottom: "0.4rem" }}>
            Implementation Checklist
          </h3>
          <p style={{ fontSize: "0.82rem", color: "var(--text-secondary)", lineHeight: 1.6 }}>
            Before pushing headers to production, verify whether inline analytical scripts or Google Fonts require SHA-256 nonces in your Content Security Policy.
          </p>
        </div>
        <div style={{ background: "#ffffff", border: "1px solid var(--border-light)", borderRadius: "var(--radius-md)", padding: "1.25rem" }}>
          <h3 style={{ fontSize: "0.95rem", fontWeight: 700, color: "var(--text-primary)", marginBottom: "0.4rem" }}>
            HSTS Preload Caution
          </h3>
          <p style={{ fontSize: "0.82rem", color: "var(--text-secondary)", lineHeight: 1.6 }}>
            Adding the <code>preload</code> token commits your domain to HTTPS indefinitely across Chromium, Firefox, and Apple WebKit. Ensure all subdomains possess valid SSL certificates.
          </p>
        </div>
      </div>
    </div>
  );
}
