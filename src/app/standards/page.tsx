import { ShieldIcon, LockIcon, AlertTriangleIcon, CheckCircleIcon } from "@/components/Icons";

const HEADERS_GUIDE = [
  {
    header: "Content-Security-Policy (CSP)",
    cwe: "CWE-79",
    severity: "High",
    purpose: "Restricts sources from which browsers can load scripts, stylesheets, images, and frames.",
    threats: "Cross-Site Scripting (XSS), data injection, and malicious iframe embeds.",
    example: "default-src 'self'; script-src 'self' https:; object-src 'none';"
  },
  {
    header: "Strict-Transport-Security (HSTS)",
    cwe: "CWE-319",
    severity: "High",
    purpose: "Commands compliant browsers to strictly communicate with the domain only over HTTPS.",
    threats: "SSL-stripping Man-in-the-Middle (MITM) attacks and cleartext cookie sniffing.",
    example: "max-age=31536000; includeSubDomains; preload"
  },
  {
    header: "X-Frame-Options",
    cwe: "CWE-1021",
    severity: "Medium",
    purpose: "Dictates whether a browser is permitted to render the web page within an <iframe> or <frame>.",
    threats: "Clickjacking and UI redress attacks tricking users into clicking hidden actions.",
    example: "DENY or SAMEORIGIN"
  },
  {
    header: "X-Content-Type-Options",
    cwe: "CWE-430",
    severity: "Low",
    purpose: "Instructs browsers to never MIME-sniff responses away from the declared Content-Type.",
    threats: "MIME confusion attacks allowing user-uploaded images to execute as JavaScript.",
    example: "nosniff"
  },
  {
    header: "Referrer-Policy",
    cwe: "CWE-200",
    severity: "Low",
    purpose: "Controls the amount of referrer information transmitted when navigating to external websites.",
    threats: "Sensitive credential or session token leakage contained in URL paths or parameters.",
    example: "strict-origin-when-cross-origin"
  },
  {
    header: "Permissions-Policy",
    cwe: "CWE-250",
    severity: "Low",
    purpose: "Explicitly delegates or denies access to browser hardware APIs like camera, microphone, and location.",
    threats: "Malicious embedded third-party ad widgets accessing client microphones or geo coordinates.",
    example: "camera=(), microphone=(), geolocation=(), payment=()"
  }
];

const DNS_GUIDE = [
  {
    name: "Sender Policy Framework (SPF)",
    cwe: "CWE-345",
    description: "DNS TXT record enumerating all authorized mail servers permitted to send email on behalf of your domain. Strict '-all' prevents forged email transmission.",
    record: "v=spf1 include:_spf.google.com -all"
  },
  {
    name: "Domain-based Message Authentication (DMARC)",
    cwe: "CWE-345",
    description: "Establishes a policy telling receiving mail servers how to treat messages failing SPF/DKIM verification. A policy of 'p=reject' instructs servers to drop unauthenticated spoofed emails immediately.",
    record: "v=DMARC1; p=reject; rua=mailto:dmarc-reports@domain.com"
  },
  {
    name: "Certificate Authority Authorization (CAA)",
    cwe: "CWE-295",
    description: "RFC 6844 record defining which Certificate Authorities (e.g. Let's Encrypt, DigiCert) are allowed to issue SSL certificates for the domain, preventing rogue or compromised CAs from issuing impersonated certs.",
    record: "0 issue \"letsencrypt.org\""
  }
];

export default function StandardsPage() {
  return (
    <div style={{ maxWidth: "1000px", margin: "0 auto" }}>
      <div style={{ marginBottom: "2rem" }}>
        <span className="page-category-tag">Engineering Reference</span>
        <h1 style={{ fontSize: "2rem", fontWeight: 800, color: "var(--text-primary)", letterSpacing: "-0.02em", marginBottom: "0.5rem" }}>
          Security Standards &amp; Threat Guide
        </h1>
        <p style={{ color: "var(--text-secondary)", fontSize: "0.95rem", lineHeight: 1.6 }}>
          Comprehensive specifications for HTTP defense headers, transport cryptography, and DNS anti-spoofing policies.
        </p>
      </div>

      {/* HTTP Headers Section */}
      <section style={{ marginBottom: "3rem" }}>
        <h2 style={{ fontSize: "1.3rem", fontWeight: 700, color: "var(--text-primary)", marginBottom: "1rem" }}>
          Perimeter Defense Headers
        </h2>

        <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
          {HEADERS_GUIDE.map((h) => (
            <div 
              key={h.header} 
              style={{
                background: "#ffffff",
                border: "1px solid var(--border-light)",
                borderRadius: "var(--radius-md)",
                padding: "1.25rem",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "0.4rem" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.92rem", fontWeight: 700, color: "var(--text-primary)" }}>
                    {h.header}
                  </span>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.72rem", color: "var(--text-muted)", background: "var(--bg-subtle)", padding: "0.15rem 0.45rem", borderRadius: "4px" }}>
                    {h.cwe}
                  </span>
                </div>
                <span className={`pill-status ${h.severity.toLowerCase()}`}>
                  Severity: {h.severity}
                </span>
              </div>

              <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)", lineHeight: 1.5, marginBottom: "0.5rem" }}>
                {h.purpose}
              </p>

              <div style={{ fontSize: "0.8rem", color: "var(--status-fail-text)", marginBottom: "0.6rem" }}>
                <strong>Mitigates Threat:</strong> {h.threats}
              </div>

              <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.78rem", background: "var(--bg-subtle)", padding: "0.45rem 0.75rem", borderRadius: "var(--radius-sm)", color: "var(--text-primary)", border: "1px solid var(--border-light)" }}>
                <strong>Recommended Directive:</strong> {h.example}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* DNS Section */}
      <section>
        <h2 style={{ fontSize: "1.3rem", fontWeight: 700, color: "var(--text-primary)", marginBottom: "1rem" }}>
          DNS Anti-Spoofing &amp; Authority Standards
        </h2>

        <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
          {DNS_GUIDE.map((d) => (
            <div 
              key={d.name} 
              style={{
                background: "#ffffff",
                border: "1px solid var(--border-light)",
                borderRadius: "var(--radius-md)",
                padding: "1.25rem",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "0.4rem" }}>
                <h3 style={{ fontSize: "0.95rem", fontWeight: 700, color: "var(--text-primary)" }}>
                  {d.name}
                </h3>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.72rem", color: "var(--text-muted)", background: "var(--bg-subtle)", padding: "0.15rem 0.45rem", borderRadius: "4px" }}>
                  {d.cwe}
                </span>
              </div>

              <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)", lineHeight: 1.5, marginBottom: "0.6rem" }}>
                {d.description}
              </p>

              <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.78rem", background: "var(--bg-subtle)", padding: "0.45rem 0.75rem", borderRadius: "var(--radius-sm)", color: "var(--text-primary)", border: "1px solid var(--border-light)" }}>
                <strong>Record Format:</strong> {d.record}
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
