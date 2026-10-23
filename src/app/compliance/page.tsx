"use client";

import { useState } from "react";
import { ShieldIcon, CheckCircleIcon, LockIcon } from "@/components/Icons";

const FRAMEWORKS = [
  { id: "all", name: "All Frameworks" },
  { id: "soc2", name: "SOC 2 Type II" },
  { id: "iso", name: "ISO/IEC 27001" },
  { id: "pci", name: "PCI-DSS v4.0" },
  { id: "hipaa", name: "HIPAA Security" },
  { id: "gdpr", name: "GDPR Article 32" },
];

const COMPLIANCE_ITEMS = [
  {
    framework: "SOC 2 Type II",
    frameworkId: "soc2",
    controlId: "CC6.6",
    title: "Logical Boundary Protection & Perimeter Filtering",
    requirement: "The entity implements logical boundaries and network filtering mechanisms to protect systems and confidential data from unauthorized external access.",
    technicalCriteria: "Strict Content-Security-Policy (CSP), X-Frame-Options (Clickjacking defense), and CORS restrictions.",
    remediation: "Deploy hardened HTTP headers and remove wildcard '*' permissions from API endpoints."
  },
  {
    framework: "SOC 2 Type II",
    frameworkId: "soc2",
    controlId: "CC6.7",
    title: "Transmission Cryptography & Data Protection",
    requirement: "Data transmitted across public networks is protected using approved cryptographic ciphers and protocols to prevent interception.",
    technicalCriteria: "Enforce TLS 1.2 or TLS 1.3 with Perfect Forward Secrecy (PFS) and disable legacy TLS 1.0/1.1.",
    remediation: "Configure SSL ciphers on load balancers to reject RC4, 3DES, and CBC suites."
  },
  {
    framework: "ISO/IEC 27001",
    frameworkId: "iso",
    controlId: "A.8.20",
    title: "Network Security Management",
    requirement: "Networks and network devices are secured, managed, and controlled to protect information in systems and applications.",
    technicalCriteria: "Prohibit public exposure of server technology banners, developer dotfiles (.git, .env), and unauthenticated debug endpoints.",
    remediation: "Suppress Server and X-Powered-By response headers in web server reverse proxy configs."
  },
  {
    framework: "ISO/IEC 27001",
    frameworkId: "iso",
    controlId: "A.8.24",
    title: "Use of Cryptography",
    requirement: "Rules for the effective use of cryptography, including cryptographic key management, are defined and implemented.",
    technicalCriteria: "Active SSL certificates issued by authorized CAs, monitored for expiration, with published CAA DNS records.",
    remediation: "Publish DNS CAA records specifying authorized issuers (e.g., Let's Encrypt, DigiCert)."
  },
  {
    framework: "PCI-DSS v4.0",
    frameworkId: "pci",
    controlId: "Req 4.1",
    title: "Protect Cardholder Data with Strong Cryptography in Transit",
    requirement: "Strong cryptography and security protocols are implemented to safeguard sensitive cardholder data during transmission over open, public networks.",
    technicalCriteria: "HTTP Strict Transport Security (HSTS) with minimum 1-year duration, includeSubDomains, and preload flag.",
    remediation: "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all web tier responses."
  },
  {
    framework: "PCI-DSS v4.0",
    frameworkId: "pci",
    controlId: "Req 6.4.3",
    title: "Manage All Payment Page Scripts",
    requirement: "All payment page scripts that are loaded and executed in the consumer's browser are managed and authorized to prevent web skimming (Magecart).",
    technicalCriteria: "Content-Security-Policy (CSP) enforcing strict script-src restrictions with SRI (Subresource Integrity).",
    remediation: "Restrict script-src to authorized payment gateways and enforce cryptographically signed script nonces."
  },
  {
    framework: "HIPAA Security",
    frameworkId: "hipaa",
    controlId: "§ 164.312(e)(1)",
    title: "Transmission Security & ePHI Integrity",
    requirement: "Implement technical security measures to guard against unauthorized access to electronic protected health information (ePHI) that is being transmitted over an electronic communications network.",
    technicalCriteria: "Mandatory HTTPS enforcement on all routes, preventing unencrypted plaintext fallback.",
    remediation: "Configure permanent HTTP 301 redirects to HTTPS and enable HSTS with long max-age."
  },
  {
    framework: "GDPR Article 32",
    frameworkId: "gdpr",
    controlId: "Art. 32(1)(a)",
    title: "Security of Processing & Pseudonymization/Encryption",
    requirement: "Taking into account the state of the art, implement appropriate technical and organizational measures to ensure a level of security appropriate to the risk.",
    technicalCriteria: "Domain anti-spoofing defense (SPF, DMARC with p=reject policy) preventing phishing attacks impersonating company personnel.",
    remediation: "Publish DMARC records with p=quarantine or p=reject to protect data subjects from domain forgery."
  }
];

export default function CompliancePage() {
  const [selectedFramework, setSelectedFramework] = useState("all");

  const filteredItems = COMPLIANCE_ITEMS.filter((item) => {
    if (selectedFramework === "all") return true;
    return item.frameworkId === selectedFramework;
  });

  return (
    <div style={{ maxWidth: "1000px", margin: "0 auto" }}>
      <div style={{ marginBottom: "2rem" }}>
        <span className="page-category-tag">Regulatory Alignment</span>
        <h1 style={{ fontSize: "2rem", fontWeight: 800, color: "var(--text-primary)", letterSpacing: "-0.02em", marginBottom: "0.5rem" }}>
          Compliance Standards Matrix
        </h1>
        <p style={{ color: "var(--text-secondary)", fontSize: "0.95rem", lineHeight: 1.6 }}>
          Review technical criteria, audit mandates, and remediation procedures for global cybersecurity frameworks.
        </p>
      </div>

      {/* Framework Filter Chips */}
      <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap", marginBottom: "1.5rem" }}>
        {FRAMEWORKS.map((f) => (
          <button
            key={f.id}
            type="button"
            className={`platform-tab-btn ${selectedFramework === f.id ? "active" : ""}`}
            onClick={() => setSelectedFramework(f.id)}
            style={{
              padding: "0.45rem 0.85rem",
              fontSize: "0.82rem",
              borderRadius: "var(--radius-sm)",
              border: selectedFramework === f.id ? "1px solid var(--text-primary)" : "1px solid var(--border-light)",
              background: selectedFramework === f.id ? "#ffffff" : "var(--bg-subtle)",
              color: selectedFramework === f.id ? "var(--text-primary)" : "var(--text-secondary)",
              cursor: "pointer"
            }}
          >
            {f.name}
          </button>
        ))}
      </div>

      {/* Controls List */}
      <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
        {filteredItems.map((ctrl, i) => (
          <div 
            key={i} 
            style={{
              background: "#ffffff",
              border: "1px solid var(--border-light)",
              borderRadius: "var(--radius-md)",
              padding: "1.25rem",
              transition: "border-color 0.15s ease"
            }}
          >
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "0.5rem", flexWrap: "wrap", gap: "0.5rem" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
                <span style={{ fontSize: "0.75rem", fontWeight: 700, color: "var(--brand-blue)", background: "var(--brand-blue-subtle)", padding: "0.15rem 0.45rem", borderRadius: "4px" }}>
                  {ctrl.framework}
                </span>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.8rem", color: "var(--text-muted)", fontWeight: 600 }}>
                  {ctrl.controlId}
                </span>
              </div>
              <span style={{ fontSize: "0.72rem", color: "var(--text-subtle)", textTransform: "uppercase", fontWeight: 600 }}>
                Audit Control
              </span>
            </div>

            <h3 style={{ fontSize: "1rem", fontWeight: 700, color: "var(--text-primary)", marginBottom: "0.4rem" }}>
              {ctrl.title}
            </h3>

            <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)", lineHeight: 1.6, marginBottom: "0.75rem" }}>
              {ctrl.requirement}
            </p>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem", fontSize: "0.8rem", background: "var(--bg-subtle)", padding: "0.75rem 1rem", borderRadius: "var(--radius-sm)" }}>
              <div>
                <strong style={{ color: "var(--text-primary)", display: "block", marginBottom: "0.2rem" }}>Technical Criteria:</strong>
                <span style={{ color: "var(--text-secondary)" }}>{ctrl.technicalCriteria}</span>
              </div>
              <div>
                <strong style={{ color: "var(--text-primary)", display: "block", marginBottom: "0.2rem" }}>Remediation Guidance:</strong>
                <span style={{ color: "var(--text-secondary)" }}>{ctrl.remediation}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
