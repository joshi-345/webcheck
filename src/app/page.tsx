"use client";

import { useState, useEffect } from "react";
import type { 
  ScanResults, 
  SecurityCheckItem, 
  Severity 
} from "@/utils/scanner";
import { 
  SearchIcon, 
  CheckIcon, 
  AlertTriangleIcon, 
  XCircleIcon, 
  LockIcon, 
  PrinterIcon, 
  DownloadIcon, 
  RefreshCwIcon,
  CopyIcon,
  ShieldIcon,
  FileCodeIcon
} from "@/components/Icons";

const DEMO_PRESETS = [
  { site: "cloudflare.com", label: "Cloudflare (Hardened)" },
  { site: "github.com", label: "GitHub (Enterprise)" },
  { site: "stripe.com", label: "Stripe (PCI-DSS Benchmark)" },
  { site: "httpbin.org", label: "httpbin.org (Demo Vulnerable)" },
];

const SCAN_STEPS = [
  "Resolving authoritative DNS records, CAA policies & IPv6 (AAAA)...",
  "Interrogating TLS 1.3 handshake & cipher suite negotiation...",
  "Auditing HTTP perimeter security headers (CSP, HSTS, XFO, COOP)...",
  "Probing sensitive vectors (.env, .git, docker-compose, security.txt)...",
  "Computing CVSS v3.1 vector & regulatory compliance matrix...",
  "Synthesizing hardened remediation blueprints & exploit trees...",
];

export default function AuditConsolePage() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<ScanResults | null>(null);
  const [error, setError] = useState("");
  const [currentStep, setCurrentStep] = useState(0);
  const [activeTab, setActiveTab] = useState<"findings" | "exploit" | "remediation" | "compliance" | "telemetry">("findings");
  const [findingFilter, setFindingFilter] = useState<"all" | "critical" | "warn" | "pass">("all");
  const [copiedCode, setCopiedCode] = useState(false);
  const [selectedPlatform, setSelectedPlatform] = useState<"nginx" | "apache" | "nextjs" | "vercel" | "dnsRecords">("nginx");

  useEffect(() => {
    let timer: NodeJS.Timeout;
    if (loading) {
      setCurrentStep(0);
      timer = setInterval(() => {
        setCurrentStep((prev) => {
          if (prev < SCAN_STEPS.length - 1) return prev + 1;
          return prev;
        });
      }, 700);
    }
    return () => clearInterval(timer);
  }, [loading]);

  const doScan = async (targetUrl: string) => {
    if (!targetUrl.trim()) return;
    setLoading(true);
    setError("");
    setResults(null);
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: targetUrl }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Autonomous scan failed to reach target host.");
      } else {
        setResults(data);
      }
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Network error encountered.");
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    doScan(url);
  };

  const handlePreset = (site: string) => {
    const full = `https://${site}`;
    setUrl(full);
    doScan(full);
  };

  const handleCopyCode = (code: string) => {
    navigator.clipboard.writeText(code);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  const handleExportJson = () => {
    if (!results) return;
    const blob = new Blob([JSON.stringify(results, null, 2)], { type: "application/json" });
    const dlUrl = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = dlUrl;
    a.download = `aegisx-security-audit-${results.target.hostname}.json`;
    a.click();
    URL.revokeObjectURL(dlUrl);
  };

  const handlePrintPdf = () => {
    window.print();
  };

  const filteredChecks = results?.checks.filter((c) => {
    if (findingFilter === "all") return true;
    if (findingFilter === "critical") return c.severity === "critical" || c.severity === "high";
    if (findingFilter === "warn") return c.status === "warn" || c.severity === "medium";
    if (findingFilter === "pass") return c.status === "pass";
    return true;
  }) || [];

  return (
    <div>
      {/* ── Minimalist Scanner Console Hero ────────────────────────── */}
      <section className="scanner-console-hero">
        <span className="page-category-tag">Attack Surface Management</span>
        <h1 className="console-title">
          Autonomous Web Security Audit
        </h1>
        <p className="console-subtitle">
          Passive analysis for HTTP defense headers, cryptographic TLS 1.3 chains, 
          email spoofing vulnerabilities, and public secret leaks.
        </p>

        <form onSubmit={handleSubmit} className="clean-search-form">
          <span className="protocol-prefix">HTTPS://</span>
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="example.com or any web host"
            required
            autoComplete="off"
            spellCheck={false}
            className="clean-input"
          />
          <button type="submit" disabled={loading} className="clean-scan-btn">
            {loading ? (
              <>
                <div className="loading-spinner-circle" style={{ width: "14px", height: "14px", borderTopColor: "#fff" }} />
                <span>Scanning...</span>
              </>
            ) : (
              <>
                <SearchIcon size={15} />
                <span>Run Audit</span>
              </>
            )}
          </button>
        </form>

        <div className="presets-row">
          <span style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontWeight: 600 }}>Demo Targets:</span>
          {DEMO_PRESETS.map((p) => (
            <button
              key={p.site}
              type="button"
              className="preset-chip"
              onClick={() => handlePreset(p.site)}
            >
              {p.label}
            </button>
          ))}
        </div>
      </section>

      {/* ── Error Notification ─────────────────────────────────────── */}
      {error && (
        <div style={{ maxWidth: "680px", margin: "1.5rem auto", background: "var(--status-fail-bg)", border: "1px solid var(--status-fail-border)", borderRadius: "var(--radius-md)", padding: "1rem 1.25rem", color: "var(--status-fail-text)", display: "flex", alignItems: "center", gap: "0.75rem", fontSize: "0.88rem" }}>
          <AlertTriangleIcon size={18} />
          <div>
            <strong>Scan Unsuccessful:</strong> {error}
          </div>
        </div>
      )}

      {/* ── Minimalist Loading Box ─────────────────────────────────── */}
      {loading && (
        <div className="loading-box">
          <div className="loading-header">
            <div className="loading-spinner-circle" />
            <div>
              <div style={{ fontSize: "0.88rem", fontWeight: 700, color: "var(--text-primary)" }}>
                Auditing {url || "target host"}
              </div>
              <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                Executing passive reconnaissance across 5 security pillars...
              </div>
            </div>
          </div>
          <div>
            {SCAN_STEPS.slice(0, currentStep + 1).map((s, idx) => (
              <div key={idx} className="step-log-item">
                <span style={{ color: "var(--text-subtle)", fontSize: "0.72rem" }}>
                  00:0{idx + 1}s
                </span>
                <span style={{ color: idx === currentStep ? "var(--brand-blue)" : "var(--status-pass-text)", fontWeight: 700, fontSize: "0.72rem" }}>
                  {idx === currentStep ? "[ACTIVE]" : "[PASSED]"}
                </span>
                <span>{s}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Results Console ────────────────────────────────────────── */}
      {results && !loading && (
        <div>
          {/* Executive Meta Bar */}
          <div className="results-header-bar">
            <div className="results-host-info">
              <span className="host-title">{results.target.hostname}</span>
              {results.target.ipAddress && (
                <span className="host-meta-tag">IP: {results.target.ipAddress}</span>
              )}
              {results.technologies.wafOrCdn && (
                <span className="host-meta-tag">{results.technologies.wafOrCdn}</span>
              )}
              <span className="host-meta-tag">{results.target.scanDurationMs}ms</span>
            </div>

            <div className="results-action-group">
              <button 
                type="button" 
                onClick={handlePrintPdf} 
                className="btn-outline"
                title="Print or export as PDF"
              >
                <PrinterIcon size={14} />
                <span>Export PDF</span>
              </button>
              <button 
                type="button" 
                onClick={handleExportJson} 
                className="btn-outline"
                title="Download JSON audit report"
              >
                <DownloadIcon size={14} />
                <span>Export JSON</span>
              </button>
              <button 
                type="button" 
                onClick={() => { setResults(null); setUrl(""); window.scrollTo({ top: 0, behavior: "smooth" }); }} 
                className="btn-outline"
                style={{ background: "var(--bg-subtle)" }}
              >
                <RefreshCwIcon size={14} />
                <span>New Scan</span>
              </button>
            </div>
          </div>

          {/* Top Metrics Row */}
          <div className="metrics-row-grid">
            
            {/* Security Posture Index */}
            <div className="metric-panel score-highlight">
              <div 
                className="score-badge-square"
                style={{
                  background: results.metrics.overallScore >= 85 ? "var(--status-pass-bg)" :
                              results.metrics.overallScore >= 70 ? "#eff6ff" :
                              results.metrics.overallScore >= 50 ? "var(--status-warn-bg)" : "var(--status-fail-bg)",
                  color: results.metrics.overallScore >= 85 ? "var(--status-pass-text)" :
                         results.metrics.overallScore >= 70 ? "#1e40af" :
                         results.metrics.overallScore >= 50 ? "var(--status-warn-text)" : "var(--status-fail-text)",
                  border: `1px solid ${
                    results.metrics.overallScore >= 85 ? "var(--status-pass-border)" :
                    results.metrics.overallScore >= 70 ? "#bfdbfe" :
                    results.metrics.overallScore >= 50 ? "var(--status-warn-border)" : "var(--status-fail-border)"
                  }`
                }}
              >
                {results.metrics.grade}
              </div>
              <div>
                <div className="metric-label">Security Posture</div>
                <div style={{ fontSize: "1.05rem", fontWeight: 700, color: "var(--text-primary)" }}>
                  {results.metrics.gradeLabel}
                </div>
                <div className="metric-foot">
                  Score: {results.metrics.overallScore}/100 ({results.metrics.passedChecks}/{results.metrics.totalChecks} checks)
                </div>
              </div>
            </div>

            {/* CVSS Risk Base */}
            <div className="metric-panel">
              <div>
                <div className="metric-label">CVSS v3.1 Risk</div>
                <div 
                  className="metric-value"
                  style={{
                    color: results.metrics.cvssScore <= 3.9 ? "var(--status-pass-text)" :
                           results.metrics.cvssScore <= 6.9 ? "var(--status-warn-text)" : "var(--status-fail-text)"
                  }}
                >
                  {results.metrics.cvssScore.toFixed(1)}
                </div>
              </div>
              <div className="metric-foot">Threat: {results.metrics.threatLevel}</div>
            </div>

            {/* TLS Protocol */}
            <div className="metric-panel">
              <div>
                <div className="metric-label">TLS Encryption</div>
                <div 
                  className="metric-value"
                  style={{
                    color: results.tlsDetails.valid ? "var(--text-primary)" : "var(--status-fail-text)"
                  }}
                >
                  {results.tlsDetails.protocol || "Insecure"}
                </div>
              </div>
              <div className="metric-foot">
                {results.tlsDetails.daysRemaining !== null 
                  ? `${results.tlsDetails.daysRemaining} days valid` 
                  : "No valid SSL"}
              </div>
            </div>

            {/* Email Anti-Spoofing */}
            <div className="metric-panel">
              <div>
                <div className="metric-label">Anti-Spoofing</div>
                <div 
                  className="metric-value"
                  style={{
                    color: results.dnsDetails.dmarcRecord ? "var(--status-pass-text)" : "var(--status-warn-text)"
                  }}
                >
                  {results.dnsDetails.dmarcPolicy ? `DMARC: ${results.dnsDetails.dmarcPolicy}` : "No DMARC"}
                </div>
              </div>
              <div className="metric-foot">
                SPF: {results.dnsDetails.spfPolicy || "Missing"}
              </div>
            </div>

            {/* Attack Surface Exposure */}
            <div className="metric-panel">
              <div>
                <div className="metric-label">Attack Surface</div>
                <div 
                  className="metric-value"
                  style={{
                    color: results.surfaceDetails.probedEndpoints.some(e => e.exposed && (e.risk === "Critical" || e.risk === "High"))
                      ? "var(--status-fail-text)" : "var(--status-pass-text)"
                  }}
                >
                  {results.surfaceDetails.probedEndpoints.filter(e => e.exposed && (e.risk === "Critical" || e.risk === "High")).length} Leaks
                </div>
              </div>
              <div className="metric-foot">9 endpoints probed</div>
            </div>

          </div>

          {/* ── 5 Pillars Row ─────────────────────────────────────────── */}
          <div className="pillars-container">
            {Object.entries(results.pillars).map(([key, pillar]) => {
              const pColor = pillar.score >= 85 ? "var(--status-pass-text)" :
                             pillar.score >= 70 ? "#1e40af" :
                             pillar.score >= 50 ? "var(--status-warn-text)" : "var(--status-fail-text)";
              const pBarColor = pillar.score >= 85 ? "#16a34a" :
                                pillar.score >= 70 ? "#2563eb" :
                                pillar.score >= 50 ? "#d97706" : "#dc2626";
              return (
                <div key={key} className="pillar-item">
                  <div className="pillar-name-row">
                    <span>{pillar.name}</span>
                    <span style={{ color: pColor, fontWeight: 700 }}>
                      {pillar.grade} ({pillar.score}%)
                    </span>
                  </div>
                  <div className="pillar-bar-track">
                    <div className="pillar-bar-fill" style={{ width: `${pillar.score}%`, background: pBarColor }} />
                  </div>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.7rem", color: "var(--text-muted)" }}>
                    <span>{pillar.passCount}/{pillar.totalCount} passed</span>
                    <span>{pillar.score >= 80 ? "Hardened" : "Remediate"}</span>
                  </div>
                </div>
              );
            })}
          </div>

          {/* ── Tab Navigation Strip ──────────────────────────────────── */}
          <div className="nav-tab-strip">
            <button
              type="button"
              className={`tab-pill-btn ${activeTab === "findings" ? "active" : ""}`}
              onClick={() => setActiveTab("findings")}
            >
              <span>Security Findings</span>
              <span className="badge-counter">{results.checks.length}</span>
            </button>
            <button
              type="button"
              className={`tab-pill-btn ${activeTab === "exploit" ? "active" : ""}`}
              onClick={() => setActiveTab("exploit")}
            >
              <span>Threat Model &amp; Exploits</span>
              <span className="badge-counter">{results.exploitChains.length}</span>
            </button>
            <button
              type="button"
              className={`tab-pill-btn ${activeTab === "remediation" ? "active" : ""}`}
              onClick={() => setActiveTab("remediation")}
            >
              <span>Hardened Configs</span>
            </button>
            <button
              type="button"
              className={`tab-pill-btn ${activeTab === "compliance" ? "active" : ""}`}
              onClick={() => setActiveTab("compliance")}
            >
              <span>Compliance Controls</span>
            </button>
            <button
              type="button"
              className={`tab-pill-btn ${activeTab === "telemetry" ? "active" : ""}`}
              onClick={() => setActiveTab("telemetry")}
            >
              <span>Network Telemetry</span>
            </button>
          </div>

          {/* ── TAB: FINDINGS ─────────────────────────────────────────── */}
          {activeTab === "findings" && (
            <div>
              <div style={{ display: "flex", gap: "0.5rem", marginBottom: "1rem", flexWrap: "wrap", alignItems: "center" }}>
                <span style={{ fontSize: "0.75rem", fontWeight: 700, color: "var(--text-muted)", textTransform: "uppercase" }}>Filter:</span>
                <button
                  type="button"
                  className={`platform-tab-btn ${findingFilter === "all" ? "active" : ""}`}
                  onClick={() => setFindingFilter("all")}
                >
                  All ({results.checks.length})
                </button>
                <button
                  type="button"
                  className={`platform-tab-btn ${findingFilter === "critical" ? "active" : ""}`}
                  onClick={() => setFindingFilter("critical")}
                >
                  Critical &amp; High ({results.checks.filter(c => c.severity === "critical" || c.severity === "high").length})
                </button>
                <button
                  type="button"
                  className={`platform-tab-btn ${findingFilter === "warn" ? "active" : ""}`}
                  onClick={() => setFindingFilter("warn")}
                >
                  Warnings ({results.checks.filter(c => c.status === "warn" || c.severity === "medium").length})
                </button>
                <button
                  type="button"
                  className={`platform-tab-btn ${findingFilter === "pass" ? "active" : ""}`}
                  onClick={() => setFindingFilter("pass")}
                >
                  Passed ({results.checks.filter(c => c.status === "pass").length})
                </button>
              </div>

              {filteredChecks.map((check) => (
                <div key={check.id} className="finding-item-card">
                  <div className="finding-top-row">
                    <div style={{ display: "flex", alignItems: "center", gap: "0.6rem", flexWrap: "wrap" }}>
                      <span className={`pill-status ${check.severity}`}>
                        {check.severity}
                      </span>
                      {check.cwe && (
                        <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.7rem", color: "var(--text-muted)", background: "var(--bg-subtle)", padding: "0.15rem 0.45rem", borderRadius: "4px" }}>
                          {check.cwe}
                        </span>
                      )}
                      <h3 className="finding-title-text">{check.title}</h3>
                    </div>
                    <span style={{ fontSize: "0.72rem", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: 600 }}>
                      {check.category}
                    </span>
                  </div>

                  <p className="finding-description">{check.description}</p>

                  {check.recommendation && (
                    <div className="finding-fix-box">
                      <strong>Remediation:</strong> {check.recommendation}
                    </div>
                  )}

                  {check.rawDetails && (
                    <div className="raw-evidence-block">
                      <strong>Raw Evidence:</strong> {check.rawDetails}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* ── TAB: EXPLOIT CHAINS ───────────────────────────────────── */}
          {activeTab === "exploit" && (
            <div>
              <div style={{ marginBottom: "1.25rem" }}>
                <h3 style={{ fontSize: "1.15rem", fontWeight: 700, color: "var(--text-primary)" }}>
                  Adversarial Attack Simulation
                </h3>
                <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)", marginTop: "0.2rem" }}>
                  Demonstrates how unauthenticated attackers chain the discovered perimeter gaps to compromise user data.
                </p>
              </div>

              {results.exploitChains.length === 0 ? (
                <div className="finding-item-card" style={{ textAlign: "center", padding: "2.5rem" }}>
                  <CheckIcon size={24} className="text-emerald-600" />
                  <h4 style={{ fontSize: "1rem", fontWeight: 700, color: "var(--status-pass-text)", marginTop: "0.5rem" }}>
                    No Critical Exploit Vectors Detected
                  </h4>
                  <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)", marginTop: "0.25rem" }}>
                    This host maintains baseline defensive controls preventing multi-stage credential theft.
                  </p>
                </div>
              ) : (
                results.exploitChains.map((chain, idx) => (
                  <div key={idx} className="exploit-flow-card">
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "0.75rem", flexWrap: "wrap", gap: "0.5rem" }}>
                      <h4 style={{ fontSize: "1rem", fontWeight: 700, color: "var(--status-fail-text)" }}>
                        {chain.title}
                      </h4>
                      <span className="pill-status critical">
                        Threat: {chain.threatLevel}
                      </span>
                    </div>

                    <div style={{ fontSize: "0.82rem", color: "var(--text-secondary)", marginBottom: "0.75rem" }}>
                      <strong>Vector Category:</strong> {chain.attackVector}
                    </div>

                    <div>
                      {chain.steps.map((step, sIdx) => (
                        <div key={sIdx} className="step-row">
                          <div className="step-digit">{sIdx + 1}</div>
                          <div style={{ fontSize: "0.85rem", color: "var(--text-secondary)", paddingTop: "0.15rem" }}>
                            {step}
                          </div>
                        </div>
                      ))}
                    </div>

                    <div style={{ marginTop: "1rem", background: "var(--status-fail-bg)", border: "1px solid var(--status-fail-border)", padding: "0.65rem 0.85rem", borderRadius: "var(--radius-sm)", fontSize: "0.82rem", color: "var(--status-fail-text)" }}>
                      <strong>Business Impact:</strong> {chain.impact}
                    </div>
                  </div>
                ))
              )}
            </div>
          )}

          {/* ── TAB: REMEDIATION ──────────────────────────────────────── */}
          {activeTab === "remediation" && (
            <div className="workbench-container">
              <div className="workbench-bar">
                <div className="platform-selector">
                  <button
                    type="button"
                    className={`platform-tab-btn ${selectedPlatform === "nginx" ? "active" : ""}`}
                    onClick={() => setSelectedPlatform("nginx")}
                  >
                    Nginx
                  </button>
                  <button
                    type="button"
                    className={`platform-tab-btn ${selectedPlatform === "apache" ? "active" : ""}`}
                    onClick={() => setSelectedPlatform("apache")}
                  >
                    Apache
                  </button>
                  <button
                    type="button"
                    className={`platform-tab-btn ${selectedPlatform === "nextjs" ? "active" : ""}`}
                    onClick={() => setSelectedPlatform("nextjs")}
                  >
                    Next.js
                  </button>
                  <button
                    type="button"
                    className={`platform-tab-btn ${selectedPlatform === "vercel" ? "active" : ""}`}
                    onClick={() => setSelectedPlatform("vercel")}
                  >
                    Vercel
                  </button>
                  <button
                    type="button"
                    className={`platform-tab-btn ${selectedPlatform === "dnsRecords" ? "active" : ""}`}
                    onClick={() => setSelectedPlatform("dnsRecords")}
                  >
                    DNS Records
                  </button>
                </div>

                <button
                  type="button"
                  className="btn-outline"
                  onClick={() => handleCopyCode(results.remediationConfigs[selectedPlatform])}
                  style={{ fontSize: "0.78rem" }}
                >
                  {copiedCode ? (
                    <>
                      <CheckIcon size={14} className="text-emerald-600" />
                      <span>Copied!</span>
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
                <code>{results.remediationConfigs[selectedPlatform]}</code>
              </pre>
            </div>
          )}

          {/* ── TAB: COMPLIANCE ───────────────────────────────────────── */}
          {activeTab === "compliance" && (
            <div>
              <div style={{ background: "#ffffff", border: "1px solid var(--border-light)", borderRadius: "var(--radius-md)", overflow: "hidden" }}>
                <table className="clean-table">
                  <thead>
                    <tr>
                      <th>Framework</th>
                      <th>Control ID</th>
                      <th>Mandate</th>
                      <th>Audit Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {results.compliance.map((c, i) => (
                      <tr key={i}>
                        <td style={{ fontWeight: 600 }}>{c.framework}</td>
                        <td style={{ fontFamily: "var(--font-mono)", fontSize: "0.8rem", color: "var(--text-muted)" }}>{c.controlId}</td>
                        <td>
                          <div style={{ fontWeight: 600, marginBottom: "0.15rem" }}>{c.title}</div>
                          <div style={{ fontSize: "0.78rem", color: "var(--text-secondary)" }}>{c.reason}</div>
                        </td>
                        <td>
                          <span className={`pill-status ${c.status === "compliant" ? "pass" : c.status === "partial" ? "medium" : "critical"}`}>
                            {c.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ── TAB: TELEMETRY ────────────────────────────────────────── */}
          {activeTab === "telemetry" && (
            <div>
              <div style={{ background: "#ffffff", border: "1px solid var(--border-light)", borderRadius: "var(--radius-md)", overflow: "hidden", marginBottom: "1.5rem" }}>
                <table className="clean-table">
                  <thead>
                    <tr>
                      <th>Probed Target Path</th>
                      <th>Risk</th>
                      <th>HTTP Status</th>
                      <th>Status Assessment</th>
                    </tr>
                  </thead>
                  <tbody>
                    {results.surfaceDetails.probedEndpoints.map((ep, i) => (
                      <tr key={i}>
                        <td style={{ fontFamily: "var(--font-mono)" }}>{ep.path}</td>
                        <td>
                          <span className={`pill-status ${ep.risk.toLowerCase()}`}>
                            {ep.risk}
                          </span>
                        </td>
                        <td style={{ fontFamily: "var(--font-mono)" }}>{ep.status}</td>
                        <td style={{ fontWeight: 600, color: ep.exposed ? "var(--status-fail-text)" : "var(--status-pass-text)" }}>
                          {ep.exposed ? "EXPOSED" : "Blocked"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
                <div style={{ background: "#ffffff", border: "1px solid var(--border-light)", borderRadius: "var(--radius-md)", padding: "1.25rem" }}>
                  <div className="metric-label">Subject Alternative Names (SANs)</div>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.78rem", color: "var(--text-secondary)", lineHeight: 1.6, marginTop: "0.5rem" }}>
                    {results.tlsDetails.sans.length > 0 
                      ? results.tlsDetails.sans.slice(0, 8).join(", ") 
                      : "None provided"}
                  </div>
                </div>
                <div style={{ background: "#ffffff", border: "1px solid var(--border-light)", borderRadius: "var(--radius-md)", padding: "1.25rem" }}>
                  <div className="metric-label">Mail Exchanger (MX) Records</div>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.78rem", color: "var(--text-secondary)", lineHeight: 1.6, marginTop: "0.5rem" }}>
                    {results.dnsDetails.mxRecords.length > 0
                      ? results.dnsDetails.mxRecords.join("\n")
                      : "No MX records found"}
                  </div>
                </div>
              </div>
            </div>
          )}

        </div>
      )}

      {/* ── Empty State Showcase ───────────────────────────────────── */}
      {!results && !loading && (
        <section style={{ marginTop: "4rem", borderTop: "1px solid var(--border-light)", paddingTop: "3rem" }}>
          <div style={{ textAlign: "center", marginBottom: "2.5rem" }}>
            <h2 style={{ fontSize: "1.5rem", fontWeight: 700, color: "var(--text-primary)", letterSpacing: "-0.02em" }}>
              Defense-in-Depth Architecture
            </h2>
            <p style={{ fontSize: "0.9rem", color: "var(--text-secondary)", marginTop: "0.4rem" }}>
              Passive inspection across perimeter, transport, identity, and compliance vectors.
            </p>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: "1.25rem" }}>
            <div style={{ background: "#ffffff", border: "1px solid var(--border-light)", borderRadius: "var(--radius-md)", padding: "1.25rem" }}>
              <div style={{ width: "32px", height: "32px", borderRadius: "6px", background: "var(--bg-subtle)", display: "flex", alignItems: "center", justifyContent: "center", marginBottom: "0.75rem", border: "1px solid var(--border-light)" }}>
                <ShieldIcon size={16} />
              </div>
              <h3 style={{ fontSize: "0.95rem", fontWeight: 700, color: "var(--text-primary)", marginBottom: "0.35rem" }}>
                Perimeter Headers
              </h3>
              <p style={{ fontSize: "0.82rem", color: "var(--text-secondary)", lineHeight: 1.5 }}>
                Evaluates CSP directives, HSTS preload, X-Frame-Options clickjacking defense, and MIME sniffing protection.
              </p>
            </div>

            <div style={{ background: "#ffffff", border: "1px solid var(--border-light)", borderRadius: "var(--radius-md)", padding: "1.25rem" }}>
              <div style={{ width: "32px", height: "32px", borderRadius: "6px", background: "var(--bg-subtle)", display: "flex", alignItems: "center", justifyContent: "center", marginBottom: "0.75rem", border: "1px solid var(--border-light)" }}>
                <LockIcon size={16} />
              </div>
              <h3 style={{ fontSize: "0.95rem", fontWeight: 700, color: "var(--text-primary)", marginBottom: "0.35rem" }}>
                TLS 1.3 Cryptography
              </h3>
              <p style={{ fontSize: "0.82rem", color: "var(--text-secondary)", lineHeight: 1.5 }}>
                Validates handshake protocols, cipher suite strength, CA issuer, expiration alerts, and ALPN HTTP/2 support.
              </p>
            </div>

            <div style={{ background: "#ffffff", border: "1px solid var(--border-light)", borderRadius: "var(--radius-md)", padding: "1.25rem" }}>
              <div style={{ width: "32px", height: "32px", borderRadius: "6px", background: "var(--bg-subtle)", display: "flex", alignItems: "center", justifyContent: "center", marginBottom: "0.75rem", border: "1px solid var(--border-light)" }}>
                <CheckIcon size={16} />
              </div>
              <h3 style={{ fontSize: "0.95rem", fontWeight: 700, color: "var(--text-primary)", marginBottom: "0.35rem" }}>
                DNS &amp; Anti-Spoofing
              </h3>
              <p style={{ fontSize: "0.82rem", color: "var(--text-secondary)", lineHeight: 1.5 }}>
                Checks Sender Policy Framework (SPF), DMARC rejection policies, CAA certificate limits, and IPv6 readiness.
              </p>
            </div>

            <div style={{ background: "#ffffff", border: "1px solid var(--border-light)", borderRadius: "var(--radius-md)", padding: "1.25rem" }}>
              <div style={{ width: "32px", height: "32px", borderRadius: "6px", background: "var(--bg-subtle)", display: "flex", alignItems: "center", justifyContent: "center", marginBottom: "0.75rem", border: "1px solid var(--border-light)" }}>
                <FileCodeIcon size={16} />
              </div>
              <h3 style={{ fontSize: "0.95rem", fontWeight: 700, color: "var(--text-primary)", marginBottom: "0.35rem" }}>
                Secret Leak Probing
              </h3>
              <p style={{ fontSize: "0.82rem", color: "var(--text-secondary)", lineHeight: 1.5 }}>
                Probes for exposure of sensitive environment variables, git directories, and RFC 9116 security.txt policies.
              </p>
            </div>
          </div>
        </section>
      )}

    </div>
  );
}
