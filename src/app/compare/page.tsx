"use client";

import { useState } from "react";
import type { ScanResults } from "@/utils/scanner";
import { 
  SearchIcon, 
  CheckIcon, 
  AlertTriangleIcon, 
  XCircleIcon, 
  PrinterIcon,
  RefreshCwIcon,
  DownloadIcon,
  ShieldIcon 
} from "@/components/Icons";

const PRESET_PAIRS = [
  { a: "httpbin.org", b: "github.com", label: "Unhardened vs Enterprise (httpbin vs GitHub)" },
  { a: "stripe.com", b: "cloudflare.com", label: "Fintech vs Edge CDN (Stripe vs Cloudflare)" },
  { a: "google.com", b: "github.com", label: "Tech Titans (Google vs GitHub)" },
];

interface ComparisonFeature {
  name: string;
  category: string;
  getValA: (r: ScanResults) => { status: "pass" | "warn" | "fail"; label: string };
  getValB: (r: ScanResults) => { status: "pass" | "warn" | "fail"; label: string };
}

const COMPARISON_FEATURES: ComparisonFeature[] = [
  {
    name: "Content-Security-Policy (CSP)",
    category: "Perimeter",
    getValA: (r) => {
      const c = r.checks.find(chk => chk.id.includes("csp"));
      return { status: c?.status || "fail", label: c?.status === "pass" ? "Enforced" : c?.status === "warn" ? "Permissive" : "Missing" };
    },
    getValB: (r) => {
      const c = r.checks.find(chk => chk.id.includes("csp"));
      return { status: c?.status || "fail", label: c?.status === "pass" ? "Enforced" : c?.status === "warn" ? "Permissive" : "Missing" };
    }
  },
  {
    name: "Strict-Transport-Security (HSTS)",
    category: "Perimeter",
    getValA: (r) => {
      const c = r.checks.find(chk => chk.id.includes("hsts"));
      return { status: c?.status || "fail", label: c?.status === "pass" ? "Active" : c?.status === "warn" ? "Weak" : "Missing" };
    },
    getValB: (r) => {
      const c = r.checks.find(chk => chk.id.includes("hsts"));
      return { status: c?.status || "fail", label: c?.status === "pass" ? "Active" : c?.status === "warn" ? "Weak" : "Missing" };
    }
  },
  {
    name: "Clickjacking Defense (X-Frame-Options)",
    category: "Perimeter",
    getValA: (r) => {
      const c = r.checks.find(chk => chk.id.includes("xfo"));
      return { status: c?.status || "fail", label: c?.status === "pass" ? "Protected" : "Vulnerable" };
    },
    getValB: (r) => {
      const c = r.checks.find(chk => chk.id.includes("xfo"));
      return { status: c?.status || "fail", label: c?.status === "pass" ? "Protected" : "Vulnerable" };
    }
  },
  {
    name: "MIME-Sniffing Defense (XCTO)",
    category: "Perimeter",
    getValA: (r) => {
      const c = r.checks.find(chk => chk.id.includes("xcto"));
      return { status: c?.status || "fail", label: c?.status === "pass" ? "nosniff" : "Missing" };
    },
    getValB: (r) => {
      const c = r.checks.find(chk => chk.id.includes("xcto"));
      return { status: c?.status || "fail", label: c?.status === "pass" ? "nosniff" : "Missing" };
    }
  },
  {
    name: "TLS Protocol Level",
    category: "Transport",
    getValA: (r) => {
      const is13 = r.tlsDetails.protocol === "TLSv1.3";
      return { status: is13 ? "pass" : r.tlsDetails.valid ? "warn" : "fail", label: r.tlsDetails.protocol || "Insecure" };
    },
    getValB: (r) => {
      const is13 = r.tlsDetails.protocol === "TLSv1.3";
      return { status: is13 ? "pass" : r.tlsDetails.valid ? "warn" : "fail", label: r.tlsDetails.protocol || "Insecure" };
    }
  },
  {
    name: "SSL Certificate Chain",
    category: "Transport",
    getValA: (r) => {
      return { status: r.tlsDetails.valid ? "pass" : "fail", label: r.tlsDetails.valid ? `Valid (${r.tlsDetails.daysRemaining}d)` : "Invalid" };
    },
    getValB: (r) => {
      return { status: r.tlsDetails.valid ? "pass" : "fail", label: r.tlsDetails.valid ? `Valid (${r.tlsDetails.daysRemaining}d)` : "Invalid" };
    }
  },
  {
    name: "SPF Email Spoofing Defense",
    category: "DNS",
    getValA: (r) => {
      const hasSpf = !!r.dnsDetails.spfRecord;
      return { status: hasSpf ? "pass" : "fail", label: r.dnsDetails.spfPolicy || "Missing" };
    },
    getValB: (r) => {
      const hasSpf = !!r.dnsDetails.spfRecord;
      return { status: hasSpf ? "pass" : "fail", label: r.dnsDetails.spfPolicy || "Missing" };
    }
  },
  {
    name: "DMARC Enforcement Policy",
    category: "DNS",
    getValA: (r) => {
      const p = r.dnsDetails.dmarcPolicy;
      return { status: p === "reject" || p === "quarantine" ? "pass" : p === "none" ? "warn" : "fail", label: p ? `p=${p}` : "Missing" };
    },
    getValB: (r) => {
      const p = r.dnsDetails.dmarcPolicy;
      return { status: p === "reject" || p === "quarantine" ? "pass" : p === "none" ? "warn" : "fail", label: p ? `p=${p}` : "Missing" };
    }
  },
  {
    name: "CAA Certificate Issuer Lockdown",
    category: "DNS",
    getValA: (r) => {
      const hasCaa = r.dnsDetails.caaRecords.length > 0;
      return { status: hasCaa ? "pass" : "warn", label: hasCaa ? "Locked" : "Open" };
    },
    getValB: (r) => {
      const hasCaa = r.dnsDetails.caaRecords.length > 0;
      return { status: hasCaa ? "pass" : "warn", label: hasCaa ? "Locked" : "Open" };
    }
  },
  {
    name: "Public Dotfiles & Secrets (.env / .git)",
    category: "Surface",
    getValA: (r) => {
      const leaks = r.surfaceDetails.probedEndpoints.filter(e => e.exposed && (e.risk === "Critical" || e.risk === "High")).length;
      return { status: leaks === 0 ? "pass" : "fail", label: leaks === 0 ? "Secure (0 leaks)" : `${leaks} Leaks!` };
    },
    getValB: (r) => {
      const leaks = r.surfaceDetails.probedEndpoints.filter(e => e.exposed && (e.risk === "Critical" || e.risk === "High")).length;
      return { status: leaks === 0 ? "pass" : "fail", label: leaks === 0 ? "Secure (0 leaks)" : `${leaks} Leaks!` };
    }
  },
  {
    name: "RFC 9116 security.txt",
    category: "Surface",
    getValA: (r) => {
      return { status: r.surfaceDetails.securityTxtFound ? "pass" : "warn", label: r.surfaceDetails.securityTxtFound ? "Published" : "Missing" };
    },
    getValB: (r) => {
      return { status: r.surfaceDetails.securityTxtFound ? "pass" : "warn", label: r.surfaceDetails.securityTxtFound ? "Published" : "Missing" };
    }
  }
];

export default function DomainComparePage() {
  const [urlA, setUrlA] = useState("httpbin.org");
  const [urlB, setUrlB] = useState("github.com");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [resultA, setResultA] = useState<ScanResults | null>(null);
  const [resultB, setResultB] = useState<ScanResults | null>(null);

  const runComparison = async (targetA: string, targetB: string) => {
    if (!targetA.trim() || !targetB.trim()) return;
    setLoading(true);
    setError("");
    setResultA(null);
    setResultB(null);

    try {
      const [resA, resB] = await Promise.all([
        fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: targetA }),
        }),
        fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: targetB }),
        })
      ]);

      const [dataA, dataB] = await Promise.all([resA.json(), resB.json()]);

      if (!resA.ok) throw new Error(`Target A scan failed: ${dataA.error || "Unable to reach domain"}`);
      if (!resB.ok) throw new Error(`Target B scan failed: ${dataB.error || "Unable to reach domain"}`);

      setResultA(dataA);
      setResultB(dataB);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Comparison failed.");
    } finally {
      setLoading(false);
    }
  };

  const handlePairClick = (pair: { a: string; b: string }) => {
    setUrlA(pair.a);
    setUrlB(pair.b);
    runComparison(pair.a, pair.b);
  };

  const handleExportComparison = () => {
    if (!resultA || !resultB) return;
    const blob = new Blob([JSON.stringify({ targetA: resultA, targetB: resultB }, null, 2)], { type: "application/json" });
    const dlUrl = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = dlUrl;
    a.download = `aegisx-comparison-${resultA.target.hostname}-vs-${resultB.target.hostname}.json`;
    a.click();
    URL.revokeObjectURL(dlUrl);
  };

  return (
    <div style={{ maxWidth: "1100px", margin: "0 auto" }}>
      <div style={{ marginBottom: "2rem" }}>
        <span className="page-category-tag">Benchmarking Engine</span>
        <h1 style={{ fontSize: "2rem", fontWeight: 800, color: "var(--text-primary)", letterSpacing: "-0.02em", marginBottom: "0.5rem" }}>
          Domain Security Posture Comparison
        </h1>
        <p style={{ color: "var(--text-secondary)", fontSize: "0.95rem", lineHeight: 1.6 }}>
          Run head-to-head differential audits to compare your application against industry leaders, 
          verify staging vs. production defensive parity, or audit third-party vendor risk.
        </p>
      </div>

      {/* Dual Search Console */}
      <div style={{ background: "var(--bg-subtle)", border: "1px solid var(--border-light)", borderRadius: "var(--radius-md)", padding: "1.25rem", marginBottom: "1.5rem" }}>
        <form onSubmit={(e) => { e.preventDefault(); runComparison(urlA, urlB); }}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem", marginBottom: "1rem" }}>
            <div>
              <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 700, color: "var(--text-secondary)", textTransform: "uppercase", marginBottom: "0.35rem" }}>
                Target Domain A (Baseline)
              </label>
              <input
                type="text"
                value={urlA}
                onChange={(e) => setUrlA(e.target.value)}
                placeholder="yourdomain.com"
                required
                style={{
                  width: "100%",
                  background: "#ffffff",
                  border: "1px solid var(--border-mid)",
                  borderRadius: "var(--radius-sm)",
                  padding: "0.55rem 0.75rem",
                  fontFamily: "var(--font-mono)",
                  fontSize: "0.9rem",
                  color: "var(--text-primary)",
                  outline: "none"
                }}
              />
            </div>

            <div>
              <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 700, color: "var(--text-secondary)", textTransform: "uppercase", marginBottom: "0.35rem" }}>
                Target Domain B (Benchmark)
              </label>
              <input
                type="text"
                value={urlB}
                onChange={(e) => setUrlB(e.target.value)}
                placeholder="competitor.com or stripe.com"
                required
                style={{
                  width: "100%",
                  background: "#ffffff",
                  border: "1px solid var(--border-mid)",
                  borderRadius: "var(--radius-sm)",
                  padding: "0.55rem 0.75rem",
                  fontFamily: "var(--font-mono)",
                  fontSize: "0.9rem",
                  color: "var(--text-primary)",
                  outline: "none"
                }}
              />
            </div>
          </div>

          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "1rem" }}>
            <div style={{ display: "flex", gap: "0.45rem", flexWrap: "wrap", alignItems: "center" }}>
              <span style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontWeight: 600 }}>Preset Pairs:</span>
              {PRESET_PAIRS.map((p, idx) => (
                <button
                  key={idx}
                  type="button"
                  className="preset-chip"
                  onClick={() => handlePairClick(p)}
                >
                  {p.label}
                </button>
              ))}
            </div>

            <button
              type="submit"
              disabled={loading}
              className="clean-scan-btn"
              style={{ padding: "0.55rem 1.25rem" }}
            >
              {loading ? (
                <>
                  <div className="loading-spinner-circle" style={{ width: "14px", height: "14px", borderTopColor: "#fff" }} />
                  <span>Comparing Hosts...</span>
                </>
              ) : (
                <>
                  <SearchIcon size={14} />
                  <span>Compare Domains</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Error state */}
      {error && (
        <div style={{ background: "var(--status-fail-bg)", border: "1px solid var(--status-fail-border)", borderRadius: "var(--radius-md)", padding: "1rem 1.25rem", color: "var(--status-fail-text)", display: "flex", alignItems: "center", gap: "0.75rem", fontSize: "0.88rem", marginBottom: "1.5rem" }}>
          <AlertTriangleIcon size={18} />
          <div>{error}</div>
        </div>
      )}

      {/* Comparison Results */}
      {resultA && resultB && !loading && (
        <div>
          {/* Executive Scorecard Diff */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem", marginBottom: "1.5rem" }}>
            
            {/* Host A Card */}
            <div style={{ background: "#ffffff", border: "1px solid var(--border-light)", borderRadius: "var(--radius-md)", padding: "1.25rem" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "0.75rem" }}>
                <span style={{ fontSize: "1.15rem", fontWeight: 700, color: "var(--text-primary)" }}>
                  {resultA.target.hostname}
                </span>
                <span className={`pill-status ${resultA.metrics.grade === "A+" || resultA.metrics.grade === "A" ? "pass" : resultA.metrics.grade === "B" ? "low" : resultA.metrics.grade === "C" ? "medium" : "critical"}`}>
                  Grade {resultA.metrics.grade}
                </span>
              </div>
              <div style={{ fontSize: "2rem", fontWeight: 800, color: "var(--text-primary)", letterSpacing: "-0.02em" }}>
                {resultA.metrics.overallScore} <span style={{ fontSize: "0.95rem", color: "var(--text-muted)", fontWeight: 500 }}>/ 100</span>
              </div>
              <div style={{ fontSize: "0.8rem", color: "var(--text-secondary)", marginTop: "0.25rem" }}>
                CVSS Risk: {resultA.metrics.cvssScore.toFixed(1)} | {resultA.metrics.passedChecks}/{resultA.metrics.totalChecks} Checks Passed
              </div>
            </div>

            {/* Host B Card */}
            <div style={{ background: "#ffffff", border: "1px solid var(--border-light)", borderRadius: "var(--radius-md)", padding: "1.25rem" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "0.75rem" }}>
                <span style={{ fontSize: "1.15rem", fontWeight: 700, color: "var(--text-primary)" }}>
                  {resultB.target.hostname}
                </span>
                <span className={`pill-status ${resultB.metrics.grade === "A+" || resultB.metrics.grade === "A" ? "pass" : resultB.metrics.grade === "B" ? "low" : resultB.metrics.grade === "C" ? "medium" : "critical"}`}>
                  Grade {resultB.metrics.grade}
                </span>
              </div>
              <div style={{ fontSize: "2rem", fontWeight: 800, color: "var(--text-primary)", letterSpacing: "-0.02em" }}>
                {resultB.metrics.overallScore} <span style={{ fontSize: "0.95rem", color: "var(--text-muted)", fontWeight: 500 }}>/ 100</span>
              </div>
              <div style={{ fontSize: "0.8rem", color: "var(--text-secondary)", marginTop: "0.25rem" }}>
                CVSS Risk: {resultB.metrics.cvssScore.toFixed(1)} | {resultB.metrics.passedChecks}/{resultB.metrics.totalChecks} Checks Passed
              </div>
            </div>
          </div>

          {/* Action Row */}
          <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.5rem", marginBottom: "1rem" }}>
            <button type="button" onClick={() => window.print()} className="btn-outline">
              <PrinterIcon size={14} />
              <span>Export Comparison PDF</span>
            </button>
            <button type="button" onClick={handleExportComparison} className="btn-outline">
              <DownloadIcon size={14} />
              <span>Export JSON</span>
            </button>
          </div>

          {/* Head-to-Head Control Diff Table */}
          <div style={{ background: "#ffffff", border: "1px solid var(--border-light)", borderRadius: "var(--radius-md)", overflow: "hidden", marginBottom: "2rem" }}>
            <table className="clean-table">
              <thead>
                <tr>
                  <th style={{ width: "35%" }}>Defensive Control Vector</th>
                  <th style={{ width: "15%" }}>Category</th>
                  <th style={{ width: "25%" }}>{resultA.target.hostname}</th>
                  <th style={{ width: "25%" }}>{resultB.target.hostname}</th>
                </tr>
              </thead>
              <tbody>
                {COMPARISON_FEATURES.map((feat, i) => {
                  const valA = feat.getValA(resultA);
                  const valB = feat.getValB(resultB);
                  return (
                    <tr key={i}>
                      <td style={{ fontWeight: 600 }}>{feat.name}</td>
                      <td style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>{feat.category}</td>
                      <td>
                        <span className={`pill-status ${valA.status}`}>
                          {valA.label}
                        </span>
                      </td>
                      <td>
                        <span className={`pill-status ${valB.status}`}>
                          {valB.label}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Pillars Comparison Grid */}
          <div style={{ background: "var(--bg-subtle)", border: "1px solid var(--border-light)", borderRadius: "var(--radius-md)", padding: "1.25rem" }}>
            <h3 style={{ fontSize: "1rem", fontWeight: 700, color: "var(--text-primary)", marginBottom: "1rem" }}>
              5-Pillar Differential Scores
            </h3>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: "0.75rem" }}>
              {["perimeter", "crypto", "dns", "surface", "compliance"].map((cat) => {
                const scoreA = (resultA.pillars as any)[cat]?.score || 0;
                const scoreB = (resultB.pillars as any)[cat]?.score || 0;
                const delta = scoreB - scoreA;
                return (
                  <div key={cat} style={{ background: "#ffffff", border: "1px solid var(--border-light)", borderRadius: "var(--radius-sm)", padding: "0.75rem" }}>
                    <div style={{ fontSize: "0.72rem", fontWeight: 700, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: "0.4rem" }}>
                      {cat}
                    </div>
                    <div style={{ fontSize: "0.85rem", color: "var(--text-primary)", display: "flex", justifyContent: "space-between" }}>
                      <span>A: {scoreA}%</span>
                      <span>B: {scoreB}%</span>
                    </div>
                    <div style={{ fontSize: "0.75rem", marginTop: "0.25rem", color: delta > 0 ? "var(--status-pass-text)" : delta < 0 ? "var(--status-fail-text)" : "var(--text-muted)" }}>
                      {delta > 0 ? `+${delta}% (B leads)` : delta < 0 ? `${delta}% (A leads)` : "Equal Parity"}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
