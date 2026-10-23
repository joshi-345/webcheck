import Link from "next/link";

export function Footer() {
  return (
    <footer className="site-footer">
      <div className="footer-container">
        <div className="footer-left">
          <span className="footer-title">AegisX Threat Intelligence</span>
          <p className="footer-sub">
            Passive, non-intrusive cybersecurity auditing and attack surface management.
          </p>
          <div className="footer-credits">
            Architected by <strong>Alisha</strong> during Cyber Defense Training at <strong>Cadpoint Computers</strong>
          </div>
        </div>

        <div className="footer-nav">
          <div className="footer-col">
            <span className="footer-col-title">Platform</span>
            <Link href="/" className="footer-link">Audit Console</Link>
            <Link href="/compare" className="footer-link">Domain Compare</Link>
            <Link href="/sandbox" className="footer-link">Attack Sandbox</Link>
            <Link href="/tools/remediation" className="footer-link">Hardening Workbench</Link>
            <Link href="/compliance" className="footer-link">Compliance Controls</Link>
          </div>
          <div className="footer-col">
            <span className="footer-col-title">Knowledge</span>
            <Link href="/standards" className="footer-link">OWASP &amp; Headers</Link>
            <a href="https://cwe.mitre.org" target="_blank" rel="noreferrer" className="footer-link">CWE Taxonomy</a>
            <a href="https://www.rfc-editor.org/rfc/rfc9116" target="_blank" rel="noreferrer" className="footer-link">RFC 9116 security.txt</a>
          </div>
        </div>
      </div>
      <div className="footer-bottom">
        <span>© {new Date().getFullYear()} AegisX Security Lab. All rights reserved.</span>
        <span>Local Audit Engine: Active</span>
      </div>
    </footer>
  );
}
