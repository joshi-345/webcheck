import dns from 'node:dns/promises';
import tls from 'node:tls';
import http from 'node:http';
import https from 'node:https';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'pass';

export interface SecurityCheckItem {
  id: string;
  category: 'perimeter' | 'crypto' | 'dns' | 'surface' | 'compliance';
  title: string;
  description: string;
  severity: Severity;
  status: 'pass' | 'fail' | 'warn';
  cwe?: string;
  recommendation?: string;
  rawDetails?: string;
}

export interface PillarScore {
  name: string;
  score: number; // 0 - 100
  passCount: number;
  totalCount: number;
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
}

export interface ComplianceControl {
  framework: 'SOC 2' | 'ISO 27001' | 'PCI-DSS 4.0' | 'HIPAA' | 'GDPR';
  controlId: string;
  title: string;
  status: 'compliant' | 'partial' | 'non-compliant';
  reason: string;
}

export interface ExploitChain {
  title: string;
  attackVector: string;
  steps: string[];
  impact: string;
  threatLevel: 'Critical' | 'High' | 'Medium' | 'Low';
}

export interface RemediationConfigs {
  nginx: string;
  apache: string;
  nextjs: string;
  vercel: string;
  dnsRecords: string;
}

export interface ScanResults {
  target: {
    inputUrl: string;
    hostname: string;
    protocol: string;
    ipAddress?: string;
    scanTimestamp: string;
    scanDurationMs: number;
  };
  metrics: {
    overallScore: number; // 0 - 100
    grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
    gradeLabel: string;
    cvssScore: number; // 0.0 - 10.0
    threatLevel: 'Low Risk' | 'Guarded' | 'Elevated' | 'High Risk' | 'Severe Exposure';
    passedChecks: number;
    totalChecks: number;
  };
  pillars: {
    perimeter: PillarScore;
    crypto: PillarScore;
    dns: PillarScore;
    surface: PillarScore;
    compliance: PillarScore;
  };
  checks: SecurityCheckItem[];
  technologies: {
    server?: string;
    wafOrCdn?: string;
    poweredBy?: string;
    httpVersion?: string;
    detectedStack: string[];
  };
  tlsDetails: {
    valid: boolean;
    authorized: boolean;
    protocol: string | null;
    cipherName: string | null;
    cipherVersion: string | null;
    issuer: string | null;
    validTo: string | null;
    daysRemaining: number | null;
    sans: string[];
    isExpiringSoon: boolean;
    alpnNegotiated?: string | null;
  };
  dnsDetails: {
    spfRecord?: string | null;
    spfPolicy?: 'hardfail' | 'softfail' | 'neutral' | 'none';
    dmarcRecord?: string | null;
    dmarcPolicy?: string | null;
    caaRecords: string[];
    mxRecords: string[];
    ipv6Supported: boolean;
    nameservers: string[];
  };
  surfaceDetails: {
    probedEndpoints: {
      path: string;
      status: number | string;
      exposed: boolean;
      risk: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
    }[];
    robotsDisallowedPaths: string[];
    securityTxtFound: boolean;
  };
  compliance: ComplianceControl[];
  exploitChains: ExploitChain[];
  remediationConfigs: RemediationConfigs;
  aiExecutiveSummary: {
    briefing: string;
    strengths: string[];
    vulnerabilities: string[];
    priorityActions: string[];
  };
}

// Timeout fetch helper
async function fetchWithTimeout(url: string, options: RequestInit = {}, timeoutMs = 6000): Promise<Response> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AegisX-Security-Auditor/2.0 (Security Audit)',
        ...(options.headers || {})
      }
    });
    clearTimeout(id);
    return res;
  } catch (err) {
    clearTimeout(id);
    throw err;
  }
}

export async function runScan(targetUrl: string): Promise<ScanResults> {
  const startTime = Date.now();
  let urlObj: URL;
  try {
    const sanitized = targetUrl.startsWith('http://') || targetUrl.startsWith('https://') 
      ? targetUrl 
      : `https://${targetUrl}`;
    urlObj = new URL(sanitized);
  } catch {
    throw new Error('Invalid URL. Please enter a valid domain or web address (e.g., example.com)');
  }

  const hostname = urlObj.hostname;
  const baseUrl = `${urlObj.protocol}//${hostname}`;
  const isHttps = urlObj.protocol === 'https:';

  const checks: SecurityCheckItem[] = [];
  const detectedStack: string[] = [];

  // 1. PRIMARY HTTP/HTTPS REQUEST & HEADERS
  let responseHeaders: Headers | null = null;
  let serverBanner: string | undefined;
  let poweredByBanner: string | undefined;
  let cdnBanner: string | undefined;
  let httpVersionStr = 'HTTP/1.1';
  let primaryIp: string | undefined;

  try {
    // Resolve IP address
    const ips = await dns.resolve4(hostname).catch(() => []);
    if (ips.length > 0) primaryIp = ips[0];
  } catch {
    // ignore
  }

  try {
    const res = await fetchWithTimeout(baseUrl, { method: 'GET', redirect: 'follow' }, 7000);
    responseHeaders = res.headers;

    serverBanner = responseHeaders.get('server') || undefined;
    poweredByBanner = responseHeaders.get('x-powered-by') || undefined;
    const cfRay = responseHeaders.get('cf-ray');
    const xCache = responseHeaders.get('x-cache');
    const via = responseHeaders.get('via');

    if (cfRay || serverBanner?.toLowerCase().includes('cloudflare')) {
      cdnBanner = 'Cloudflare WAF / CDN';
      detectedStack.push('Cloudflare');
    } else if (via?.toLowerCase().includes('cloudfront') || xCache?.toLowerCase().includes('cloudfront')) {
      cdnBanner = 'AWS CloudFront';
      detectedStack.push('AWS CloudFront');
    } else if (via?.toLowerCase().includes('fastly')) {
      cdnBanner = 'Fastly Edge CDN';
      detectedStack.push('Fastly');
    } else if (responseHeaders.get('x-vercel-id')) {
      cdnBanner = 'Vercel Edge Network';
      detectedStack.push('Vercel');
    }

    if (serverBanner) detectedStack.push(`Server: ${serverBanner}`);
    if (poweredByBanner) detectedStack.push(`Engine: ${poweredByBanner}`);

  } catch (err: any) {
    // If fetch failed on HTTPS, try fallback or note error
    checks.push({
      id: 'http-connect-fail',
      category: 'perimeter',
      title: 'HTTP Service Reachability',
      description: `Target server connection error: ${err.message || 'Timed out'}`,
      severity: 'critical',
      status: 'fail',
      recommendation: 'Ensure port 80/443 is open and server is configured to accept public HTTPS requests.',
    });
  }

  // --- Header checks ---
  const cspHeader = responseHeaders?.get('content-security-policy');
  const hstsHeader = responseHeaders?.get('strict-transport-security');
  const xfoHeader = responseHeaders?.get('x-frame-options');
  const xctoHeader = responseHeaders?.get('x-content-type-options');
  const referrerHeader = responseHeaders?.get('referrer-policy');
  const permissionsHeader = responseHeaders?.get('permissions-policy') || responseHeaders?.get('feature-policy');
  const coopHeader = responseHeaders?.get('cross-origin-opener-policy');
  const corpHeader = responseHeaders?.get('cross-origin-resource-policy');
  const setCookieHeader = responseHeaders?.get('set-cookie');

  // CSP
  if (cspHeader) {
    const hasUnsafe = /'unsafe-inline'|'unsafe-eval'/i.test(cspHeader);
    if (hasUnsafe) {
      checks.push({
        id: 'header-csp-unsafe',
        category: 'perimeter',
        title: 'Content-Security-Policy (CSP) - Unsafe Directives Present',
        description: 'CSP is present, but contains "unsafe-inline" or "unsafe-eval", which degrades defense against Cross-Site Scripting (XSS).',
        severity: 'medium',
        status: 'warn',
        cwe: 'CWE-79',
        recommendation: 'Migrate script tags to cryptographic nonces (nonce-...) or SHA-256 hashes instead of allowing unsafe-inline.',
        rawDetails: cspHeader.slice(0, 160) + (cspHeader.length > 160 ? '...' : '')
      });
    } else {
      checks.push({
        id: 'header-csp-pass',
        category: 'perimeter',
        title: 'Content-Security-Policy (CSP) - Strictly Enforced',
        description: 'Robust CSP detected. Prevents Cross-Site Scripting (XSS), malicious code execution, and data exfiltration.',
        severity: 'pass',
        status: 'pass',
        recommendation: 'Maintain continuous CSP monitoring with report-to or report-uri endpoints.',
        rawDetails: cspHeader.slice(0, 140) + '...'
      });
    }
  } else {
    checks.push({
      id: 'header-csp-missing',
      category: 'perimeter',
      title: 'Content-Security-Policy (CSP) Missing',
      description: 'No Content-Security-Policy header returned. Site is vulnerable to stored, reflected, and DOM-based Cross-Site Scripting (XSS).',
      severity: 'high',
      status: 'fail',
      cwe: 'CWE-79',
      recommendation: 'Deploy a Content-Security-Policy restricting script-src, object-src, and frame-ancestors.',
    });
  }

  // HSTS
  if (hstsHeader) {
    const hasSubdomains = /includesubdomains/i.test(hstsHeader);
    const hasPreload = /preload/i.test(hstsHeader);
    const maxAgeMatch = hstsHeader.match(/max-age=(\d+)/i);
    const maxAgeSec = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
    const isLongEnough = maxAgeSec >= 15552000; // >= 180 days

    if (isLongEnough && hasSubdomains) {
      checks.push({
        id: 'header-hsts-strong',
        category: 'perimeter',
        title: 'Strict-Transport-Security (HSTS) - Enterprise Hardened',
        description: `HSTS configured with max-age=${maxAgeSec}s (${Math.round(maxAgeSec / 86400)} days), includeSubDomains: ${hasSubdomains}, preload: ${hasPreload}.`,
        severity: 'pass',
        status: 'pass',
        recommendation: hasPreload ? 'HSTS Preload is active.' : 'Consider adding "preload" and submitting domain to hstspreload.org.',
        rawDetails: hstsHeader
      });
    } else {
      checks.push({
        id: 'header-hsts-weak',
        category: 'perimeter',
        title: 'Strict-Transport-Security (HSTS) - Weak Configuration',
        description: `HSTS is present but has a short duration (${maxAgeSec}s) or is missing includeSubDomains.`,
        severity: 'medium',
        status: 'warn',
        cwe: 'CWE-319',
        recommendation: 'Set max-age=31536000; includeSubDomains; preload in your HSTS header.',
        rawDetails: hstsHeader
      });
    }
  } else {
    checks.push({
      id: 'header-hsts-missing',
      category: 'perimeter',
      title: 'Strict-Transport-Security (HSTS) Missing',
      description: 'Browsers may attempt unencrypted HTTP connections, opening users up to SSL-stripping and Man-in-the-Middle (MITM) attacks.',
      severity: 'high',
      status: 'fail',
      cwe: 'CWE-319',
      recommendation: 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload".',
    });
  }

  // X-Frame-Options
  if (xfoHeader) {
    checks.push({
      id: 'header-xfo-pass',
      category: 'perimeter',
      title: 'X-Frame-Options Clickjacking Defense',
      description: `X-Frame-Options is set to "${xfoHeader}". Prevents iframe clickjacking attacks.`,
      severity: 'pass',
      status: 'pass',
      recommendation: 'Keep active or pair with CSP frame-ancestors.',
      rawDetails: xfoHeader
    });
  } else {
    checks.push({
      id: 'header-xfo-missing',
      category: 'perimeter',
      title: 'X-Frame-Options Missing (Clickjacking Vulnerability)',
      description: 'This web page can be embedded inside unauthorized iframes on external domains, facilitating UI redress attacks.',
      severity: 'medium',
      status: 'fail',
      cwe: 'CWE-1021',
      recommendation: 'Set "X-Frame-Options: DENY" or "SAMEORIGIN".',
    });
  }

  // X-Content-Type-Options
  if (xctoHeader && xctoHeader.toLowerCase().includes('nosniff')) {
    checks.push({
      id: 'header-xcto-pass',
      category: 'perimeter',
      title: 'MIME-Sniffing Protection Enabled',
      description: 'X-Content-Type-Options is set to "nosniff", blocking MIME confusion attacks and script execution masquerading as images.',
      severity: 'pass',
      status: 'pass',
      recommendation: 'Standard configuration verified.',
    });
  } else {
    checks.push({
      id: 'header-xcto-missing',
      category: 'perimeter',
      title: 'Missing X-Content-Type-Options: nosniff',
      description: 'Browsers may attempt MIME sniffing, executing scripts disguised as text or image file formats.',
      severity: 'low',
      status: 'fail',
      cwe: 'CWE-430',
      recommendation: 'Send "X-Content-Type-Options: nosniff" with all responses.',
    });
  }

  // Referrer-Policy
  if (referrerHeader) {
    checks.push({
      id: 'header-referrer-pass',
      category: 'perimeter',
      title: 'Referrer-Policy Configured',
      description: `Referrer-Policy header present (${referrerHeader}). Protects user privacy across external navigation.`,
      severity: 'pass',
      status: 'pass',
      rawDetails: referrerHeader
    });
  } else {
    checks.push({
      id: 'header-referrer-warn',
      category: 'perimeter',
      title: 'Referrer-Policy Not Explicitly Set',
      description: 'Sensitive path parameters or session tokens in URLs could leak to external third parties in HTTP Referer headers.',
      severity: 'low',
      status: 'warn',
      cwe: 'CWE-200',
      recommendation: 'Set "Referrer-Policy: strict-origin-when-cross-origin".',
    });
  }

  // Permissions-Policy
  if (permissionsHeader) {
    checks.push({
      id: 'header-permissions-pass',
      category: 'perimeter',
      title: 'Browser Hardware & Permissions-Policy Hardened',
      description: 'Permissions-Policy limits browser hardware APIs (microphone, camera, geolocation, payment).',
      severity: 'pass',
      status: 'pass',
      rawDetails: permissionsHeader.slice(0, 100) + '...'
    });
  } else {
    checks.push({
      id: 'header-permissions-missing',
      category: 'perimeter',
      title: 'Permissions-Policy Header Missing',
      description: 'No hardware API restriction policy set. Third-party embedded widgets could request camera, mic, or location.',
      severity: 'info',
      status: 'warn',
      recommendation: 'Define "Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()".',
    });
  }

  // Cross-Origin Isolation (COOP / CORP)
  if (coopHeader) {
    checks.push({
      id: 'header-coop-pass',
      category: 'perimeter',
      title: 'Cross-Origin Opener Isolation Active',
      description: `COOP set to "${coopHeader}", mitigating Spectre side-channel attacks and window hijacking.`,
      severity: 'pass',
      status: 'pass',
    });
  }

  // Server / Tech Disclosure
  if (poweredByBanner || (serverBanner && /\d+\.\d+/.test(serverBanner))) {
    checks.push({
      id: 'tech-banner-leak',
      category: 'perimeter',
      title: 'Server Banner / Technology Information Disclosure',
      description: `Server leaks specific software fingerprints: "${[serverBanner, poweredByBanner].filter(Boolean).join(', ')}". Aids reconnaissance for targeted CVE exploits.`,
      severity: 'medium',
      status: 'warn',
      cwe: 'CWE-200',
      recommendation: 'Suppress server disclosure headers ("Server", "X-Powered-By") in web server configs.',
      rawDetails: `Server: ${serverBanner || 'none'} | X-Powered-By: ${poweredByBanner || 'none'}`
    });
  } else {
    checks.push({
      id: 'tech-banner-hidden',
      category: 'perimeter',
      title: 'Server Fingerprint Obfuscation',
      description: 'Internal backend frameworks and detailed version numbers are securely obfuscated.',
      severity: 'pass',
      status: 'pass',
      recommendation: 'Maintain stealth headers policy in production.',
    });
  }

  // Cookie Security
  if (setCookieHeader) {
    const isSecure = /secure/i.test(setCookieHeader);
    const isHttpOnly = /httponly/i.test(setCookieHeader);
    const isSameSite = /samesite=(strict|lax)/i.test(setCookieHeader);

    if (isSecure && isHttpOnly && isSameSite) {
      checks.push({
        id: 'cookie-hygiene-pass',
        category: 'perimeter',
        title: 'Cookie Security Attributes Hardened',
        description: 'Cookies enforce Secure, HttpOnly, and SameSite flags, mitigating XSS session theft and CSRF.',
        severity: 'pass',
        status: 'pass',
      });
    } else {
      checks.push({
        id: 'cookie-hygiene-warn',
        category: 'perimeter',
        title: 'Cookie Security Flags Incomplete',
        description: `Set-Cookie header detected with missing security flags (Secure: ${isSecure}, HttpOnly: ${isHttpOnly}, SameSite: ${isSameSite}).`,
        severity: 'medium',
        status: 'warn',
        cwe: 'CWE-614',
        recommendation: 'Ensure all session cookies include "; Secure; HttpOnly; SameSite=Lax".',
      });
    }
  }

  // 2. TLS & CRYPTOGRAPHIC DEEP INSPECTION
  const tlsDetails: ScanResults['tlsDetails'] = {
    valid: false,
    authorized: false,
    protocol: null,
    cipherName: null,
    cipherVersion: null,
    issuer: null,
    validTo: null,
    daysRemaining: null,
    sans: [],
    isExpiringSoon: false,
    alpnNegotiated: null,
  };

  await new Promise<void>((resolve) => {
    try {
      const socket = tls.connect({
        host: hostname,
        port: 443,
        servername: hostname,
        rejectUnauthorized: false,
        ALPNProtocols: ['h2', 'http/1.1'],
      }, () => {
        tlsDetails.authorized = socket.authorized;
        tlsDetails.valid = socket.authorized;
        tlsDetails.protocol = socket.getProtocol();
        tlsDetails.alpnNegotiated = socket.alpnProtocol || null;
        
        const cipher = socket.getCipher();
        if (cipher) {
          tlsDetails.cipherName = cipher.name;
          tlsDetails.cipherVersion = cipher.version;
        }

        const cert = socket.getPeerCertificate(true);
        if (cert && cert.valid_to) {
          tlsDetails.validTo = cert.valid_to;
          if (cert.issuer) {
            const org = cert.issuer.O;
            const cn = cert.issuer.CN;
            tlsDetails.issuer = Array.isArray(org) ? org.join(', ') : (org || (Array.isArray(cn) ? cn.join(', ') : cn) || 'Authorized CA');
          } else {
            tlsDetails.issuer = 'Authorized CA';
          }
          
          const expiryDate = new Date(cert.valid_to);
          const now = new Date();
          const msDiff = expiryDate.getTime() - now.getTime();
          const days = Math.round(msDiff / (1000 * 60 * 60 * 24));
          tlsDetails.daysRemaining = days;
          tlsDetails.isExpiringSoon = days <= 21;

          if (cert.subjectaltname) {
            tlsDetails.sans = cert.subjectaltname.split(', ').map(s => s.replace('DNS:', ''));
          }
        }

        socket.end();
        resolve();
      });

      socket.setTimeout(5000, () => {
        socket.destroy();
        resolve();
      });

      socket.on('error', () => {
        resolve();
      });
    } catch {
      resolve();
    }
  });

  // Evaluate TLS checks
  if (tlsDetails.valid) {
    checks.push({
      id: 'tls-cert-valid',
      category: 'crypto',
      title: 'Valid SSL/TLS Certificate Chain',
      description: `Issued by ${tlsDetails.issuer || 'trusted authority'}. Valid for ${tlsDetails.daysRemaining !== null ? `${tlsDetails.daysRemaining} days remaining` : 'current session'}.`,
      severity: 'pass',
      status: 'pass',
      rawDetails: `Issuer: ${tlsDetails.issuer} | Valid until: ${tlsDetails.validTo}`
    });

    if (tlsDetails.isExpiringSoon && tlsDetails.daysRemaining !== null) {
      checks.push({
        id: 'tls-cert-expiring',
        category: 'crypto',
        title: 'SSL Certificate Expiring Imminently',
        description: `Certificate will expire in only ${tlsDetails.daysRemaining} days! Service outage and security warnings imminent if not renewed.`,
        severity: 'high',
        status: 'warn',
        cwe: 'CWE-295',
        recommendation: 'Trigger automated ACME / Let’s Encrypt renewal immediately.',
      });
    }
  } else {
    checks.push({
      id: 'tls-cert-invalid',
      category: 'crypto',
      title: 'Invalid or Self-Signed SSL/TLS Certificate',
      description: 'The SSL/TLS certificate fails browser trust verification. Visitors will be blocked by alarming security interstitial warnings.',
      severity: 'critical',
      status: 'fail',
      cwe: 'CWE-295',
      recommendation: 'Install a recognized certificate from Let’s Encrypt or an authorized Certificate Authority.',
    });
  }

  // Protocol evaluation
  if (tlsDetails.protocol === 'TLSv1.3') {
    checks.push({
      id: 'tls-protocol-13',
      category: 'crypto',
      title: 'State-of-the-Art TLS 1.3 Protocol Negotiated',
      description: `Negotiated cutting-edge TLS 1.3 with cipher ${tlsDetails.cipherName || 'AES-GCM'}. Provides 0-RTT handshakes and perfect forward secrecy (PFS).`,
      severity: 'pass',
      status: 'pass',
      rawDetails: `Protocol: ${tlsDetails.protocol} | Cipher: ${tlsDetails.cipherName}`
    });
  } else if (tlsDetails.protocol === 'TLSv1.2') {
    checks.push({
      id: 'tls-protocol-12',
      category: 'crypto',
      title: 'TLS 1.2 Protocol in Use',
      description: `Secure TLS 1.2 established with cipher ${tlsDetails.cipherName || 'standard'}.`,
      severity: 'pass',
      status: 'pass',
      recommendation: 'Enable TLS 1.3 support on your load balancer / web server for enhanced performance and quantum-resistant cipher suites.',
    });
  } else if (tlsDetails.protocol === 'TLSv1' || tlsDetails.protocol === 'TLSv1.1') {
    checks.push({
      id: 'tls-protocol-deprecated',
      category: 'crypto',
      title: 'Obsolete & Deprecated TLS Version Detected',
      description: `Connection negotiated using ${tlsDetails.protocol}. Vulnerable to POODLE, BEAST, and Sweet32 cryptographic attacks.`,
      severity: 'critical',
      status: 'fail',
      cwe: 'CWE-326',
      recommendation: 'Disable TLS 1.0 and TLS 1.1 in SSL protocols configuration immediately. Enforce TLS 1.2 and TLS 1.3 only.',
    });
  }

  // ALPN / HTTP/2 support
  if (tlsDetails.alpnNegotiated === 'h2') {
    checks.push({
      id: 'crypto-alpn-h2',
      category: 'compliance',
      title: 'HTTP/2 Protocol Enabled (ALPN)',
      description: 'Server supports binary multiplexed HTTP/2 via Application-Layer Protocol Negotiation (ALPN).',
      severity: 'pass',
      status: 'pass',
    });
  }

  // 3. DNS, EMAIL SPOOFING, CAA & DNSSEC
  const dnsDetails: ScanResults['dnsDetails'] = {
    spfRecord: null,
    spfPolicy: 'none',
    dmarcRecord: null,
    dmarcPolicy: null,
    caaRecords: [],
    mxRecords: [],
    ipv6Supported: false,
    nameservers: [],
  };

  // Nameservers
  try {
    const ns = await dns.resolveNs(hostname).catch(() => []);
    dnsDetails.nameservers = ns;
  } catch {
    // ignore
  }

  // MX Records
  try {
    const mx = await dns.resolveMx(hostname).catch(() => []);
    dnsDetails.mxRecords = mx.map(m => `${m.exchange} (priority ${m.priority})`);
  } catch {
    // ignore
  }

  // IPv6 (AAAA)
  try {
    const aaaa = await dns.resolve6(hostname).catch(() => []);
    if (aaaa.length > 0) {
      dnsDetails.ipv6Supported = true;
      checks.push({
        id: 'dns-ipv6-pass',
        category: 'compliance',
        title: 'Modern IPv6 Infrastructure Ready',
        description: `Domain has active AAAA records (${aaaa.slice(0, 2).join(', ')}). Ready for global next-gen network routing.`,
        severity: 'pass',
        status: 'pass',
      });
    }
  } catch {
    // ignore
  }

  // CAA Records (RFC 6844)
  try {
    const caa = await dns.resolveCaa(hostname).catch(() => []);
    if (caa.length > 0) {
      dnsDetails.caaRecords = caa.map(c => `${c.issue || c.issuewild || 'tag'}`);
      checks.push({
        id: 'dns-caa-pass',
        category: 'dns',
        title: 'CAA (Certificate Authority Authorization) Record Published',
        description: `CAA record locks down which CAs are allowed to issue SSL certificates for this domain (${dnsDetails.caaRecords.join(', ')}). Prevents rogue CA impersonation.`,
        severity: 'pass',
        status: 'pass',
        rawDetails: JSON.stringify(caa)
      });
    } else {
      checks.push({
        id: 'dns-caa-missing',
        category: 'dns',
        title: 'Missing CAA (Certificate Authority Authorization) Records',
        description: 'Any public Certificate Authority globally is permitted to issue certificates for your domain without restriction if compromised.',
        severity: 'medium',
        status: 'warn',
        cwe: 'CWE-295',
        recommendation: 'Add a DNS CAA record specifying your authorized CAs (e.g. 0 issue "letsencrypt.org").',
      });
    }
  } catch {
    // ignore
  }

  // SPF Record
  try {
    const txtRecords = await dns.resolveTxt(hostname).catch(() => []);
    const flat = txtRecords.flat();
    const spf = flat.find(r => r.startsWith('v=spf1'));

    if (spf) {
      dnsDetails.spfRecord = spf;
      if (spf.includes('-all')) {
        dnsDetails.spfPolicy = 'hardfail';
        checks.push({
          id: 'dns-spf-hardfail',
          category: 'dns',
          title: 'SPF Record Configured (Hardfail Enforced)',
          description: 'Sender Policy Framework (SPF) is strictly set with "-all". Phishing emails spoofing your domain will be rejected by mail servers.',
          severity: 'pass',
          status: 'pass',
          rawDetails: spf
        });
      } else if (spf.includes('~all')) {
        dnsDetails.spfPolicy = 'softfail';
        checks.push({
          id: 'dns-spf-softfail',
          category: 'dns',
          title: 'SPF Record Configured (Softfail)',
          description: 'SPF is configured with "~all" (Softfail). Emails from unauthorized servers might still land in spam rather than being blocked.',
          severity: 'pass',
          status: 'pass',
          recommendation: 'Tighten SPF policy from "~all" to "-all" once all valid sending IPs/services are cataloged.',
          rawDetails: spf
        });
      } else {
        dnsDetails.spfPolicy = 'neutral';
        checks.push({
          id: 'dns-spf-weak',
          category: 'dns',
          title: 'SPF Record Weak Policy (?all)',
          description: 'SPF policy contains neutral or permissive qualifiers, offering zero spoofing protection.',
          severity: 'medium',
          status: 'warn',
          cwe: 'CWE-345',
          recommendation: 'Update SPF policy to enforce "-all".',
          rawDetails: spf
        });
      }
    } else {
      checks.push({
        id: 'dns-spf-missing',
        category: 'dns',
        title: 'No SPF (Sender Policy Framework) Record Found',
        description: 'Adversaries and spammers can easily impersonate your domain in phishing and CEO-fraud attacks without detection.',
        severity: 'high',
        status: 'fail',
        cwe: 'CWE-345',
        recommendation: 'Publish a TXT record for SPF: "v=spf1 include:_spf.google.com ~all".',
      });
    }
  } catch {
    checks.push({
      id: 'dns-spf-error',
      category: 'dns',
      title: 'SPF Record Resolution Issue',
      description: 'Could not query TXT records on authoritative nameservers.',
      severity: 'medium',
      status: 'warn',
      recommendation: 'Verify domain DNS zone configuration.',
    });
  }

  // DMARC Record
  try {
    const dmarcRecords = await dns.resolveTxt(`_dmarc.${hostname}`).catch(() => []);
    const flatDmarc = dmarcRecords.flat();
    const dmarc = flatDmarc.find(r => r.startsWith('v=DMARC1'));

    if (dmarc) {
      dnsDetails.dmarcRecord = dmarc;
      const policyMatch = dmarc.match(/p=([a-z]+)/i);
      const policy = policyMatch ? policyMatch[1].toLowerCase() : 'none';
      dnsDetails.dmarcPolicy = policy;

      if (policy === 'reject') {
        checks.push({
          id: 'dns-dmarc-reject',
          category: 'dns',
          title: 'DMARC Policy Configured with Strict Rejection (p=reject)',
          description: 'Maximum email authentication defense. Unauthenticated emails claiming to originate from your domain are immediately discarded by world mail systems.',
          severity: 'pass',
          status: 'pass',
          rawDetails: dmarc
        });
      } else if (policy === 'quarantine') {
        checks.push({
          id: 'dns-dmarc-quarantine',
          category: 'dns',
          title: 'DMARC Policy Active (p=quarantine)',
          description: 'Failing emails are redirected to junk/spam folders. Good protection while monitoring delivery reports.',
          severity: 'pass',
          status: 'pass',
          rawDetails: dmarc
        });
      } else {
        checks.push({
          id: 'dns-dmarc-none',
          category: 'dns',
          title: 'DMARC Policy in Passive Mode (p=none)',
          description: 'DMARC is in monitoring mode only (p=none). Phishing messages spoofing your brand are still delivered to recipient inboxes.',
          severity: 'medium',
          status: 'warn',
          cwe: 'CWE-345',
          recommendation: 'Graduate DMARC policy from "p=none" to "p=quarantine" and ultimately "p=reject".',
          rawDetails: dmarc
        });
      }
    } else {
      checks.push({
        id: 'dns-dmarc-missing',
        category: 'dns',
        title: 'Missing DMARC Policy Record',
        description: 'Domain lacks a DMARC policy on _dmarc subdomain. Leaves users and customers exposed to deceptive phishing campaigns.',
        severity: 'high',
        status: 'fail',
        cwe: 'CWE-345',
        recommendation: 'Add TXT record at _dmarc.yourdomain with: "v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc-reports@yourdomain".',
      });
    }
  } catch {
    checks.push({
      id: 'dns-dmarc-missing-err',
      category: 'dns',
      title: 'Missing DMARC Policy Record',
      description: 'Domain lacks a DMARC record on _dmarc subdomain.',
      severity: 'high',
      status: 'fail',
      cwe: 'CWE-345',
      recommendation: 'Add TXT record at _dmarc.yourdomain with: "v=DMARC1; p=reject;".',
    });
  }

  // 4. ATTACK SURFACE & SENSITIVE PATH PROBING
  const surfaceDetails: ScanResults['surfaceDetails'] = {
    probedEndpoints: [],
    robotsDisallowedPaths: [],
    securityTxtFound: false,
  };

  const sensitiveTargets: { path: string; risk: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info'; label: string }[] = [
    { path: '/.env', risk: 'Critical', label: 'Environment secrets file' },
    { path: '/.git/config', risk: 'Critical', label: 'Git repository configuration' },
    { path: '/.git/HEAD', risk: 'Critical', label: 'Git repository pointer' },
    { path: '/docker-compose.yml', risk: 'High', label: 'Container orchestration spec' },
    { path: '/package.json', risk: 'Medium', label: 'Node package dependencies manifest' },
    { path: '/wp-config.php.bak', risk: 'Critical', label: 'WordPress database config backup' },
    { path: '/.DS_Store', risk: 'Low', label: 'macOS Finder directory metadata' },
    { path: '/robots.txt', risk: 'Info', label: 'Web crawler directive file' },
    { path: '/.well-known/security.txt', risk: 'Info', label: 'RFC 9116 Vulnerability disclosure contact' },
  ];

  await Promise.allSettled(
    sensitiveTargets.map(async (t) => {
      try {
        const probeRes = await fetchWithTimeout(`${baseUrl}${t.path}`, { method: 'GET' }, 3500);
        const status = probeRes.status;
        const textPreview = status === 200 ? await probeRes.text().catch(() => '') : '';

        // Validate if 200 is real file or a SPA/404 HTML fallback
        const isHtmlPage = textPreview.includes('<!DOCTYPE html') || textPreview.includes('<html');
        const isTrueExposed = status === 200 && (
          t.path === '/robots.txt' ? textPreview.toLowerCase().includes('user-agent') :
          t.path.includes('security.txt') ? textPreview.toLowerCase().includes('contact:') :
          t.path.includes('.git') ? (textPreview.includes('repositoryformatversion') || textPreview.includes('ref: refs/')) :
          t.path === '/.env' ? (!isHtmlPage && (textPreview.includes('=') || textPreview.length > 0)) :
          t.path === '/package.json' ? textPreview.includes('"name"') :
          !isHtmlPage
        );

        surfaceDetails.probedEndpoints.push({
          path: t.path,
          status: status,
          exposed: isTrueExposed,
          risk: t.risk,
        });

        if (t.path === '/robots.txt' && isTrueExposed) {
          const lines = textPreview.split('\n');
          const disallowed = lines
            .filter(l => l.toLowerCase().startsWith('disallow:'))
            .map(l => l.replace(/disallow:\s*/i, '').trim())
            .filter(Boolean)
            .slice(0, 8);
          surfaceDetails.robotsDisallowedPaths = disallowed;
        }

        if (t.path.includes('security.txt') && isTrueExposed) {
          surfaceDetails.securityTxtFound = true;
        }

        if (isTrueExposed && (t.risk === 'Critical' || t.risk === 'High')) {
          checks.push({
            id: `leak-${t.path.replace(/[^a-zA-Z0-9]/g, '-')}`,
            category: 'surface',
            title: `CRITICAL EXPOSURE: ${t.path} Publicly Accessible`,
            description: `The file "${t.path}" is exposed to anonymous public download. This may leak production secrets, API credentials, private repository history, or database passwords!`,
            severity: 'critical',
            status: 'fail',
            cwe: 'CWE-200',
            recommendation: `Add web server rules to deny access to "${t.path}" or delete it from the web root immediately.`,
            rawDetails: `HTTP ${status} OK - File contents returned (${textPreview.slice(0, 60)}...)`
          });
        }
      } catch {
        surfaceDetails.probedEndpoints.push({
          path: t.path,
          status: 'Timeout',
          exposed: false,
          risk: t.risk,
        });
      }
    })
  );

  // Security.txt check evaluation
  if (surfaceDetails.securityTxtFound) {
    checks.push({
      id: 'surface-security-txt-pass',
      category: 'surface',
      title: 'RFC 9116 security.txt Published',
      description: 'Domain complies with standard RFC 9116 vulnerability disclosure protocols, providing ethical security researchers a clear contact channel.',
      severity: 'pass',
      status: 'pass',
    });
  } else {
    checks.push({
      id: 'surface-security-txt-missing',
      category: 'surface',
      title: 'Missing security.txt (RFC 9116)',
      description: 'No vulnerability disclosure contact file located at /.well-known/security.txt. Makes it difficult for ethical hackers to report zero-day vulnerabilities safely.',
      severity: 'low',
      status: 'warn',
      recommendation: 'Deploy /.well-known/security.txt containing Contact: security@yourdomain.com and Canonical URL.',
    });
  }

  // 5. SCORING & PILLARS CALCULATION
  const pillarCategories: ('perimeter' | 'crypto' | 'dns' | 'surface' | 'compliance')[] = [
    'perimeter', 'crypto', 'dns', 'surface', 'compliance'
  ];

  const pillarResults: Record<string, PillarScore> = {};

  let totalScoreWeight = 100;
  let deductions = 0;

  checks.forEach(c => {
    if (c.status === 'fail') {
      if (c.severity === 'critical') deductions += 28;
      else if (c.severity === 'high') deductions += 15;
      else if (c.severity === 'medium') deductions += 8;
      else if (c.severity === 'low') deductions += 4;
    } else if (c.status === 'warn') {
      if (c.severity === 'high') deductions += 8;
      else if (c.severity === 'medium') deductions += 4;
      else if (c.severity === 'low') deductions += 2;
    }
  });

  const overallScore = Math.max(8, Math.min(100, Math.round(100 - deductions)));

  // Calculate each pillar
  pillarCategories.forEach(cat => {
    const catChecks = checks.filter(c => c.category === cat);
    const passCount = catChecks.filter(c => c.status === 'pass').length;
    const totalCount = Math.max(1, catChecks.length);
    let pScore = 100;
    
    catChecks.forEach(c => {
      if (c.status === 'fail') {
        pScore -= (c.severity === 'critical' ? 35 : c.severity === 'high' ? 22 : 12);
      } else if (c.status === 'warn') {
        pScore -= (c.severity === 'high' ? 12 : 6);
      }
    });
    pScore = Math.max(15, Math.min(100, pScore));

    let grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F' = 'F';
    if (pScore >= 95) grade = 'A+';
    else if (pScore >= 88) grade = 'A';
    else if (pScore >= 78) grade = 'B';
    else if (pScore >= 65) grade = 'C';
    else if (pScore >= 50) grade = 'D';

    pillarResults[cat] = {
      name: cat.toUpperCase(),
      score: pScore,
      passCount,
      totalCount,
      grade
    };
  });

  // Overall grade
  let grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F' = 'F';
  let gradeLabel = 'Critical Exposure';
  let threatLevel: ScanResults['metrics']['threatLevel'] = 'Severe Exposure';
  let cvssScore = 8.8;

  if (overallScore >= 94) {
    grade = 'A+';
    gradeLabel = 'Enterprise Hardened';
    threatLevel = 'Low Risk';
    cvssScore = 1.2;
  } else if (overallScore >= 85) {
    grade = 'A';
    gradeLabel = 'Strong Defense Posture';
    threatLevel = 'Guarded';
    cvssScore = 2.8;
  } else if (overallScore >= 74) {
    grade = 'B';
    gradeLabel = 'Moderate Security';
    threatLevel = 'Elevated';
    cvssScore = 4.6;
  } else if (overallScore >= 60) {
    grade = 'C';
    gradeLabel = 'Vulnerable Configuration';
    threatLevel = 'High Risk';
    cvssScore = 6.4;
  } else if (overallScore >= 45) {
    grade = 'D';
    gradeLabel = 'High Exposure';
    threatLevel = 'High Risk';
    cvssScore = 7.9;
  } else {
    grade = 'F';
    gradeLabel = 'Critical Compromise Risk';
    threatLevel = 'Severe Exposure';
    cvssScore = 9.4;
  }

  // 6. COMPLIANCE CONTROLS MAPPING
  const compliance: ComplianceControl[] = [
    {
      framework: 'SOC 2',
      controlId: 'CC6.6',
      title: 'Logical Boundaries & Perimeter Filtering',
      status: (!cspHeader || !hstsHeader) ? 'non-compliant' : 'compliant',
      reason: (!cspHeader || !hstsHeader)
        ? 'Missing CSP or HSTS headers violates perimeter boundary isolation requirements.'
        : 'Perimeter headers prevent unauthorized external code execution.'
    },
    {
      framework: 'ISO 27001',
      controlId: 'A.8.24',
      title: 'Use of Cryptography & Key Management',
      status: tlsDetails.valid && tlsDetails.protocol !== 'TLSv1' ? 'compliant' : 'non-compliant',
      reason: tlsDetails.valid 
        ? `Valid TLS ${tlsDetails.protocol} encryption meets cryptographic controls.`
        : 'Insecure or invalid transport encryption breaches ISO cryptographic mandates.'
    },
    {
      framework: 'PCI-DSS 4.0',
      controlId: 'Req 4.1',
      title: 'Strong Cryptography for Cardholder Data in Transit',
      status: isHttps && tlsDetails.valid && (tlsDetails.protocol === 'TLSv1.2' || tlsDetails.protocol === 'TLSv1.3') ? 'compliant' : 'non-compliant',
      reason: tlsDetails.protocol === 'TLSv1.3' || tlsDetails.protocol === 'TLSv1.2'
        ? 'TLS protocol conforms to PCI-DSS 4.0 minimum cryptographic cipher requirements.'
        : 'PCI-DSS prohibits legacy encryption and unencrypted transport.'
    },
    {
      framework: 'HIPAA',
      controlId: '§ 164.312(e)(1)',
      title: 'Transmission Security & ePHI Protection',
      status: hstsHeader && tlsDetails.valid ? 'compliant' : 'partial',
      reason: hstsHeader && tlsDetails.valid
        ? 'Enforced HTTPS prevents interception of electronic Protected Health Information (ePHI).'
        : 'Absence of strict HTTPS downgrade protection risks ePHI interception.'
    },
    {
      framework: 'GDPR',
      controlId: 'Article 32',
      title: 'Security of Processing & Data Confidentiality',
      status: (!dnsDetails.spfRecord || !dnsDetails.dmarcRecord) ? 'partial' : 'compliant',
      reason: (!dnsDetails.spfRecord || !dnsDetails.dmarcRecord)
        ? 'Missing email authentication (SPF/DMARC) exposes users to identity theft and phishing.'
        : 'Domain identity and transport integrity conform to Art. 32 standards.'
    }
  ];

  // 7. EXPLOIT CHAINS & THREAT MODEL
  const exploitChains: ExploitChain[] = [];

  if (!cspHeader) {
    exploitChains.push({
      title: 'Stored XSS Session Hijacking Chain',
      attackVector: 'Cross-Site Scripting (XSS)',
      steps: [
        'Attacker injects obfuscated script tag into user-controlled input field.',
        'Browser executes malicious JavaScript because Content-Security-Policy is absent.',
        'Script reads document.cookie or localStorage authentication tokens and transmits to attacker C2.',
        'Attacker impersonates authenticated administrators or customers.'
      ],
      impact: 'Full account takeover and privileged command execution.',
      threatLevel: 'Critical'
    });
  }

  if (!hstsHeader) {
    exploitChains.push({
      title: 'SSL-Stripping Man-in-the-Middle (MITM) Downgrade',
      attackVector: 'Cryptographic Transport Downgrade',
      steps: [
        'Victim connects to public Wi-Fi or compromised LAN.',
        'Adversary intercepts initial plaintext HTTP request before 301 redirect.',
        'Adversary strips TLS handshake, serving plaintext HTTP proxy to the victim.',
        'All credentials and sensitive POST bodies are captured in transit.'
      ],
      impact: 'Cleartext credential harvesting and session sniffing.',
      threatLevel: 'High'
    });
  }

  if (!dnsDetails.dmarcRecord || dnsDetails.dmarcPolicy === 'none') {
    exploitChains.push({
      title: 'Domain Spoofing & Executive Impersonation Phishing',
      attackVector: 'Email Header Forgery',
      steps: [
        'Attacker configures an open mail relay using your domain in the "From:" header.',
        'Recipient mail server checks _dmarc TXT record and finds no enforcement policy.',
        'Phishing email reaches employee or customer inbox with authentic domain display.',
        'Victims trust the communication, resulting in wire transfer fraud or credential theft.'
      ],
      impact: 'Brand reputational devastation and Business Email Compromise (BEC).',
      threatLevel: 'High'
    });
  }

  if (!xfoHeader) {
    exploitChains.push({
      title: 'Clickjacking UI Redress Attack',
      attackVector: 'Iframe Transparency Manipulation',
      steps: [
        'Attacker embeds target application inside an invisible <iframe> on an attacker site.',
        'Attacker overlays enticing clickable game or survey buttons directly over target sensitive action buttons.',
        'Authenticated user clicks thinking they are playing a game, inadvertently triggering account deletion or permission grants.'
      ],
      impact: 'Unintended state-changing operations performed by authenticated users.',
      threatLevel: 'Medium'
    });
  }

  // 8. REMEDIATION CODE GENERATOR (Ready to paste)
  const remediationConfigs: RemediationConfigs = {
    nginx: `# ========================================================
# AegisX Hardened Security Headers for Nginx
# Place inside server { ... } block
# ========================================================

# 1. Prevent Clickjacking
add_header X-Frame-Options "SAMEORIGIN" always;

# 2. Block MIME Sniffing
add_header X-Content-Type-Options "nosniff" always;

# 3. Enforce HTTPS & Preload (HSTS - 1 Year)
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

# 4. Strict Content Security Policy (Adjust domains as needed)
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; font-src 'self' https: data:; connect-src 'self' https:; frame-ancestors 'self';" always;

# 5. Referrer Policy & Permissions
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;

# 6. Block Sensitive Dotfiles & Git Folders
location ~ /\\.(?!well-known) {
    deny all;
    return 404;
}`,

    apache: `# ========================================================
# AegisX Hardened Security Directives (.htaccess / httpd.conf)
# ========================================================
<IfModule mod_headers.c>
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:;"
</IfModule>

# Block access to hidden directories (.git, .env)
<FilesMatch "^\\.(?!well-known)">
    Order allow,deny
    Deny from all
</FilesMatch>`,

    nextjs: `// ========================================================
// Next.js (next.config.mjs / next.config.js) Security Headers
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
          { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains; preload' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
          {
            key: 'Content-Security-Policy',
            value: "default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;",
          },
        ],
      },
    ];
  },
};

export default nextConfig;`,

    vercel: `{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        { "key": "X-Frame-Options", "value": "SAMEORIGIN" },
        { "key": "X-Content-Type-Options", "value": "nosniff" },
        { "key": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains; preload" },
        { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" },
        { "key": "Permissions-Policy", "value": "camera=(), microphone=(), geolocation=()" }
      ]
    }
  ]
}`,

    dnsRecords: `; ========================================================
; AegisX Recommended DNS Zone Records for ${hostname}
; Add these TXT and CAA entries to your DNS provider
; ========================================================

; 1. SPF Record (Prevents email spoofing)
@   IN  TXT   "v=spf1 include:_spf.google.com ~all"

; 2. DMARC Policy Record
_dmarc.${hostname}.  IN  TXT   "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc-reports@${hostname}"

; 3. CAA Records (Restricts SSL issuers to Let's Encrypt and DigiCert)
@   IN  CAA   0 issue "letsencrypt.org"
@   IN  CAA   0 issue "digicert.com"
@   IN  CAA   0 iodef "mailto:security@${hostname}"`
  };

  // 9. AI EXECUTIVE SUMMARY
  const strengths: string[] = [];
  const vulnerabilities: string[] = [];
  const priorityActions: string[] = [];

  if (tlsDetails.valid && tlsDetails.protocol === 'TLSv1.3') strengths.push('Modern TLS 1.3 cryptographic transport actively safeguards against interception.');
  if (hstsHeader) strengths.push('Strict-Transport-Security guarantees encrypted traffic delivery across all user sessions.');
  if (dnsDetails.spfPolicy === 'hardfail' || dnsDetails.spfPolicy === 'softfail') strengths.push('Sender Policy Framework records are active to defend domain reputation.');
  if (surfaceDetails.securityTxtFound) strengths.push('Complies with RFC 9116 ethical vulnerability disclosure standards.');

  if (!cspHeader) {
    vulnerabilities.push('Critical absence of Content-Security-Policy (CSP) exposes the web surface to script injection (XSS).');
    priorityActions.push('Deploy Content-Security-Policy header restricting script-src and object-src.');
  }
  if (!hstsHeader) {
    vulnerabilities.push('Missing HSTS header permits active SSL-stripping downgrade attacks.');
    priorityActions.push('Enable Strict-Transport-Security with max-age=31536000 and includeSubDomains.');
  }
  if (!dnsDetails.dmarcRecord) {
    vulnerabilities.push('Absence of DMARC records enables attackers to forge emails claiming to come from your domain.');
    priorityActions.push(`Create TXT record at _dmarc.${hostname} with p=quarantine or p=reject.`);
  }
  if (!xfoHeader) {
    vulnerabilities.push('Missing X-Frame-Options allows clickjacking via deceptive third-party iframes.');
    priorityActions.push('Configure X-Frame-Options: SAMEORIGIN across all page routes.');
  }

  const durationMs = Date.now() - startTime;

  return {
    target: {
      inputUrl: targetUrl,
      hostname,
      protocol: urlObj.protocol,
      ipAddress: primaryIp,
      scanTimestamp: new Date().toISOString(),
      scanDurationMs: durationMs,
    },
    metrics: {
      overallScore,
      grade,
      gradeLabel,
      cvssScore,
      threatLevel,
      passedChecks: checks.filter(c => c.status === 'pass').length,
      totalChecks: checks.length,
    },
    pillars: {
      perimeter: pillarResults.perimeter,
      crypto: pillarResults.crypto,
      dns: pillarResults.dns,
      surface: pillarResults.surface,
      compliance: pillarResults.compliance,
    },
    checks,
    technologies: {
      server: serverBanner,
      wafOrCdn: cdnBanner,
      poweredBy: poweredByBanner,
      httpVersion: httpVersionStr,
      detectedStack,
    },
    tlsDetails,
    dnsDetails,
    surfaceDetails,
    compliance,
    exploitChains,
    remediationConfigs,
    aiExecutiveSummary: {
      briefing: `Security posture audit for ${hostname} reveals an overall Security Posture Index of ${overallScore}/100 (${grade} - ${gradeLabel}). ${
        vulnerabilities.length > 0 
          ? `Identified ${vulnerabilities.length} primary risk vectors requiring immediate remediation.` 
          : 'High baseline security hygiene maintained across perimeter, transport, and identity layers.'
      }`,
      strengths: strengths.length > 0 ? strengths : ['Basic HTTP/HTTPS connectivity operational.'],
      vulnerabilities: vulnerabilities.length > 0 ? vulnerabilities : ['No critical perimeter misconfigurations identified.'],
      priorityActions: priorityActions.length > 0 ? priorityActions : ['Continue routine automated attack-surface regression testing.'],
    }
  };
}
