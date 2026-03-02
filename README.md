# Web Vuln by Example

**37 hands-on web security labs** in a single Node.js app. Each vulnerability is shown two ways: **how to exploit it** and **how to fix it** — with syntax-highlighted source code, attack flow diagrams, and inline explanations.

No Docker. No external databases. Just `npm install && npm start`.

## Why this exists

Most security training tools are either **CTF-style** (exploit only, no fix shown) or **heavyweight** (Docker, LAMP, external databases). This project fills the gap: a lightweight teaching tool where you can see the vulnerable code and the secure code side-by-side, understand **why** each fix works, and test both in your browser.

Built for:
- Students learning web security
- Developers building security awareness
- Instructors who need a quick lab setup
- Anyone preparing for security certifications

## Quick Start

### Option 1: npm

```bash
git clone https://gitlab.com/YOUR_USERNAME/web-vuln-by-example.git
cd web-vuln-by-example
npm install
npm start
```

### Option 2: Docker

```bash
docker build -t web-vuln-by-example .
docker run -p 3000:3000 web-vuln-by-example
```

Open **http://localhost:3000** — the index page links to every lab.

## Labs

### XSS & Client-Side Security (Labs 1-19)

| # | Lab | CWE | Routes |
|---|-----|-----|--------|
| 1 | DOM XSS | CWE-79 | `/dom-xss` `/fixed-dom` |
| 2 | Open Redirect | CWE-601 | `/vuln-redirect` `/fixed-redirect` |
| 3 | Content Security Policy (CSP) | — | `/csp-none` `/csp-strict` `/csp-nonce` `/csp-report-only` `/csp-unsafe-inline` |
| 4 | Template Engine Escaping | CWE-79 | `/ejs-escaped` `/ejs-raw` `/ejs-with-csp` |
| 5 | Stored XSS | CWE-79 | `/stored-xss` `/stored-xss-fixed` |
| 6 | Reflected XSS (Server-Side) | CWE-79 | `/reflected` `/reflected-fixed` |
| 7 | Cookie Theft + HttpOnly | CWE-1004 | `/cookie-theft` `/cookie-theft-fixed` |
| 8 | Postmessage XSS | CWE-79 | `/postmessage-xss` `/postmessage-xss-fixed` |
| 9 | JSON Injection in Script Tags | CWE-79 | `/json-injection` `/json-injection-fixed` |
| 10 | URL Parsing Confusion | CWE-79 | `/url-confusion` `/url-confusion-fixed` |
| 11 | DOMPurify Sanitizer | — | `/dompurify-demo` `/dompurify-bypass` |
| 12 | DOM Clobbering | CWE-79 | `/dom-clobbering` `/dom-clobbering-fixed` |
| 13 | Mutation XSS (mXSS) | CWE-79 | `/mxss` |
| 14 | Prototype Pollution | CWE-1321 | `/proto-pollution` `/proto-pollution-fixed` |
| 15 | Dangling Markup Injection | CWE-116 | `/dangling-markup` |
| 16 | Trusted Types | — | `/trusted-types` `/trusted-types-report` |
| 17 | Subresource Integrity (SRI) | — | `/sri-demo` `/sri-tampered` |
| 18 | Sandbox Iframes | — | `/sandbox-iframe` `/sandbox-iframe-none` |
| 19 | Security Headers Audit | — | `/headers-audit` |

### Injection Attacks (Labs 20-22)

| # | Lab | CWE | Routes |
|---|-----|-----|--------|
| 20 | SQL Injection | CWE-89 | `/sqli` `/sqli-fixed` |
| 21 | Command Injection | CWE-78 | `/cmdi` `/cmdi-fixed` |
| 22 | Server-Side Template Injection | CWE-1336 | `/ssti` `/ssti-fixed` |

### Broken Access & Trust (Labs 23-26)

| # | Lab | CWE | Routes |
|---|-----|-----|--------|
| 23 | CSRF | CWE-352 | `/csrf` `/csrf-fixed` `/csrf-attacker` |
| 24 | IDOR | CWE-639 | `/idor` `/idor-fixed` |
| 25 | Mass Assignment | CWE-915 | `/mass-assign` `/mass-assign-fixed` |
| 26 | JWT Weaknesses | CWE-347 | `/jwt-demo` `/jwt-verify` `/jwt-verify-fixed` |

### Server-Side Vulnerabilities (Labs 27-29)

| # | Lab | CWE | Routes |
|---|-----|-----|--------|
| 27 | Path Traversal | CWE-22 | `/path-traversal` `/path-traversal-fixed` |
| 28 | SSRF | CWE-918 | `/ssrf` `/ssrf-fixed` |
| 29 | XXE | CWE-611 | `/xxe` `/xxe-fixed` |

### HTTP & Browser Security (Labs 30-32)

| # | Lab | CWE | Routes |
|---|-----|-----|--------|
| 30 | CORS Misconfiguration | CWE-942 | `/cors-misconfig` `/cors-attacker` |
| 31 | Clickjacking | CWE-1021 | `/clickjack` `/clickjack-fixed` |
| 32 | CRLF / Header Injection | CWE-113 | `/crlf` `/crlf-fixed` |

### Application Logic (Labs 33-37)

| # | Lab | CWE | Routes |
|---|-----|-----|--------|
| 33 | Insecure Deserialization | CWE-502 | `/deserialize` `/deserialize-fixed` |
| 34 | ReDoS | CWE-1333 | `/redos` `/redos-fixed` |
| 35 | Insecure Randomness | CWE-330 | `/weak-random` |
| 36 | Sensitive Data in Errors | CWE-200 | `/error-leak` `/error-leak-fixed` |
| 37 | Race Conditions | CWE-362 | `/race-condition` `/race-condition-fixed` |

## How Each Lab Works

Every lab follows the same structure:

1. **Vulnerable version** — a working exploit you can trigger in your browser
2. **Fixed version** — the same scenario with proper defenses applied
3. **Source code** — syntax-highlighted, showing the exact vulnerable line and the fix
4. **Attack flow** — step-by-step explanation of how the exploit works
5. **Details** — expandable section with defense best practices

## What to Explore in DevTools

- **Console** — CSP violations (Lab 3), Trusted Types errors (Lab 16)
- **Network > Response Headers** — security headers (Labs 3, 16, 17, 19, 30, 31)
- **Network > Requests** — CSRF auto-submissions (Lab 23), SSRF requests (Lab 28)
- **Application > Cookies** — HttpOnly flag (Lab 7), SameSite attribute (Lab 23)
- **Elements** — DOM differences between `innerHTML` and `textContent` (Lab 1)

## Tech Stack

- **Runtime:** Node.js
- **Framework:** Express 5
- **Database:** SQLite in-memory (better-sqlite3) — for Lab 20 only
- **Dependencies:** dompurify, jsdom, jsonwebtoken, fast-xml-parser
- **Setup:** `npm install` — no Docker, no external services

## Notes

- All data is in-memory — restart the server to reset state
- Lab 16 (Trusted Types) requires Chromium (Chrome/Edge)
- Lab 21 (Command Injection) uses `ping` — works on macOS/Linux
- Lab 29 (XXE) is simulated — Node.js XML parsers are safe by default; the lab explains what happens in vulnerable parsers (Java, PHP, Python lxml)
- Lab 32 (CRLF) is simulated — Express 5 blocks CRLF in headers natively

## Contributing

Contributions welcome. To add a new lab:

1. Add routes in `server.js` following the existing pattern (vulnerable + fixed)
2. Include syntax-highlighted source code, attack flow, and `<details>` explainer
3. Add the lab to the index page and this README
4. Test: `npm start`, verify routes return 200, verify exploit works and fix blocks it

## License

MIT
