# Web Vuln by Example

**43 hands-on web security labs** in a single Node.js app. Each vulnerability is shown two ways: **how to exploit it** and **how to fix it** — with syntax-highlighted source code, attack flow diagrams, and inline explanations.

No Docker required. No external databases. Just `npm install && npm start`.

## Why this exists

Most security training tools are either **CTF-style** (exploit only, no fix shown) or **heavyweight** (Docker, LAMP, external databases). This project fills the gap: a lightweight teaching tool where you can see the vulnerable code and the secure code side-by-side, understand **why** each fix works, and test both in your browser.

Built for:
- Students learning web security
- Developers building security awareness
- Instructors who need a quick lab setup
- Anyone preparing for security certifications

## Quick Start

```bash
npm install
npm start
# Open http://localhost:3000
```

### Docker

```bash
docker build -t web-vuln-by-example .
docker run -p 3010:3010 web-vuln-by-example
```

## Labs

### XSS & Client-Side Security (Labs 1-19)

| # | Lab | CWE |
|---|-----|-----|
| 1 | DOM XSS (`innerHTML` vs `textContent`) | CWE-79 |
| 2 | Open Redirect + XSS via `location` | CWE-601 |
| 3 | Content Security Policy (5 variants) | CWE-693 |
| 4 | Template Engine Escaping (EJS) | CWE-79 |
| 5 | Stored XSS (guestbook) | CWE-79 |
| 6 | Reflected XSS (server-side) | CWE-79 |
| 7 | Cookie Theft + HttpOnly | CWE-1004 |
| 8 | Postmessage XSS | CWE-345 |
| 9 | JSON Injection in Script Tags | CWE-79 |
| 10 | URL Parsing Confusion | CWE-601 |
| 11 | DOMPurify Sanitizer | CWE-79 |
| 12 | DOM Clobbering | CWE-79 |
| 13 | Mutation XSS (mXSS) | CWE-79 |
| 14 | Prototype Pollution to XSS | CWE-1321 |
| 15 | Dangling Markup Injection | CWE-116 |
| 16 | Trusted Types | CWE-79 |
| 17 | Subresource Integrity (SRI) | CWE-353 |
| 18 | Sandbox Iframes | CWE-1021 |
| 19 | Security Headers Audit | CWE-693 |

### Injection Attacks (Labs 20-22)

| # | Lab | CWE |
|---|-----|-----|
| 20 | SQL Injection | CWE-89 |
| 21 | Command Injection | CWE-78 |
| 22 | Server-Side Template Injection (SSTI) | CWE-1336 |

### Broken Access & Trust (Labs 23-26)

| # | Lab | CWE |
|---|-----|-----|
| 23 | CSRF | CWE-352 |
| 24 | IDOR | CWE-639 |
| 25 | Mass Assignment | CWE-915 |
| 26 | JWT Weaknesses | CWE-347 |

### Server-Side (Labs 27-29)

| # | Lab | CWE |
|---|-----|-----|
| 27 | Path Traversal | CWE-22 |
| 28 | SSRF | CWE-918 |
| 29 | XXE | CWE-611 |

### HTTP & Browser (Labs 30-32)

| # | Lab | CWE |
|---|-----|-----|
| 30 | CORS Misconfiguration | CWE-942 |
| 31 | Clickjacking | CWE-1021 |
| 32 | CRLF / Header Injection | CWE-113 |

### Application Logic (Labs 33-37)

| # | Lab | CWE |
|---|-----|-----|
| 33 | Insecure Deserialization | CWE-502 |
| 34 | ReDoS | CWE-1333 |
| 35 | Insecure Randomness | CWE-330 |
| 36 | Sensitive Data in Errors | CWE-200 |
| 37 | Race Conditions | CWE-362 |

### Crypto & Input Handling (Labs 38-43)

| # | Lab | CWE |
|---|-----|-----|
| 38 | HTTP Parameter Pollution | CWE-235 |
| 39 | Insecure Password Storage | CWE-916 |
| 40 | Host Header Injection | CWE-644 |
| 41 | Prototype Pollution | CWE-1321 |
| 42 | Timing Attack | CWE-208 |
| 43 | File Upload | CWE-434 |

## How Each Lab Works

Every lab follows the same structure:

1. **Landing page** — explains the vulnerability, shows source code, links to try it
2. **Vulnerable variant** — a working exploit you can trigger in your browser
3. **Fixed variant** — the same scenario with proper defenses applied
4. **Source code** — syntax-highlighted, with the bug and fix called out
5. **Attack flow** — step-by-step explanation of how the exploit works
6. **Details** — expandable section with defense best practices

## Testing

```bash
npm test
```

122 functional tests via `supertest` + Node's built-in test runner (`node:test`). Tests verify every route returns 200, pages contain expected sections, and vuln/fix behavior works correctly (SQLi returns all users vs none, command injection executes vs blocks, CSRF accepts vs rejects, etc.).

## What to Explore in DevTools

- **Console** — CSP violations (Lab 3), Trusted Types errors (Lab 16)
- **Network > Response Headers** — security headers (Labs 3, 16, 17, 19, 30, 31)
- **Network > Requests** — CSRF auto-submissions (Lab 23), SSRF requests (Lab 28)
- **Application > Cookies** — HttpOnly flag (Lab 7), SameSite attribute (Lab 23)
- **Elements** — DOM differences between `innerHTML` and `textContent` (Lab 1)

## Tech Stack

- **Runtime:** Node.js 22+
- **Framework:** Express 5
- **Database:** SQLite in-memory (better-sqlite3) — for Lab 20 only
- **Dependencies:** dompurify, jsdom, jsonwebtoken, fast-xml-parser
- **UI:** Dark mode, sidebar navigation, mobile-responsive — pure CSS, no frameworks

## Notes

- All data is in-memory — restart the server to reset state
- Lab 16 (Trusted Types) requires Chromium (Chrome/Edge)
- Lab 21 (Command Injection) uses `ping` — works on macOS/Linux
- Lab 29 (XXE) is simulated — Node.js XML parsers are safe by default
- Lab 32 (CRLF) is simulated — Express 5 blocks CRLF in headers natively

## Contributing

Contributions welcome. To add a new lab:

1. Add routes in `server.js` following the existing pattern (vulnerable + fixed)
2. Include syntax-highlighted source code, attack flow, and `<details>` explainer
3. Add the lab to `LAB_NAV` in `server.js` with the CWE number
4. Add tests in `server.test.js`
5. Update this README

## License

MIT
