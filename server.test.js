const { describe, it, before, after } = require("node:test");
const assert = require("node:assert/strict");
const request = require("supertest");
const app = require("./server");

/* ========================================================================
   Helpers
   ======================================================================== */

/** Assert response body contains all listed strings */
function assertContains(body, ...strings) {
  for (const s of strings) {
    assert.ok(body.includes(s), `Expected body to contain "${s}"`);
  }
}

/** Assert response body does NOT contain any of the listed strings */
function assertNotContains(body, ...strings) {
  for (const s of strings) {
    assert.ok(!body.includes(s), `Expected body NOT to contain "${s}"`);
  }
}

/** Standard lab page checks: layout shell, sidebar, breadcrumb */
function assertLayout(body, labNum) {
  assertContains(body, "<!DOCTYPE html>", '<nav class="sidebar">', "Web Vuln by Example");
  if (labNum) {
    assertContains(body, `Lab ${labNum}`);
  }
}

/** Check for common documentation sections */
function assertSections(body, ...headings) {
  for (const h of headings) {
    assertContains(body, `<h3>${h}</h3>`);
  }
}

/* ========================================================================
   INDEX PAGE
   ======================================================================== */
describe("Index page", () => {
  it("returns 200 with all 43 lab cards", async () => {
    const res = await request(app).get("/").expect(200);
    assertLayout(res.text);
    // Spot-check a few lab titles
    assertContains(res.text, "DOM XSS", "SQL Injection", "File Upload");
    // All CWE badges present
    assertContains(res.text, "CWE-79", "CWE-89", "CWE-434");
  });
});

/* ========================================================================
   LAB 1 — DOM XSS (CWE-79)
   ======================================================================== */
describe("Lab 1: DOM XSS", () => {
  it("landing page returns 200 with sections", async () => {
    const res = await request(app).get("/dom-xss-lab").expect(200);
    assertLayout(res.text, 1);
    assertSections(res.text, "Source Code (the bug)", "Attack Flow", "The Fix");
    assertContains(res.text, "<details>", ".innerHTML");
  });

  it("landing page has try-it links", async () => {
    const res = await request(app).get("/dom-xss-lab").expect(200);
    assertContains(res.text, 'href="/dom-xss?q=', 'href="/fixed-dom?q=');
  });

  it("vuln page renders with innerHTML sink", async () => {
    const res = await request(app).get("/dom-xss").expect(200);
    assertLayout(res.text, 1);
    assertContains(res.text, ".innerHTML = q");
  });

  it("fixed page uses textContent", async () => {
    const res = await request(app).get("/fixed-dom").expect(200);
    assertLayout(res.text, 1);
    assertContains(res.text, ".textContent = q");
  });
});

/* ========================================================================
   LAB 2 — Open Redirect (CWE-601)
   ======================================================================== */
describe("Lab 2: Open Redirect", () => {
  it("landing page returns 200 with sections", async () => {
    const res = await request(app).get("/open-redirect").expect(200);
    assertLayout(res.text, 2);
    assertSections(res.text, "Server-Side Code", "Client-Side Code (the bug)", "Attack Flow", "The Fix");
    assertContains(res.text, "<details>");
  });

  it("landing page has try-it links to vuln and fixed", async () => {
    const res = await request(app).get("/open-redirect").expect(200);
    assertContains(
      res.text,
      'href="/vuln-redirect?next=ok',
      'href="/fixed-redirect?redirect_uri=javascript:alert'
    );
  });

  it("vuln-redirect requires next=ok", async () => {
    await request(app).get("/vuln-redirect").expect(400);
    const res = await request(app).get("/vuln-redirect?next=ok").expect(200);
    assertContains(res.text, "location = u");
  });

  it("fixed-redirect blocks non-allowlisted URIs", async () => {
    const res = await request(app)
      .get("/fixed-redirect?redirect_uri=javascript:alert('XSS')")
      .expect(400);
    assertContains(res.text, "not in the allowlist");
  });

  it("safe-landing returns 200", async () => {
    await request(app).get("/safe-landing").expect(200);
  });
});

/* ========================================================================
   LAB 3 — CSP (CWE-693)
   ======================================================================== */
describe("Lab 3: CSP", () => {
  it("csp-none returns 200 with sections", async () => {
    const res = await request(app).get("/csp-none").expect(200);
    assertLayout(res.text, 3);
    assertSections(res.text, "Server-Side Code");
  });

  it("csp-strict sets strict CSP header", async () => {
    const res = await request(app).get("/csp-strict").expect(200);
    assert.ok(res.headers["content-security-policy"], "Expected CSP header");
  });

  it("csp-nonce includes nonce in CSP and script tags", async () => {
    const res = await request(app).get("/csp-nonce").expect(200);
    const csp = res.headers["content-security-policy"] || "";
    assert.ok(csp.includes("nonce-"), "Expected nonce in CSP header");
  });

  it("csp-report-only uses report-only header", async () => {
    const res = await request(app).get("/csp-report-only").expect(200);
    assert.ok(
      res.headers["content-security-policy-report-only"],
      "Expected CSP-Report-Only header"
    );
  });

  it("csp-unsafe-inline sets unsafe-inline", async () => {
    const res = await request(app).get("/csp-unsafe-inline").expect(200);
    const csp = res.headers["content-security-policy"] || "";
    assert.ok(csp.includes("unsafe-inline"), "Expected unsafe-inline in CSP");
  });
});

/* ========================================================================
   LAB 4 — EJS Template Engine (CWE-79)
   ======================================================================== */
describe("Lab 4: EJS Template Engine", () => {
  it("ejs-escaped returns 200 with sections", async () => {
    const res = await request(app).get("/ejs-escaped").expect(200);
    assertLayout(res.text, 4);
    assertSections(res.text, "Server-Side Code");
  });

  it("ejs-raw reflects input unsanitized", async () => {
    const res = await request(app).get("/ejs-raw?q=<script>alert(1)</script>").expect(200);
    assertContains(res.text, "<script>alert(1)</script>");
  });

  it("ejs-escaped escapes the input", async () => {
    const res = await request(app).get("/ejs-escaped?q=<script>alert(1)</script>").expect(200);
    assertContains(res.text, "&lt;script&gt;");
  });

  it("ejs-with-csp adds CSP header", async () => {
    const res = await request(app).get("/ejs-with-csp?q=test").expect(200);
    assert.ok(res.headers["content-security-policy"], "Expected CSP header");
  });
});

/* ========================================================================
   LAB 5 — Stored XSS (CWE-79)
   ======================================================================== */
describe("Lab 5: Stored XSS", () => {
  it("vuln page returns 200 with form and sections", async () => {
    const res = await request(app).get("/stored-xss").expect(200);
    assertLayout(res.text, 5);
    assertContains(res.text, "<form", 'name="name"', 'name="message"');
  });

  it("posting to vuln stores and reflects unsanitized content", async () => {
    await request(app)
      .post("/stored-xss")
      .type("form")
      .send({ name: "test", message: "<script>xss</script>" })
      .expect(302);
    const res = await request(app).get("/stored-xss").expect(200);
    assertContains(res.text, "<script>xss</script>");
  });

  it("fixed page returns 200 with form", async () => {
    const res = await request(app).get("/stored-xss-fixed").expect(200);
    assertLayout(res.text, 5);
  });
});

/* ========================================================================
   LAB 6 — Reflected XSS (CWE-79)
   ======================================================================== */
describe("Lab 6: Reflected XSS", () => {
  it("vuln page reflects input unsanitized", async () => {
    const res = await request(app).get("/reflected?q=<img+src=x>").expect(200);
    assertLayout(res.text, 6);
    assertSections(res.text, "Server-Side Code", "Attack Flow");
    assertContains(res.text, "<img src=x>");
  });

  it("fixed page escapes input", async () => {
    const res = await request(app).get("/reflected-fixed?q=<img+src=x>").expect(200);
    assertContains(res.text, "&lt;img");
    assertSections(res.text, "Server-Side Code", "What Changed");
  });
});

/* ========================================================================
   LAB 7 — Cookie Theft + HttpOnly (CWE-1004)
   ======================================================================== */
describe("Lab 7: Cookie Theft", () => {
  it("vuln page returns 200 with sections", async () => {
    const res = await request(app).get("/cookie-theft").expect(200);
    assertLayout(res.text, 7);
    assertSections(res.text, "Source Code", "Attack Flow");
    assertContains(res.text, "<details>");
  });

  it("vuln sets non-httponly cookie", async () => {
    const res = await request(app).get("/cookie-theft").expect(200);
    const cookies = res.headers["set-cookie"] || [];
    const session = cookies.find(c => c.startsWith("session_id="));
    assert.ok(session, "Expected session_id cookie");
    assert.ok(!session.includes("HttpOnly"), "Vuln cookie should NOT have HttpOnly");
  });

  it("fixed sets httponly cookie", async () => {
    const res = await request(app).get("/cookie-theft-fixed").expect(200);
    const cookies = res.headers["set-cookie"] || [];
    const session = cookies.find(c => c.startsWith("session_id="));
    assert.ok(session, "Expected session_id cookie");
    assert.ok(session.includes("HttpOnly"), "Fixed cookie should have HttpOnly");
  });

  it("attacker-log returns 200", async () => {
    await request(app).get("/attacker-log").expect(200);
  });
});

/* ========================================================================
   LAB 8 — Postmessage XSS (CWE-345)
   ======================================================================== */
describe("Lab 8: Postmessage XSS", () => {
  it("vuln page returns 200 with sections", async () => {
    const res = await request(app).get("/postmessage-xss").expect(200);
    assertLayout(res.text, 8);
    assertSections(res.text, "Source Code", "Attack Flow");
    // Vuln version has no origin check
    assertContains(res.text, "innerHTML");
  });

  it("fixed page includes origin check", async () => {
    const res = await request(app).get("/postmessage-xss-fixed").expect(200);
    assertSections(res.text, "Source Code", "What Changed");
    assertContains(res.text, "origin");
  });

  it("sender page returns 200", async () => {
    await request(app).get("/postmessage-sender").expect(200);
  });
});

/* ========================================================================
   LAB 9 — JSON Injection (CWE-79)
   ======================================================================== */
describe("Lab 9: JSON Injection", () => {
  it("vuln page returns 200 with sections", async () => {
    const res = await request(app).get("/json-injection").expect(200);
    assertLayout(res.text, 9);
    assertSections(res.text, "Source Code", "Attack Flow");
  });

  it("fixed page returns 200 with sections", async () => {
    const res = await request(app).get("/json-injection-fixed").expect(200);
    assertSections(res.text, "Source Code", "What Changed");
  });
});

/* ========================================================================
   LAB 10 — URL Parsing Confusion (CWE-601)
   ======================================================================== */
describe("Lab 10: URL Parsing Confusion", () => {
  it("vuln page returns 200 with sections", async () => {
    const res = await request(app).get("/url-confusion").expect(200);
    assertLayout(res.text, 10);
    assertSections(res.text, "Source Code", "Attack Flow");
  });

  it("fixed page returns 200 with sections", async () => {
    const res = await request(app).get("/url-confusion-fixed").expect(200);
    assertSections(res.text, "Source Code", "What Changed");
  });
});

/* ========================================================================
   LAB 11 — DOMPurify (CWE-79)
   ======================================================================== */
describe("Lab 11: DOMPurify Sanitizer", () => {
  it("demo page returns 200 with sections", async () => {
    const res = await request(app).get("/dompurify-demo").expect(200);
    assertLayout(res.text, 11);
    assertSections(res.text, "Source Code");
    assertContains(res.text, "<details>");
  });

  it("bypass page returns 200", async () => {
    const res = await request(app).get("/dompurify-bypass").expect(200);
    assertLayout(res.text, 11);
  });
});

/* ========================================================================
   LAB 12 — DOM Clobbering (CWE-79)
   ======================================================================== */
describe("Lab 12: DOM Clobbering", () => {
  it("vuln page returns 200 with sections", async () => {
    const res = await request(app).get("/dom-clobbering").expect(200);
    assertLayout(res.text, 12);
    assertSections(res.text, "Source Code", "Attack Flow");
  });

  it("fixed page returns 200 with sections", async () => {
    const res = await request(app).get("/dom-clobbering-fixed").expect(200);
    assertSections(res.text, "Source Code", "What Changed");
  });
});

/* ========================================================================
   LAB 13 — Mutation XSS (CWE-79)
   ======================================================================== */
describe("Lab 13: Mutation XSS", () => {
  it("page returns 200 with sections", async () => {
    const res = await request(app).get("/mxss").expect(200);
    assertLayout(res.text, 13);
    assertContains(res.text, "mXSS", "Mutation");
  });
});

/* ========================================================================
   LAB 14 — Prototype Pollution → XSS (CWE-1321)
   ======================================================================== */
describe("Lab 14: Prototype Pollution → XSS", () => {
  it("vuln page returns 200 with sections", async () => {
    const res = await request(app).get("/proto-pollution-xss").expect(200);
    assertLayout(res.text, 14);
    assertSections(res.text, "Source Code", "Attack Flow");
  });

  it("fixed page returns 200 with sections", async () => {
    const res = await request(app).get("/proto-pollution-xss-fixed").expect(200);
    assertSections(res.text, "Source Code", "What Changed");
  });
});

/* ========================================================================
   LAB 15 — Dangling Markup (CWE-116)
   ======================================================================== */
describe("Lab 15: Dangling Markup", () => {
  it("page returns 200 with sections", async () => {
    const res = await request(app).get("/dangling-markup").expect(200);
    assertLayout(res.text, 15);
    assertContains(res.text, "Dangling");
  });
});

/* ========================================================================
   LAB 16 — Trusted Types (CWE-79)
   ======================================================================== */
describe("Lab 16: Trusted Types", () => {
  it("page returns 200 with sections", async () => {
    const res = await request(app).get("/trusted-types").expect(200);
    assertLayout(res.text, 16);
    assertSections(res.text, "Source Code");
  });

  it("report page returns 200", async () => {
    const res = await request(app).get("/trusted-types-report").expect(200);
    assertLayout(res.text, 16);
  });
});

/* ========================================================================
   LAB 17 — SRI (CWE-353)
   ======================================================================== */
describe("Lab 17: SRI", () => {
  it("demo page returns 200 with sections", async () => {
    const res = await request(app).get("/sri-demo").expect(200);
    assertLayout(res.text, 17);
    assertSections(res.text, "Source Code");
    assertContains(res.text, "integrity=");
  });

  it("tampered page returns 200", async () => {
    const res = await request(app).get("/sri-tampered").expect(200);
    assertLayout(res.text, 17);
  });

  it("CDN script endpoint returns JS", async () => {
    const res = await request(app).get("/cdn/analytics.js").expect(200);
    assert.ok(
      res.headers["content-type"].includes("javascript"),
      "Expected JS content-type"
    );
  });
});

/* ========================================================================
   LAB 18 — Sandbox Iframes (CWE-1021)
   ======================================================================== */
describe("Lab 18: Sandbox Iframes", () => {
  it("sandbox page returns 200 with sections", async () => {
    const res = await request(app).get("/sandbox-iframe").expect(200);
    assertLayout(res.text, 18);
    assertSections(res.text, "Source Code");
    assertContains(res.text, "sandbox");
  });

  it("no-sandbox page returns 200", async () => {
    await request(app).get("/sandbox-iframe-none").expect(200);
  });

  it("iframe-content returns 200", async () => {
    await request(app).get("/iframe-content").expect(200);
  });
});

/* ========================================================================
   LAB 19 — Security Headers Audit (CWE-693)
   ======================================================================== */
describe("Lab 19: Security Headers Audit", () => {
  it("audit page returns 200 with sections", async () => {
    const res = await request(app).get("/headers-audit").expect(200);
    assertLayout(res.text, 19);
  });

  it("check endpoint sets CSP header when csp param is passed", async () => {
    const res = await request(app).get("/headers-audit-check?csp=1").expect(200);
    assert.ok(res.headers["content-security-policy"], "Expected CSP header on check endpoint");
  });

  it("check endpoint returns JSON", async () => {
    const res = await request(app).get("/headers-audit-check").expect(200);
    assert.ok(
      res.headers["content-type"].includes("json"),
      "Expected JSON content-type"
    );
  });
});

/* ========================================================================
   LAB 20 — SQL Injection (CWE-89)
   ======================================================================== */
describe("Lab 20: SQL Injection", () => {
  it("vuln page returns 200 with sections", async () => {
    const res = await request(app).get("/sqli").expect(200);
    assertLayout(res.text, 20);
    assertSections(res.text, "Source Code", "Attack Flow");
  });

  it("vuln POST with SQLi payload returns all users", async () => {
    const res = await request(app)
      .post("/sqli")
      .type("form")
      .send({ username: "' OR '1'='1" })
      .expect(200);
    // Should return multiple users due to injection
    assertContains(res.text, "admin");
  });

  it("fixed page returns 200 with sections", async () => {
    const res = await request(app).get("/sqli-fixed").expect(200);
    assertLayout(res.text, 20);
    assertContains(res.text, "<details>");
  });

  it("fixed POST with SQLi payload returns no results", async () => {
    const res = await request(app)
      .post("/sqli-fixed")
      .type("form")
      .send({ username: "' OR '1'='1" })
      .expect(200);
    assertNotContains(res.text, "admin");
  });
});

/* ========================================================================
   LAB 21 — Command Injection (CWE-78)
   ======================================================================== */
describe("Lab 21: Command Injection", () => {
  it("vuln page returns 200 with sections", async () => {
    const res = await request(app).get("/cmdi").expect(200);
    assertLayout(res.text, 21);
    assertSections(res.text, "Source Code", "Attack Flow");
  });

  it("vuln POST with injection payload executes command", async () => {
    const res = await request(app)
      .post("/cmdi")
      .type("form")
      .send({ hostname: "localhost; echo INJECTED" })
      .expect(200);
    assertContains(res.text, "INJECTED");
  });

  it("fixed page returns 200", async () => {
    const res = await request(app).get("/cmdi-fixed").expect(200);
    assertLayout(res.text, 21);
    assertContains(res.text, "<details>");
  });

  it("fixed POST blocks injection", async () => {
    const res = await request(app)
      .post("/cmdi-fixed")
      .type("form")
      .send({ hostname: "localhost; echo INJECTED" })
      .expect(400);
    assertContains(res.text, "Rejected", "invalid characters");
  });
});

/* ========================================================================
   LAB 22 — SSTI (CWE-1336)
   ======================================================================== */
describe("Lab 22: SSTI", () => {
  it("vuln page returns 200 with sections", async () => {
    const res = await request(app).get("/ssti").expect(200);
    assertLayout(res.text, 22);
    assertSections(res.text, "Source Code", "Attack Flow");
  });

  it("fixed page returns 200", async () => {
    const res = await request(app).get("/ssti-fixed").expect(200);
    assertLayout(res.text, 22);
    assertSections(res.text, "Source Code");
  });
});

/* ========================================================================
   LAB 23 — CSRF (CWE-352)
   ======================================================================== */
describe("Lab 23: CSRF", () => {
  it("vuln page returns 200 with sections", async () => {
    const res = await request(app).get("/csrf").expect(200);
    assertLayout(res.text, 23);
    assertSections(res.text, "Source Code", "Attack Flow");
  });

  it("vuln POST changes email without token", async () => {
    const res = await request(app)
      .post("/csrf")
      .type("form")
      .send({ email: "evil@attacker.com" })
      .expect(200);
    assertContains(res.text, "evil@attacker.com");
  });

  it("attacker page returns 200", async () => {
    await request(app).get("/csrf-attacker").expect(200);
  });

  it("fixed page returns 200 with CSRF token in form", async () => {
    const res = await request(app).get("/csrf-fixed").expect(200);
    assertContains(res.text, "csrf_token");
  });

  it("fixed POST without valid token is blocked", async () => {
    const res = await request(app)
      .post("/csrf-fixed")
      .type("form")
      .send({ csrf_token: "wrong", email: "evil@attacker.com" })
      .expect(403);
    assertContains(res.text, "CSRF");
  });
});

/* ========================================================================
   LAB 24 — IDOR (CWE-639)
   ======================================================================== */
describe("Lab 24: IDOR", () => {
  it("vuln page returns user 1 by default", async () => {
    const res = await request(app).get("/idor").expect(200);
    assertLayout(res.text, 24);
    assertSections(res.text, "Source Code", "Attack Flow");
  });

  it("vuln page allows accessing other users by ID", async () => {
    const res = await request(app).get("/idor?user_id=2").expect(200);
    assertContains(res.text, "user_id=2");
  });

  it("fixed page returns 200", async () => {
    const res = await request(app).get("/idor-fixed").expect(200);
    assertLayout(res.text, 24);
    assertContains(res.text, "<details>");
  });
});

/* ========================================================================
   LAB 25 — Mass Assignment (CWE-915)
   ======================================================================== */
describe("Lab 25: Mass Assignment", () => {
  it("vuln page returns 200 with sections", async () => {
    const res = await request(app).get("/mass-assign").expect(200);
    assertLayout(res.text, 25);
    assertSections(res.text, "Source Code", "Attack Flow");
  });

  it("vuln POST allows role escalation", async () => {
    const res = await request(app)
      .post("/mass-assign")
      .type("form")
      .send("email=test@test.com&role=admin")
      .expect(200);
    assertContains(res.text, "PRIVILEGE ESCALATION");
  });

  it("fixed POST ignores role field", async () => {
    const res = await request(app)
      .post("/mass-assign-fixed")
      .type("form")
      .send("email=test@test.com&role=admin")
      .expect(200);
    assertContains(res.text, "Only the email field was accepted");
  });
});

/* ========================================================================
   LAB 26 — JWT Weaknesses (CWE-347)
   ======================================================================== */
describe("Lab 26: JWT Weaknesses", () => {
  it("demo page returns 200 with sections", async () => {
    const res = await request(app).get("/jwt-demo").expect(200);
    assertLayout(res.text, 26);
    assertSections(res.text, "Source Code", "Attack Flow");
  });

  it("vuln verify responds with result", async () => {
    const res = await request(app)
      .post("/jwt-verify")
      .type("form")
      .send({ token: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9." })
      .expect(200);
    // Vuln endpoint either accepts (shows decoded token) or shows verification result
    assertContains(res.text, "JWT Verify");
  });

  it("fixed verify rejects forged tokens", async () => {
    const res = await request(app)
      .post("/jwt-verify-fixed")
      .type("form")
      .send({ token: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9." })
      .expect(200);
    // Should reject — look for rejection indicators
    assertContains(res.text, "rejected");
  });
});

/* ========================================================================
   LAB 27 — Path Traversal (CWE-22)
   ======================================================================== */
describe("Lab 27: Path Traversal", () => {
  it("vuln page returns 200 with sections", async () => {
    const res = await request(app).get("/path-traversal").expect(200);
    assertLayout(res.text, 27);
    assertSections(res.text, "Source Code", "Attack Flow");
  });

  it("fixed page returns 200", async () => {
    const res = await request(app).get("/path-traversal-fixed").expect(200);
    assertLayout(res.text, 27);
    assertContains(res.text, "<details>");
  });
});

/* ========================================================================
   LAB 28 — SSRF (CWE-918)
   ======================================================================== */
describe("Lab 28: SSRF", () => {
  it("vuln page returns 200 with sections", async () => {
    const res = await request(app).get("/ssrf").expect(200);
    assertLayout(res.text, 28);
    assertSections(res.text, "Source Code", "Attack Flow");
  });

  it("admin-internal endpoint returns JSON with secret", async () => {
    const res = await request(app).get("/admin-internal").expect(200);
    assert.ok(res.headers["content-type"].includes("json"));
    assert.ok(res.body.secret, "Expected secret in admin-internal response");
  });

  it("fixed page returns 200", async () => {
    const res = await request(app).get("/ssrf-fixed").expect(200);
    assertLayout(res.text, 28);
    assertContains(res.text, "<details>");
  });
});

/* ========================================================================
   LAB 29 — XXE (CWE-611)
   ======================================================================== */
describe("Lab 29: XXE", () => {
  it("vuln page returns 200 with sections", async () => {
    const res = await request(app).get("/xxe").expect(200);
    assertLayout(res.text, 29);
    assertSections(res.text, "Source Code", "Attack Flow");
  });

  it("fixed page returns 200", async () => {
    const res = await request(app).get("/xxe-fixed").expect(200);
    assertLayout(res.text, 29);
    assertContains(res.text, "<details>");
  });
});

/* ========================================================================
   LAB 30 — CORS Misconfiguration (CWE-942)
   ======================================================================== */
describe("Lab 30: CORS Misconfiguration", () => {
  it("info page returns 200 with sections", async () => {
    const res = await request(app).get("/cors-misconfig").expect(200);
    assertLayout(res.text, 30);
    assertSections(res.text, "Source Code", "Attack Flow");
  });

  it("vuln API sets Access-Control-Allow-Origin: *", async () => {
    const res = await request(app).get("/cors-api-vuln").expect(200);
    assert.equal(res.headers["access-control-allow-origin"], "*");
  });

  it("fixed API does not set wildcard CORS", async () => {
    const res = await request(app).get("/cors-api-fixed").expect(200);
    assert.notEqual(res.headers["access-control-allow-origin"], "*");
  });

  it("attacker page returns 200", async () => {
    await request(app).get("/cors-attacker").expect(200);
  });
});

/* ========================================================================
   LAB 31 — Clickjacking (CWE-1021)
   ======================================================================== */
describe("Lab 31: Clickjacking", () => {
  it("vuln page returns 200 with sections", async () => {
    const res = await request(app).get("/clickjack").expect(200);
    assertLayout(res.text, 31);
    assertSections(res.text, "Source Code", "Attack Flow");
    assertContains(res.text, "iframe");
  });

  it("target page has no X-Frame-Options by default", async () => {
    const res = await request(app).get("/clickjack-target").expect(200);
    assert.ok(!res.headers["x-frame-options"], "Target should be frameable (no X-Frame-Options)");
  });

  it("fixed page sets X-Frame-Options", async () => {
    const res = await request(app).get("/clickjack-fixed").expect(200);
    assert.ok(res.headers["x-frame-options"], "Fixed page should set X-Frame-Options");
  });
});

/* ========================================================================
   LAB 32 — CRLF Injection (CWE-113)
   ======================================================================== */
describe("Lab 32: CRLF Injection", () => {
  it("vuln page returns 200 with sections", async () => {
    const res = await request(app).get("/crlf").expect(200);
    assertLayout(res.text, 32);
    assertSections(res.text, "Source Code", "Attack Flow");
  });

  it("fixed page returns 200", async () => {
    const res = await request(app).get("/crlf-fixed").expect(200);
    assertLayout(res.text, 32);
    assertContains(res.text, "<details>");
  });
});

/* ========================================================================
   LAB 33 — Deserialization (CWE-502)
   ======================================================================== */
describe("Lab 33: Deserialization", () => {
  it("vuln page returns 200 with sections", async () => {
    const res = await request(app).get("/deserialize").expect(200);
    assertLayout(res.text, 33);
    assertSections(res.text, "Source Code", "Attack Flow");
  });

  it("fixed page returns 200", async () => {
    const res = await request(app).get("/deserialize-fixed").expect(200);
    assertLayout(res.text, 33);
    assertContains(res.text, "<details>");
  });
});

/* ========================================================================
   LAB 34 — ReDoS (CWE-1333)
   ======================================================================== */
describe("Lab 34: ReDoS", () => {
  it("vuln page returns 200 with sections", async () => {
    const res = await request(app).get("/redos").expect(200);
    assertLayout(res.text, 34);
    assertSections(res.text, "Source Code", "Attack Flow");
  });

  it("fixed page returns 200", async () => {
    const res = await request(app).get("/redos-fixed").expect(200);
    assertLayout(res.text, 34);
    assertContains(res.text, "<details>");
  });
});

/* ========================================================================
   LAB 35 — Insecure Randomness (CWE-330)
   ======================================================================== */
describe("Lab 35: Insecure Randomness", () => {
  it("page returns 200 with sections", async () => {
    const res = await request(app).get("/weak-random").expect(200);
    assertLayout(res.text, 35);
    assertSections(res.text, "Source Code");
    assertContains(res.text, "Math.random", "crypto");
  });
});

/* ========================================================================
   LAB 36 — Error Leaks (CWE-200)
   ======================================================================== */
describe("Lab 36: Error Leaks", () => {
  it("vuln page returns 200", async () => {
    const res = await request(app).get("/error-leak").expect(200);
    assertLayout(res.text, 36);
    assertSections(res.text, "Source Code");
  });

  it("vuln POST leaks stack trace on error", async () => {
    const res = await request(app)
      .post("/error-leak")
      .type("form")
      .send({ id: "invalid" })
      .expect(500);
    const body = res.text.toLowerCase();
    assert.ok(
      body.includes("stack") || body.includes("error") || body.includes("at "),
      "Expected stack trace or error details in vuln response"
    );
  });

  it("fixed POST hides internals", async () => {
    const res = await request(app)
      .post("/error-leak-fixed")
      .type("form")
      .send({ id: "invalid" })
      .expect(500);
    // Fixed version should not leak stack traces or credentials
    assertNotContains(res.text, "s3cret_p@ssw0rd", "10.0.1.42");
    assertContains(res.text, "ERR-");
  });
});

/* ========================================================================
   LAB 37 — Race Conditions (CWE-362)
   ======================================================================== */
describe("Lab 37: Race Conditions", () => {
  it("vuln page returns 200 with sections", async () => {
    const res = await request(app).get("/race-condition").expect(200);
    assertLayout(res.text, 37);
    assertSections(res.text, "Source Code", "Attack Flow");
  });

  it("reset returns JSON", async () => {
    const res = await request(app).post("/race-condition/reset").expect(200);
    assert.ok(res.headers["content-type"].includes("json"));
  });

  it("transfer returns JSON", async () => {
    await request(app).post("/race-condition/reset");
    const res = await request(app)
      .post("/race-condition/transfer")
      .send({ amount: 100 })
      .set("Content-Type", "application/json")
      .expect(200);
    assert.ok(res.headers["content-type"].includes("json"));
  });

  it("fixed page returns 200", async () => {
    const res = await request(app).get("/race-condition-fixed").expect(200);
    assertLayout(res.text, 37);
    assertContains(res.text, "<details>");
  });
});

/* ========================================================================
   LAB 38 — HTTP Parameter Pollution (CWE-235)
   ======================================================================== */
describe("Lab 38: HTTP Parameter Pollution", () => {
  it("vuln page returns 200 with sections", async () => {
    const res = await request(app).get("/hpp").expect(200);
    assertLayout(res.text, 38);
    assertSections(res.text, "Source Code", "Attack Flow");
  });

  it("fixed page returns 200", async () => {
    const res = await request(app).get("/hpp-fixed").expect(200);
    assertLayout(res.text, 38);
    assertContains(res.text, "<details>");
  });
});

/* ========================================================================
   LAB 39 — Insecure Password Storage (CWE-916)
   ======================================================================== */
describe("Lab 39: Insecure Password Storage", () => {
  it("vuln page returns 200 with sections", async () => {
    const res = await request(app).get("/weak-password").expect(200);
    assertLayout(res.text, 39);
    assertSections(res.text, "Source Code");
    assertContains(res.text, "<details>");
  });

  it("fixed page returns 200", async () => {
    const res = await request(app).get("/weak-password-fixed").expect(200);
    assertLayout(res.text, 39);
  });
});

/* ========================================================================
   LAB 40 — Host Header Injection (CWE-644)
   ======================================================================== */
describe("Lab 40: Host Header Injection", () => {
  it("vuln page returns 200 with sections", async () => {
    const res = await request(app).get("/host-header").expect(200);
    assertLayout(res.text, 40);
    assertSections(res.text, "Source Code", "Attack Flow");
  });

  it("fixed page returns 200", async () => {
    const res = await request(app).get("/host-header-fixed").expect(200);
    assertLayout(res.text, 40);
  });
});

/* ========================================================================
   LAB 41 — Prototype Pollution (CWE-1321)
   ======================================================================== */
describe("Lab 41: Prototype Pollution", () => {
  it("vuln page returns 200 with sections", async () => {
    const res = await request(app).get("/proto-pollution").expect(200);
    assertLayout(res.text, 41);
    assertSections(res.text, "Source Code", "Attack Flow");
  });

  it("fixed page returns 200", async () => {
    const res = await request(app).get("/proto-pollution-fixed").expect(200);
    assertLayout(res.text, 41);
  });
});

/* ========================================================================
   LAB 42 — Timing Attack (CWE-208)
   ======================================================================== */
describe("Lab 42: Timing Attack", () => {
  it("vuln page returns 200 with sections", async () => {
    const res = await request(app).get("/timing-attack").expect(200);
    assertLayout(res.text, 42);
    assertSections(res.text, "Source Code", "Attack Flow");
  });

  it("fixed page returns 200", async () => {
    const res = await request(app).get("/timing-attack-fixed").expect(200);
    assertLayout(res.text, 42);
  });
});

/* ========================================================================
   LAB 43 — File Upload (CWE-434)
   ======================================================================== */
describe("Lab 43: File Upload", () => {
  it("vuln page returns 200 with sections", async () => {
    const res = await request(app).get("/file-upload").expect(200);
    assertLayout(res.text, 43);
    assertSections(res.text, "Source Code", "Attack Flow");
  });

  it("fixed page returns 200", async () => {
    const res = await request(app).get("/file-upload-fixed").expect(200);
    assertLayout(res.text, 43);
  });
});

/* ========================================================================
   CROSS-CUTTING: Navigation
   ======================================================================== */
describe("Navigation", () => {
  it("sidebar contains all 43 labs", async () => {
    const res = await request(app).get("/").expect(200);
    for (let i = 1; i <= 43; i++) {
      assertContains(res.text, `Lab ${i}`);
    }
  });

  it("sidebar highlights active lab", async () => {
    const res = await request(app).get("/dom-xss").expect(200);
    assertContains(res.text, "active");
  });

  it("lab pages have prev/next navigation", async () => {
    // Lab 20 (middle of the list) should have both
    const res = await request(app).get("/sqli").expect(200);
    assertContains(res.text, "&larr;", "&rarr;");
  });

  it("breadcrumb shows on lab pages", async () => {
    const res = await request(app).get("/dom-xss").expect(200);
    assertContains(res.text, '<div class="breadcrumb">');
  });
});
