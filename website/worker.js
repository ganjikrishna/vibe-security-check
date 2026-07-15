const SECURITY_HEADERS = [
  ["content-security-policy", "Content Security Policy", "high", "Reduces cross-site scripting and content-injection risk.", "Add a Content-Security-Policy header. Start with default-src 'self', then explicitly allow only the sources your app needs."],
  ["strict-transport-security", "HTTP Strict Transport Security", "high", "Tells browsers to use HTTPS for future visits.", "After confirming every page works over HTTPS, add Strict-Transport-Security: max-age=31536000; includeSubDomains."],
  ["x-content-type-options", "MIME sniffing protection", "medium", "Prevents browsers from guessing unsafe content types.", "Add X-Content-Type-Options: nosniff to every response."],
  ["x-frame-options", "Clickjacking protection", "medium", "Restricts embedding the site in frames.", "Add frame-ancestors 'none' to Content-Security-Policy, or X-Frame-Options: DENY for legacy browsers."],
  ["referrer-policy", "Referrer policy", "low", "Limits information sent when visitors follow links.", "Add Referrer-Policy: strict-origin-when-cross-origin, or a stricter policy if appropriate."],
  ["permissions-policy", "Browser permissions policy", "low", "Restricts access to browser features.", "Disable unused browser capabilities, for example Permissions-Policy: camera=(), microphone=(), geolocation=()."],
];

const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" },
});

function validateTarget(value) {
  let url;
  try { url = new URL(value); } catch { throw new Error("Enter a valid public HTTPS URL."); }
  if (url.protocol !== "https:") throw new Error("Only HTTPS websites can be scanned.");
  if (url.username || url.password || url.port) throw new Error("Credentials and custom ports are not allowed.");
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal")) throw new Error("Private or local hosts are not allowed.");
  if (/^(?:127\.|10\.|0\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/.test(host) || host === "::1" || host.includes(":")) throw new Error("Private or literal IP targets are not allowed.");
  url.hash = "";
  return url;
}

function cookieFindings(headers) {
  const raw = headers.get("set-cookie") || "";
  if (!raw) return [];
  const findings = [];
  if (!/;\s*secure\b/i.test(raw)) findings.push({ id: "COOKIE-SECURE", severity: "high", title: "Cookie may be missing Secure", detail: "At least one observed cookie did not include the Secure attribute.", remediation: "Set Secure on every session or authentication cookie so browsers send it only over HTTPS." });
  if (!/;\s*httponly\b/i.test(raw)) findings.push({ id: "COOKIE-HTTPONLY", severity: "medium", title: "Cookie may be missing HttpOnly", detail: "At least one observed cookie did not include the HttpOnly attribute.", remediation: "Set HttpOnly on cookies that JavaScript does not need to read, especially session cookies." });
  if (!/;\s*samesite=/i.test(raw)) findings.push({ id: "COOKIE-SAMESITE", severity: "low", title: "Cookie may be missing SameSite", detail: "At least one observed cookie did not include an explicit SameSite policy.", remediation: "Set SameSite=Lax by default. Use Strict when possible, or None; Secure only for intentional cross-site use." });
  return findings;
}

async function scanWebsite(request) {
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid request." }, 400); }
  let target;
  try { target = validateTarget(String(body.url || "").trim()); } catch (error) { return json({ error: error.message }, 400); }
  let response;
  try {
    response = await fetch(target.toString(), { method: "GET", redirect: "manual", headers: { "user-agent": "VibeSecurityCheck/1.0 passive-security-review" }, signal: AbortSignal.timeout(8000) });
  } catch {
    return json({ error: "The website could not be reached safely within eight seconds." }, 422);
  }
  const findings = [];
  const passed = [];
  for (const [header, title, severity, detail, remediation] of SECURITY_HEADERS) {
    if (response.headers.has(header)) passed.push({ id: header, title });
    else findings.push({ id: `HEADER-${header.toUpperCase()}`, severity, title: `${title} not observed`, detail, remediation });
  }
  findings.push(...cookieFindings(response.headers));
  if (response.headers.has("server")) findings.push({ id: "SERVER-DISCLOSURE", severity: "low", title: "Server technology is disclosed", detail: "The Server header may reveal implementation details.", remediation: "Remove or generalize the Server header at the application, reverse proxy, or hosting layer." });
  const penalties = { high: 15, medium: 7, low: 3 };
  const score = Math.max(0, 100 - findings.reduce((sum, item) => sum + penalties[item.severity], 0));
  const risk = findings.some(x => x.severity === "high") ? "high" : findings.some(x => x.severity === "medium") ? "medium" : findings.length ? "low" : "clear";
  return json({ target: target.origin, checkedAt: new Date().toISOString(), status: response.status, score, risk, findings, passed, limitations: "Passive response-header review only. No exploit attempts, port scans, authenticated checks, source-code review, dependency analysis, or proof of security." });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname === "/api/scan") return scanWebsite(request);
    if (request.method === "GET" && url.pathname === "/api/health") return json({ status: "ok" });
    return env.ASSETS.fetch(request);
  },
};
