const SECURITY_HEADERS = [
  ["content-security-policy", "Content Security Policy", "high", "browser", "Reduces cross-site scripting and content-injection risk.", "Add a Content-Security-Policy header. Start with default-src 'self', then explicitly allow only required sources."],
  ["strict-transport-security", "HTTP Strict Transport Security", "high", "transport", "Tells browsers to use HTTPS for future visits.", "After confirming every page works over HTTPS, add Strict-Transport-Security: max-age=31536000; includeSubDomains."],
  ["x-content-type-options", "MIME sniffing protection", "medium", "browser", "Prevents browsers from guessing unsafe content types.", "Add X-Content-Type-Options: nosniff to every response."],
  ["x-frame-options", "Clickjacking protection", "medium", "browser", "Restricts embedding the site in frames.", "Add frame-ancestors 'none' to Content-Security-Policy, or X-Frame-Options: DENY for legacy browsers."],
  ["referrer-policy", "Referrer policy", "low", "privacy", "Limits information sent when visitors follow links.", "Add Referrer-Policy: strict-origin-when-cross-origin, or a stricter policy if appropriate."],
  ["permissions-policy", "Browser permissions policy", "low", "privacy", "Restricts access to browser capabilities.", "Disable unused capabilities, for example Permissions-Policy: camera=(), microphone=(), geolocation=()."],
  ["cross-origin-opener-policy", "Cross-origin opener policy", "low", "isolation", "Helps isolate the page from cross-origin windows.", "Add Cross-Origin-Opener-Policy: same-origin unless your application intentionally relies on cross-origin opener relationships."],
];
const PENALTIES = { high: 15, medium: 7, low: 3 };
const EMBEDDED_INDEX = globalThis.__VIBE_INDEX_HTML__ || null;
const WINDOW_MS = 60_000;
const MAX_SCANS = 8;
const visitors = new Map();

const API_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "permissions-policy": "camera=(), microphone=(), geolocation=()",
};
const json = (data, status = 200, extra = {}) => new Response(JSON.stringify(data), { status, headers: { ...API_HEADERS, ...extra } });

function rateLimit(request) {
  const now = Date.now();
  const key = request.headers.get("cf-connecting-ip") || "unknown";
  const current = visitors.get(key);
  if (!current || now - current.started > WINDOW_MS) {
    visitors.set(key, { started: now, count: 1 });
    return null;
  }
  current.count += 1;
  if (current.count > MAX_SCANS) {
    const retry = Math.max(1, Math.ceil((WINDOW_MS - (now - current.started)) / 1000));
    return json({ error: "Too many scans from this connection. Please wait a minute and try again." }, 429, { "retry-after": String(retry) });
  }
  return null;
}

function validateTarget(value) {
  if (!value || value.length > 2048) throw new Error("Enter a valid public HTTPS URL under 2,048 characters.");
  let url;
  try { url = new URL(value); } catch { throw new Error("Enter a valid public HTTPS URL."); }
  if (url.protocol !== "https:") throw new Error("Only HTTPS websites can be scanned.");
  if (url.username || url.password || url.port) throw new Error("Credentials and custom ports are not allowed.");
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  if (!host || host.length > 253 || host.includes("%")) throw new Error("The hostname is not valid.");
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal") || host.endsWith(".home") || host.endsWith(".lan")) throw new Error("Private or local hosts are not allowed.");
  if (/^(?:127\.|10\.|0\.|169\.254\.|192\.168\.|198\.18\.|172\.(?:1[6-9]|2\d|3[01])\.)/.test(host) || host === "::1" || host.includes(":")) throw new Error("Private or literal IP targets are not allowed.");
  url.hash = "";
  return url;
}

function cookieFindings(headers) {
  const values = typeof headers.getSetCookie === "function" ? headers.getSetCookie() : (headers.get("set-cookie") ? [headers.get("set-cookie")] : []);
  const findings = [];
  values.forEach((raw, index) => {
    const label = values.length > 1 ? `Cookie ${index + 1}` : "Observed cookie";
    if (!/;\s*secure\b/i.test(raw)) findings.push({ id: `COOKIE-SECURE-${index}`, severity: "high", category: "cookies", title: `${label} may be missing Secure`, detail: "The cookie did not include the Secure attribute.", remediation: "Set Secure on session and authentication cookies so browsers send them only over HTTPS." });
    if (!/;\s*httponly\b/i.test(raw)) findings.push({ id: `COOKIE-HTTPONLY-${index}`, severity: "medium", category: "cookies", title: `${label} may be missing HttpOnly`, detail: "The cookie did not include the HttpOnly attribute.", remediation: "Set HttpOnly on cookies JavaScript does not need to read, especially session cookies." });
    if (!/;\s*samesite=/i.test(raw)) findings.push({ id: `COOKIE-SAMESITE-${index}`, severity: "low", category: "cookies", title: `${label} may be missing SameSite`, detail: "The cookie did not include an explicit SameSite policy.", remediation: "Set SameSite=Lax by default. Use Strict when possible, or None; Secure only for intentional cross-site use." });
  });
  return findings;
}

async function scanWebsite(request) {
  const limited = rateLimit(request);
  if (limited) return limited;
  const declared = Number(request.headers.get("content-length") || 0);
  if (declared > 4096) return json({ error: "The request is too large." }, 413);
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid request." }, 400); }
  let target;
  try { target = validateTarget(String(body.url || "").trim()); } catch (error) { return json({ error: error.message }, 400); }
  if (target.hostname === new URL(request.url).hostname) return json({ error: "This scanner cannot scan its own hostname from inside the same hosting service. Use an independent security-header checker for this address." }, 400);
  let response;
  const started = Date.now();
  try {
    response = await fetch(target.toString(), { method: "GET", redirect: "manual", headers: { "user-agent": "VibeSecurityCheck/2.0 passive-security-review", "accept": "text/html,application/xhtml+xml" }, signal: AbortSignal.timeout(8000) });
  } catch {
    return json({ error: "The website could not be reached safely within eight seconds." }, 422);
  }
  const findings = [], passed = [];
  for (const [header, title, severity, category, detail, remediation] of SECURITY_HEADERS) {
    if (response.headers.has(header)) passed.push({ id: header, title, category });
    else findings.push({ id: `HEADER-${header.toUpperCase()}`, severity, category, title: `${title} not observed`, detail, remediation });
  }
  findings.push(...cookieFindings(response.headers));
  const server = response.headers.get("server") || "";
  if (server && !/^(?:cloudflare|cloudfront|akamai|fastly)$/i.test(server.trim())) findings.push({ id: "SERVER-DISCLOSURE", severity: "low", category: "exposure", title: "Server technology is disclosed", detail: "The Server header may reveal implementation details.", remediation: "Remove or generalize the Server header at the application, reverse proxy, or hosting layer." });
  if (response.status >= 300 && response.status < 400) findings.push({ id: "REDIRECT-NOT-FOLLOWED", severity: "low", category: "transport", title: "The URL returned a redirect", detail: "For safety, this passive check does not follow redirects automatically.", remediation: "Scan the final HTTPS destination directly and confirm redirects never downgrade to HTTP." });
  const score = Math.max(0, 100 - findings.reduce((sum, item) => sum + PENALTIES[item.severity], 0));
  const risk = findings.some(x => x.severity === "high") ? "high" : findings.some(x => x.severity === "medium") ? "medium" : findings.length ? "low" : "clear";
  const grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F";
  const counts = { high: findings.filter(x => x.severity === "high").length, medium: findings.filter(x => x.severity === "medium").length, low: findings.filter(x => x.severity === "low").length };
  return json({ version: "2.0", target: target.origin, checkedAt: new Date().toISOString(), durationMs: Date.now() - started, status: response.status, score, grade, risk, counts, findings, passed, limitations: "Passive response-header review only. No exploit attempts, redirect following, port scans, authenticated checks, source-code review, dependency analysis, or proof of security." });
}

async function serveAsset(request, env) {
  const url = new URL(request.url);
  const response = url.pathname === "/" && EMBEDDED_INDEX ? new Response(EMBEDDED_INDEX, { headers: { "content-type": "text/html; charset=utf-8" } }) : await env.ASSETS.fetch(request);
  const headers = new Headers(response.headers);
  headers.set("x-content-type-options", "nosniff");
  headers.set("referrer-policy", "strict-origin-when-cross-origin");
  headers.set("permissions-policy", "camera=(), microphone=(), geolocation=()");
  headers.set("x-frame-options", "DENY");
  headers.set("strict-transport-security", "max-age=31536000; includeSubDomains");
  headers.set("cross-origin-opener-policy", "same-origin");
  headers.set("cross-origin-resource-policy", "same-origin");
  headers.set("content-security-policy", "default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname === "/api/scan") return scanWebsite(request);
    if (request.method === "GET" && url.pathname === "/api/health") return json({ status: "ok", version: "2.0" });
    if (url.pathname.startsWith("/api/")) return json({ error: "Not found." }, 404);
    return serveAsset(request, env);
  },
};
