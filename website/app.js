const form = document.querySelector('#scan-form');
const results = document.querySelector('#results');
const button = form.querySelector('button');

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  button.disabled = true;
  button.innerHTML = 'Scanning safely…';
  results.className = 'results';
  results.innerHTML = '<div class="result-head"><div class="score loading">···</div><div><span class="risk">Passive check</span><h2>Looking at public protections…</h2><p>One response. No exploit attempts, deep crawl, or intrusive testing.</p></div></div>';

  try {
    if (window.location.protocol === 'file:') {
      await new Promise((resolve) => setTimeout(resolve, 650));
      render(makeDemoReport(form.url.value), true);
      return;
    }

    const response = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ url: form.url.value }),
    });
    const report = await response.json();
    if (!response.ok) throw new Error(report.error || 'The scan could not be completed.');
    render(report, false);
  } catch (error) {
    results.innerHTML = `<div class="error"><strong>We couldn't complete that check</strong><p>${escapeHtml(error.message)}</p><p>The scanner service must be published before it can inspect a live website.</p></div>`;
  } finally {
    button.disabled = false;
    button.innerHTML = 'Run passive check <span>→</span>';
    results.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
});

function makeDemoReport(value) {
  let target = 'https://example.com';
  try { target = new URL(value).origin; } catch { /* Keep the safe example URL. */ }
  return {
    target,
    status: 200,
    score: 72,
    risk: 'medium',
    findings: [
      { severity: 'high', title: 'Content Security Policy not observed', detail: 'A strong CSP can reduce cross-site scripting and content-injection risk.', remediation: "Add a Content-Security-Policy header. Start with default-src 'self', then allow only required sources." },
      { severity: 'medium', title: 'Clickjacking protection not observed', detail: 'Frame restrictions help prevent the site from being embedded in a malicious page.', remediation: "Add frame-ancestors 'none' to Content-Security-Policy, or X-Frame-Options: DENY." },
      { severity: 'low', title: 'Referrer policy not observed', detail: 'A referrer policy limits information shared when visitors follow links.', remediation: 'Add Referrer-Policy: strict-origin-when-cross-origin.' },
    ],
    passed: [
      { title: 'HTTPS transport' },
      { title: 'MIME sniffing protection' },
      { title: 'Secure cookie flags' },
    ],
    limitations: 'Illustrative local demo data only. Publish the scanner to perform a real passive response-header review.',
  };
}

function render(report, isDemo) {
  const findings = report.findings.map((item) => `<div class="finding"><div class="sev ${item.severity}">${item.severity}</div><div><h3>${escapeHtml(item.title)}</h3><p>${escapeHtml(item.detail)}</p>${item.remediation ? `<div class="fix"><strong>Recommended fix</strong><p>${escapeHtml(item.remediation)}</p></div>` : ''}</div></div>`).join('');
  const demoNotice = isDemo ? '<div class="passed"><strong>Local demo mode:</strong> These sample results demonstrate the report experience; they are not findings from the URL entered.</div>' : '';
  results.innerHTML = `${demoNotice}<div class="result-head"><div><div class="score" style="--score:${report.score}%"><span>${report.score}<small>/100</small></span></div><span class="risk">${escapeHtml(report.risk)} risk</span></div><div><h2>${escapeHtml(report.target)}</h2><p><strong>${report.findings.length}</strong> items to review · <strong>${report.passed.length}</strong> observed protections · HTTP ${report.status}</p><p>${escapeHtml(report.limitations)}</p></div></div>${findings || '<div class="passed"><strong>Great start—no findings from these passive checks.</strong> This does not prove the website is secure.</div>'}<div class="passed"><strong>Protections we observed:</strong> ${report.passed.map((item) => escapeHtml(item.title)).join(' · ') || 'None from the configured checks'}</div>`;
}

function escapeHtml(value) {
  const node = document.createElement('div');
  node.textContent = String(value);
  return node.innerHTML;
}
