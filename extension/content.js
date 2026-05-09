const PG_API       = "https://phishguard-ov40.onrender.com/scan-url";
const PG_MAX_LINKS = 50;
const PG_TRUSTED   = new Set([
  "google.com","gmail.com","youtube.com","apple.com","icloud.com",
  "microsoft.com","live.com","outlook.com","amazon.com","github.com",
  "githubusercontent.com","facebook.com","fb.com","instagram.com",
  "twitter.com","x.com","netflix.com","linkedin.com","dropbox.com",
  "wikipedia.org","stackoverflow.com","reddit.com","stripe.com",
  "cloudflare.com","paypal.com","mozilla.org",
]);

function getRootDomain(host) {
  const p = host.replace(/^www\./, "").split(".").filter(Boolean);
  return p.length >= 2 ? p.slice(-2).join(".") : host;
}
function getHost(url) {
  try { const p = new URL(url); return ["http:","https:"].includes(p.protocol) ? p.hostname.replace(/^www\./, "").toLowerCase() : ""; }
  catch { return ""; }
}
function isTrusted(url) { return PG_TRUSTED.has(getRootDomain(getHost(url))); }
function isSameSite(url) {
  const cur = getRootDomain(getHost(window.location.href));
  const tgt = getRootDomain(getHost(url));
  return cur && tgt && cur === tgt;
}
function isSkippable(a) {
  if (!a || !a.href) return true;
  const h = a.href;
  return (!h.startsWith("http://") && !h.startsWith("https://")) ||
    h.includes("mailto:") || h.includes("tel:") || h.includes("#") ||
    isSameSite(h) || isTrusted(h);
}

function injectStyles() {
  if (document.getElementById("pg-styles")) return;
  const s = document.createElement("style");
  s.id = "pg-styles";
  s.textContent = `
    .pg-overlay { position:fixed;inset:0;z-index:2147483647;background:rgba(0,0,0,.75);display:flex;align-items:center;justify-content:center;animation:pgFadeIn .2s ease; }
    @keyframes pgFadeIn { from{opacity:0} to{opacity:1} }
    .pg-dialog { background:#0c1220;border-radius:20px;padding:28px 24px 20px;width:360px;max-width:90vw;border:1px solid rgba(239,68,68,.4);box-shadow:0 24px 64px rgba(0,0,0,.6);font-family:system-ui,sans-serif;animation:pgSlideUp .25s ease; }
    .pg-dialog.suspicious { border-color:rgba(245,158,11,.4); }
    @keyframes pgSlideUp { from{opacity:0;transform:translateY(16px)} to{opacity:1;transform:translateY(0)} }
    .pg-dh { display:flex;align-items:center;gap:12px;margin-bottom:16px; }
    .pg-di { width:44px;height:44px;border-radius:12px;display:flex;align-items:center;justify-content:center;flex-shrink:0;background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.3); }
    .pg-dialog.suspicious .pg-di { background:rgba(245,158,11,.12);border-color:rgba(245,158,11,.3); }
    .pg-di svg { width:22px;height:22px; }
    .pg-dt { font-size:18px;font-weight:800;color:#ef4444; }
    .pg-dialog.suspicious .pg-dt { color:#f59e0b; }
    .pg-dd { font-size:12px;color:#64748b;margin-top:2px;font-family:monospace; }
    .pg-sr { display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:14px; }
    .pg-sb { background:rgba(2,6,23,.8);border:1px solid #1e2d45;border-radius:10px;padding:10px 12px; }
    .pg-sl { font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.5px;margin-bottom:3px; }
    .pg-sv { font-size:14px;font-weight:700;color:#e2e8f0; }
    .pg-rb { background:rgba(2,6,23,.6);border:1px solid #1e2d45;border-radius:10px;padding:12px;margin-bottom:16px; }
    .pg-rt { font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px; }
    .pg-rl { display:flex;gap:8px;font-size:12px;color:#cbd5e1;line-height:1.5;margin-bottom:4px; }
    .pg-rl::before { content:"•";color:#ef4444;flex-shrink:0; }
    .pg-dialog.suspicious .pg-rl::before { color:#f59e0b; }
    .pg-br { display:grid;grid-template-columns:1fr 1fr;gap:10px; }
    .pg-btn { padding:11px;border-radius:10px;border:none;font-size:13px;font-weight:700;cursor:pointer;transition:opacity .2s; }
    .pg-btn:hover { opacity:.85; }
    .pg-back { background:linear-gradient(135deg,#1d4ed8,#0e7490);color:#fff; }
    .pg-proc { background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.3);color:#fca5a5; }
    .pg-dialog.suspicious .pg-proc { background:rgba(245,158,11,.1);border-color:rgba(245,158,11,.3);color:#fde68a; }
  `;
  document.documentElement.appendChild(s);
}

function showWarning(result, href) {
  injectStyles();
  const cls = result.verdict === "Phishing" ? "" : " suspicious";
  const icon = result.verdict === "Phishing"
    ? `<svg viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`
    : `<svg viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
  const reasons = (result.reasons || []).slice(0, 4);
  const ov = document.createElement("div");
  ov.className = "pg-overlay";
  ov.innerHTML = `<div class="pg-dialog${cls}">
    <div class="pg-dh"><div class="pg-di">${icon}</div><div><div class="pg-dt">PhishGuard Warning</div><div class="pg-dd">${result.domain || href}</div></div></div>
    <div class="pg-sr">
      <div class="pg-sb"><div class="pg-sl">Verdict</div><div class="pg-sv">${result.verdict}</div></div>
      <div class="pg-sb"><div class="pg-sl">Risk Score</div><div class="pg-sv">${result.risk_score}/100</div></div>
      <div class="pg-sb"><div class="pg-sl">Severity</div><div class="pg-sv">${result.severity}</div></div>
      <div class="pg-sb"><div class="pg-sl">Signals</div><div class="pg-sv">${reasons.length}</div></div>
    </div>
    <div class="pg-rb"><div class="pg-rt">Why PhishGuard flagged this</div>${reasons.map(r=>`<div class="pg-rl">${r}</div>`).join("")}</div>
    <div class="pg-br">
      <button class="pg-btn pg-back" id="pgBack">Go Back (Safe)</button>
      <button class="pg-btn pg-proc" id="pgProc">Proceed Anyway</button>
    </div>
  </div>`;
  document.body.appendChild(ov);
  document.getElementById("pgBack").onclick = () => ov.remove();
  document.getElementById("pgProc").onclick = () => { ov.remove(); window.location.href = href; };
  ov.addEventListener("click", e => { if (e.target === ov) ov.remove(); });
}

async function scanUrl(url) {
  try {
    const r = await fetch(PG_API, { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({url}) });
    return await r.json();
  } catch { return null; }
}

function applyBadge(anchor, result) {
  if (!result || anchor.dataset.pgScanned) return;
  anchor.dataset.pgScanned = "1";
  const { verdict, risk_score: score } = result;
  if (verdict === "Phishing" && score >= 60) {
    anchor.style.cssText += "outline:2px solid #ef4444 !important;background-color:rgba(239,68,68,.1) !important;border-radius:3px;";
    anchor.title = `PhishGuard: Phishing (${score}/100)`;
  } else if (verdict === "Suspicious" && score >= 35) {
    anchor.style.cssText += "outline:2px solid #f59e0b !important;background-color:rgba(245,158,11,.08) !important;border-radius:3px;";
    anchor.title = `PhishGuard: Suspicious (${score}/100)`;
  }
}

async function scanPageLinks() {
  const anchors = [...document.querySelectorAll("a[href]")].filter(a => !isSkippable(a) && !a.dataset.pgScanned);
  const unique = [...new Map(anchors.map(a => [a.href, a])).values()].slice(0, PG_MAX_LINKS);
  for (const anchor of unique) { const r = await scanUrl(anchor.href); if (r) applyBadge(anchor, r); }
}

document.addEventListener("click", async e => {
  const anchor = e.target.closest("a[href]");
  if (isSkippable(anchor)) return;
  const result = await scanUrl(anchor.href);
  if (!result) return;
  const { verdict, risk_score: score } = result;
  if ((verdict === "Phishing" && score >= 60) || (verdict === "Suspicious" && score >= 35)) {
    e.preventDefault(); e.stopImmediatePropagation();
    showWarning(result, anchor.href);
  }
}, true);

injectStyles();
setTimeout(scanPageLinks, 1800);
new MutationObserver(() => {
  const fresh = [...document.querySelectorAll("a[href]")].filter(a => !isSkippable(a) && !a.dataset.pgScanned);
  if (fresh.length) scanPageLinks();
}).observe(document.body, { childList:true, subtree:true });