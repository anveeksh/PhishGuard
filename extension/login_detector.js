(function() {
"use strict";
if (window.__pgLoginLoaded) return;
window.__pgLoginLoaded = true;

const PG_LOGIN_API = "https://phishguard-ov40.onrender.com/scan-url";
const PG_LOGIN_TRUSTED = new Set([
  "google.com","gmail.com","apple.com","microsoft.com","amazon.com",
  "github.com","facebook.com","twitter.com","x.com","linkedin.com",
  "netflix.com","dropbox.com","coinbase.com","binance.com","paypal.com",
  "stripe.com","shopify.com","slack.com","notion.so","figma.com",
  "bharatmatrimony.com","shaadi.com","naukri.com","flipkart.com",
  "paytm.com","phonepe.com","irctc.co.in","stackoverflow.com"
]);

function pgRoot(host) {
  const p = host.replace(/^www\./, "").split(".").filter(Boolean);
  return p.length >= 2 ? p.slice(-2).join(".") : host;
}
function pgCurrentRoot() {
  return pgRoot(window.location.hostname.replace(/^www\./, "").toLowerCase());
}
function pgTrusted() { return PG_LOGIN_TRUSTED.has(pgCurrentRoot()); }
function hasPassword() { return document.querySelectorAll("input[type=password]").length > 0; }

function injectStyles() {
  if (document.getElementById("pg-login-styles")) return;
  const s = document.createElement("style");
  s.id = "pg-login-styles";
  s.textContent = `
    #pg-login-banner {
      position:fixed;top:0;left:0;right:0;z-index:2147483647;
      font-family:system-ui,sans-serif;animation:pgBS 0.3s ease;
    }
    @keyframes pgBS{from{transform:translateY(-100%);opacity:0}to{transform:translateY(0);opacity:1}}
    #pg-login-banner .pgi{display:flex;align-items:center;gap:12px;padding:12px 20px;font-size:13px;}
    #pg-login-banner.phishing .pgi{background:#1a0a0a;border-bottom:2px solid #ef4444;color:#fca5a5;}
    #pg-login-banner.suspicious .pgi{background:#1a1200;border-bottom:2px solid #f59e0b;color:#fde68a;}
    #pg-login-banner .pgsc{margin-left:auto;font-size:11px;font-family:monospace;opacity:.8;white-space:nowrap;}
    #pg-login-banner .pgcl{background:none;border:none;color:inherit;cursor:pointer;font-size:18px;padding:0 4px;opacity:.7;}
    #pg-form-overlay{position:fixed;inset:0;z-index:2147483646;background:rgba(0,0,0,.85);display:flex;align-items:center;justify-content:center;animation:pgFI .2s ease;}
    @keyframes pgFI{from{opacity:0}to{opacity:1}}
    #pg-form-dialog{background:#0c1220;border:1px solid rgba(239,68,68,.5);border-radius:20px;padding:28px 24px;width:380px;max-width:90vw;font-family:system-ui,sans-serif;box-shadow:0 24px 64px rgba(0,0,0,.7);animation:pgSU .25s ease;}
    @keyframes pgSU{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}}
    #pg-form-dialog h2{font-size:18px;font-weight:800;color:#ef4444;margin-bottom:6px;}
    #pg-form-dialog .pgdom{font-size:12px;color:#64748b;font-family:monospace;margin-bottom:16px;}
    #pg-form-dialog .pgst{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px;}
    #pg-form-dialog .pgsb{background:rgba(2,6,23,.8);border:1px solid #1e2d45;border-radius:10px;padding:10px 12px;}
    #pg-form-dialog .pgsl{font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.5px;margin-bottom:3px;}
    #pg-form-dialog .pgsv{font-size:14px;font-weight:700;color:#e2e8f0;}
    #pg-form-dialog .pgrb{background:rgba(2,6,23,.6);border:1px solid #1e2d45;border-radius:10px;padding:12px;margin-bottom:16px;max-height:120px;overflow-y:auto;}
    #pg-form-dialog .pgrb p{font-size:12px;color:#cbd5e1;line-height:1.5;margin-bottom:4px;}
    #pg-form-dialog .pgrb p::before{content:"• ";color:#ef4444;}
    #pg-form-dialog .pgbr{display:grid;grid-template-columns:1fr 1fr;gap:10px;}
    #pg-form-dialog .pgbt{padding:11px;border-radius:10px;border:none;font-size:13px;font-weight:700;cursor:pointer;font-family:system-ui,sans-serif;}
    #pg-form-dialog .pglv{background:linear-gradient(135deg,#1d4ed8,#0e7490);color:#fff;}
    #pg-form-dialog .pgsy{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:#fca5a5;}
  `;
  document.documentElement.appendChild(s);
}

function showBanner(result) {
  if (document.getElementById("pg-login-banner")) return;
  const cls = result.verdict === "Phishing" ? "phishing" : "suspicious";
  const b = document.createElement("div");
  b.id = "pg-login-banner"; b.className = cls;
  b.innerHTML = `<div class="pgi">
    <strong>PhishGuard:</strong>
    This login page scored ${result.risk_score}/100 — ${result.verdict === "Phishing" ? "possible fake login, do not enter your password." : "verify this domain before entering credentials."}
    <span class="pgsc">${result.verdict} ${result.risk_score}/100</span>
    <button class="pgcl" id="pgBC">×</button>
  </div>`;
  document.body.insertBefore(b, document.body.firstChild);
  document.getElementById("pgBC").onclick = () => b.remove();
}

function showDialog(result) {
  if (document.getElementById("pg-form-overlay")) return;
  const ov = document.createElement("div");
  ov.id = "pg-form-overlay";
  const reasons = (result.reasons || []).slice(0, 5);
  ov.innerHTML = `<div id="pg-form-dialog">
    <h2>⚠ Suspicious Login Page</h2>
    <div class="pgdom">${window.location.hostname}</div>
    <div class="pgst">
      <div class="pgsb"><div class="pgsl">Verdict</div><div class="pgsv">${result.verdict}</div></div>
      <div class="pgsb"><div class="pgsl">Risk Score</div><div class="pgsv">${result.risk_score}/100</div></div>
      <div class="pgsb"><div class="pgsl">Severity</div><div class="pgsv">${result.severity}</div></div>
      <div class="pgsb"><div class="pgsl">Signals</div><div class="pgsv">${reasons.length}</div></div>
    </div>
    <div class="pgrb">${reasons.map(r=>`<p>${r}</p>`).join("")}</div>
    <div class="pgbr">
      <button class="pgbt pglv" id="pgLV">Leave Page (Safe)</button>
      <button class="pgbt pgsy" id="pgSY">Stay Anyway</button>
    </div>
  </div>`;
  document.body.appendChild(ov);
  document.getElementById("pgLV").onclick = () => history.back();
  document.getElementById("pgSY").onclick = () => ov.remove();
}

async function checkPage() {
  if (!hasPassword() || pgTrusted()) return;
  try {
    const r = await fetch(PG_LOGIN_API, {
      method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({url: window.location.href})
    });
    const result = await r.json();
    if (result.verdict === "Phishing" && result.risk_score >= 60) {
      injectStyles(); showBanner(result); showDialog(result);
    } else if (result.verdict === "Suspicious" && result.risk_score >= 35) {
      injectStyles(); showBanner(result);
    }
  } catch {}
}

let pgChecked = false;
if (hasPassword()) {
  setTimeout(checkPage, 800);
} else {
  const obs = new MutationObserver(() => {
    if (!pgChecked && hasPassword()) {
      pgChecked = true; obs.disconnect(); setTimeout(checkPage, 500);
    }
  });
  obs.observe(document.body, {childList:true, subtree:true});
}
})();
