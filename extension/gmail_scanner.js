(function() {
"use strict";
if (window.__pgGmailLoaded) return;
window.__pgGmailLoaded = true;

const GMAIL_API = "http://127.0.0.1:8000/scan-url";
const GMAIL_TRUSTED = new Set([
  "google.com","gmail.com","youtube.com","apple.com","microsoft.com",
  "amazon.com","github.com","facebook.com","twitter.com","x.com",
  "linkedin.com","wikipedia.org","stackoverflow.com","stripe.com",
  "cloudflare.com","paypal.com","mozilla.org","accounts.google.com",
  "bharatmatrimony.com","shaadi.com","naukri.com","flipkart.com","myntra.com",
  "irctc.co.in","zomato.com","swiggy.com","paytm.com","phonepe.com","hdfc.com","sbi.co.in"
]);

function gmailHost(url) {
  try { const p = new URL(url); return ["http:","https:"].includes(p.protocol) ? p.hostname.replace(/^www\./, "").toLowerCase() : ""; }
  catch { return ""; }
}
function gmailRoot(host) {
  const p = host.split(".").filter(Boolean);
  return p.length >= 2 ? p.slice(-2).join(".") : host;
}
function gmailTrusted(url) { return GMAIL_TRUSTED.has(gmailRoot(gmailHost(url))); }

function injectStyles() {
  if (document.getElementById("pg-gmail-styles")) return;
  const s = document.createElement("style");
  s.id = "pg-gmail-styles";
  s.textContent = `
    .pg-gph { outline: 2px solid #ef4444 !important; background: rgba(239,68,68,0.12) !important; border-radius: 3px !important; padding: 0 2px !important; }
    .pg-gsu { outline: 2px solid #f59e0b !important; background: rgba(245,158,11,0.08) !important; border-radius: 3px !important; padding: 0 2px !important; }
    .pg-badge { display:inline-block; font-size:10px; font-weight:700; padding:1px 6px; border-radius:4px; margin-left:4px; vertical-align:middle; font-family:monospace; }
    .pg-badge.ph { background:rgba(239,68,68,0.15); border:1px solid rgba(239,68,68,0.4); color:#ef4444; }
    .pg-badge.su { background:rgba(245,158,11,0.1); border:1px solid rgba(245,158,11,0.3); color:#f59e0b; }
    .pg-wbar { display:flex; align-items:center; gap:10px; padding:10px 16px; margin:8px 0; background:rgba(239,68,68,0.08); border:1px solid rgba(239,68,68,0.3); border-radius:10px; font-family:system-ui,sans-serif; font-size:13px; color:#fca5a5; }
    .pg-wbar.su { background:rgba(245,158,11,0.06); border-color:rgba(245,158,11,0.3); color:#fde68a; }
  `;
  document.documentElement.appendChild(s);
}

async function gmailScan(url) {
  try {
    const r = await fetch(GMAIL_API, { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({url}) });
    return await r.json();
  } catch { return null; }
}

function addWarningBar(container, verdict, count) {
  if (container.querySelector(".pg-wbar")) return;
  const bar = document.createElement("div");
  bar.className = `pg-wbar${verdict === "Phishing" ? "" : " su"}`;
  bar.innerHTML = `<strong>PhishGuard:</strong> ${count} suspicious link${count>1?"s":""} detected in this email. Do not click unknown links.`;
  container.insertBefore(bar, container.firstChild);
}

async function scanBody(body) {
  if (body.dataset.pgDone) return;
  body.dataset.pgDone = "1";
  const links = [...body.querySelectorAll("a[href]")].filter(a => {
    const h = a.href;
    return (h.startsWith("http://") || h.startsWith("https://")) && !gmailTrusted(h);
  }).slice(0, 25);
  if (!links.length) return;
  let worst = null, count = 0;
  for (const a of links) {
    const res = await gmailScan(a.href);
    if (!res) continue;
    if (res.verdict === "Phishing" && res.risk_score >= 60) {
      a.classList.add("pg-gph");
      a.title = `PhishGuard: Phishing (${res.risk_score}/100)`;
      const b = document.createElement("span");
      b.className = "pg-badge ph"; b.textContent = `⚠ PHISHING ${res.risk_score}/100`;
      a.insertAdjacentElement("afterend", b);
      count++; worst = "Phishing";
    } else if (res.verdict === "Suspicious" && res.risk_score >= 35) {
      a.classList.add("pg-gsu");
      const b = document.createElement("span");
      b.className = "pg-badge su"; b.textContent = `⚠ ${res.risk_score}/100`;
      a.insertAdjacentElement("afterend", b);
      count++; if (!worst) worst = "Suspicious";
    }
  }
  if (count > 0 && worst) {
    const c = body.closest(".a3s") || body.closest("[data-message-id]") || body.parentElement;
    if (c) addWarningBar(c, worst, count);
  }
}

function init() {
  injectStyles();
  document.querySelectorAll(".a3s, .a3s.aiL, .ii.gt").forEach(b => scanBody(b));
  new MutationObserver(muts => {
    for (const m of muts) for (const n of m.addedNodes) {
      if (n.nodeType !== 1) continue;
      if (n.classList?.contains("a3s") || n.classList?.contains("ii")) scanBody(n);
      n.querySelectorAll?.(".a3s, .ii.gt").forEach(b => scanBody(b));
    }
  }).observe(document.body, { childList:true, subtree:true });
  console.log("[PhishGuard] Gmail scanner active.");
}

init();
})();
