const API = "https://phishguard-ov40.onrender.com/scan-url";
const scanBtn    = document.getElementById("scanBtn");
const btnText    = document.getElementById("btnText");
const statusDot  = document.getElementById("statusDot");
const statusText = statusDot.querySelector(".status-text");
const currentUrl = document.getElementById("currentUrl");
const resultCard = document.getElementById("resultCard");
const idleState  = document.getElementById("idleState");
const errorState = document.getElementById("errorState");
const errorMsg   = document.getElementById("errorMsg");

chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
  if (tab && tab.url) {
    try { currentUrl.textContent = new URL(tab.url).hostname; }
    catch { currentUrl.textContent = tab.url; }
  }
});

function setScanning(on) {
  scanBtn.disabled = on;
  scanBtn.classList.toggle("loading", on);
  btnText.textContent = on ? "Scanning..." : "Scan This Page";
  statusText.textContent = on ? "Scanning" : "Ready";
  statusDot.className = "pg-status" + (on ? " scanning" : "");
}

function showError(msg) {
  idleState.style.display  = "none";
  resultCard.style.display = "none";
  errorState.style.display = "flex";
  errorMsg.textContent = msg;
  statusDot.className = "pg-status error";
  statusText.textContent = "Error";
}

function showResult(data) {
  idleState.style.display  = "none";
  errorState.style.display = "none";
  resultCard.style.display = "block";
  const cls = data.verdict.toLowerCase();
  resultCard.className = "pg-result " + cls;
  const icons = {
    Safe: `<svg viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`,
    Phishing: `<svg viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
    Suspicious: `<svg viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`
  };
  document.getElementById("verdictIcon").innerHTML  = icons[data.verdict] || icons.Suspicious;
  document.getElementById("verdictLabel").textContent  = data.verdict;
  document.getElementById("verdictDomain").textContent = data.domain || "-";
  document.getElementById("scoreNum").textContent      = data.risk_score;
  document.getElementById("metaSeverity").textContent  = data.severity;
  document.getElementById("metaSignals").textContent   = (data.reasons || []).length;
  const list = document.getElementById("reasonsList");
  list.innerHTML = "";
  (data.reasons || ["No indicators detected."]).forEach(r => {
    const el = document.createElement("div");
    el.className = "pg-reason-item";
    el.innerHTML = `<span class="pg-reason-dot"></span><span>${r}</span>`;
    list.appendChild(el);
  });
  statusText.textContent = data.verdict;
  statusDot.className = "pg-status";
}

scanBtn.addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) { showError("Could not get current tab URL."); return; }
  setScanning(true);
  try {
    const res = await fetch(API, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: tab.url }),
    });
    if (!res.ok) throw new Error("Server error: " + res.status);
    showResult(await res.json());
  } catch (err) {
    showError("Backend not running. Run: uvicorn main:app --reload");
  } finally {
    setScanning(false);
  }
});