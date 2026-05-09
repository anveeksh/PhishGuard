from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import asyncio
from ml_engine import ensemble_scan
from safe_browsing import check_safe_browsing
from virustotal import check_virustotal
from whois_lookup import get_domain_age

app = FastAPI(title="PhishGuard API", version="4.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

scan_history = []

class UrlScanRequest(BaseModel):
    url: str

class TextScanRequest(BaseModel):
    text: str

@app.get("/")
def health_check():
    return {
        "status": "running",
        "product": "PhishGuard",
        "version": "4.0",
        "engines": ["ML Ensemble", "Rule Engine", "Google Safe Browsing", "VirusTotal", "WHOIS"]
    }

@app.post("/scan-url")
async def scan_url(request: UrlScanRequest):
    # Run ML + GSB + VirusTotal in parallel, WHOIS in thread
    result, gsb, vt = await asyncio.gather(
        asyncio.to_thread(ensemble_scan, request.url),
        check_safe_browsing(request.url),
        check_virustotal(request.url),
    )

    # WHOIS lookup (run in thread — blocking I/O)
    whois_data = await asyncio.to_thread(get_domain_age, result["domain"])

    # Apply Google Safe Browsing
    if gsb.get("flagged"):
        result["risk_score"] = max(result["risk_score"], 85)
        result["verdict"]    = "Phishing"
        result["severity"]   = "Critical"
        result["reasons"]    = [f"Google Safe Browsing: {gsb['threat_type']}"] + result["reasons"]

    # Apply VirusTotal
    if vt.get("flagged"):
        result["risk_score"] = max(result["risk_score"], 80)
        result["verdict"]    = "Phishing"
        result["severity"]   = "Critical"
        result["reasons"]    = [f"VirusTotal: {vt['malicious']} engines flagged as malicious"] + result["reasons"]

    # Apply WHOIS age signal
    if whois_data.get("reason"):
        result["risk_score"] = min(result["risk_score"] + whois_data["risk_score"], 100)
        result["reasons"]    = result["reasons"] + [whois_data["reason"]]
        if result["risk_score"] >= 60:
            result["verdict"]   = "Phishing"
            result["severity"]  = "Critical"
        elif result["risk_score"] >= 25 and result["verdict"] == "Safe":
            result["verdict"]   = "Suspicious"
            result["severity"]  = "Medium"

    # Attach all intel
    result["gsb_flagged"]    = gsb.get("flagged", False)
    result["gsb_threat"]     = gsb.get("threat_type")
    result["vt_available"]   = vt.get("available", False)
    result["vt_flagged"]     = vt.get("flagged", False)
    result["vt_malicious"]   = vt.get("malicious", 0)
    result["vt_total"]       = vt.get("total", 0)
    result["whois_age_days"] = whois_data.get("age_days")
    result["whois_created"]  = whois_data.get("created")
    result["whois_registrar"]= whois_data.get("registrar")
    result["whois_verdict"]  = whois_data.get("verdict")

    scan_history.insert(0, result)
    return result

@app.post("/scan-text")
def scan_text(request: TextScanRequest):
    text = request.text.lower()
    suspicious_terms = [
        "verify your account","password expired","urgent action",
        "click here","login immediately","account suspended",
        "confirm your identity","payment failed","security alert"
    ]
    hits = [t for t in suspicious_terms if t in text]
    score = min(len(hits) * 20 + (10 if "http" in text else 0), 100)
    if score >= 70:   verdict, severity = "Phishing", "High"
    elif score >= 35: verdict, severity = "Suspicious", "Medium"
    else:             verdict, severity = "Safe", "Low"
    return {"risk_score": score, "verdict": verdict, "severity": severity, "matched_indicators": hits}

@app.get("/history")
def get_history():
    return {"count": len(scan_history), "items": scan_history[:20]}

@app.post("/explain")
async def explain(request: UrlScanRequest):
    result, gsb, vt = await asyncio.gather(
        asyncio.to_thread(ensemble_scan, request.url),
        check_safe_browsing(request.url),
        check_virustotal(request.url),
    )
    whois_data = await asyncio.to_thread(get_domain_age, result["domain"])
    notes = []
    if gsb.get("flagged"):  notes.append(f"Google Safe Browsing flagged as {gsb['threat_type']}.")
    if vt.get("flagged"):   notes.append(f"VirusTotal: {vt['malicious']} engines flagged.")
    if whois_data.get("reason"): notes.append(whois_data["reason"])
    extra = " ".join(notes)
    explanation = f"PhishGuard analyzed {result['domain']} and classified it as {result['verdict']} with a risk score of {result['risk_score']}/100. {extra} Signals: {chr(32).join(result['reasons'])}"
    return {
        "url": result["url"],
        "explanation": explanation,
        "recommendation": "Do not enter passwords or payment details unless you fully trust this website."
    }
