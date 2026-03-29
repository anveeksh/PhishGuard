"""
web/app.py — PhishGuard Pro Flask Backend
Author: Anveeksh Rao | github.com/anveeksh
"""
import sys, os, json, re, csv, io
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.features import extract_features, FEATURE_NAMES
from utils.helpers import models_trained

app = Flask(__name__)
CORS(app)

SCAN_HISTORY = []

def load_models():
    from models import random_forest, xgboost_model, neural_network
    return random_forest, xgboost_model, neural_network

def scan_single(url):
    if not url.startswith(("http://","https://")):
        url = "http://" + url
    features = extract_features(url)
    rf, xgb, nn = load_models()
    rf_label,  rf_conf  = rf.predict(features)
    xgb_label, xgb_conf = xgb.predict(features)
    nn_label,  nn_conf  = nn.predict(features)
    votes   = [rf_label, xgb_label, nn_label]
    verdict = "phishing" if votes.count("phishing") >= 2 else "legitimate"
    avg     = round((rf_conf + xgb_conf + nn_conf) / 3, 2)
    result  = {
        "url"    : url,
        "verdict": verdict,
        "confidence": avg,
        "models" : {
            "Random Forest" : {"label": rf_label,  "confidence": round(rf_conf,  2)},
            "XGBoost"       : {"label": xgb_label, "confidence": round(xgb_conf, 2)},
            "Neural Network": {"label": nn_label,  "confidence": round(nn_conf,  2)},
        },
        "timestamp": datetime.now().isoformat(),
    }
    SCAN_HISTORY.append(result)
    return result

# ─── Routes ─────────────────────────────────────────────────

@app.route("/")
def index():
    phish  = sum(1 for s in SCAN_HISTORY if s["verdict"] == "phishing")
    legit  = len(SCAN_HISTORY) - phish
    return render_template("index.html",
        total=len(SCAN_HISTORY), phish=phish, legit=legit,
        history=SCAN_HISTORY[-7:][::-1])

@app.route("/scanner")
def scanner():
    return render_template("scanner.html")

@app.route("/email")
def email_page():
    return render_template("email.html")

@app.route("/qr")
def qr_page():
    return render_template("qr.html")

@app.route("/batch")
def batch_page():
    return render_template("batch.html")

@app.route("/history")
def history_page():
    return render_template("history.html",
        history=SCAN_HISTORY[::-1])

# ─── API Endpoints ───────────────────────────────────────────

@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json()
    url  = data.get("url","").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    if not models_trained():
        return jsonify({"error": "Models not trained. Run phishguard.py first."}), 500
    try:
        result = scan_single(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/email", methods=["POST"])
def api_email():
    data    = request.get_json()
    content = data.get("content","")
    urls    = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', content)
    urls    = list(set(urls))
    if not urls:
        return jsonify({"urls": [], "message": "No URLs found in email"})
    if not models_trained():
        return jsonify({"error": "Models not trained"}), 500
    results = []
    for url in urls[:20]:
        try:
            results.append(scan_single(url))
        except Exception:
            pass
    phish = sum(1 for r in results if r["verdict"] == "phishing")
    return jsonify({
        "total"  : len(results),
        "phishing": phish,
        "legitimate": len(results) - phish,
        "results": results
    })

@app.route("/api/qr", methods=["POST"])
def api_qr():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["file"]
    try:
        from PIL import Image
        from pyzbar.pyzbar import decode
        img    = Image.open(file.stream)
        codes  = decode(img)
        if not codes:
            return jsonify({"error": "No QR code found in image"}), 400
        url = codes[0].data.decode("utf-8")
        if not models_trained():
            return jsonify({"error": "Models not trained"}), 500
        result = scan_single(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/batch", methods=["POST"])
def api_batch():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file    = request.files["file"]
    content = file.read().decode("utf-8")
    lines   = [l.strip() for l in content.splitlines() if l.strip()]
    if not models_trained():
        return jsonify({"error": "Models not trained"}), 500
    results = []
    for url in lines[:500]:
        try:
            results.append(scan_single(url))
        except Exception:
            pass
    phish = sum(1 for r in results if r["verdict"] == "phishing")
    return jsonify({
        "total"     : len(results),
        "phishing"  : phish,
        "legitimate": len(results) - phish,
        "results"   : results
    })

@app.route("/api/whois", methods=["POST"])
def api_whois():
    data   = request.get_json()
    domain = data.get("domain","").strip()
    if not domain:
        return jsonify({"error": "No domain provided"}), 400
    try:
        import whois
        from urllib.parse import urlparse
        if domain.startswith(("http://","https://")):
            domain = urlparse(domain).netloc
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        age_days = (datetime.now() - created).days if created else None
        suspicious = age_days is not None and age_days < 30
        return jsonify({
            "domain"    : domain,
            "registrar" : str(w.registrar),
            "created"   : str(created),
            "age_days"  : age_days,
            "suspicious": suspicious,
            "country"   : str(w.country),
            "emails"    : str(w.emails),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/typosquat", methods=["POST"])
def api_typosquat():
    data   = request.get_json()
    domain = data.get("domain","").strip().lower()
    if not domain:
        return jsonify({"error": "No domain provided"}), 400
    brands = [
        "google","facebook","amazon","apple","microsoft","paypal",
        "netflix","instagram","twitter","linkedin","github","youtube",
        "yahoo","outlook","dropbox","spotify","uber","airbnb",
    ]
    similar = []
    for brand in brands:
        if domain != brand and (
            brand in domain or
            domain in brand or
            _levenshtein(domain.split(".")[0], brand) <= 2
        ):
            similar.append({
                "brand"      : brand + ".com",
                "similarity" : "high" if _levenshtein(domain.split(".")[0], brand) <= 1 else "medium",
            })
    return jsonify({
        "domain" : domain,
        "similar": similar,
        "is_suspicious": len(similar) > 0,
    })

def _levenshtein(s1, s2):
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j+1]+1, curr[j]+1,
                            prev[j]+(c1 != c2)))
        prev = curr
    return prev[len(s2)]

@app.route("/api/history")
def api_history():
    return jsonify(SCAN_HISTORY[::-1])

@app.route("/api/stats")
def api_stats():
    phish = sum(1 for s in SCAN_HISTORY if s["verdict"] == "phishing")
    return jsonify({
        "total"     : len(SCAN_HISTORY),
        "phishing"  : phish,
        "legitimate": len(SCAN_HISTORY) - phish,
        "rate"      : round(phish / len(SCAN_HISTORY) * 100, 1) if SCAN_HISTORY else 0,
    })

if __name__ == "__main__":
    print("\n🔍 PhishGuard Pro — Web Dashboard")
    print("   http://localhost:5001")
    print("   Press CTRL+C to stop\n")
    app.run(debug=True, port=5001)
