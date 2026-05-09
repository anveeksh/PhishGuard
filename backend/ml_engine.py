"""
ml_engine.py  —  PhishGuard
"""

import os
import joblib
import numpy as np
from scanner import extract_features, _features_dict, _get_reasons, _registered_domain

TRUSTED_REGISTERED_DOMAINS = {
    "google.com", "gmail.com", "youtube.com",
    "apple.com",  "icloud.com",
    "microsoft.com", "live.com", "outlook.com", "azure.com",
    "amazon.com",
    "github.com", "githubusercontent.com",
    "facebook.com", "fb.com", "instagram.com",
    "twitter.com", "x.com",
    "netflix.com", "linkedin.com", "dropbox.com",
    "coinbase.com", "binance.com",
    "wikipedia.org", "mozilla.org", "python.org",
    "stackoverflow.com", "reddit.com", "medium.com",
    "stripe.com", "cloudflare.com", "steampowered.com",
    "paypal.com",
}

CRITICAL_SIGNALS = ["typosquat", "brand", "ip address", "shortener", "non-ascii", "homoglyph"]
HIGH_SIGNALS     = ["https", "high-risk tld", "redirect", "dga", "ip_plus", "entropy + no"]

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phishguard_ensemble.joblib")

def _load_bundle():
    if not os.path.exists(MODEL_PATH):
        print(f"[!] Model not found — rule-engine-only mode.")
        return None
    bundle = joblib.load(MODEL_PATH)
    print(f"[✓] PhishGuard model loaded: {list(bundle.get('models', {}).keys())}")
    return bundle

BUNDLE = _load_bundle()

def _ml_predict(url):
    if BUNDLE is None:
        return {"available": False, "ml_score": None, "models": {}}
    feature_keys = BUNDLE.get("feature_keys", [])
    if feature_keys:
        fd = _features_dict(url)
        values = []
        for key in feature_keys:
            val = fd.get(key, 0)
            values.append(int(val) if isinstance(val, bool) else float(val))
        x = np.array(values, dtype=np.float32).reshape(1, -1)
    else:
        x = extract_features(url).reshape(1, -1)
    model_probs = {}
    for name, model in BUNDLE["models"].items():
        try:
            prob = model.predict_proba(x)[0][1]
            model_probs[name] = round(float(prob), 4)
        except Exception as e:
            print(f"[!] Model {name} failed: {e}")
    if not model_probs:
        return {"available": False, "ml_score": None, "models": {}}
    avg_prob = sum(model_probs.values()) / len(model_probs)
    return {"available": True, "ml_score": round(avg_prob * 100), "models": model_probs}

def _rule_score(reasons):
    critical = sum(1 for r in reasons if any(k in r.lower() for k in CRITICAL_SIGNALS))
    high     = sum(1 for r in reasons if any(k in r.lower() for k in HIGH_SIGNALS))
    other    = len(reasons) - critical - high
    return min((critical * 35) + (high * 18) + (other * 8), 100)

def ensemble_scan(url):
    fd      = _features_dict(url)
    reasons = _get_reasons(fd)
    rule_sc = _rule_score(reasons)
    ml      = _ml_predict(url)

    # If rule engine fires critical signals, trust rules over ML
    has_critical = any(any(k in r.lower() for k in CRITICAL_SIGNALS) for r in reasons)
    if has_critical:
        final_score = rule_sc
    elif ml["available"] and ml["ml_score"] is not None:
        final_score = round(rule_sc * 0.55 + ml["ml_score"] * 0.45)
    else:
        final_score = rule_sc

    reg = _registered_domain(fd["domain"])
    if reg in TRUSTED_REGISTERED_DOMAINS:
        reasons     = [r for r in reasons if "keyword" not in r.lower() and "entropy" not in r.lower()]
        final_score = min(final_score, 20)

    final_score = min(final_score, 100)

    if final_score >= 60:
        verdict, severity = "Phishing", "Critical"
    elif final_score >= 25:
        verdict, severity = "Suspicious", "Medium"
    else:
        verdict, severity = "Safe", "Low"

    return {
        "url":          fd["url"],
        "domain":       fd["domain"],
        "verdict":      verdict,
        "severity":     severity,
        "risk_score":   final_score,
        "rule_score":   rule_sc,
        "ml_score":     ml["ml_score"],
        "ml_available": ml["available"],
        "ml_models":    ml["models"],
        "reasons":      reasons if reasons else ["No phishing indicators detected."],
        "engine":       "Hybrid Rule Engine + Random Forest + XGBoost + Neural Network",
    }
