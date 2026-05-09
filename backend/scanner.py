"""
PhishGuard ML Engine
====================
Ensemble of XGBoost + Random Forest + Neural Network (MLP)
with 45 hand-engineered features.

Usage
-----
    # First run — trains on synthetic + rule-augmented data, saves model
    python phishguard_ml.py --train

    # Scan a URL
    python phishguard_ml.py --scan "http://paypal-secure.verify-account.xyz/login"

    # Scan a file of URLs (one per line)
    python phishguard_ml.py --batch urls.txt

    # Re-train on your own labeled CSV  (columns: url, label  where label=1 phishing, 0 safe)
    python phishguard_ml.py --train --data my_dataset.csv

Requirements
------------
    pip install xgboost scikit-learn numpy pandas
"""

import argparse
import json
import math
import os
import pickle
import re
import sys
import unicodedata
import warnings
from urllib.parse import urlparse, unquote, parse_qs

import numpy as np

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────────────────────────────────────
# 1.  CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

MODEL_PATH = "phishguard_model.pkl"

SUSPICIOUS_WORDS = [
    "login", "verify", "update", "secure", "account", "bank", "password",
    "confirm", "signin", "wallet", "payment", "invoice", "support", "limited",
    "urgent", "alert", "suspended", "unlock", "authorize", "validate", "recover",
    "restore", "billing", "checkout", "purchase", "refund", "transaction",
    "credential", "authenticate", "webscr", "redirect", "click", "free", "prize",
    "winner", "reward", "claim", "bonus", "offer", "discount", "coupon",
    "security", "maintenance", "unusual", "activity", "access", "portal",
]

SHORTENERS = [
    "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly",
    "cutt.ly","rebrand.ly","shorturl.at","shorte.st","adf.ly","bc.vc",
    "lnkd.in","dlvr.it","mcaf.ee","soo.gd","cli.gs","su.pr","snipurl.com",
]

BRAND_SAFE = {
    "paypal":    ["paypal.com"],
    "apple":     ["apple.com"],
    "google":    ["google.com"],
    "microsoft": ["microsoft.com","live.com","outlook.com"],
    "amazon":    ["amazon.com"],
    "netflix":   ["netflix.com"],
    "facebook":  ["facebook.com","fb.com"],
    "instagram": ["instagram.com"],
    "twitter":   ["twitter.com","x.com"],
    "github":    ["github.com"],
    "binance":   ["binance.com"],
    "coinbase":  ["coinbase.com"],
    "dropbox":   ["dropbox.com"],
    "linkedin":  ["linkedin.com"],
    "chase":     ["chase.com"],
    "wellsfargo":["wellsfargo.com"],
    "citibank":  ["citibank.com"],
    "hsbc":      ["hsbc.com"],
    "steam":     ["steampowered.com","store.steampowered.com"],
}

HIGH_RISK_TLDS = {
    ".tk",".ml",".ga",".cf",".gq",".xyz",".top",".club",".online",
    ".site",".work",".info",".biz",".click",".link",".live",".ws",
    ".buzz",".icu",".vip",".cam",".uno",".email",".pw",".cc",
}

HOMOGLYPHS = {
    "а":"a","е":"e","о":"o","р":"p","с":"c","х":"x",
    "ѕ":"s","і":"i","ј":"j","ԁ":"d","ɡ":"g","ⅼ":"l","ℓ":"l",
    "0":"o","1":"l","3":"e","4":"a","5":"s","7":"t","@":"a",
}

REDIRECT_PARAMS = {"url","redirect","return","next","goto","redir","target","link","forward","continue"}

FEATURE_NAMES = [
    # --- Length ---
    "url_length", "domain_length", "path_length", "query_length",
    # --- Counts ---
    "dot_count", "hyphen_count", "underscore_count", "slash_count",
    "at_count", "question_count", "equal_count", "amp_count",
    "digit_count", "uppercase_count", "special_char_count",
    # --- Ratios ---
    "digit_ratio", "uppercase_ratio", "consonant_ratio", "vowel_ratio",
    "letter_ratio",
    # --- Entropy ---
    "url_entropy", "domain_entropy", "path_entropy",
    # --- Structural flags ---
    "uses_https", "has_ip", "has_port", "is_shortened",
    "has_double_slash", "has_double_extension", "has_at_symbol",
    "has_percent_encoding", "has_redirect_param",
    # --- Domain flags ---
    "subdomain_count", "domain_starts_with_digit",
    "is_dga_like", "is_typosquat", "has_non_ascii", "high_risk_tld",
    # --- Semantic flags ---
    "brand_impersonated", "suspicious_word_count",
    # --- Combo signals ---
    "brand_plus_high_risk_tld", "ip_plus_no_https", "many_subdomains_plus_brand",
    "high_entropy_plus_no_https",
    # --- Composite ---
    "structural_risk_composite",
]

assert len(FEATURE_NAMES) == 45, f"Expected 45 features, got {len(FEATURE_NAMES)}"


# ─────────────────────────────────────────────────────────────────────────────
# 2.  FEATURE ENGINEERING  (45 features)
# ─────────────────────────────────────────────────────────────────────────────

def _entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return round(-sum((c/n)*math.log2(c/n) for c in freq.values()), 4)

def _normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://","https://")):
        url = "https://" + url
    return url

def _normalize_homoglyphs(text: str) -> str:
    out = []
    for ch in text:
        ch = unicodedata.normalize("NFKC", ch)
        out.append(HOMOGLYPHS.get(ch, ch))
    return "".join(out)

def _has_ip(domain: str) -> bool:
    return bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", domain))

def _registered_domain(domain: str) -> str:
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain

def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b): a, b = b, a
    row = list(range(len(b)+1))
    for i, ca in enumerate(a, 1):
        nr = [i]
        for j, cb in enumerate(b, 1):
            nr.append(min(row[j]+1, nr[j-1]+1, row[j-1]+(ca!=cb)))
        row = nr
    return row[-1]

SAFE_SUBDOMAIN_WORDS = {
    "apps", "mail", "shop", "store", "play", "news", "blog", "help",
    "docs", "wiki", "api", "cdn", "dev", "web", "www", "beta", "auth",
    "user", "users", "meet", "chat", "talk", "live", "stream", "cloud",
    "drive", "maps", "plus", "home", "team", "work", "corp", "open",
    "info", "data", "media", "images", "static", "assets", "support",
}

def _is_typosquat(domain: str) -> tuple:
    reg = _registered_domain(domain)
    # If registered domain is in a brand safe list -> never a typosquat
    for brand, safelist in BRAND_SAFE.items():
        if any(reg == s or reg.endswith("." + s) for s in safelist):
            return False, None

    labels = [_normalize_homoglyphs(l) for l in domain.split(".") if len(l) >= 4]
    for lbl in labels:
        # Skip common legitimate subdomain words
        if lbl in SAFE_SUBDOMAIN_WORDS:
            continue
        for brand, safelist in BRAND_SAFE.items():
            if lbl == brand:
                return True, brand
            dist = _levenshtein(lbl, brand)
            # Require similar length to avoid e.g. "apps" matching "apple"
            if 1 <= dist <= 2 and abs(len(lbl) - len(brand)) <= 2:
                return True, brand
    return False, None

def _brand_impersonated(domain: str, url_lower: str) -> bool:
    reg = _registered_domain(domain)
    for brand, safelist in BRAND_SAFE.items():
        if brand in url_lower:
            if not any(reg == s or reg.endswith("."+s) for s in safelist):
                return True
    return False

def _is_dga(domain: str) -> bool:
    label = _registered_domain(domain).split(".")[0]
    if len(label) < 6:
        return False
    if len(label) > 12 and _entropy(label) > 3.5:
        return True
    consonants = len(re.sub(r"[aeiou0-9\-_]","", label))
    if consonants / max(len(label), 1) > 0.72:
        return True
    return False

def _has_non_ascii(domain: str) -> bool:
    try:
        domain.encode("ascii")
        return False
    except UnicodeEncodeError:
        return True

def _get_tld(domain: str) -> str:
    parts = domain.split(".")
    return ("." + parts[-1]) if parts else ""

def extract_features(url: str) -> np.ndarray:
    """Return a (45,) float32 feature vector."""
    norm   = _normalize_url(url)
    parsed = urlparse(norm)

    domain = parsed.netloc.lower()
    if ":" in domain and not _has_ip(domain):
        domain = domain.rsplit(":", 1)[0]

    path      = parsed.path.lower()
    query     = parsed.query.lower()
    full      = unquote(norm).lower()
    full_hg   = _normalize_homoglyphs(full)
    domain_hg = _normalize_homoglyphs(domain)

    suspicious_hits = sum(1 for w in SUSPICIOUS_WORDS if w in full_hg)
    is_typo, _      = _is_typosquat(domain)
    brand_imp       = _brand_impersonated(domain, full_hg)
    tld             = _get_tld(domain)
    subdomains      = max(0, len(domain.split(".")) - 2)

    # ---- 45 features ----
    url_len      = len(norm)
    dom_len      = len(domain)
    path_len     = len(path)
    query_len    = len(query)

    dot_c   = norm.count(".")
    hyph_c  = domain.count("-")  # count hyphens in domain only, not full path
    under_c = norm.count("_")
    slash_c = norm.count("/")
    at_c    = norm.count("@")
    q_c     = norm.count("?")
    eq_c    = norm.count("=")
    amp_c   = norm.count("&")
    dig_c   = sum(ch.isdigit() for ch in norm)
    up_c    = sum(ch.isupper() for ch in norm)
    spec_c  = sum(not ch.isalnum() and ch not in ":/.-_?=&#%" for ch in norm)

    n = max(len(norm), 1)
    dig_ratio  = dig_c / n
    up_ratio   = up_c  / n
    letters    = sum(ch.isalpha() for ch in norm)
    let_ratio  = letters / n
    vowels     = sum(ch in "aeiouAEIOU" for ch in norm)
    vowel_r    = vowels / max(letters, 1)
    cons_r     = 1.0 - vowel_r

    url_ent  = _entropy(norm)
    dom_ent  = _entropy(domain)
    path_ent = _entropy(path)

    uses_https    = float(parsed.scheme == "https")
    has_ip        = float(_has_ip(domain))
    has_port      = float(bool(re.search(r":\d{2,5}", parsed.netloc)))
    is_short      = float(any(s in domain for s in SHORTENERS))
    dbl_slash     = float("//" in norm[8:])
    dbl_ext       = float(len(re.findall(r"\.\w{2,5}", path)) >= 2)
    has_at        = float(at_c > 0)
    pct_enc       = float(norm.count("%") > 3)
    has_redir     = float(any(k.lower() in REDIRECT_PARAMS for k in parse_qs(parsed.query)))

    sub_c         = float(subdomains)
    dom_digit     = float(bool(domain) and domain[0].isdigit())
    dga           = float(_is_dga(domain))
    typo          = float(is_typo)
    non_ascii     = float(_has_non_ascii(domain))
    hi_risk_tld   = float(tld in HIGH_RISK_TLDS)

    brand         = float(brand_imp)
    susp_w        = float(min(suspicious_hits, 10))

    # Combo / interaction features
    brand_tld     = brand * hi_risk_tld
    ip_nohttp     = has_ip * (1.0 - uses_https)
    sub_brand     = float(subdomains >= 2) * brand
    ent_nohttp    = float(url_ent > 4.5) * (1.0 - uses_https)

    vec = np.array([
        url_len, dom_len, path_len, query_len,
        dot_c, hyph_c, under_c, slash_c,
        at_c, q_c, eq_c, amp_c,
        dig_c, up_c, spec_c,
        dig_ratio, up_ratio, cons_r, vowel_r, let_ratio,
        url_ent, dom_ent, path_ent,
        uses_https, has_ip, has_port, is_short,
        dbl_slash, dbl_ext, has_at, pct_enc, has_redir,
        sub_c, dom_digit, dga, typo, non_ascii, hi_risk_tld,
        brand, susp_w,
        brand_tld, ip_nohttp, sub_brand, ent_nohttp,
        # 45th feature: overall structural risk composite
        float(has_ip + (1-uses_https) + typo + brand + dga + hi_risk_tld),
    ], dtype=np.float32)

    assert vec.shape == (45,), f"Feature shape mismatch: {vec.shape}"
    return vec


def extract_features_batch(urls: list) -> np.ndarray:
    return np.vstack([extract_features(u) for u in urls])


# ─────────────────────────────────────────────────────────────────────────────
# 3.  SYNTHETIC TRAINING DATA
# ─────────────────────────────────────────────────────────────────────────────

SAFE_URLS = [
    "https://github.com",
    "https://github.com/user/repo",
    "https://google.com/search?q=python",
    "https://www.google.com",
    "https://apple.com/iphone",
    "https://microsoft.com/en-us/windows",
    "https://amazon.com/s?k=laptop",
    "https://stackoverflow.com/questions/123456",
    "https://en.wikipedia.org/wiki/Machine_learning",
    "https://www.bbc.co.uk/news",
    "https://www.reuters.com",
    "https://www.nytimes.com",
    "https://netflix.com/browse",
    "https://www.linkedin.com/in/johndoe",
    "https://twitter.com/elonmusk",
    "https://instagram.com/natgeo",
    "https://dropbox.com/sh/abc123",
    "https://coinbase.com/dashboard",
    "https://binance.com/en/trade",
    "https://docs.python.org/3/",
    "https://pypi.org/project/requests",
    "https://arxiv.org/abs/2106.00001",
    "https://stripe.com/docs",
    "https://cloudflare.com",
    "https://aws.amazon.com/ec2",
    "https://developer.mozilla.org/en-US/docs",
    "https://www.reddit.com/r/netsec",
    "https://medium.com/@user/article",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://zoom.us/j/12345678",
    "https://slack.com/intl/en-us",
    "https://notion.so/workspace",
    "https://figma.com/file/abc",
    "https://vercel.com/dashboard",
    "https://heroku.com/apps",
    "https://digitalocean.com/products",
    "https://hub.docker.com/r/library/python",
    "https://kubernetes.io/docs",
    "https://pytorch.org/tutorials",
    "https://huggingface.co/models",
]

PHISHING_URLS = [
    "http://paypal-secure-login.verify-account.xyz/signin?redirect=true",
    "http://192.168.1.1/bank-login",
    "https://g00gle.com/update-account",
    "https://аpple.com/invoice",
    "http://login.paypal.com.phishing-site.tk/webscr",
    "https://amazon-support-billing.com/confirm-payment",
    "http://login-paypal.com.security.info",
    "http://192.0.2.1/secure/account/login.php",
    "https://faceb00k.com/login",
    "http://secure-paypal-update.com/account/confirm",
    "https://microsoft-support-alert.xyz/update",
    "http://amazon.verify-purchase.tk/account",
    "https://netf1ix.com/signin/account",
    "http://bit.ly/3xmalware",
    "https://dropbox-shared-file.xyz/download",
    "http://chase-bank-login.com/secure/signin",
    "https://apple-id-verify.top/account/restore",
    "http://google-accounts-signin.club/verify",
    "https://secure-instagram-login.xyz/account",
    "http://twitter-support-team.online/verify",
    "https://steam-trade-offer.tk/accept",
    "http://bank0famerica.com/secure/login",
    "https://citibank-account-alert.biz/verify",
    "http://paypai.com/myaccount/signin",
    "https://amaz0n.com/account/update",
    "http://microsofft.com/security/update",
    "https://goggle.com/accounts/signin",
    "http://lnstagram.com/login",
    "https://facbook.com/login",
    "http://twltter.com/account/verify",
    "https://githud.com/login",
    "http://binanse.com/en/login",
    "https://c0inbase.com/signin",
    "http://dr0pbox.com/download",
    "https://llnkedin.com/in/verify",
    "http://support-paypal-account.com/update?redirect=https://paypal.com",
    "https://secure.apple-id-locked.online/unlock",
    "http://amazon-prime-renewal.xyz/billing/update",
    "https://microsoft-account-verify.tk/password/reset",
    "http://netflix-billing-update.club/account/payment",
    # DGA-style
    "http://xkj29fhqp.top/login",
    "https://mz7q2r9t.xyz/account",
    "http://pqr8yv3.tk/secure",
    "https://nkwz8b4m.online/verify",
    "http://rfx9t2.ml/update",
    # IP-based
    "http://185.220.101.34/login",
    "http://45.33.32.156/paypal/signin",
    "http://198.51.100.0/bank/account",
    # Heavy encoding / obfuscation
    "http://pay%70al-login.com/account",
    "https://secure%2Eapple%2Ecom.phish.xyz/verify",
]

# Augment with programmatic variations
def _augment(urls, n_each=3):
    import random
    rng = random.Random(42)
    extra = []
    tlds = [".tk",".xyz",".top",".info",".online",".biz",".club"]
    brands = list(BRAND_SAFE.keys())
    for _ in range(n_each * len(urls)):
        brand = rng.choice(brands)
        tld   = rng.choice(tlds)
        word1 = rng.choice(SUSPICIOUS_WORDS[:15])
        word2 = rng.choice(SUSPICIOUS_WORDS[15:])
        t     = rng.randint(0, 4)
        if t == 0:
            extra.append(f"http://{brand}-{word1}-{word2}{tld}/{word1}")
        elif t == 1:
            extra.append(f"http://secure-{brand}-{word2}.com.{tld}/signin")
        elif t == 2:
            ip = f"{rng.randint(1,254)}.{rng.randint(0,254)}.{rng.randint(0,254)}.{rng.randint(1,254)}"
            extra.append(f"http://{ip}/{word1}/{word2}")
        elif t == 3:
            chars = "abcdefghijklmnopqrstuvwxyz0123456789"
            dga = "".join(rng.choice(chars) for _ in range(rng.randint(10,18)))
            extra.append(f"http://{dga}{tld}/{word1}")
        else:
            sub = ".".join(rng.choice(brands) for _ in range(rng.randint(1,2)))
            extra.append(f"http://{sub}.{brand}{tld}/login")
    return extra

def _build_dataset():
    phish_aug = _augment(PHISHING_URLS, n_each=5)
    all_phish = PHISHING_URLS + phish_aug
    all_safe  = SAFE_URLS

    X_phish = extract_features_batch(all_phish)
    X_safe  = extract_features_batch(all_safe)
    y_phish = np.ones(len(all_phish),  dtype=np.int32)
    y_safe  = np.zeros(len(all_safe),  dtype=np.int32)

    X = np.vstack([X_phish, X_safe])
    y = np.concatenate([y_phish, y_safe])
    return X, y


# ─────────────────────────────────────────────────────────────────────────────
# 4.  MODEL  — XGBoost + Random Forest + MLP ensemble
# ─────────────────────────────────────────────────────────────────────────────

def _build_ensemble():
    """
    Returns a VotingClassifier-style ensemble.
    XGBoost is imported lazily so the file is usable even if xgboost
    isn't installed yet (falls back to RF + MLP only with a warning).
    """
    from sklearn.ensemble import RandomForestClassifier, VotingClassifier, GradientBoostingClassifier
    from sklearn.neural_network import MLPClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.pipeline import Pipeline

    rf = RandomForestClassifier(
        n_estimators=400,
        max_depth=None,
        min_samples_leaf=1,
        max_features="sqrt",
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )

    # Gradient Boosting as XGBoost stand-in if xgboost unavailable
    try:
        from xgboost import XGBClassifier
        xgb = XGBClassifier(
            n_estimators=400,
            max_depth=6,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            scale_pos_weight=1,
            use_label_encoder=False,
            eval_metric="logloss",
            random_state=42,
            n_jobs=-1,
        )
        print("  [✓] XGBoost loaded")
    except ImportError:
        xgb = GradientBoostingClassifier(
            n_estimators=400,
            max_depth=5,
            learning_rate=0.05,
            subsample=0.8,
            random_state=42,
        )
        print("  [!] xgboost not installed — using GradientBoosting instead.")
        print("      Install with:  pip install xgboost")

    mlp = Pipeline([
        ("scaler", StandardScaler()),
        ("nn", MLPClassifier(
            hidden_layer_sizes=(128, 64, 32),
            activation="relu",
            solver="adam",
            alpha=0.001,
            learning_rate="adaptive",
            max_iter=500,
            random_state=42,
            early_stopping=True,
            validation_fraction=0.1,
        )),
    ])

    ensemble = VotingClassifier(
        estimators=[
            ("xgb", xgb),
            ("rf",  rf),
            ("mlp", mlp),
        ],
        voting="soft",           # average predicted probabilities
        weights=[2, 1, 1],       # XGBoost gets double weight
    )
    return ensemble


# ─────────────────────────────────────────────────────────────────────────────
# 5.  RULE ENGINE  (fallback explainability layer — always runs)
# ─────────────────────────────────────────────────────────────────────────────

RULES = [
    (lambda f: f["url_length"] > 100,         "URL is abnormally long (>100 chars)."),
    (lambda f: f["url_length"] > 75,           "URL is unusually long."),
    (lambda f: f["subdomain_count"] >= 4,      "Excessive subdomain depth (4+)."),
    (lambda f: f["subdomain_count"] >= 2,      "Multiple subdomains detected."),
    (lambda f: f["dot_count"] >= 6,            "Many dots — possible subdomain stacking."),
    (lambda f: f["hyphen_count"] >= 4,         "Many hyphens in domain — common in fake sites."),
    (lambda f: f["hyphen_count"] >= 2,         "Multiple hyphens in domain."),
    (lambda f: f["has_at_symbol"],             "@-symbol detected — can redirect to different host."),
    (lambda f: f["has_percent_encoding"],      "Heavy percent-encoding — possible obfuscation."),
    (lambda f: f["has_double_slash"],          "Double slash after scheme — redirect trick."),
    (lambda f: f["has_double_extension"],      "Double file extension — malware delivery tactic."),
    (lambda f: f["has_port"],                  "Non-standard port — unusual for legitimate sites."),
    (lambda f: f["url_entropy"] > 5.0,         "Very high URL entropy — strongly obfuscated."),
    (lambda f: f["url_entropy"] > 4.3,         "Elevated URL entropy — random-looking URL."),
    (lambda f: f["domain_entropy"] > 4.2,      "Very high domain entropy — likely auto-generated."),
    (lambda f: 3.8 < f["domain_entropy"] <= 4.2, "High domain entropy — unusual structure."),
    (lambda f: f["digit_ratio"] > 0.25,        "High digit ratio in URL."),
    (lambda f: not f["uses_https"],            "No HTTPS — connection is unencrypted."),
    (lambda f: f["has_ip"],                    "Raw IP address as domain — no legit site does this."),
    (lambda f: f["is_shortened"],              "Link shortener — hides true destination."),
    (lambda f: f["is_typosquat"],              f"Typosquatting detected — close match to known brand."),
    (lambda f: f["has_non_ascii"],             "Non-ASCII in domain — possible homoglyph attack."),
    (lambda f: f["high_risk_tld"],             "High-risk TLD — frequently abused in phishing."),
    (lambda f: f["brand_impersonated"],        "Brand name impersonated in non-official domain."),
    (lambda f: f["suspicious_word_count"] >= 3,"Multiple suspicious keywords detected."),
    (lambda f: 0 < f["suspicious_word_count"] < 3, "Suspicious keyword(s) in URL."),
    (lambda f: f["has_redirect_param"],        "Redirect parameter — may forward to malicious site."),
    (lambda f: f["is_dga_like"],               "Domain looks DGA-generated — random, unpronounceable."),
    (lambda f: f["domain_starts_with_digit"],  "Domain label starts with digit — uncommon for real sites."),
    (lambda f: f["brand_plus_high_risk_tld"],  "Brand name + high-risk TLD — classic phishing combo."),
    (lambda f: f["ip_plus_no_https"],          "IP address + no HTTPS — extremely high risk."),
    (lambda f: f["many_subdomains_plus_brand"],"Brand in subdomain of foreign domain."),
    (lambda f: f["high_entropy_plus_no_https"],"High entropy + no HTTPS — obfuscated insecure URL."),
]

def _features_dict(url: str) -> dict:
    """Named feature dict for the rule engine."""
    norm   = _normalize_url(url)
    parsed = urlparse(norm)
    domain = parsed.netloc.lower()
    if ":" in domain and not _has_ip(domain):
        domain = domain.rsplit(":", 1)[0]
    path   = parsed.path.lower()
    full   = unquote(norm).lower()
    full_hg = _normalize_homoglyphs(full)
    tld    = _get_tld(domain)
    is_typo, _ = _is_typosquat(domain)
    brand_imp  = _brand_impersonated(domain, full_hg)
    subdoms    = max(0, len(domain.split(".")) - 2)
    susp_w     = sum(1 for w in SUSPICIOUS_WORDS if w in full_hg)
    url_ent    = _entropy(norm)
    dom_ent    = _entropy(domain)
    uses_https = parsed.scheme == "https"
    has_ip_v   = _has_ip(domain)
    hi_tld     = tld in HIGH_RISK_TLDS

    return {
        "url": norm, "domain": domain,
        "url_length": len(norm),
        "subdomain_count": subdoms,
        "dot_count": norm.count("."),
        "hyphen_count": domain.count("-"),  # domain hyphens only
        "has_at_symbol": norm.count("@") > 0,
        "has_percent_encoding": norm.count("%") > 3,
        "has_double_slash": "//" in norm[8:],
        "has_double_extension": len(re.findall(r"\.\w{2,5}", path)) >= 2,
        "has_port": bool(re.search(r":\d{2,5}", parsed.netloc)),
        "url_entropy": url_ent,
        "domain_entropy": dom_ent,
        "digit_ratio": sum(c.isdigit() for c in norm) / max(len(norm), 1),
        "uses_https": uses_https,
        "has_ip": has_ip_v,
        "is_shortened": any(s in domain for s in SHORTENERS),
        "is_typosquat": is_typo,
        "has_non_ascii": _has_non_ascii(domain),
        "high_risk_tld": hi_tld,
        "brand_impersonated": brand_imp,
        "suspicious_word_count": susp_w,
        "has_redirect_param": any(k.lower() in REDIRECT_PARAMS for k in parse_qs(parsed.query)),
        "is_dga_like": _is_dga(domain),
        "domain_starts_with_digit": bool(domain) and domain[0].isdigit(),
        "brand_plus_high_risk_tld": brand_imp and hi_tld,
        "ip_plus_no_https": has_ip_v and not uses_https,
        "many_subdomains_plus_brand": subdoms >= 2 and brand_imp,
        "high_entropy_plus_no_https": url_ent > 4.5 and not uses_https,
    }

def _get_reasons(fd: dict) -> list:
    return [msg for cond, msg in RULES if cond(fd)]


# ─────────────────────────────────────────────────────────────────────────────
# 6.  TRAIN / LOAD
# ─────────────────────────────────────────────────────────────────────────────

def train(data_csv: str | None = None, save_path: str = MODEL_PATH):
    from sklearn.model_selection import StratifiedKFold, cross_val_score

    print("\n━━━  PhishGuard ML — Training  ━━━")

    if data_csv and os.path.exists(data_csv):
        import pandas as pd
        df = pd.read_csv(data_csv)
        assert "url" in df.columns and "label" in df.columns, \
            "CSV must have 'url' and 'label' columns."
        print(f"  [✓] Loaded {len(df)} samples from {data_csv}")
        X = extract_features_batch(df["url"].tolist())
        y = df["label"].values.astype(np.int32)
    else:
        print("  [i] No CSV provided — using built-in synthetic dataset.")
        X, y = _build_dataset()

    print(f"  [i] Dataset: {len(y)} samples  |  "
          f"phishing={y.sum()}  safe={(y==0).sum()}")

    ensemble = _build_ensemble()

    print("  [i] Running 5-fold cross-validation …")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scores = cross_val_score(ensemble, X, y, cv=cv, scoring="f1", n_jobs=-1)
    print(f"  [✓] CV F1: {scores.mean():.4f} ± {scores.std():.4f}")

    print("  [i] Fitting final model on full dataset …")
    ensemble.fit(X, y)

    # Feature importances from RF
    try:
        rf_model = ensemble.named_estimators_["rf"]
        importances = rf_model.feature_importances_
        top = sorted(zip(FEATURE_NAMES, importances), key=lambda x: -x[1])[:10]
        print("\n  Top-10 features (Random Forest):")
        for name, imp in top:
            bar = "█" * int(imp * 60)
            print(f"    {name:<35} {imp:.4f}  {bar}")
    except Exception:
        pass

    with open(save_path, "wb") as f:
        pickle.dump(ensemble, f)
    print(f"\n  [✓] Model saved → {save_path}\n")
    return ensemble


def load_model(path: str = MODEL_PATH):
    if not os.path.exists(path):
        print(f"  [!] No trained model found at '{path}'. Training now …")
        return train(save_path=path)
    with open(path, "rb") as f:
        return pickle.load(f)


# ─────────────────────────────────────────────────────────────────────────────
# 7.  SCAN  — ML + rule engine combined
# ─────────────────────────────────────────────────────────────────────────────

# Registered domains that are always safe — ML score is zeroed for these
TRUSTED_REGISTERED_DOMAINS = {
    "google.com", "gmail.com", "youtube.com", "google.co",
    "apple.com", "icloud.com",
    "microsoft.com", "live.com", "outlook.com", "azure.com",
    "amazon.com", "aws.amazon.com",
    "github.com", "githubusercontent.com",
    "facebook.com", "fb.com", "instagram.com",
    "twitter.com", "x.com",
    "netflix.com", "linkedin.com", "dropbox.com",
    "coinbase.com", "binance.com",
    "wikipedia.org", "mozilla.org", "python.org",
    "stackoverflow.com", "reddit.com", "medium.com",
    "stripe.com", "shopify.com", "cloudflare.com",
    "steampowered.com", "paypal.com",
}

def scan(url: str, model=None) -> dict:
    if model is None:
        model = load_model()

    fd        = _features_dict(url)
    reasons   = _get_reasons(fd)

    # Whitelist: if registered domain is trusted, zero ML score and only use rules
    reg_domain = _registered_domain(fd["domain"])
    is_trusted = reg_domain in TRUSTED_REGISTERED_DOMAINS

    vec = extract_features(url).reshape(1, -1)
    ml_prob   = 0.0 if is_trusted else float(model.predict_proba(vec)[0][1])

    # Rule-based score — suppress suspicious-word rule for trusted domains
    if is_trusted:
        reasons = [r for r in reasons if "keyword" not in r.lower() and "entropy" not in r.lower()]
    rule_score = min(len(reasons) * 12, 100)

    # Blend: 70% ML probability + 30% rule signal
    blended = 0.70 * ml_prob + 0.30 * (rule_score / 100)
    risk_score = round(blended * 100)

    if risk_score >= 60 or (ml_prob >= 0.75 and reasons):
        verdict  = "Phishing"
        severity = "Critical"
    elif risk_score >= 30 or ml_prob >= 0.45:
        verdict  = "Suspicious"
        severity = "Medium"
    else:
        verdict  = "Safe"
        severity = "Low"

    return {
        "url":        fd["url"],
        "domain":     fd["domain"],
        "verdict":    verdict,
        "severity":   severity,
        "risk_score": risk_score,
        "ml_prob":    round(float(ml_prob), 4),
        "reasons":    reasons if reasons else ["No phishing indicators detected."],
        "features":   {k: (bool(v) if isinstance(v, (bool, np.bool_)) else
                           float(v) if isinstance(v, (float, np.floating)) else
                           int(v)   if isinstance(v, (int, np.integer)) else v)
                       for k, v in fd.items()},
    }


def scan_many(urls: list, model=None) -> list:
    if model is None:
        model = load_model()
    results = [scan(u, model) for u in urls]
    return sorted(results, key=lambda r: r["risk_score"], reverse=True)


# ─────────────────────────────────────────────────────────────────────────────
# 8.  CLI
# ─────────────────────────────────────────────────────────────────────────────

def _print_result(r: dict):
    colors = {"Phishing": "\033[91m", "Suspicious": "\033[93m", "Safe": "\033[92m"}
    reset  = "\033[0m"
    c      = colors.get(r["verdict"], "")
    bar    = "█" * int(r["risk_score"] / 5)
    print(f"\n{'═'*62}")
    print(f"  URL      : {r['url']}")
    print(f"  Domain   : {r['domain']}")
    print(f"  Verdict  : {c}{r['verdict']}{reset}   Score: {r['risk_score']}/100   "
          f"ML-P(phish): {r['ml_prob']:.2%}")
    print(f"  Severity : {r['severity']}")
    print(f"  Risk     : [{bar:<20}]")
    print(f"  Signals  :")
    for reason in r["reasons"]:
        print(f"    • {reason}")
    print(f"{'═'*62}")


def main():
    parser = argparse.ArgumentParser(description="PhishGuard ML Scanner")
    parser.add_argument("--train",  action="store_true", help="Train / retrain the model")
    parser.add_argument("--scan",   type=str,            help="Scan a single URL")
    parser.add_argument("--batch",  type=str,            help="Scan URLs from a file (one per line)")
    parser.add_argument("--data",   type=str,            default=None,
                                                         help="CSV file with 'url','label' columns for training")
    parser.add_argument("--model",  type=str,            default=MODEL_PATH,
                                                         help=f"Model path (default: {MODEL_PATH})")
    parser.add_argument("--json",   action="store_true", help="Output results as JSON")
    args = parser.parse_args()

    if args.train:
        train(data_csv=args.data, save_path=args.model)

    if args.scan:
        model = load_model(args.model)
        r = scan(args.scan, model)
        if args.json:
            print(json.dumps(r, indent=2))
        else:
            _print_result(r)

    if args.batch:
        if not os.path.exists(args.batch):
            print(f"File not found: {args.batch}")
            sys.exit(1)
        with open(args.batch) as f:
            urls = [l.strip() for l in f if l.strip()]
        model = load_model(args.model)
        results = scan_many(urls, model)
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print(f"\nScanned {len(results)} URLs — sorted by risk:")
            for r in results:
                _print_result(r)

    if not any([args.train, args.scan, args.batch]):
        # Demo mode
        print("\n━━━  PhishGuard ML — Demo  ━━━")
        model = load_model(args.model)
        demo = [
            ("Should be SAFE",       "https://github.com"),
            ("Should be SAFE",       "https://google.com/search?q=test"),
            ("Should be PHISHING",   "http://paypal-secure-login.verify-account.xyz/signin?redirect=true"),
            ("Should be PHISHING",   "http://192.168.1.1/bank-login"),
            ("Should be PHISHING",   "https://faceb00k.com/login"),          # digit homoglyph
            ("Should be PHISHING",   "https://аpple.com/invoice"),           # Cyrillic а
            ("Should be PHISHING",   "http://login.paypal.com.evil.tk/webscr"),
            ("Should be PHISHING",   "https://amazon-support-billing.com/confirm-payment"),
            ("Should be SUSPICIOUS", "https://12.748-ryghjv-bhgf.com"),      # DGA-like
            ("Should be PHISHING",   "https://g00gle.com/update-account"),
            ("Should be PHISHING",   "http://login-paypal.com.security.info"),
        ]
        for expected, url in demo:
            r = scan(url, model)
            match = "✓" if expected.split()[2].lower() == r["verdict"].lower() else "✗"
            print(f"  [{match}] {expected:<25} → {r['verdict']:<10} "
                  f"score={r['risk_score']:>3}  ml={r['ml_prob']:.2%}  {url[:55]}")


if __name__ == "__main__":
    main()