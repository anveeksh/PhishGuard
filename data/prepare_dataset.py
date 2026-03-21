"""
data/prepare_dataset.py — Download & Prepare Phishing Dataset
Sources:
  - PhishTank (phishing URLs)
  - Tranco Top List (legitimate URLs)
Author: Anveeksh Rao | github.com/anveeksh
"""
import os
import csv
import random
import requests
import pandas as pd
from utils.banner import success, error, info, warn
from utils.features import extract_features, FEATURE_NAMES

PHISH_CSV  = "data/phishing_urls.csv"
LEGIT_CSV  = "data/legit_urls.csv"
DATASET    = "data/dataset.csv"
SAMPLE_SIZE = 5000


def download_phishtank():
    info("Downloading PhishTank verified phishing URLs...")
    url = "http://data.phishtank.com/data/online-valid.csv"
    try:
        r = requests.get(url, timeout=60,
                         headers={"User-Agent": "phishtank/PhishGuard-Research"})
        if r.status_code == 200:
            with open(PHISH_CSV, "wb") as f:
                f.write(r.content)
            df = pd.read_csv(PHISH_CSV)
            info(f"Downloaded {len(df):,} phishing URLs from PhishTank")
            return True
        else:
            warn(f"PhishTank returned {r.status_code}")
            return False
    except Exception as e:
        warn(f"PhishTank download failed: {e}")
        return False


def download_tranco():
    info("Downloading Tranco top legitimate domains...")
    url = "https://tranco-list.eu/top-1m.csv.zip"
    try:
        import zipfile, io
        r = requests.get(url, timeout=60)
        if r.status_code == 200:
            z = zipfile.ZipFile(io.BytesIO(r.content))
            with z.open(z.namelist()[0]) as f:
                lines = [line.decode().strip().split(",")[1]
                         for line in f.readlines()[:20000]
                         if b"," in line]
            with open(LEGIT_CSV, "w") as f:
                f.write("url\n")
                for domain in lines:
                    f.write(f"https://{domain}\n")
            info(f"Saved {len(lines):,} legitimate domains")
            return True
        else:
            warn(f"Tranco returned {r.status_code}")
            return False
    except Exception as e:
        warn(f"Tranco download failed: {e}")
        return False


def use_builtin_legit():
    """Fallback: built-in list of known legitimate URLs."""
    warn("Using built-in legitimate URL list as fallback.")
    legit = [
        "https://google.com","https://github.com","https://microsoft.com",
        "https://apple.com","https://amazon.com","https://youtube.com",
        "https://facebook.com","https://twitter.com","https://linkedin.com",
        "https://wikipedia.org","https://stackoverflow.com","https://reddit.com",
        "https://netflix.com","https://adobe.com","https://dropbox.com",
        "https://salesforce.com","https://slack.com","https://zoom.us",
        "https://shopify.com","https://stripe.com","https://twilio.com",
        "https://cloudflare.com","https://digitalocean.com","https://heroku.com",
        "https://northeastern.edu","https://mit.edu","https://harvard.edu",
        "https://nist.gov","https://cisa.gov","https://owasp.org",
    ]
    # Expand with variations
    expanded = []
    for u in legit:
        expanded.append(u)
        domain = u.replace("https://","")
        expanded.append(f"https://www.{domain}")
        expanded.append(f"https://{domain}/about")
        expanded.append(f"https://{domain}/contact")
        expanded.append(f"https://{domain}/login")
    with open(LEGIT_CSV, "w") as f:
        f.write("url\n")
        for u in expanded:
            f.write(f"{u}\n")
    return True


def build_dataset():
    info("Building feature dataset...\n")
    rows = []

    # Load phishing URLs
    phish_urls = []
    if os.path.exists(PHISH_CSV):
        try:
            df = pd.read_csv(PHISH_CSV)
            col = "url" if "url" in df.columns else df.columns[1]
            phish_urls = df[col].dropna().tolist()
            info(f"Loaded {len(phish_urls):,} phishing URLs")
        except Exception as e:
            warn(f"Could not load phishing CSV: {e}")

    if not phish_urls:
        warn("No phishing URLs found. Using synthetic examples.")
        phish_urls = _synthetic_phishing()

    # Load legit URLs
    legit_urls = []
    if os.path.exists(LEGIT_CSV):
        try:
            df = pd.read_csv(LEGIT_CSV)
            col = "url" if "url" in df.columns else df.columns[0]
            legit_urls = df[col].dropna().tolist()
            info(f"Loaded {len(legit_urls):,} legitimate URLs")
        except Exception as e:
            warn(f"Could not load legit CSV: {e}")

    if not legit_urls:
        warn("No legit URLs found. Using built-in list.")
        use_builtin_legit()
        df = pd.read_csv(LEGIT_CSV)
        legit_urls = df["url"].dropna().tolist()

    # Balance dataset
    n = min(SAMPLE_SIZE, len(phish_urls), len(legit_urls))
    info(f"Sampling {n:,} URLs per class ({n*2:,} total)\n")

    phish_sample = random.sample(phish_urls, n)
    legit_sample = random.sample(legit_urls, n)

    info("Extracting features from phishing URLs...")
    for i, url in enumerate(phish_sample):
        if i % 500 == 0:
            info(f"  Processed {i}/{n}...")
        feats = extract_features(str(url))
        rows.append(feats + [1])

    info("Extracting features from legitimate URLs...")
    for i, url in enumerate(legit_sample):
        if i % 500 == 0:
            info(f"  Processed {i}/{n}...")
        feats = extract_features(str(url))
        rows.append(feats + [0])

    # Shuffle and save
    random.shuffle(rows)
    cols = FEATURE_NAMES + ["label"]
    df   = pd.DataFrame(rows, columns=cols)
    df.to_csv(DATASET, index=False)

    phish_count = df["label"].sum()
    legit_count = len(df) - phish_count
    success(f"\nDataset built → {DATASET}")
    success(f"Total samples : {len(df):,}")
    success(f"Phishing      : {int(phish_count):,}")
    success(f"Legitimate    : {int(legit_count):,}")
    return DATASET


def _synthetic_phishing():
    """Synthetic phishing URLs for demo/fallback purposes."""
    templates = [
        "http://paypal-secure-login.{tld}/verify?user=victim&token=abc123",
        "http://192.168.1.{n}/banking/login.php?redirect=paypal",
        "http://amazon-account-{n}.tk/signin/update-billing",
        "http://secure-{n}.microsoft-login.ga/oauth?token=xyz",
        "http://bit.ly/{code}",
        "http://appleid-verify-{n}.ml/account/locked",
        "http://login-{n}.paypal-secure.cf/confirm",
        "http://www.free-winner-{n}.xyz/claim-prize?id={n}",
        "http://update-your-account-{n}.top/banking/verify",
        "http://chase-bank-secure-{n}.tk/login/authenticate",
    ]
    import string, random as r
    urls = []
    tlds = ["com","net","org","info","biz"]
    for _ in range(3000):
        t = r.choice(templates)
        n_val = r.randint(100, 9999)
        code  = "".join(r.choices(string.ascii_lowercase + string.digits, k=6))
        tld   = r.choice(tlds)
        urls.append(t.format(n=n_val, code=code, tld=tld))
    return urls


def run():
    info("=== PhishGuard Dataset Preparation ===\n")
    os.makedirs("data", exist_ok=True)

    # Try downloading real data
    phish_ok = download_phishtank()
    legit_ok  = download_tranco()

    if not legit_ok:
        use_builtin_legit()

    # Build feature dataset
    path = build_dataset()
    return path
