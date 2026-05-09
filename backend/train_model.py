import csv
import random
from pathlib import Path

import joblib
import numpy as np

from scanner import extract_features
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

try:
    from xgboost import XGBClassifier
    XGBOOST_AVAILABLE = True
except Exception:
    XGBOOST_AVAILABLE = False


DATA_DIR = Path("data")
PHISHING_CSV = DATA_DIR / "phishing_urls.csv"
LEGIT_CSV = DATA_DIR / "legit_urls.csv"

FEATURE_KEYS = [
    "url_length",
    "domain_length",
    "path_length",
    "subdomain_count",
    "dot_count",
    "hyphen_count",
    "question_marks",
    "equal_signs",
    "digit_ratio",
    "digit_count",
    "url_entropy",
    "domain_entropy",
    "suspicious_word_count",
    "uses_https",
    "has_ip_address",
    "is_shortened",
    "is_typosquat",
    "has_non_ascii",
    "high_risk_tld",
    "brand_impersonated",
    "has_redirect_param",
    "at_symbol",
    "percent_encoding",
    "double_slash",
    "has_double_extension",
    "has_port",
]


SEED_PHISHING = [
    "paypal-secure-login.xyz",
    "login-paypal.com.security.info",
    "verify-account-paypal.xyz/signin",
    "facebook-login-security-update.top",
    "g00gle.com/update-account",
    "appleid-login-support.xyz",
    "amazon-billing-confirmation.site",
    "microsoft365-password-reset.info",
    "secure-bank-update-login.com",
    "coinbase-wallet-verify.online",
    "netflix-payment-failed.xyz",
    "github-security-alert-login.info",
    "http://192.168.1.1/bank-login",
    "http://login.paypal.com.phishing-site.tk/webscr",
    "https://bit.ly/3xABCDef",
    "https://amazon-support-billing.com/confirm-payment",
    "www.c1t1bank.com",
    "faceb00k.com",
    "secure-chase-billing.info",
    "bankofamerica-login-alert.xyz",
]

SEED_LEGIT = [
    "https://github.com",
    "https://google.com",
    "https://apple.com",
    "https://microsoft.com",
    "https://amazon.com",
    "https://netflix.com",
    "https://facebook.com",
    "https://instagram.com",
    "https://linkedin.com",
    "https://paypal.com",
    "https://coinbase.com",
    "https://binance.com",
    "https://northeastern.edu",
    "https://openai.com",
    "https://cloudflare.com",
    "https://owasp.org",
    "https://chase.com",
    "https://bankofamerica.com",
    "https://citibank.com",
]


def read_urls_from_csv(path: Path) -> list[str]:
    urls = []

    if not path.exists():
        return urls

    with open(path, "r", encoding="utf-8", errors="ignore") as file:
        sample = file.read(2048)
        file.seek(0)

        has_header = "url" in sample.lower()

        if has_header:
            reader = csv.DictReader(file)
            for row in reader:
                value = row.get("url") or row.get("URL") or row.get("phish_detail_url")
                if value:
                    urls.append(value.strip())
        else:
            reader = csv.reader(file)
            for row in reader:
                if row and row[0].strip():
                    urls.append(row[0].strip())

    return list(dict.fromkeys(urls))


def mutate_phishing() -> str:
    brands = [
        "paypal", "google", "apple", "amazon", "facebook", "microsoft",
        "chase", "citibank", "bankofamerica", "github", "coinbase"
    ]

    actions = [
        "login", "secure", "verify", "account", "update", "support",
        "billing", "confirm", "signin", "unlock", "password"
    ]

    tlds = [".xyz", ".top", ".info", ".site", ".online", ".tk", ".click", ".live"]

    brand = random.choice(brands)
    action1 = random.choice(actions)
    action2 = random.choice(actions)
    tld = random.choice(tlds)

    patterns = [
        f"https://{action1}-{brand}-{action2}{tld}/signin",
        f"https://{brand}-{action1}-{action2}{tld}/login",
        f"http://login-{brand}.security{tld}/account",
        f"https://secure-{brand}.verify-account{tld}/update",
        f"http://{brand}-support-billing{tld}/confirm-payment",
    ]

    return random.choice(patterns)


def mutate_legit() -> str:
    domains = [
        "github.com", "google.com", "apple.com", "microsoft.com", "amazon.com",
        "netflix.com", "facebook.com", "instagram.com", "linkedin.com",
        "paypal.com", "cloudflare.com", "owasp.org", "northeastern.edu",
        "openai.com", "chase.com", "bankofamerica.com", "citibank.com"
    ]

    paths = ["", "/", "/about", "/support", "/login", "/docs", "/security"]

    return "https://" + random.choice(domains) + random.choice(paths)


def vectorize(url: str) -> list[float]:
    features = extract_features(url)
    row = []

    for key in FEATURE_KEYS:
        value = features.get(key, 0)
        row.append(int(value) if isinstance(value, bool) else float(value))

    return row


def build_dataset():
    phishing_urls = SEED_PHISHING + read_urls_from_csv(PHISHING_CSV)
    legit_urls = SEED_LEGIT + read_urls_from_csv(LEGIT_CSV)

    phishing_urls = list(dict.fromkeys([u for u in phishing_urls if u]))
    legit_urls = list(dict.fromkeys([u for u in legit_urls if u]))

    for _ in range(1000):
        phishing_urls.append(mutate_phishing())

    for _ in range(1000):
        legit_urls.append(mutate_legit())

    urls = phishing_urls + legit_urls
    labels = [1] * len(phishing_urls) + [0] * len(legit_urls)

    X = np.array([vectorize(url) for url in urls])
    y = np.array(labels)

    print(f"Loaded phishing URLs: {len(phishing_urls)}")
    print(f"Loaded legitimate URLs: {len(legit_urls)}")
    print(f"Total samples: {len(urls)}")
    print(f"Feature count: {len(FEATURE_KEYS)}")

    return X, y


def train():
    X, y = build_dataset()

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y,
    )

    models = {}

    rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=14,
        random_state=42,
        class_weight="balanced",
    )
    rf.fit(X_train, y_train)
    models["random_forest"] = rf

    nn = Pipeline([
        ("scaler", StandardScaler()),
        ("mlp", MLPClassifier(
            hidden_layer_sizes=(96, 48, 24),
            activation="relu",
            max_iter=700,
            random_state=42,
        )),
    ])
    nn.fit(X_train, y_train)
    models["neural_network"] = nn

    if XGBOOST_AVAILABLE:
        xgb = XGBClassifier(
            n_estimators=300,
            max_depth=5,
            learning_rate=0.045,
            subsample=0.9,
            colsample_bytree=0.9,
            eval_metric="logloss",
            random_state=42,
        )
        xgb.fit(X_train, y_train)
        models["xgboost"] = xgb

    print("\nModel Evaluation")
    print("=" * 45)

    for name, model in models.items():
        preds = model.predict(X_test)
        print(f"\n{name}")
        print("Accuracy:", accuracy_score(y_test, preds))
        print(classification_report(y_test, preds))

    joblib.dump(
        {
            "models": models,
            "feature_keys": FEATURE_KEYS,
        },
        "phishguard_ensemble.joblib",
    )

    print("\nSaved: phishguard_ensemble.joblib")


if __name__ == "__main__":
    train()