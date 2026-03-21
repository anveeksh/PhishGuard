"""
utils/features.py — URL Feature Extraction (30+ features)
Author: Anveeksh Rao | github.com/anveeksh
"""
import re
import math
import tldextract
from urllib.parse import urlparse

SHORTENERS = {
    "bit.ly","tinyurl.com","goo.gl","ow.ly","t.co",
    "buff.ly","adf.ly","tiny.cc","is.gd","rb.gy",
    "cutt.ly","shorturl.at","bl.ink","snip.ly",
}

SUSPICIOUS_KEYWORDS = [
    "login","signin","secure","account","update","verify",
    "banking","paypal","ebay","amazon","apple","microsoft",
    "support","confirm","password","credential","suspend",
    "unusual","activity","limited","access","click","free",
    "winner","prize","urgent","alert","warning",
]

FEATURE_NAMES = [
    "url_length","domain_length","path_length","query_length",
    "num_dots","num_hyphens","num_underscores","num_slashes",
    "num_digits","num_special_chars","num_subdomains",
    "has_ip","has_https","has_http","is_shortener",
    "has_at_symbol","has_double_slash","has_suspicious_keyword",
    "suspicious_keyword_count","digit_ratio","letter_ratio",
    "special_ratio","entropy","tld_length","subdomain_length",
    "path_depth","has_port","query_param_count",
    "has_suspicious_tld","consecutive_digits",
    "vowel_ratio","domain_digit_ratio","has_brand_keyword",
]

SUSPICIOUS_TLDS = {
    ".tk",".ml",".ga",".cf",".gq",".xyz",".top",
    ".club",".work",".date",".faith",".racing",".review",
}

def calculate_entropy(text):
    if not text:
        return 0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    n = len(text)
    entropy = 0
    for count in freq.values():
        p = count / n
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)

def extract_features(url):
    try:
        if not url.startswith(("http://","https://")):
            url = "http://" + url

        parsed   = urlparse(url)
        ext      = tldextract.extract(url)
        domain   = parsed.netloc.lower()
        path     = parsed.path.lower()
        query    = parsed.query.lower()
        full_url = url.lower()

        # IP address check
        ip_pattern = re.compile(
            r"^(?:\d{1,3}\.){3}\d{1,3}$|"
            r"0x[0-9a-f]+|"
            r"\d{8,10}"
        )
        has_ip = 1 if ip_pattern.search(domain.split(":")[0]) else 0

        # Subdomain analysis
        subdomains = ext.subdomain.split(".") if ext.subdomain else []
        num_subdomains = len([s for s in subdomains if s])

        # Keyword analysis
        kw_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in full_url)

        # TLD check
        tld = "." + ext.suffix if ext.suffix else ""
        has_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

        # Consecutive digits
        consecutive = max(
            (len(m.group()) for m in re.finditer(r"\d+", domain)),
            default=0
        )

        # Character ratios
        url_len = len(url)
        digits  = sum(c.isdigit() for c in full_url)
        letters = sum(c.isalpha() for c in full_url)
        special = sum(not c.isalnum() for c in full_url)

        # New discriminating features
        domain_str   = ext.domain if ext.domain else ""
        vowels       = sum(1 for c in domain_str if c in "aeiou")
        vowel_ratio  = round(vowels / len(domain_str), 4) if domain_str else 0
        dom_digits   = sum(c.isdigit() for c in domain_str)
        dom_dig_ratio= round(dom_digits / len(domain_str), 4) if domain_str else 0
        brand_keywords = ["google","facebook","amazon","apple","microsoft",
                          "paypal","ebay","netflix","instagram","twitter",
                          "linkedin","github","youtube","yahoo","outlook"]
        has_brand    = 1 if any(b in full_url for b in brand_keywords) else 0

        features = [
            url_len,
            len(ext.domain) if ext.domain else 0,
            len(path),
            len(query),
            full_url.count("."),
            full_url.count("-"),
            full_url.count("_"),
            full_url.count("/"),
            digits,
            special,
            num_subdomains,
            has_ip,
            1 if parsed.scheme == "https" else 0,
            1 if parsed.scheme == "http"  else 0,
            1 if domain in SHORTENERS      else 0,
            1 if "@" in full_url           else 0,
            1 if "//" in path              else 0,
            1 if kw_count > 0              else 0,
            kw_count,
            round(digits  / url_len, 4) if url_len else 0,
            round(letters / url_len, 4) if url_len else 0,
            round(special / url_len, 4) if url_len else 0,
            calculate_entropy(ext.domain if ext.domain else domain),
            len(ext.suffix) if ext.suffix else 0,
            len(ext.subdomain) if ext.subdomain else 0,
            path.count("/"),
            1 if parsed.port else 0,
            len(parsed.query.split("&")) if parsed.query else 0,
            has_suspicious_tld,
            consecutive,
            vowel_ratio,
            dom_dig_ratio,
            has_brand,
        ]
        return features

    except Exception:
        return [0] * len(FEATURE_NAMES)
