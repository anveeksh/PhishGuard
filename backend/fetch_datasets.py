import csv
import zipfile
from pathlib import Path

import requests

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

PHISHING_OUT = DATA_DIR / "phishing_urls.csv"
LEGIT_OUT = DATA_DIR / "legit_urls.csv"


def save_urls(path, urls):
    urls = list(dict.fromkeys([u.strip() for u in urls if u and u.strip()]))

    with open(path, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["url"])

        for url in urls:
            writer.writerow([url])

    print(f"Saved {len(urls)} URLs to {path}")


def fetch_urlhaus():
    print("Fetching URLhaus malicious URL feed...")

    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    response = requests.get(url, timeout=30)

    lines = response.text.splitlines()
    urls = []

    for line in lines:
        if line.startswith("#") or not line.strip():
            continue

        parts = list(csv.reader([line]))[0]

        if len(parts) > 2:
            urls.append(parts[2])

    return urls


def fetch_tranco():
    print("Fetching Tranco legitimate domain list...")

    url = "https://tranco-list.eu/top-1m.csv.zip"
    zip_path = DATA_DIR / "tranco.zip"

    response = requests.get(url, timeout=60)
    zip_path.write_bytes(response.content)

    domains = []

    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        file_name = zip_ref.namelist()[0]

        with zip_ref.open(file_name) as file:
            decoded = file.read().decode("utf-8", errors="ignore").splitlines()

            for line in decoded[:10000]:
                parts = line.split(",")

                if len(parts) >= 2:
                    domains.append("https://" + parts[1].strip())

    zip_path.unlink(missing_ok=True)

    return domains


def main():
    phishing_urls = fetch_urlhaus()
    legit_urls = fetch_tranco()

    save_urls(PHISHING_OUT, phishing_urls)
    save_urls(LEGIT_OUT, legit_urls)


if __name__ == "__main__":
    main()