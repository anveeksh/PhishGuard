<p align="center">
  <img src="https://img.shields.io/badge/version-2.0.0-cyan?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/python-3.8%2B-blue?style=for-the-badge&logo=python"/>
  <img src="https://img.shields.io/badge/flask-web%20app-orange?style=for-the-badge&logo=flask"/>
  <img src="https://img.shields.io/badge/accuracy-99.5%25-brightgreen?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge"/>
</p>

<h1 align="center">🎣 PhishGuard Pro</h1>
<h4 align="center">AI-Powered Phishing URL Detection — Web Dashboard + CLI</h4>

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#research">Research</a> •
  <a href="#license">License</a>
</p>

---

## 📌 Overview

**PhishGuard Pro** is an open-source AI-powered phishing URL detection system that uses three machine learning models to classify any URL as phishing or legitimate in real time — just from the URL structure, without loading the page.

Built as both a **research tool** and a **practical web application**, PhishGuard Pro helps everyday users stay safe from phishing attacks by scanning URLs before clicking them.

> ⚠️ For authorized testing and educational use only.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔍 URL Scanner | Scan any URL with 3 AI models simultaneously |
| 📧 Email Scanner | Paste email content — auto-extracts and scans all links |
| 📷 QR Code Scanner | Upload QR image — decodes and scans the hidden URL |
| 📂 Batch Scanner | Upload CSV/TXT with up to 500 URLs — scan all at once |
| 🕵️ WHOIS Checker | Check domain age and registration details |
| 🔎 Typosquat Detector | Detect look-alike domains mimicking brands |
| 📊 SIEM Dashboard | Real-time threat monitoring dashboard |
| 📋 Scan History | Full log of all scanned URLs with verdicts |
| 📄 PDF Reports | Auto-generate professional pentest-style reports |

---

## 🤖 AI Models

| Model | Accuracy | F1 Score | AUC-ROC |
|---|---|---|---|
| Random Forest | 99.5% | 99.5% | 99.70% |
| XGBoost | 99.5% | 99.5% | 99.81% |
| Neural Network | 99.5% | 99.5% | 99.84% |

**Dataset:** 10,020 balanced URLs — PhishTank (phishing) + Tranco Top 1M (legitimate)

---

## ⚙️ Installation
```bash
git clone https://github.com/anveeksh/PhishGuard.git
cd PhishGuard
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

### Train the Models First
```bash
python3 phishguard.py
# Select [1] Download Dataset
# Select [2] Train All Models
```

### Launch Web Dashboard
```bash
python3 web/app.py
# Open http://localhost:5001
```

### Or Use CLI
```bash
python3 phishguard.py
# Select [3] Scan Single URL
```

---

## 🖥️ Web Dashboard
```
http://localhost:5001          → Main dashboard
http://localhost:5001/scanner  → URL scanner
http://localhost:5001/email    → Email scanner
http://localhost:5001/qr       → QR code scanner
http://localhost:5001/batch    → Batch scan
http://localhost:5001/history  → Scan history
```

---

## 🔬 Research

This tool was built as part of a CY5010 research project at Northeastern University.

**Research Question:** Which ML algorithm performs best at detecting phishing URLs, and what are the fundamental limitations of URL-only detection?

**Key Finding:** All 3 models achieved 99.5% accuracy on the test set — but produced false positives at 95.4% confidence on legitimate personal domains, revealing a fundamental limitation of URL-structural detection approaches.

**References:**
- Sahingoz et al. (2019). Machine learning based phishing detection from URLs. *Expert Systems with Applications, 117*, 345–357.
- Mohammad et al. (2014). Predicting phishing websites based on self-structuring neural network. *Neural Computing and Applications, 25*(2), 443–458.

---

## 📁 Project Structure
```
PhishGuard/
├── phishguard.py          ← CLI entry point
├── web/
│   ├── app.py             ← Flask web backend
│   └── templates/         ← HTML dashboard pages
├── models/                ← ML model files
├── utils/
│   ├── features.py        ← 33 URL feature extractor
│   ├── banner.py          ← CLI UI
│   └── helpers.py         ← Utilities
├── data/                  ← Dataset preparation
└── requirements.txt
```

---

## 📄 License

MIT License — see LICENSE file.

---

## 👤 Author

**Anveeksh Rao (Ish)**
MS Cybersecurity — Northeastern University

[![Portfolio](https://img.shields.io/badge/Portfolio-anveekshmrao.com-cyan?style=flat-square)](https://anveekshmrao.com)
[![GitHub](https://img.shields.io/badge/GitHub-anveeksh-black?style=flat-square&logo=github)](https://github.com/anveeksh)

---

<p align="center">Made with ❤️ for educational use only — always hack ethically!</p>
