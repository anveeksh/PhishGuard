#!/usr/bin/env python3
"""
phishguard.py — Main Entry Point
AI-Powered Phishing URL Detection System
Author: Anveeksh Rao | github.com/anveeksh
"""
import os, sys
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"

from colorama import init
init(autoreset=True)

from utils.banner import (print_banner, print_menu, print_module_header,
                           info, warn, error, success, phish, legit)
from utils.helpers import clear_screen, press_enter, models_trained, add_scan, get_history, save_results
from utils.features import extract_features, FEATURE_NAMES


def train_all_models():
    print_module_header("Training All Models")
    import pandas as pd
    import numpy as np
    from sklearn.model_selection import train_test_split
    from models import random_forest, xgboost_model, neural_network
    from models.comparator import compare

    dataset = "data/dataset.csv"
    if not os.path.exists(dataset):
        warn("Dataset not found. Running dataset preparation first...")
        from data.prepare_dataset import run as prepare
        prepare()

    info("Loading dataset...")
    df = pd.read_csv(dataset)
    info(f"Dataset shape : {df.shape}")
    info(f"Phishing      : {int(df['label'].sum()):,}")
    info(f"Legitimate    : {int((df['label']==0).sum()):,}\n")

    X = df[FEATURE_NAMES].values
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    info(f"Train size : {len(X_train):,}")
    info(f"Test size  : {len(X_test):,}\n")

    all_metrics = []

    # Random Forest
    print()
    _, rf_metrics = random_forest.train(X_train, y_train, X_test, y_test)
    all_metrics.append(rf_metrics)

    # XGBoost
    print()
    _, xgb_metrics = xgboost_model.train(X_train, y_train, X_test, y_test)
    all_metrics.append(xgb_metrics)

    # Neural Network
    print()
    _, nn_metrics, _ = neural_network.train(X_train, y_train, X_test, y_test)
    all_metrics.append(nn_metrics)

    # Compare
    print()
    compare(all_metrics)
    save_results("training_metrics", all_metrics)
    press_enter()


def scan_url(url=None):
    print_module_header("Single URL Scanner")
    if not models_trained():
        warn("Models not trained yet! Run [2] Train All Models first.")
        press_enter()
        return

    from models import random_forest, xgboost_model, neural_network

    if not url:
        url = input("  Enter URL to scan: ").strip()
    if not url:
        error("No URL entered.")
        press_enter()
        return

    info(f"Scanning: {url}\n")
    features = extract_features(url)

    results = {}

    # Run all 3 models
    rf_label,  rf_conf  = random_forest.predict(features)
    xgb_label, xgb_conf = xgboost_model.predict(features)
    nn_label,  nn_conf  = neural_network.predict(features)

    results = {
        "Random Forest" : (rf_label,  rf_conf),
        "XGBoost"       : (xgb_label, xgb_conf),
        "Neural Network": (nn_label,  nn_conf),
    }

    print()
    info("  ┌─────────────────────────────────────────┐")
    info("  │         Prediction Results               │")
    info("  ├─────────────────────────────────────────┤")
    for model, (label, conf) in results.items():
        bar = "█" * int(conf / 5) + "░" * (20 - int(conf / 5))
        if label == "phishing":
            phish(f"  {model:<16} → PHISHING  {conf:5.1f}% [{bar}]")
        else:
            legit(f"  {model:<16} → LEGIT     {conf:5.1f}% [{bar}]")
    info("  └─────────────────────────────────────────┘")

    # Ensemble vote
    votes     = [l for l, _ in results.values()]
    avg_conf  = sum(c for _, c in results.values()) / len(results)
    phish_v   = votes.count("phishing")
    legit_v   = votes.count("legitimate")
    verdict   = "phishing" if phish_v >= 2 else "legitimate"

    print()
    if verdict == "phishing":
        phish(f"  ENSEMBLE VERDICT: PHISHING ({phish_v}/3 models agree | avg {avg_conf:.1f}% confidence)")
    else:
        legit(f"  ENSEMBLE VERDICT: LEGITIMATE ({legit_v}/3 models agree | avg {avg_conf:.1f}% confidence)")

    add_scan(url, verdict, avg_conf, "ensemble")
    save_results("scan", {"url": url, "verdict": verdict,
                          "confidence": avg_conf, "models": {
                              k: {"label": v[0], "confidence": v[1]}
                              for k, v in results.items()
                          }})
    press_enter()


def batch_scan():
    print_module_header("Batch URL Scanner")
    if not models_trained():
        warn("Models not trained yet! Run [2] Train All Models first.")
        press_enter()
        return

    path = input("  Enter path to URL file (one URL per line): ").strip()
    if not os.path.exists(path):
        error(f"File not found: {path}")
        press_enter()
        return

    with open(path, "r") as f:
        urls = [line.strip() for line in f if line.strip()]

    info(f"Scanning {len(urls):,} URLs...\n")
    results = []
    phish_count = 0

    for i, url in enumerate(urls, 1):
        features   = extract_features(url)
        from models import random_forest
        label, conf = random_forest.predict(features)
        results.append({"url": url, "verdict": label, "confidence": conf})
        if label == "phishing":
            phish_count += 1
            phish(f"  [{i:3d}] {label.upper():<12} {conf:5.1f}%  {url[:60]}")
        else:
            legit(f"  [{i:3d}] {label.upper():<12} {conf:5.1f}%  {url[:60]}")

    print()
    info(f"Scan complete!")
    info(f"  Total     : {len(urls):,}")
    phish(f"  Phishing  : {phish_count:,}")
    legit(f"  Legitimate: {len(urls) - phish_count:,}")

    save_results("batch_scan", results)
    press_enter()


def compare_models():
    print_module_header("Model Performance Comparison")
    import json
    path = "results/model_comparison.json"
    if not os.path.exists(path):
        warn("No comparison data found. Train models first ([2]).")
        press_enter()
        return
    with open(path) as f:
        metrics = json.load(f)
    from models.comparator import compare
    compare(metrics)
    press_enter()


def generate_report():
    print_module_header("Research Report Generator")
    import json
    from datetime import datetime
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                     Table, TableStyle, HRFlowable,
                                     PageBreak, Image)

    metrics_path = "results/model_comparison.json"
    if not os.path.exists(metrics_path):
        warn("No model metrics found. Train models first ([2]).")
        press_enter()
        return

    with open(metrics_path) as f:
        metrics = json.load(f)

    os.makedirs("reports", exist_ok=True)
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reports/PhishGuard_Research_Report_{ts}.pdf"
    doc      = SimpleDocTemplate(filename, pagesize=A4,
                                  rightMargin=2*cm, leftMargin=2*cm,
                                  topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    story  = []

    title_s = ParagraphStyle("T", parent=styles["Title"],
        fontSize=22, textColor=colors.HexColor("#1a1a2e"),
        spaceAfter=6, fontName="Helvetica-Bold")
    h1_s = ParagraphStyle("H1", parent=styles["Heading1"],
        fontSize=15, textColor=colors.HexColor("#16213e"),
        spaceBefore=12, spaceAfter=6, fontName="Helvetica-Bold")
    h2_s = ParagraphStyle("H2", parent=styles["Heading2"],
        fontSize=12, textColor=colors.HexColor("#0f3460"),
        spaceBefore=8, spaceAfter=4, fontName="Helvetica-Bold")
    body_s = ParagraphStyle("B", parent=styles["Normal"],
        fontSize=10, leading=14, spaceAfter=4)
    code_s = ParagraphStyle("C", parent=styles["Normal"],
        fontSize=9, fontName="Courier", leading=12,
        backColor=colors.HexColor("#f4f4f4"), spaceAfter=4,
        leftIndent=10, rightIndent=10)

    # Cover
    story.append(Spacer(1, 2*cm))
    story.append(Paragraph("PhishGuard: AI-Powered Phishing URL Detection", title_s))
    story.append(Paragraph("A Comparative Study of Machine Learning Algorithms", h2_s))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1a1a2e")))
    story.append(Spacer(1, 0.4*cm))

    meta = [
        ["Author"      , "Anveeksh Rao"],
        ["Institution" , "Northeastern University, Khoury College"],
        ["Course"      , "CY5010 — Cybersecurity Research"],
        ["Date"        , datetime.now().strftime("%B %d, %Y")],
        ["Tool"        , "PhishGuard v1.0 | github.com/anveeksh"],
    ]
    mt = Table(meta, colWidths=[4*cm, 12*cm])
    mt.setStyle(TableStyle([
        ("FONTNAME", (0,0),(0,-1),"Helvetica-Bold"),
        ("FONTSIZE", (0,0),(-1,-1),10),
        ("ROWBACKGROUNDS",(0,0),(-1,-1),
         [colors.HexColor("#f8f9fa"), colors.white]),
        ("TOPPADDING",(0,0),(-1,-1),5),
        ("BOTTOMPADDING",(0,0),(-1,-1),5),
        ("LEFTPADDING",(0,0),(-1,-1),8),
    ]))
    story.append(mt)
    story.append(PageBreak())

    # Abstract
    story.append(Paragraph("1. Abstract", h1_s))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#ccc")))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        "Phishing attacks remain one of the most prevalent and damaging forms of cybercrime, "
        "targeting individuals and organizations through deceptive URLs that mimic legitimate "
        "services. This research presents PhishGuard, an automated phishing URL detection "
        "system that leverages machine learning to classify URLs as phishing or legitimate "
        "using 30 engineered features. Three algorithms were evaluated: Random Forest, XGBoost, "
        "and a Neural Network. The system was trained and tested on a balanced dataset combining "
        "PhishTank verified phishing URLs and Tranco top legitimate domains.", body_s))
    story.append(PageBreak())

    # Results
    story.append(Paragraph("2. Model Performance Results", h1_s))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#ccc")))
    story.append(Spacer(1, 0.3*cm))

    headers = ["Model","Accuracy%","Precision%","Recall%","F1%","AUC-ROC%"]
    rows    = [headers]
    for m in metrics:
        rows.append([m["model"], m["accuracy"], m["precision"],
                     m["recall"], m["f1"], m["auc_roc"]])

    rt = Table(rows, colWidths=[4*cm,3*cm,3*cm,2.5*cm,2.5*cm,3*cm])
    rt.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("FONTSIZE",(0,0),(-1,-1),10),
        ("ALIGN",(1,0),(-1,-1),"CENTER"),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),
         [colors.HexColor("#f0f8ff"), colors.white]),
        ("GRID",(0,0),(-1,-1),0.5,colors.HexColor("#ddd")),
        ("TOPPADDING",(0,0),(-1,-1),6),
        ("BOTTOMPADDING",(0,0),(-1,-1),6),
    ]))
    story.append(rt)
    story.append(Spacer(1, 0.5*cm))

    # Best model
    best = max(metrics, key=lambda x: x["f1"])
    story.append(Paragraph(
        f"The best performing model was <b>{best['model']}</b> with an F1 Score of "
        f"<b>{best['f1']}%</b> and AUC-ROC of <b>{best['auc_roc']}%</b>.", body_s))

    # Charts
    chart_path = "results/model_comparison_chart.png"
    cm_path    = "results/confusion_matrices.png"
    if os.path.exists(chart_path):
        story.append(PageBreak())
        story.append(Paragraph("3. Performance Charts", h1_s))
        story.append(HRFlowable(width="100%",thickness=1,color=colors.HexColor("#ccc")))
        story.append(Spacer(1,0.3*cm))
        story.append(Image(chart_path, width=16*cm, height=8*cm))
    if os.path.exists(cm_path):
        story.append(Spacer(1,0.5*cm))
        story.append(Paragraph("4. Confusion Matrices", h1_s))
        story.append(HRFlowable(width="100%",thickness=1,color=colors.HexColor("#ccc")))
        story.append(Spacer(1,0.3*cm))
        story.append(Image(cm_path, width=16*cm, height=6*cm))

    # Feature list
    story.append(PageBreak())
    story.append(Paragraph("5. Feature Engineering (30 Features)", h1_s))
    story.append(HRFlowable(width="100%",thickness=1,color=colors.HexColor("#ccc")))
    story.append(Spacer(1,0.3*cm))
    story.append(Paragraph(
        "The following 30 URL-based features were engineered for classification:", body_s))
    feat_text = " · ".join(FEATURE_NAMES)
    story.append(Paragraph(feat_text, code_s))

    # References
    story.append(PageBreak())
    story.append(Paragraph("6. References", h1_s))
    story.append(HRFlowable(width="100%",thickness=1,color=colors.HexColor("#ccc")))
    story.append(Spacer(1,0.2*cm))
    refs = [
        "[1] Mohammad, R. M., Thabtah, F., & McCluskey, L. (2014). Predicting phishing websites "
        "based on self-structuring neural network. Neural Computing and Applications, 25(2), 443-458.",
        "[2] Sahingoz, O. K., et al. (2019). Machine learning based phishing detection from URLs. "
        "Expert Systems with Applications, 117, 345-357.",
        "[3] OWASP Foundation. (2023). Phishing Prevention Cheat Sheet.",
        "[4] PhishTank. (2024). PhishTank Developer Information. https://www.phishtank.com/developer_info.php",
        "[5] Tranco. (2024). A Research-Oriented Top Sites Ranking. https://tranco-list.eu",
    ]
    for ref in refs:
        story.append(Paragraph(ref, body_s))
        story.append(Spacer(1, 0.2*cm))

    try:
        doc.build(story)
        success(f"Research Report → {filename}")
    except Exception as e:
        error(f"Report generation failed: {e}")
    press_enter()


def main():
    while True:
        clear_screen()
        print_banner()
        print_menu()

        history = get_history()
        if history:
            warn(f"  Session scans: {len(history)} URLs scanned")

        choice = input("\n  Enter option: ").strip()

        if choice == "1":
            clear_screen()
            from data.prepare_dataset import run as prepare
            prepare()
            press_enter()
        elif choice == "2":
            clear_screen()
            train_all_models()
        elif choice == "3":
            clear_screen()
            scan_url()
        elif choice == "4":
            clear_screen()
            batch_scan()
        elif choice == "5":
            clear_screen()
            compare_models()
        elif choice == "6":
            clear_screen()
            generate_report()
        elif choice == "0":
            clear_screen()
            info("Exiting PhishGuard. Stay safe online! 👋")
            sys.exit(0)
        else:
            warn("Invalid option.")

if __name__ == "__main__":
    main()
