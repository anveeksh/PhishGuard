"""
utils/helpers.py — Shared utilities for PhishGuard
Author: Anveeksh Rao | github.com/anveeksh
"""
import os, json, csv
from datetime import datetime

SCAN_HISTORY = []

def save_results(name, data):
    os.makedirs("results", exist_ok=True)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"results/{name}_{ts}.json"
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path

def add_scan(url, prediction, confidence, model):
    SCAN_HISTORY.append({
        "url"        : url,
        "prediction" : prediction,
        "confidence" : confidence,
        "model"      : model,
        "timestamp"  : datetime.now().isoformat()
    })

def get_history():
    return SCAN_HISTORY

def clear_screen():
    os.system("clear")

def press_enter():
    input("\n  Press ENTER to return to menu...")

def models_trained():
    required = [
        "models/random_forest.pkl",
        "models/xgboost_model.pkl",
        "models/neural_network.keras",
        "models/scaler.pkl",
    ]
    return all(os.path.exists(p) for p in required)
