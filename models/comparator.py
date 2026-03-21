"""
models/comparator.py — Model Performance Comparison & Visualization
Author: Anveeksh Rao | github.com/anveeksh
"""
import os
import json
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from tabulate import tabulate
from utils.banner import success, error, info, warn, print_module_header

RESULTS_PATH = "results/model_comparison.json"

def compare(metrics_list):
    print_module_header("Model Performance Comparison")
    if not metrics_list:
        warn("No metrics to compare. Train models first.")
        return

    # Print comparison table
    headers = ["Model", "Accuracy%", "Precision%", "Recall%", "F1%", "AUC-ROC%"]
    rows = []
    for m in metrics_list:
        rows.append([
            m["model"], m["accuracy"], m["precision"],
            m["recall"], m["f1"], m["auc_roc"]
        ])

    print()
    print(tabulate(rows, headers=headers, tablefmt="rounded_outline"))
    print()

    # Best model
    best = max(metrics_list, key=lambda x: x["f1"])
    success(f"Best model by F1 Score: {best['model']} ({best['f1']}%)")

    # Save results
    os.makedirs("results", exist_ok=True)
    with open(RESULTS_PATH, "w") as f:
        json.dump(metrics_list, f, indent=2)
    success(f"Comparison saved → {RESULTS_PATH}")

    # Generate charts
    generate_bar_chart(metrics_list)
    generate_confusion_matrices(metrics_list)
    return best


def generate_bar_chart(metrics_list):
    models     = [m["model"] for m in metrics_list]
    metrics_keys = ["accuracy","precision","recall","f1","auc_roc"]
    labels     = ["Accuracy","Precision","Recall","F1","AUC-ROC"]
    colors     = ["#4C9BE8","#5DBF7E","#F5A623","#E85D75","#9B59B6"]

    x   = np.arange(len(models))
    w   = 0.15
    fig, ax = plt.subplots(figsize=(12, 6))
    fig.patch.set_facecolor("#1a1a2e")
    ax.set_facecolor("#16213e")

    for i, (key, label, color) in enumerate(zip(metrics_keys, labels, colors)):
        vals = [m[key] for m in metrics_list]
        bars = ax.bar(x + i * w, vals, w, label=label, color=color, alpha=0.85)
        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., h + 0.3,
                    f"{h:.1f}", ha="center", va="bottom",
                    color="white", fontsize=7)

    ax.set_xlabel("Models", color="white", fontsize=11)
    ax.set_ylabel("Score (%)", color="white", fontsize=11)
    ax.set_title("PhishGuard — Model Performance Comparison",
                 color="white", fontsize=13, pad=15)
    ax.set_xticks(x + w * 2)
    ax.set_xticklabels(models, color="white", fontsize=10)
    ax.tick_params(colors="white")
    ax.set_ylim(0, 110)
    ax.legend(loc="lower right", facecolor="#1a1a2e", labelcolor="white")
    ax.spines[:].set_color("#444")
    ax.grid(axis="y", alpha=0.2, color="white")

    os.makedirs("results", exist_ok=True)
    path = "results/model_comparison_chart.png"
    plt.tight_layout()
    plt.savefig(path, dpi=150, bbox_inches="tight",
                facecolor="#1a1a2e")
    plt.close()
    success(f"Bar chart saved → {path}")


def generate_confusion_matrices(metrics_list):
    n    = len(metrics_list)
    fig, axes = plt.subplots(1, n, figsize=(5 * n, 4))
    fig.patch.set_facecolor("#1a1a2e")
    if n == 1:
        axes = [axes]

    for ax, m in zip(axes, metrics_list):
        cm = np.array(m["confusion"])
        sns.heatmap(
            cm, annot=True, fmt="d", ax=ax,
            cmap="Blues",
            xticklabels=["Legit","Phish"],
            yticklabels=["Legit","Phish"],
            linewidths=0.5,
        )
        ax.set_title(m["model"], color="white", fontsize=11, pad=10)
        ax.set_xlabel("Predicted", color="white")
        ax.set_ylabel("Actual",    color="white")
        ax.tick_params(colors="white")
        ax.set_facecolor("#16213e")

    fig.suptitle("Confusion Matrices", color="white",
                 fontsize=13, y=1.02)
    os.makedirs("results", exist_ok=True)
    path = "results/confusion_matrices.png"
    plt.tight_layout()
    plt.savefig(path, dpi=150, bbox_inches="tight",
                facecolor="#1a1a2e")
    plt.close()
    success(f"Confusion matrices saved → {path}")
