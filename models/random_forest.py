"""
models/random_forest.py — Random Forest Classifier
Author: Anveeksh Rao | github.com/anveeksh
"""
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, precision_score,
                              recall_score, f1_score, confusion_matrix,
                              roc_auc_score)
from utils.banner import success, error, info, warn

MODEL_PATH = "models/random_forest.pkl"

def train(X_train, y_train, X_test, y_test):
    info("Training Random Forest...")
    info(f"  Trees     : 200")
    info(f"  Max depth : None (fully grown)")
    info(f"  Features  : sqrt\n")
    clf = RandomForestClassifier(
        n_estimators     = 200,
        max_depth        = None,
        min_samples_split= 2,
        min_samples_leaf = 1,
        max_features     = "sqrt",
        random_state     = 42,
        n_jobs           = -1,
        class_weight     = "balanced",
    )
    clf.fit(X_train, y_train)
    joblib.dump(clf, MODEL_PATH)
    success(f"Random Forest saved → {MODEL_PATH}")
    metrics = evaluate(clf, X_test, y_test)
    return clf, metrics

def evaluate(clf, X_test, y_test):
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]
    metrics = {
        "model"    : "Random Forest",
        "accuracy" : round(accuracy_score(y_test, y_pred)   * 100, 2),
        "precision": round(precision_score(y_test, y_pred)  * 100, 2),
        "recall"   : round(recall_score(y_test, y_pred)     * 100, 2),
        "f1"       : round(f1_score(y_test, y_pred)         * 100, 2),
        "auc_roc"  : round(roc_auc_score(y_test, y_prob)    * 100, 2),
        "confusion": confusion_matrix(y_test, y_pred).tolist(),
    }
    _print_metrics(metrics)
    return metrics

def predict(url_features, threshold=0.5):
    try:
        clf = joblib.load(MODEL_PATH)
        features = np.array(url_features).reshape(1, -1)
        prob     = clf.predict_proba(features)[0][1]
        label    = "phishing" if prob >= threshold else "legitimate"
        return label, round(float(prob) * 100, 2)
    except Exception as e:
        error(f"Random Forest prediction failed: {e}")
        return "error", 0.0

def get_feature_importance():
    try:
        clf = joblib.load(MODEL_PATH)
        return clf.feature_importances_
    except Exception:
        return None

def _print_metrics(m):
    success(f"Random Forest Results:")
    info(f"  Accuracy  : {m['accuracy']}%")
    info(f"  Precision : {m['precision']}%")
    info(f"  Recall    : {m['recall']}%")
    info(f"  F1 Score  : {m['f1']}%")
    info(f"  AUC-ROC   : {m['auc_roc']}%")
