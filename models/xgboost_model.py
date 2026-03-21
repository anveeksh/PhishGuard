"""
models/xgboost_model.py — XGBoost Classifier
Author: Anveeksh Rao | github.com/anveeksh
"""
import joblib
import numpy as np
from xgboost import XGBClassifier
from sklearn.metrics import (accuracy_score, precision_score,
                              recall_score, f1_score, confusion_matrix,
                              roc_auc_score)
from utils.banner import success, error, info, warn

MODEL_PATH = "models/xgboost_model.pkl"

def train(X_train, y_train, X_test, y_test):
    info("Training XGBoost...")
    info(f"  Estimators  : 200")
    info(f"  Max depth   : 6")
    info(f"  Learning rate: 0.1\n")
    clf = XGBClassifier(
        n_estimators      = 200,
        max_depth         = 6,
        learning_rate     = 0.1,
        subsample         = 0.8,
        colsample_bytree  = 0.8,
        use_label_encoder = False,
        eval_metric       = "logloss",
        random_state      = 42,
        n_jobs            = -1,
    )
    clf.fit(
        X_train, y_train,
        eval_set        = [(X_test, y_test)],
        verbose         = False,
    )
    joblib.dump(clf, MODEL_PATH)
    success(f"XGBoost saved → {MODEL_PATH}")
    metrics = evaluate(clf, X_test, y_test)
    return clf, metrics

def evaluate(clf, X_test, y_test):
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]
    metrics = {
        "model"    : "XGBoost",
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
        clf      = joblib.load(MODEL_PATH)
        features = np.array(url_features).reshape(1, -1)
        prob     = clf.predict_proba(features)[0][1]
        label    = "phishing" if prob >= threshold else "legitimate"
        return label, round(float(prob) * 100, 2)
    except Exception as e:
        error(f"XGBoost prediction failed: {e}")
        return "error", 0.0

def _print_metrics(m):
    success(f"XGBoost Results:")
    info(f"  Accuracy  : {m['accuracy']}%")
    info(f"  Precision : {m['precision']}%")
    info(f"  Recall    : {m['recall']}%")
    info(f"  F1 Score  : {m['f1']}%")
    info(f"  AUC-ROC   : {m['auc_roc']}%")
