"""
models/neural_network.py — Neural Network Classifier (TensorFlow/Keras)
Author: Anveeksh Rao | github.com/anveeksh
"""
import os
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
import numpy as np
import joblib
from sklearn.metrics import (accuracy_score, precision_score,
                              recall_score, f1_score, confusion_matrix,
                              roc_auc_score)
from utils.banner import success, error, info, warn

MODEL_PATH  = "models/neural_network.keras"
SCALER_PATH = "models/scaler.pkl"

def train(X_train, y_train, X_test, y_test):
    import tensorflow as tf
    from tensorflow import keras
    from sklearn.preprocessing import StandardScaler

    info("Training Neural Network...")
    info(f"  Architecture: 30 → 128 → 64 → 32 → 1")
    info(f"  Activation  : ReLU + Sigmoid output")
    info(f"  Epochs      : 50 | Batch: 32\n")

    # Scale features
    scaler  = StandardScaler()
    X_tr_sc = scaler.fit_transform(X_train)
    X_te_sc = scaler.transform(X_test)
    joblib.dump(scaler, SCALER_PATH)

    # Build model
    model = keras.Sequential([
        keras.layers.Input(shape=(X_train.shape[1],)),
        keras.layers.Dense(128, activation="relu"),
        keras.layers.BatchNormalization(),
        keras.layers.Dropout(0.3),
        keras.layers.Dense(64, activation="relu"),
        keras.layers.BatchNormalization(),
        keras.layers.Dropout(0.2),
        keras.layers.Dense(32, activation="relu"),
        keras.layers.Dropout(0.1),
        keras.layers.Dense(1, activation="sigmoid"),
    ])

    model.compile(
        optimizer = keras.optimizers.Adam(learning_rate=0.001),
        loss      = "binary_crossentropy",
        metrics   = ["accuracy"],
    )

    callbacks = [
        keras.callbacks.EarlyStopping(
            monitor="val_loss", patience=5,
            restore_best_weights=True
        ),
        keras.callbacks.ReduceLROnPlateau(
            monitor="val_loss", factor=0.5,
            patience=3, min_lr=1e-6
        ),
    ]

    history = model.fit(
        X_tr_sc, y_train,
        validation_data = (X_te_sc, y_test),
        epochs          = 50,
        batch_size      = 32,
        callbacks       = callbacks,
        verbose         = 0,
    )

    model.save(MODEL_PATH)
    success(f"Neural Network saved → {MODEL_PATH}")

    metrics = evaluate(model, X_te_sc, y_test)
    return model, metrics, history

def evaluate(model, X_test, y_test):
    y_prob = model.predict(X_test, verbose=0).flatten()
    y_pred = (y_prob >= 0.5).astype(int)
    metrics = {
        "model"    : "Neural Network",
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
        import tensorflow as tf
        model   = tf.keras.models.load_model(MODEL_PATH)
        scaler  = joblib.load(SCALER_PATH)
        features = np.array(url_features).reshape(1, -1)
        scaled   = scaler.transform(features)
        prob     = float(model.predict(scaled, verbose=0)[0][0])
        label    = "phishing" if prob >= threshold else "legitimate"
        return label, round(prob * 100, 2)
    except Exception as e:
        error(f"Neural Network prediction failed: {e}")
        return "error", 0.0

def _print_metrics(m):
    success(f"Neural Network Results:")
    info(f"  Accuracy  : {m['accuracy']}%")
    info(f"  Precision : {m['precision']}%")
    info(f"  Recall    : {m['recall']}%")
    info(f"  F1 Score  : {m['f1']}%")
    info(f"  AUC-ROC   : {m['auc_roc']}%")
