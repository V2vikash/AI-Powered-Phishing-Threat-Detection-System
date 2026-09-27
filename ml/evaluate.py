"""
Model Evaluation & Diagnostic Utility

Loads trained model artifact and dataset, performs rigorous evaluation metrics,
displays confusion matrix, classification report, and top feature importances.
"""

import os
import sys
import joblib
import pandas as pd
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score

# Add workspace root to sys.path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from ml.preprocessing import load_and_preprocess_data


def evaluate_model():
    ml_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(ml_dir, "model", "phishing_model.pkl")
    dataset_path = os.path.join(ml_dir, "dataset", "phishing_dataset.csv")

    if not os.path.exists(model_path):
        print(f"[Evaluation] Model artifact missing at {model_path}. Training first...")
        from ml.train import train_model
        train_model()

    print(f"[Evaluation] Loading model artifact from {model_path}...")
    artifact = joblib.load(model_path)
    model = artifact["model"]
    feature_names = artifact["feature_names"]

    X_train, X_test, y_train, y_test, _ = load_and_preprocess_data(dataset_path)

    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    print("\n" + "="*50)
    print("      MODEL EVALUATION & METRICS REPORT      ")
    print("="*50)
    print(f"Accuracy  : {acc * 100:.2f}%")
    print(f"Precision : {prec * 100:.2f}%")
    print(f"Recall    : {rec * 100:.2f}%")
    print(f"F1-Score  : {f1 * 100:.2f}%")
    print("-" * 50)
    print("Confusion Matrix:")
    print(f"  True Negatives  (Legitimate as Legitimate) : {tn}")
    print(f"  False Positives (Legitimate as Phishing)   : {fp}")
    print(f"  False Negatives (Phishing as Legitimate)   : {fn}")
    print(f"  True Positives  (Phishing as Phishing)     : {tp}")
    print("-" * 50)
    print("Detailed Classification Report:\n")
    print(classification_report(y_test, y_pred, target_names=["Legitimate (0)", "Phishing (1)"]))

    # Feature Importances
    if hasattr(model, "feature_importances_"):
        importances = model.feature_importances_
        indices = np.argsort(importances)[::-1]
        print("-" * 50)
        print("Top 10 Feature Importances:")
        for idx in range(min(10, len(feature_names))):
            feat_idx = indices[idx]
            print(f"  {idx+1:2d}. {feature_names[feat_idx]:<25} : {importances[feat_idx]:.4f}")
    print("="*50 + "\n")


if __name__ == "__main__":
    evaluate_model()
