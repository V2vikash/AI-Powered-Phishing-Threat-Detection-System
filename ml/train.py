"""
ML Model Training Pipeline

Trains a Random Forest Classifier on extracted URL features, evaluates performance,
and serializes the trained model artifact to backend/models/ and ml/model/.
"""

import os
import sys
import joblib
import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

# Add workspace root to sys.path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from ml.preprocessing import load_and_preprocess_data
from ml.dataset.generate_dataset import create_dataset


def train_model() -> str:
    ml_dir = os.path.dirname(os.path.abspath(__file__))
    dataset_path = os.path.join(ml_dir, "dataset", "phishing_dataset.csv")

    # Generate dataset if missing
    if not os.path.exists(dataset_path):
        print("[Train Pipeline] Dataset missing. Generating new dataset...")
        create_dataset(dataset_path, count_per_class=1500)

    X_train, X_test, y_train, y_test, feature_names = load_and_preprocess_data(dataset_path)

    print("[Train Pipeline] Training Random Forest Classifier...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        min_samples_split=5,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)

    # Evaluate on test split
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    print("\n--- Training Results ---")
    print(f"Accuracy : {accuracy * 100:.2f}%")
    print(f"Precision: {precision * 100:.2f}%")
    print(f"Recall   : {recall * 100:.2f}%")
    print(f"F1-Score : {f1 * 100:.2f}%\n")

    # Save artifact containing model and metadata
    artifact = {
        "model": model,
        "feature_names": feature_names,
        "trained_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "metrics": {
            "accuracy": round(float(accuracy), 4),
            "precision": round(float(precision), 4),
            "recall": round(float(recall), 4),
            "f1_score": round(float(f1), 4)
        }
    }

    backend_model_dir = os.path.join(ROOT_DIR, "backend", "models")
    ml_model_dir = os.path.join(ml_dir, "model")
    os.makedirs(backend_model_dir, exist_ok=True)
    os.makedirs(ml_model_dir, exist_ok=True)

    backend_target = os.path.join(backend_model_dir, "phishing_model.pkl")
    ml_target = os.path.join(ml_model_dir, "phishing_model.pkl")

    joblib.dump(artifact, backend_target)
    joblib.dump(artifact, ml_target)

    print(f"[Train Pipeline] Model artifact successfully saved to:")
    print(f"  - {backend_target}")
    print(f"  - {ml_target}")

    return backend_target


if __name__ == "__main__":
    train_model()
