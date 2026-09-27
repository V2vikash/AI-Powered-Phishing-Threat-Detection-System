"""
ML Data Preprocessing Module

Loads raw dataset, executes feature extraction using feature_extractor service,
and prepares train/test matrices for machine learning pipelines.
"""

import os
import sys
import pandas as pd
import numpy as np
from typing import Tuple, List

# Add workspace root to sys.path to allow importing backend services
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from backend.services.feature_extractor import extract_feature_vector, FEATURE_KEYS
from sklearn.model_selection import train_test_split


def load_and_preprocess_data(dataset_path: str, test_size: float = 0.2, random_state: int = 42) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, List[str]]:
    """
    Loads raw CSV dataset, extracts URL feature vectors, and returns split datasets.
    """
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset not found at {dataset_path}. Run generate_dataset.py first.")

    df = pd.read_csv(dataset_path)
    print(f"[Preprocessing] Processing {len(df)} records from {dataset_path}...")

    X_list = []
    y_list = df["label"].values

    for idx, row in df.iterrows():
        url = str(row["url"])
        feats = extract_feature_vector(url)
        X_list.append(feats)

    X = np.array(X_list, dtype=np.float64)
    y = np.array(y_list, dtype=np.int64)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )

    print(f"[Preprocessing] Data split complete: Train shape {X_train.shape}, Test shape {X_test.shape}")
    return X_train, X_test, y_train, y_test, FEATURE_KEYS


if __name__ == "__main__":
    ds_path = os.path.join(os.path.dirname(__file__), "dataset", "phishing_dataset.csv")
    if not os.path.exists(ds_path):
        from ml.dataset.generate_dataset import create_dataset
        create_dataset(ds_path)
    
    load_and_preprocess_data(ds_path)
