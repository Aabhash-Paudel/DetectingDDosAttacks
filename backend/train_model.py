"""
train_model.py
Replicates the exact notebook pipeline from "Detecting DDoS Attacks.ipynb":
  CSV → Feature Extraction from Flow ID → IP splitting → Sort by Timestamp
  → Drop cols → Missing value check → RandomUnderSampler → 70/30 split
  → RandomForestClassifier → model.pkl + features.json
"""

import os, json, joblib
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score, accuracy_score
from imblearn.under_sampling import RandomUnderSampler

DATASET_PATH = os.path.join(os.path.dirname(__file__), "..", "ddos_dataset.csv")
MODEL_PATH   = os.path.join(os.path.dirname(__file__), "model.pkl")
FEATURES_PATH = os.path.join(os.path.dirname(__file__), "features.json")

def train():
    print("[1/8] Loading dataset...")
    # Read Timestamp as plain string to avoid slow dateutil parsing
    df = pd.read_csv(DATASET_PATH, index_col=None, low_memory=False)
    print(f"      Shape: {df.shape}")

    print("[2/8] Extracting Source / Destination from Flow ID...")
    df[['Source', 'Destination', 'Source Port', 'Dest Port', 'Other']] = (
        df['Flow ID'].str.split('-', expand=True)
    )

    print("[3/8] Sorting by Timestamp...")
    df = df.sort_values("Timestamp")

    print("[4/8] Dropping unnecessary columns (Timestamp, ports, Other)...")
    df = df.drop(columns=["Timestamp", "Source Port", "Dest Port", "Other"])

    print("[5/8] Splitting IP addresses into octets...")
    df[['SourceIP_1', 'SourceIP_2', 'SourceIP_3', 'SourceIP_4']] = (
        df['Source'].str.split('.', expand=True)
    )
    df[['DestinationIP_1', 'DestinationIP_2', 'DestinationIP_3', 'DestinationIP_4']] = (
        df['Destination'].str.split('.', expand=True)
    )
    df = df.drop(columns=["Source", "Destination", "Flow ID"])

    print("[6/8] Checking missing values...")
    missing = df.isna().sum()
    if missing.any():
        print(f"      Missing: {missing[missing > 0].to_dict()}")
    df = df.fillna(0)

    print("[6.5/8] Label encoding (1=DDoS, 0=Benign)...")
    le = LabelEncoder()
    df['Label'] = le.fit_transform(df['Label'])
    print(f"      Classes: {dict(zip(le.classes_, le.transform(le.classes_)))}")

    print("[7/8] RandomUnderSampler to handle class imbalance...")
    #  Dataset is 80% benign / 20% DDoS → undersample benign
    X = df.drop('Label', axis=1)
    y = df['Label']
    rus = RandomUnderSampler(random_state=42)
    X_rus, y_rus = rus.fit_resample(X, y)
    print(f"      After undersampling: {pd.Series(y_rus).value_counts().to_dict()}")

    # Save ordered feature columns (used by preprocessor at inference time)
    feature_cols = list(X_rus.columns)
    with open(FEATURES_PATH, 'w') as f:
        json.dump(feature_cols, f, indent=2)
    print(f"      Feature list saved -> features.json ({len(feature_cols)} features)")

    print("[8/8] Train/test split 70/30 -> fit RandomForest...")
    X_train, X_test, y_train, y_test = train_test_split(
        X_rus, y_rus, test_size=0.3, random_state=42
    )
    # Cast to numeric
    X_train = X_train.apply(pd.to_numeric, errors='coerce').fillna(0)
    X_test  = X_test.apply(pd.to_numeric, errors='coerce').fillna(0)

    clf = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)
    clf.fit(X_train, y_train)

    # Evaluate
    y_pred  = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]
    acc     = accuracy_score(y_test, y_pred)
    roc     = roc_auc_score(y_test, y_proba)
    print(f"\n[OK] Accuracy  : {acc:.6f}")
    print(f"[OK] ROC-AUC   : {roc:.10f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Benign", "DDoS"]))

    joblib.dump(clf, MODEL_PATH)
    print(f"\n[SAVED] Model saved -> {MODEL_PATH}")

if __name__ == "__main__":
    train()
