"""
preprocessor.py
Shared feature normalization layer used by ALL input parsers.
Ensures every DataFrame that reaches the model has the exact same
feature columns in the exact same order as features.json.
"""

import os, json
import pandas as pd
import numpy as np

FEATURES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "features.json")

def _load_feature_cols():
    if not os.path.exists(FEATURES_PATH):
        raise FileNotFoundError(
            "features.json not found. Run train_model.py first."
        )
    with open(FEATURES_PATH) as f:
        return json.load(f)


def split_ip(df: pd.DataFrame, col: str, prefix: str) -> pd.DataFrame:
    """Split an IP-address column (dot-notation) into 4 octet columns."""
    parts = df[col].astype(str).str.split('.', expand=True)
    # Pad in case of shorter splits
    for i in range(4):
        octet_col = f"{prefix}_{i+1}"
        df[octet_col] = parts[i] if i < len(parts.columns) else 0
    return df


def preprocess(df: pd.DataFrame, flow_meta: pd.DataFrame = None) -> pd.DataFrame:
    """
    Normalize any incoming DataFrame to match model feature order.

    Parameters
    ----------
    df : DataFrame with at minimum the raw columns from a parser.
    flow_meta : Optional DataFrame with [flow_id, source_ip, dest_ip] kept
                separately for the response payload (not fed to model).

    Returns
    -------
    X : DataFrame with exactly the columns in features.json, in order.
    """
    feature_cols = _load_feature_cols()

    # --- Strip whitespace from column names ---
    df.columns = [c.strip() for c in df.columns]

    # --- If 'Source' or 'Destination' IP cols exist, split them ---
    if 'Source' in df.columns and 'SourceIP_1' not in df.columns:
        df = split_ip(df, 'Source', 'SourceIP')
        df = df.drop(columns=['Source'], errors='ignore')

    if 'Destination' in df.columns and 'DestinationIP_1' not in df.columns:
        df = split_ip(df, 'Destination', 'DestinationIP')
        df = df.drop(columns=['Destination'], errors='ignore')

    # --- Drop columns not in feature set ---
    extra_cols = [c for c in df.columns if c not in feature_cols]
    if extra_cols:
        df = df.drop(columns=extra_cols, errors='ignore')

    # --- Add any missing feature columns as 0 ---
    for col in feature_cols:
        if col not in df.columns:
            df[col] = 0

    # --- Reorder to match training feature order ---
    df = df[feature_cols]

    # --- Cast to numeric, fill NaN ---
    df = df.apply(pd.to_numeric, errors='coerce').fillna(0).astype(np.float32)

    return df
