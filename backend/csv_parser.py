"""
csv_parser.py
Parses CIC-format CSVs (same schema as ddos_dataset.csv) and returns:
  - X : DataFrame ready for preprocessor → model
  - meta : DataFrame with [flow_id, source_ip, dest_ip] for the response
"""

import io
import pandas as pd
from preprocessor import preprocess


REQUIRED_COLS = {"Fwd Pkt Len Mean", "Fwd Seg Size Avg",
                 "Init Fwd Win Byts", "Init Bwd Win Byts", "Fwd Seg Size Min"}

FLOW_ID_COL   = "Flow ID"
TIMESTAMP_COL = "Timestamp"
LABEL_COL     = "Label"


def parse_csv(file_bytes: bytes) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Parse a CIC-format CSV file.

    Returns
    -------
    X    : preprocessed feature DataFrame
    meta : DataFrame with columns [flow_id, source_ip, dest_ip]
    """
    try:
        df = pd.read_csv(io.StringIO(file_bytes.decode("utf-8", errors="replace")))
    except Exception as e:
        raise ValueError(f"Cannot read CSV: {e}")

    if df.empty:
        raise ValueError("Uploaded CSV is empty.")

    # Strip whitespace from column names
    df.columns = [c.strip() for c in df.columns]

    # Check required feature columns exist
    missing = REQUIRED_COLS - set(df.columns)
    if missing:
        raise ValueError(
            f"CSV missing required columns: {missing}. "
            "Make sure this is a CIC-format network flow CSV."
        )

    # --- Build meta (flow identity) ---
    meta_rows = []
    if FLOW_ID_COL in df.columns:
        for _, row in df.iterrows():
            fid = row.get(FLOW_ID_COL, "")
            parts = str(fid).split("-")
            src  = parts[0] if len(parts) > 0 else ""
            dst  = parts[1] if len(parts) > 1 else ""
            meta_rows.append({"flow_id": fid, "source_ip": src, "dest_ip": dst})

        # Extract Source / Destination for IP splitting
        df[['Source', 'Destination', 'Source Port', 'Dest Port', 'Other']] = (
            df[FLOW_ID_COL].str.split('-', expand=True, n=4)
        )
    else:
        for i in range(len(df)):
            meta_rows.append({"flow_id": f"row_{i}", "source_ip": "", "dest_ip": ""})

    meta = pd.DataFrame(meta_rows)

    # Sort by Timestamp if present (mirrors notebook)
    if TIMESTAMP_COL in df.columns:
        try:
            df[TIMESTAMP_COL] = pd.to_datetime(df[TIMESTAMP_COL], errors='coerce')
            df = df.sort_values(TIMESTAMP_COL)
            meta = meta.iloc[df.index].reset_index(drop=True)
        except Exception:
            pass
        df = df.drop(columns=[TIMESTAMP_COL], errors='ignore')

    # Drop label so it doesn't bleed into features
    df = df.drop(columns=[LABEL_COL, FLOW_ID_COL, "Source Port",
                           "Dest Port", "Other"], errors='ignore')

    # Run through shared preprocessor
    X = preprocess(df)

    return X, meta
