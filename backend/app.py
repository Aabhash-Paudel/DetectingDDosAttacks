"""
app.py - Flask REST API for DDoS Detection
=========================================
Endpoints:
  GET  /health        → {"status":"ok","model_loaded":true}
  POST /predict       → JSON features → single prediction
  POST /upload-csv    → CIC-format CSV → bulk predictions
  POST /upload-pcap   → .pcap/.pcapng → bulk predictions
  GET  /stats         → session stats (total, ddos, benign, ratio, threat_level)
"""

import os, sys, json
import numpy as np
import pandas as pd
import joblib

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename

# Resolve backend directory so local imports work when called from anywhere
BACKEND_DIR  = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BACKEND_DIR, "..", "frontend")
MODEL_PATH   = os.path.join(BACKEND_DIR, "model.pkl")
FEATURES_PATH = os.path.join(BACKEND_DIR, "features.json")

sys.path.insert(0, BACKEND_DIR)
from preprocessor import preprocess
from csv_parser   import parse_csv
from pcap_parser  import parse_pcap

# ─── Security ─────────────────────────────────────────────────────────────────
MAX_FILE_BYTES   = 10 * 1024 * 1024   # 10 MB
ALLOWED_CSV_EXT  = {".csv"}
ALLOWED_PCAP_EXT = {".pcap", ".pcapng"}
ALLOWED_ALL_EXT  = ALLOWED_CSV_EXT | ALLOWED_PCAP_EXT

# ─── App Setup ────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder=FRONTEND_DIR)
CORS(app)
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_BYTES

# ─── Load Model Once at Startup ───────────────────────────────────────────────
if not os.path.exists(MODEL_PATH):
    print("⚠  model.pkl not found. Run backend/train_model.py first.")
    model = None
else:
    model = joblib.load(MODEL_PATH)
    print("✅ Model loaded.")

with open(FEATURES_PATH) as f:
    FEATURE_COLS = json.load(f)

# ─── Session Stats (in-memory) ────────────────────────────────────────────────
session_stats = {"total": 0, "ddos": 0, "benign": 0,
                 "confidence_sum": 0.0}


def _compute_stats():
    t  = session_stats["total"]
    d  = session_stats["ddos"]
    b  = session_stats["benign"]
    cs = session_stats["confidence_sum"]
    ddos_ratio = round(d / t, 4) if t > 0 else 0.0
    avg_conf   = round(cs / t, 4) if t > 0 else 0.0
    if ddos_ratio > 0.7:
        threat = "HIGH"
    elif ddos_ratio > 0.3:
        threat = "MEDIUM"
    else:
        threat = "LOW"
    return {"total": t, "ddos": d, "benign": b,
            "ddos_ratio": ddos_ratio, "avg_confidence": avg_conf,
            "threat_level": threat}


def _make_predictions(X: pd.DataFrame, meta: pd.DataFrame):
    """Run batch prediction and update session stats. Returns list of dicts.
    Supports hybrid detection: if meta contains _heuristic_ddos column (from
    PCAP parser), flows flagged by heuristic are classified as DDoS even if
    the ML model says Benign."""
    if model is None:
        raise RuntimeError("Model not loaded. Train the model first.")

    preds   = model.predict(X)
    probas  = model.predict_proba(X)
    confs   = np.max(probas, axis=1)

    # Check for heuristic flags from PCAP parser
    has_heuristic = (meta is not None and "_heuristic_ddos" in meta.columns)

    results = []
    for i, (pred, conf) in enumerate(zip(preds, confs)):
        label = "DDoS" if pred == 1 else "Benign"
        threat_prob = float(probas[i][1])
        detection_method = "ml"

        # Heuristic override: if flagged by pattern analysis, mark as DDoS
        if has_heuristic and i < len(meta) and meta.iloc[i].get("_heuristic_ddos", False):
            if pred != 1:  # ML said Benign, but heuristic says DDoS
                label       = "DDoS"
                ml_prob_val = float(meta.iloc[i].get("_ml_ddos_prob", threat_prob))
                threat_prob = max(ml_prob_val, 0.85)  # boost confidence
                conf        = threat_prob
                detection_method = "heuristic"

        is_ddos = (label == "DDoS")
        session_stats["total"]  += 1
        session_stats["ddos"]   += int(is_ddos)
        session_stats["benign"] += int(not is_ddos)
        session_stats["confidence_sum"] += float(conf)

        row = {
            "prediction":  label,
            "confidence":  round(float(conf) * 100, 2),
            "ddos_prob":   round(threat_prob * 100, 2),
            "method":      detection_method,
        }
        if meta is not None and i < len(meta):
            row["flow_id"]   = str(meta.iloc[i].get("flow_id", f"flow_{i}"))
            row["source_ip"] = str(meta.iloc[i].get("source_ip", ""))
            row["dest_ip"]   = str(meta.iloc[i].get("dest_ip", ""))

        results.append(row)

    return results


def _secure_ext(filename: str, allowed: set) -> str:
    """Validate and return lowercase extension, or raise ValueError."""
    name = secure_filename(filename)
    ext  = os.path.splitext(name)[1].lower()
    if ext not in allowed:
        raise ValueError(
            f"File type '{ext}' not allowed. Allowed: {', '.join(sorted(allowed))}"
        )
    return ext


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the frontend SPA."""
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/style.css")
def serve_css():
    return send_from_directory(FRONTEND_DIR, "style.css")


@app.route("/app.js")
def serve_js():
    return send_from_directory(FRONTEND_DIR, "app.js")


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "model_loaded": model is not None})


@app.route("/stats", methods=["GET"])
def stats():
    return jsonify(_compute_stats())


@app.route("/stats/reset", methods=["POST"])
def reset_stats():
    session_stats.update({"total": 0, "ddos": 0, "benign": 0, "confidence_sum": 0.0})
    return jsonify({"status": "reset"})


@app.route("/predict", methods=["POST"])
def predict():
    """
    Manual single-flow prediction.
    Expects JSON with keys:
      source_ip, dest_ip,
      Fwd Pkt Len Mean, Fwd Seg Size Avg,
      Init Fwd Win Byts, Init Bwd Win Byts, Fwd Seg Size Min
    """
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400

    data = request.get_json()
    if not data:
        return jsonify({"error": "Empty request body"}), 400

    source_ip = data.pop("source_ip", "0.0.0.0")
    dest_ip   = data.pop("dest_ip",   "0.0.0.0")

    row = {k: v for k, v in data.items()}
    row["Source"]      = source_ip
    row["Destination"] = dest_ip

    try:
        df   = pd.DataFrame([row])
        X    = preprocess(df)
        meta = pd.DataFrame([{"flow_id": "manual",
                               "source_ip": source_ip,
                               "dest_ip": dest_ip}])
        results = _make_predictions(X, meta)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    return jsonify(results[0])


@app.route("/upload-csv", methods=["POST"])
def upload_csv():
    """Upload a CIC-format CSV and get bulk predictions."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided. Field name must be 'file'."}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename."}), 400

    try:
        _secure_ext(f.filename, ALLOWED_CSV_EXT)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    file_bytes = f.read()
    if not file_bytes:
        return jsonify({"error": "Uploaded file is empty."}), 400

    try:
        X, meta = parse_csv(file_bytes)
        results = _make_predictions(X, meta)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Processing error: {e}"}), 500

    return jsonify({"count": len(results), "results": results,
                    "stats": _compute_stats()})


@app.route("/upload-pcap", methods=["POST"])
def upload_pcap():
    """Upload a .pcap or .pcapng file and get bulk predictions."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided. Field name must be 'file'."}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename."}), 400

    try:
        _secure_ext(f.filename, ALLOWED_PCAP_EXT)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    file_bytes = f.read()
    if not file_bytes:
        return jsonify({"error": "Uploaded file is empty."}), 400

    try:
        X, meta = parse_pcap(file_bytes)
        results = _make_predictions(X, meta)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Processing error: {e}"}), 500

    return jsonify({"count": len(results), "results": results,
                    "stats": _compute_stats()})


# ─── Error Handlers ───────────────────────────────────────────────────────────

@app.errorhandler(413)
def file_too_large(e):
    return jsonify({"error": f"File too large. Maximum size is {MAX_FILE_BYTES // (1024*1024)} MB."}), 413


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found."}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error."}), 500


# ─── Entry Point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
