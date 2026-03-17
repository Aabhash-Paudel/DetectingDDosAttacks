#!/usr/bin/env bash
set -euo pipefail

echo "============================================"
echo "  DDoS Shield - Setup and Run (Linux/macOS)"
echo "============================================"
echo ""

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

# Check Python
if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is not installed."
  echo "Install Python 3.9+ and re-run."
  exit 1
fi

VENV_DIR=".venv"
PY="$VENV_DIR/bin/python"

echo "[1/4] Creating virtual environment (local)..."
if [ ! -d "$VENV_DIR" ]; then
  python3 -m venv "$VENV_DIR"
fi

echo "[2/4] Installing dependencies..."
"$PY" -m pip install --upgrade pip >/dev/null
"$PY" -m pip install -r requirements.txt

if [ ! -f "backend/model.pkl" ]; then
  echo "[3/4] Training model (first run only, may take ~30 seconds)..."
  "$PY" backend/train_model.py
else
  echo "[3/4] Model already trained, skipping."
fi

echo "[4/4] Starting DDoS Shield server..."
echo ""
echo " -----------------------------------------------"
echo "  Open your browser at: http://localhost:5000"
echo " -----------------------------------------------"
echo ""
PYTHONUNBUFFERED=1 "$PY" backend/app.py
