# DDoS Shield — Real-time DDoS Attack Detection

A full-stack web application for detecting Distributed Denial of Service (DDoS) attacks using Machine Learning. Upload Wireshark PCAP files, CIC-format CSV data, or manually enter network flow features to get instant threat analysis.

![Python](https://img.shields.io/badge/Python-3.9+-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-REST%20API-green?logo=flask)
![scikit-learn](https://img.shields.io/badge/scikit--learn-RandomForest-orange?logo=scikit-learn)

---

## Features

- **3 Input Modes**: Manual feature entry, CSV upload, PCAP upload
- **Hybrid Detection**: ML model (RandomForest) + Heuristic pattern analysis
- **Real-time Dashboard**: Dark-themed UI with threat gauge, donut chart, stats
- **PCAP Analysis**: Reconstructs TCP flows from Wireshark captures using Scapy
- **CSV Analysis**: Supports CIC-format network flow CSVs (CSE-CIC-IDS2018)
- **Threat Level**: Automatic HIGH/MEDIUM/LOW classification
- **Security**: File size limits, extension validation, sanitized uploads
- **Cross-platform**: Works on Windows, Linux, and macOS

## Quick Start

### Windows
```
Double-click run.bat
```

### Linux / macOS
```bash
chmod +x run.sh
./run.sh
```

### Manual Setup
```bash
python -m venv .venv
# Linux/macOS:
. .venv/bin/activate
# Windows (PowerShell):
#   .\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python backend/train_model.py   # Train model (first time only)
python backend/app.py           # Start server
# Open http://localhost:5000
```

## Publish to GitHub

### Option A: GitHub CLI (recommended)
```bash
# from the repo root
git add .
git commit -m "Initial commit"

# login once
gh auth login

# create the repo on GitHub and push
gh repo create DetectingDDosAttacks --public --source . --remote origin --push
```

### Option B: Create repo on GitHub website (manual remote)
```bash
git add .
git commit -m "Initial commit"

# create an empty repo on GitHub, then set the remote URL:
git remote add origin https://github.com/<YOUR_USER>/<YOUR_REPO>.git
git branch -M main
git push -u origin main
```

## Clone & Run (Windows / Linux)
```bash
git clone https://github.com/<YOUR_USER>/<YOUR_REPO>.git
cd <YOUR_REPO>
```

- **Windows**: double-click `run.bat`
- **Linux/macOS**:

```bash
chmod +x run.sh
./run.sh
```

## Architecture

```
Frontend (HTML/CSS/JS)
        ↓
Flask API (app.py)  ← Security layer, model loaded once at startup
        ↓
Input Parsers
   ├── csv_parser.py       (CIC-format CSV → DataFrame)
   └── pcap_parser.py      (PCAP → TCP flow stats → DataFrame)
        ↓
preprocessor.py             (normalize columns, IP encoding, feature order)
        ↓
model.pkl (Random Forest)   +   Heuristic Detector (for packet-level attacks)
        ↓
Response: prediction + confidence + stats + threat_level
```

## Model Performance

| Metric | Score |
|---|---|
| **Accuracy** | 99.99% |
| **ROC-AUC** | 0.9999 |
| **Precision** | 1.00 |
| **Recall** | 1.00 |
| **F1-Score** | 1.00 |

Trained on the **CSE-CIC-IDS2018** dataset (500K flows, 80% benign / 20% DDoS).
Class imbalance handled with `RandomUnderSampler` → 100K balanced samples.

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Health check + model status |
| `/predict` | POST | Manual feature input → single prediction |
| `/upload-csv` | POST | CIC-format CSV → bulk predictions |
| `/upload-pcap` | POST | Wireshark .pcap/.pcapng → bulk predictions |
| `/stats` | GET | Session statistics + threat level |
| `/stats/reset` | POST | Reset session counters |

## Dataset

The dataset is a subsampled version of the **CSE-CIC-IDS2018**, **CICIDS2017**, and **CIC DoS** datasets (2017). It consists of 80% benign and 20% DDoS traffic, representing a realistic ratio of normal-to-DDoS traffic.

### Features Used (13 total)
- `Fwd Pkt Len Mean` — Mean forward packet length
- `Fwd Seg Size Avg` — Average forward segment size
- `Init Fwd Win Byts` — Initial forward window bytes
- `Init Bwd Win Byts` — Initial backward window bytes
- `Fwd Seg Size Min` — Minimum forward segment size
- `SourceIP_1..4` — Source IP octets
- `DestinationIP_1..4` — Destination IP octets

## Tech Stack

- **Backend**: Python, Flask, scikit-learn, Scapy, pandas, joblib
- **Frontend**: HTML5, CSS3 (glassmorphism dark theme), JavaScript, Chart.js
- **ML**: RandomForestClassifier + heuristic pattern detection

## PCAP Test Results

| Capture | Flows | DDoS Detected | Method |
|---|---|---|---|
| TCP Reflection SYN-ACK | 7,674 | 100% | Heuristic |
| TCP SYN Flood (spoofed) | 37,669 | 100% | Heuristic |
| CIC-format CSV | 10 | 100% | ML |

## License

This project is for educational purposes.
