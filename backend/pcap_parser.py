"""
pcap_parser.py
Parses .pcap / .pcapng files using Scapy.
Reconstructs TCP flows and computes CIC-compatible flow-level features.

Uses a HYBRID approach:
  1. ML model prediction (RandomForest on CIC features) — works best for
     application-layer DDoS (HTTP floods, Slowloris, etc.)
  2. Heuristic pattern detection — catches packet-layer DDoS (SYN floods,
     amplification, reflection) which the CIC model may miss

The final prediction per flow is: DDoS if EITHER detector flags it.
"""

import tempfile, os
import pandas as pd
import numpy as np
from collections import defaultdict, Counter

try:
    from scapy.all import rdpcap, TCP, IP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from preprocessor import preprocess


def _flow_key(pkt):
    return (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)


def _reverse_key(key):
    src, dst, sp, dp = key
    return (dst, src, dp, sp)


def _heuristic_detect(flows, meta_rows):
    """
    Heuristic DDoS detection for packet-level attacks.
    Returns a boolean array: True = likely DDoS per flow.

    Heuristics:
    - Many unique source IPs targeting same destination  → DDoS
    - Flows with only SYN packets (no payload)           → SYN flood
    - Flows with only 1-2 packets (no handshake)         → Flood
    - High concentration to single dest port             → Targeted attack
    """
    n = len(meta_rows)
    scores = np.zeros(n)

    # Count destination IPs and ports
    dst_counter = Counter()
    dst_port_counter = Counter()
    for m in meta_rows:
        dst_counter[m["dest_ip"]] += 1
        parts = m["flow_id"].split("-")
        if len(parts) >= 4:
            dst_port_counter[parts[2]] += 1  # dst port

    # Check patterns per flow
    for i, (canon, pkts_list) in enumerate(flows.items()):
        src_ip, dst_ip, sport, dport = canon

        n_pkts     = len(pkts_list)
        fwd_pkts   = [p for p in pkts_list if p[0]]
        bwd_pkts   = [p for p in pkts_list if not p[0]]
        fwd_payloads = [p[2] for p in pkts_list if p[0]]  # tcp payload sizes

        # 1. Many sources → same dest (amplification/reflection)
        if dst_counter[dst_ip] > 50:
            scores[i] += 3.0

        # 2. Single-packet or few-packet flows (no handshake = flood)
        if n_pkts <= 2:
            scores[i] += 1.0

        # 3. No TCP payload (SYN flood, SYN-ACK reflection)
        if all(p == 0 for p in fwd_payloads):
            scores[i] += 1.5

        # 4. Only one direction (unidirectional = typical flood)
        if len(bwd_pkts) == 0 or len(fwd_pkts) == 0:
            scores[i] += 1.0

        # 5. All SYN or SYN-ACK flags (flood pattern)
        flags_list = [p[3] for p in pkts_list]
        syn_count = sum(1 for f in flags_list if (f & 0x02))
        if syn_count == n_pkts:
            scores[i] += 2.0

        # 6. High dest port concentration
        if dst_port_counter.get(str(dport), 0) > 100:
            scores[i] += 1.0

    # Score > 3.0 → likely DDoS
    return scores >= 3.0


def parse_pcap(file_bytes: bytes) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Parse PCAP/PCAPNG → per-flow CIC features + heuristic detection.
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy is not installed. Install with: pip install scapy")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name

    try:
        pkts = rdpcap(tmp_path)
    except Exception as e:
        raise ValueError(f"Cannot read PCAP file: {e}")
    finally:
        os.unlink(tmp_path)

    if not pkts:
        raise ValueError("PCAP file contains no packets.")

    tcp_pkts = [p for p in pkts if p.haslayer(IP) and p.haslayer(TCP)]
    if not tcp_pkts:
        raise ValueError("No TCP/IP packets found in the PCAP file.")

    # ── Reconstruct flows ─────────────────────────────────────────
    flows      = defaultdict(list)
    flow_first = {}
    seen_keys  = {}

    for pkt in tcp_pkts:
        try:
            key = _flow_key(pkt)
            rev = _reverse_key(key)

            if key in seen_keys:
                canon  = seen_keys[key]
                is_fwd = (canon == key)
            elif rev in seen_keys:
                canon  = seen_keys[rev]
                is_fwd = False
            else:
                canon = key
                seen_keys[key] = canon
                is_fwd = True

            ip_payload  = len(pkt[IP].payload)
            tcp_payload = len(pkt[TCP].payload)
            flags       = pkt[TCP].flags
            window      = pkt[TCP].window

            flows[canon].append((is_fwd, ip_payload, tcp_payload, int(flags), window))

            if canon not in flow_first:
                flow_first[canon] = {"init_fwd_win": -1, "init_bwd_win": -1}

            fi = flow_first[canon]
            if is_fwd and fi["init_fwd_win"] == -1 and (int(flags) & 0x02):
                fi["init_fwd_win"] = window
            if not is_fwd and fi["init_bwd_win"] == -1 and (int(flags) & 0x12) == 0x12:
                fi["init_bwd_win"] = window
        except Exception:
            continue

    if not flows:
        raise ValueError("No identifiable TCP flows in the PCAP file.")

    # ── Build feature rows (original + swapped direction) ─────────
    rows_orig = []
    rows_swap = []
    meta_rows = []

    for canon, pkts_list in flows.items():
        src_ip, dst_ip, sport, dport = canon
        flow_id = f"{src_ip}-{dst_ip}-{sport}-{dport}"

        fwd_ip_lens  = [il for (fwd, il, _, _, _) in pkts_list if fwd]
        fwd_tcp_lens = [tl for (fwd, _, tl, _, _) in pkts_list if fwd]

        fi = flow_first.get(canon, {"init_fwd_win": -1, "init_bwd_win": -1})
        fwd_pkt_mean = float(pd.Series(fwd_ip_lens).mean())  if fwd_ip_lens  else 0.0
        fwd_seg_avg  = float(pd.Series(fwd_tcp_lens).mean()) if fwd_tcp_lens else 0.0
        fwd_seg_min  = float(min(fwd_tcp_lens))              if fwd_tcp_lens else 0.0
        init_fwd     = fi["init_fwd_win"]
        init_bwd     = fi["init_bwd_win"]

        rows_orig.append({
            "Source": src_ip, "Destination": dst_ip,
            "Fwd Pkt Len Mean": fwd_pkt_mean, "Fwd Seg Size Avg": fwd_seg_avg,
            "Init Fwd Win Byts": init_fwd, "Init Bwd Win Byts": init_bwd,
            "Fwd Seg Size Min": fwd_seg_min,
        })
        rows_swap.append({
            "Source": dst_ip, "Destination": src_ip,
            "Fwd Pkt Len Mean": fwd_pkt_mean, "Fwd Seg Size Avg": fwd_seg_avg,
            "Init Fwd Win Byts": init_bwd, "Init Bwd Win Byts": init_fwd,
            "Fwd Seg Size Min": fwd_seg_min,
        })
        meta_rows.append({"flow_id": flow_id, "source_ip": src_ip, "dest_ip": dst_ip})

    # ── Batch ML prediction (both directions) ────────────────────
    import joblib, json
    model_path    = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model.pkl")
    model = joblib.load(model_path)

    X_orig = preprocess(pd.DataFrame(rows_orig))
    X_swap = preprocess(pd.DataFrame(rows_swap))

    prob_orig = model.predict_proba(X_orig)[:, 1]
    prob_swap = model.predict_proba(X_swap)[:, 1]

    # Best ML probability per flow
    ml_prob = np.maximum(prob_orig, prob_swap)

    # ── Heuristic detection ──────────────────────────────────────
    heuristic_ddos = _heuristic_detect(flows, meta_rows)

    # ── Combine: pick best direction features, boost with heuristic ──
    use_swap = prob_swap > prob_orig
    final_rows = []
    for i in range(len(rows_orig)):
        final_rows.append(rows_swap[i] if use_swap[i] else rows_orig[i])

    meta = pd.DataFrame(meta_rows)
    X = preprocess(pd.DataFrame(final_rows))

    # Store heuristic flags so app.py can use the hybrid result
    meta["_heuristic_ddos"] = heuristic_ddos
    meta["_ml_ddos_prob"]   = ml_prob

    return X, meta
