# Networl-Intrusion-Detection-System-python-
# Network Intrusion Detection System (Python)

A lightweight, rule-based Network Intrusion Detection System — a from-scratch equivalent to the detection core of Snort/Suricata, built in Python with scapy for live packet capture.

## What's in this repo

| File | Description |
|------|--------------|
| rules.txt | Detection signatures (brute-force, port scans, SQLi, ICMP floods, etc.) in a simplified Snort-like syntax |
| rules.py | Parses rules.txt into rule objects |
| detector.py | Stateful detection engine — threshold tracking, port-scan tracking, signature matching |
| alerting.py | Console alerts, JSON-lines logging, and a safe (dry-run by default) response/blocking mechanism |
| nids.py | Main entry point — live capture via scapy, wired to the detector |
| generate_demo_alerts.py | Replays synthetic attacks through the real engine, for testing without live traffic |
| dashboard.py | Visualizes alerts.log as a 4-panel PNG dashboard |
| test_detector.py | Unit tests verifying detection logic correctness |

## How to run it

```bash
pip install scapy matplotlib

python test_detector.py
python generate_demo_alerts.py
python dashboard.py
python nids.py -i "Wi-Fi
