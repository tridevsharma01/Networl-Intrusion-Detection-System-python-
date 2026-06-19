import json
import sys
from collections import Counter
from datetime import datetime

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

SEVERITY_COLORS = {"Low": "#8FA3C4", "Medium": "#F2C14E", "High": "#F0A05A", "Critical": "#E63946"}
SEVERITY_ORDER = ["Low", "Medium", "High", "Critical"]


def load_alerts(path="alerts.log"):
    alerts = []
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    alerts.append(json.loads(line))
    except FileNotFoundError:
        print(f"No alert log found at '{path}'. Run nids.py or generate_demo_alerts.py first.")
        sys.exit(1)
    return alerts


def build_dashboard(alerts, out_path="nids_dashboard.png"):
    if not alerts:
        print("alerts.log is empty — nothing to visualize.")
        return

    severity_counts = Counter(a["severity"] for a in alerts)
    message_counts = Counter(a["message"] for a in alerts)
    src_ip_counts = Counter(a["src_ip"] for a in alerts)
    times = sorted(a["timestamp"] for a in alerts)

    fig = plt.figure(figsize=(13, 8))
    fig.suptitle("NIDS Detection Dashboard", fontsize=18, fontweight="bold", color="#1B2A4A")

    ax1 = fig.add_subplot(2, 2, 1)
    sevs = [s for s in SEVERITY_ORDER if s in severity_counts]
    counts = [severity_counts[s] for s in sevs]
    colors = [SEVERITY_COLORS[s] for s in sevs]
    ax1.bar(sevs, counts, color=colors)
    ax1.set_title("Alerts by Severity")
    ax1.set_ylabel("Count")
    for i, c in enumerate(counts):
        ax1.text(i, c + 0.05, str(c), ha="center", fontweight="bold")

    ax2 = fig.add_subplot(2, 2, 2)
    top_messages = message_counts.most_common(6)
    labels = [m[:35] + ("…" if len(m) > 35 else "") for m, _ in top_messages]
    values = [c for _, c in top_messages]
    ax2.barh(labels[::-1], values[::-1], color="#1B2A4A")
    ax2.set_title("Top Alert Types")
    ax2.set_xlabel("Count")

    ax3 = fig.add_subplot(2, 2, 3)
    dt_times = [datetime.fromtimestamp(t) for t in times]
    ax3.plot(dt_times, range(1, len(dt_times) + 1), marker="o", color="#E63946", linewidth=1.5)
    ax3.set_title("Cumulative Alerts Over Time")
    ax3.set_ylabel("Total alerts")
    fig.autofmt_xdate()

    ax4 = fig.add_subplot(2, 2, 4)
    top_ips = src_ip_counts.most_common(6)
    ip_labels = [ip for ip, _ in top_ips]
    ip_values = [c for _, c in top_ips]
    ax4.bar(ip_labels, ip_values, color="#5C6B82")
    ax4.set_title("Top Source IPs by Alert Count")
    ax4.set_ylabel("Alerts")
    ax4.tick_params(axis="x", rotation=30)

    plt.tight_layout(rect=[0, 0, 1, 0.96])
    plt.savefig(out_path, dpi=150)
    print(f"Dashboard saved to {out_path}")

    print("\nSummary")
    print("=" * 50)
    print(f"Total alerts: {len(alerts)}")
    for s in SEVERITY_ORDER:
        if s in severity_counts:
            print(f"  {s:<8}: {severity_counts[s]}")
    print(f"\nTop source IPs:")
    for ip, c in top_ips:
        print(f"  {ip:<16} {c} alert(s)")


if __name__ == "__main__":
    alerts = load_alerts()
    build_dashboard(alerts)