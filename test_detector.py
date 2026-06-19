from rules import parse_rules
from detector import Detector, PacketInfo


def run_case(name, rules_path, packets, expected_min_alerts, expect_message_substr=None):
    rules = parse_rules(rules_path)
    alerts = []
    det = Detector(rules, on_alert=lambda a: alerts.append(a))
    for pkt in packets:
        det.process(pkt)
    ok = len(alerts) >= expected_min_alerts
    if expect_message_substr and ok:
        ok = any(expect_message_substr.lower() in a.message.lower() for a in alerts)
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {name}  (alerts fired: {len(alerts)})")
    for a in alerts:
        print(f"          -> {a.severity:<8} {a.message}  ({a.detail})")
    return ok


def main():
    all_ok = True
    t0 = 1000.0

    pkts = [PacketInfo("10.0.0.5", "192.168.1.10", "TCP", 22, timestamp=t0 + i) for i in range(5)]
    all_ok &= run_case("SSH brute-force (5 attempts/10s)", "rules.txt", pkts, 1, "brute-force")

    pkts = [PacketInfo("10.0.0.6", "192.168.1.10", "TCP", 22, timestamp=t0 + i) for i in range(3)]
    rules = parse_rules("rules.txt")
    alerts = []
    det = Detector(rules, on_alert=lambda a: alerts.append(a))
    for p in pkts:
        det.process(p)
    ok = len(alerts) == 0
    print(f"[{'PASS' if ok else 'FAIL'}] SSH below threshold should stay silent  (alerts fired: {len(alerts)})")
    all_ok &= ok

    pkts = [PacketInfo("10.0.0.7", "192.168.1.10", "TCP", 1000 + i, timestamp=t0 + i * 0.1) for i in range(20)]
    all_ok &= run_case("Port scan (20 ports/5s)", "rules.txt", pkts, 1, "port scan")

    pkts = [PacketInfo("10.0.0.8", "192.168.1.10", "TCP", 80,
                        payload_text="id=1 UNION SELECT username,password FROM users", timestamp=t0)]
    all_ok &= run_case("SQL injection payload signature", "rules.txt", pkts, 1, "sql injection")

    pkts = [PacketInfo("10.0.0.9", "192.168.1.10", "TCP", 23, timestamp=t0)]
    all_ok &= run_case("Telnet (insecure protocol) immediate alert", "rules.txt", pkts, 1, "telnet")

    pkts = [PacketInfo("10.0.0.10", "192.168.1.10", "ICMP", None, timestamp=t0 + i * 0.1) for i in range(25)]
    all_ok &= run_case("ICMP flood (25 pings/5s)", "rules.txt", pkts, 1, "icmp flood")

    print("\n" + ("ALL TESTS PASSED" if all_ok else "SOME TESTS FAILED"))
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())