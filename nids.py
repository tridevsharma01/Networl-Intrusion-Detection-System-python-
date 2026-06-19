import argparse
import sys

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

from rules import parse_rules
from detector import Detector, PacketInfo
from alerting import AlertManager


def packet_to_info(pkt):
    if not pkt.haslayer(IP):
        return None
    ip = pkt[IP]
    if pkt.haslayer(TCP):
        proto, dport = "TCP", pkt[TCP].dport
    elif pkt.haslayer(UDP):
        proto, dport = "UDP", pkt[UDP].dport
    elif pkt.haslayer(ICMP):
        proto, dport = "ICMP", None
    else:
        return None
    payload_text = ""
    if pkt.haslayer(Raw):
        try:
            payload_text = bytes(pkt[Raw].load).decode("utf-8", errors="ignore")
        except Exception:
            payload_text = ""
    return PacketInfo(src_ip=ip.src, dst_ip=ip.dst, proto=proto, dst_port=dport, payload_text=payload_text)


def main():
    ap = argparse.ArgumentParser(description="Lightweight rule-based NIDS")
    ap.add_argument("-i", "--interface", default=None)
    ap.add_argument("--rules", default="rules.txt")
    ap.add_argument("--log", default="alerts.log")
    ap.add_argument("--block", action="store_true")
    ap.add_argument("--block-after", type=int, default=3)
    args = ap.parse_args()

    try:
        rules = parse_rules(args.rules)
    except Exception as e:
        print(f"Failed to load rules from {args.rules}: {e}")
        sys.exit(1)

    print(f"Loaded {len(rules)} detection rules from {args.rules}")
    print("Dry-run mode" if not args.block else "WARNING: --block enabled")

    mgr = AlertManager(log_path=args.log, dry_run=not args.block, block_after_repeats=args.block_after)
    detector = Detector(rules, on_alert=mgr.handle)

    def on_packet(pkt):
        info = packet_to_info(pkt)
        if info:
            detector.process(info)

    print(f"Starting capture on interface: {args.interface or 'default'} — Ctrl+C to stop\n")
    try:
        sniff(iface=args.interface, prn=on_packet, store=False)
    except PermissionError:
        print("\nPermission denied — run as Administrator/root.")
    except KeyboardInterrupt:
        print("\nCapture stopped.")


if __name__ == "__main__":
    main()