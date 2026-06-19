import json
import time
from collections import defaultdict

SEVERITY_RANK = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}

ANSI = {
    "Low": "\033[37m", "Medium": "\033[33m", "High": "\033[31m",
    "Critical": "\033[1;31m", "reset": "\033[0m",
}


class AlertManager:
    def __init__(self, log_path="alerts.log", dry_run=True,
                 auto_block_severity="Critical", block_after_repeats=3):
        self.log_path = log_path
        self.dry_run = dry_run
        self.auto_block_severity = auto_block_severity
        self.block_after_repeats = block_after_repeats
        self._repeat_counts = defaultdict(int)
        self._blocked_ips = set()

    def handle(self, alert):
        self._print_alert(alert)
        self._log_alert(alert)
        self._maybe_respond(alert)

    def _print_alert(self, alert):
        color = ANSI.get(alert.severity, "")
        reset = ANSI["reset"]
        ts = time.strftime("%H:%M:%S", time.localtime(alert.timestamp))
        port_part = f":{alert.dst_port}" if alert.dst_port else ""
        print(f"{color}[{ts}] [{alert.severity.upper():<8}] {alert.message}{reset}")
        print(f"           src={alert.src_ip} -> dst={alert.dst_ip}{port_part} "
              f"proto={alert.proto} {('(' + alert.detail + ')') if alert.detail else ''}")

    def _log_alert(self, alert):
        with open(self.log_path, "a") as f:
            f.write(json.dumps(alert.to_dict()) + "\n")

    def _maybe_respond(self, alert):
        if SEVERITY_RANK.get(alert.severity, 0) < SEVERITY_RANK.get(self.auto_block_severity, 3):
            return
        self._repeat_counts[alert.src_ip] += 1
        if self._repeat_counts[alert.src_ip] < self.block_after_repeats:
            return
        if alert.src_ip in self._blocked_ips:
            return
        self._blocked_ips.add(alert.src_ip)
        self._respond_block(alert.src_ip)

    def _respond_block(self, ip):
        cmd_windows = f'netsh advfirewall firewall add rule name="NIDS_BLOCK_{ip}" dir=in action=block remoteip={ip}'
        cmd_linux = f"sudo iptables -A INPUT -s {ip} -j DROP"
        print(f"\033[1;31m[RESPONSE] Repeated high-severity activity from {ip} — recommended action: BLOCK\033[0m")
        if self.dry_run:
            print(f"           (dry run — no firewall rule applied) Would run:")
            print(f"             Windows: {cmd_windows}")
            print(f"             Linux:   {cmd_linux}")
        else:
            import subprocess
            try:
                subprocess.run(cmd_windows, shell=True, check=True)
                print(f"           Firewall rule applied for {ip}")
            except Exception as e:
                print(f"           Failed to apply firewall rule: {e}")
        with open("blocklist.txt", "a") as f:
            f.write(f"{ip}\n")