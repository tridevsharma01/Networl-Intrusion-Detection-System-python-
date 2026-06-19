import time
from collections import defaultdict, deque


class PacketInfo:
    _slots_ = ("timestamp", "src_ip", "dst_ip", "proto", "dst_port", "payload_text")

    def __init__(self, src_ip, dst_ip, proto, dst_port, payload_text="", timestamp=None):
        self.timestamp = timestamp if timestamp is not None else time.time()
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.proto = proto.upper()
        self.dst_port = dst_port
        self.payload_text = payload_text or ""


class Alert:
    def __init__(self, rule, pkt, detail=""):
        self.rule = rule
        self.timestamp = pkt.timestamp
        self.src_ip = pkt.src_ip
        self.dst_ip = pkt.dst_ip
        self.proto = pkt.proto
        self.dst_port = pkt.dst_port
        self.message = rule.message
        self.severity = rule.severity
        self.detail = detail

    def to_dict(self):
        return {
            "timestamp": self.timestamp, "src_ip": self.src_ip, "dst_ip": self.dst_ip,
            "proto": self.proto, "dst_port": self.dst_port, "message": self.message,
            "severity": self.severity, "rule_id": self.rule.rule_id, "detail": self.detail,
        }


class Detector:
    def __init__(self, rules, on_alert=None):
        self.rules = rules
        self.on_alert = on_alert
        self._hit_windows = defaultdict(deque)
        self._scan_ports = defaultdict(dict)
        self._armed = defaultdict(lambda: True)

    def process(self, pkt: PacketInfo):
        fired = []
        for rule in self.rules:
            if not rule.matches_static(pkt.proto, pkt.dst_port, pkt.payload_text):
                continue
            if rule.is_scan_rule:
                alert = self._check_scan(rule, pkt)
            elif rule.threshold_count:
                alert = self._check_threshold(rule, pkt)
            else:
                alert = Alert(rule, pkt)
            if alert:
                fired.append(alert)
                if self.on_alert:
                    self.on_alert(alert)
        return fired

    def _check_threshold(self, rule, pkt):
        key = (rule.rule_id, pkt.src_ip)
        window = self._hit_windows[key]
        window.append(pkt.timestamp)
        cutoff = pkt.timestamp - rule.threshold_seconds
        while window and window[0] < cutoff:
            window.popleft()
        if len(window) >= rule.threshold_count:
            if self._armed[key]:
                self._armed[key] = False
                return Alert(rule, pkt, detail=f"{len(window)} hits in {rule.threshold_seconds}s")
            return None
        else:
            self._armed[key] = True
            return None

    def _check_scan(self, rule, pkt):
        key = (rule.rule_id, pkt.src_ip)
        ports = self._scan_ports[key]
        ports[pkt.dst_port] = pkt.timestamp
        cutoff = pkt.timestamp - rule.threshold_seconds
        for p in [p for p, ts in ports.items() if ts < cutoff]:
            del ports[p]
        if len(ports) >= rule.threshold_count:
            if self._armed[key]:
                self._armed[key] = False
                return Alert(rule, pkt, detail=f"{len(ports)} distinct ports in {rule.threshold_seconds}s")
            return None
        else:
            self._armed[key] = True
            return None