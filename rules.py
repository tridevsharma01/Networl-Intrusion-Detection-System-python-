import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Rule:
    rule_id: int
    proto: str
    port: str
    message: str
    threshold_count: Optional[int] = None
    threshold_seconds: Optional[int] = None
    content: Optional[str] = None
    is_scan_rule: bool = False
    severity: str = field(default="Medium")

    def matches_static(self, proto, dst_port, payload_text):
        if self.proto != "ANY" and self.proto != proto:
            return False
        if self.port != "ANY" and str(dst_port) != self.port:
            return False
        if self.content:
            if not payload_text or self.content.lower() not in payload_text.lower():
                return False
        return True


_LINE_RE = re.compile(
    r'^ALERT\s+(?P<proto>TCP|UDP|ICMP|ANY)\s+(?P<port>\S+)\s+"(?P<msg>[^"]+)"(?P<rest>.*)$',
    re.IGNORECASE,
)
_THRESHOLD_RE = re.compile(r'THRESHOLD=(\d+)/(\d+)')
_CONTENT_RE = re.compile(r'CONTENT="([^"]+)"')
_SCAN_RE = re.compile(r'SCAN=true', re.IGNORECASE)
_SEVERITY_RE = re.compile(r'SEVERITY=(\w+)', re.IGNORECASE)


def parse_rules(path):
    rules = []
    with open(path, "r") as f:
        for i, raw_line in enumerate(f, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            m = _LINE_RE.match(line)
            if not m:
                raise ValueError(f"Could not parse rule on line {i}: {raw_line!r}")

            proto = m.group("proto").upper()
            port = m.group("port").upper()
            msg = m.group("msg")
            rest = m.group("rest")

            threshold_count = threshold_seconds = None
            t = _THRESHOLD_RE.search(rest)
            if t:
                threshold_count, threshold_seconds = int(t.group(1)), int(t.group(2))

            content_match = _CONTENT_RE.search(rest)
            content = content_match.group(1) if content_match else None

            is_scan = bool(_SCAN_RE.search(rest))

            sev_match = _SEVERITY_RE.search(rest)
            severity = sev_match.group(1).capitalize() if sev_match else _default_severity(is_scan, content, proto)

            rules.append(Rule(
                rule_id=len(rules) + 1,
                proto=proto,
                port=port,
                message=msg,
                threshold_count=threshold_count,
                threshold_seconds=threshold_seconds,
                content=content,
                is_scan_rule=is_scan,
                severity=severity,
            ))
    return rules


def _default_severity(is_scan, content, proto):
    if content:
        return "High"
    if is_scan:
        return "Medium"
    if proto == "ICMP":
        return "Low"
    return "Medium"