from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Optional

from loglens.parsers import Event

SEV_INFO, SEV_WARN, SEV_HIGH = "info", "warn", "high"

# Defaults — all tunable from the CLI.
DEFAULTS = {
    "brute_force": {"threshold": 5, "window": 600},
    "port_scan": {"threshold": 10, "window": 600},
    "web_scan": {"threshold": 20, "window": 300},
    "error_spike": {"threshold": 15, "window": 600},
    "suspicious_paths": True,
}

SUSPICIOUS_PATH_FRAGMENTS = (
    "/.env", "/.git", "wp-login", "/xmlrpc.php", "/phpmyadmin",
    "/etc/passwd", "../", "%2e%2e", ".aws/credentials", "/.ssh",
)


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    detail: str
    ip: str = ""
    first_ts: float = 0.0
    last_ts: float = 0.0
    count: int = 0

    @property
    def icon(self) -> str:
        return {"info": "·", "warn": "!", "high": "✗"}[self.severity]


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def detect(
    events: list[Event],
    *,
    brute_threshold: int = 5,
    brute_window: int = 600,
    scan_threshold: int = 10,
    scan_window: int = 600,
    webscan_threshold: int = 20,
    webscan_window: int = 300,
    spike_threshold: int = 15,
    spike_window: int = 600,
) -> list[Finding]:
    findings: list[Finding] = []
    findings += _brute_force(events, brute_threshold, brute_window)
    findings += _user_spray(events)
    findings += _web_scan(events, webscan_threshold, webscan_window)
    findings += _error_spike(events, spike_threshold, spike_window)
    findings += _suspicious_paths(events)
    return findings


def sliding_windows(timestamps: list[float], window: float):
    """Yield (start_idx, end_idx_exclusive) of a maximal burst inside `window`."""
    if not timestamps:
        return
    start = 0
    for i in range(1, len(timestamps) + 1):
        if i == len(timestamps) or timestamps[i] - timestamps[start] > window:
            yield start, i
            start = i


def _brute_force(events, threshold, window) -> list[Finding]:
    by_key: dict[tuple[str, str], list[float]] = defaultdict(list)
    for e in events:
        if e.kind == "auth" and e.failed and e.ip:
            by_key[(e.ip, e.user)].append(e.ts)

    # Also aggregate per-IP across users: password spraying hides per-user counts.
    per_ip_all: dict[str, list[float]] = defaultdict(list)
    for (ip, user), tss in by_key.items():
        per_ip_all[ip].extend(tss)

    out: list[Finding] = []
    reported_ips: set[str] = set()
    for ip, tss in sorted(per_ip_all.items(), key=lambda kv: -len(kv[1])):
        tss.sort()
        for s, t in sliding_windows(tss, window):
            count = t - s
            if count >= threshold and ip not in reported_ips:
                users = {e.user for e in events
                         if e.kind == "auth" and e.failed and e.ip == ip}
                out.append(Finding(
                    rule="brute_force", severity=SEV_HIGH,
                    title=f"Fuerza bruta SSH desde {ip}",
                    detail=f"{count} fallos en ≤{int(window)}s · usuarios: "
                           f"{', '.join(sorted(users)) or 'desconocidos'}",
                    ip=ip, first_ts=tss[s], last_ts=tss[t - 1], count=count))
                break
        else:
            continue
    return out


def _user_spray(events) -> list[Finding]:
    """One IP failing against many distinct usernames = account enumeration."""
    threshold = 4
    by_ip_users: dict[str, set] = defaultdict(set)
    by_ip_ts: dict[str, list[float]] = defaultdict(list)
    for e in events:
        if e.kind == "auth" and e.failed and e.ip and e.user:
            by_ip_users[e.ip].add(e.user.lower())
            by_ip_ts[e.ip].append(e.ts)
    out: list[Finding] = []
    for ip, users in by_ip_users.items():
        if len(users) >= 4:
            tss = sorted(by_ip_ts[ip])
            span = tss[-1] - tss[0]
            out.append(Finding(
                rule="user_spray", severity=SEV_WARN,
                title=f"Enumeración de usuarios desde {ip}",
                detail=f"{len(users)} usuarios distintos probados en {int(span)}s",
                ip=ip, first_ts=tss[0], last_ts=tss[-1], count=len(users)))
    return out


def _web_scan(events, threshold, window) -> list[Finding]:
    by_ip: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.kind == "web" and e.failed and _is_ip(e.ip):
            by_ip[e.ip].append(e)
    out: list[Finding] = []
    for ip, evs in by_ip.items():
        evs.sort(key=lambda e: e.ts)
        tss = [e.ts for e in evs]
        best: Optional[tuple[int, int]] = None
        for s, t in sliding_windows(tss, window):
            if t - s >= (best[1] - best[0] if best else threshold):
                best = (s, t)
        if best and best[1] - best[0] >= threshold:
            paths = Counter(e.path.split("?")[0] for e in evs[best[0]:best[1]])
            top = ", ".join(f"{p}×{c}" for p, c in paths.most_common(3))
            statuses = Counter(e.status for e in evs[best[0]:best[1]])
            stat_s = " ".join(f"{s}×{c}" for s, c in sorted(statuses.items()))
            out.append(Finding(
                rule="web_scan", severity=SEV_HIGH,
                title=f"Escaneo web desde {ip}",
                detail=f"{best[1]-best[0]} respuestas 4xx en ≤{int(window)}s ({stat_s}) · {top}",
                ip=ip, first_ts=tss[best[0]], last_ts=tss[best[1] - 1],
                count=best[1] - best[0]))
    return out


def _error_spike(events, threshold, window) -> list[Finding]:
    tss = [e.ts for e in events if e.kind == "web" and e.status >= 500]
    out: list[Finding] = []
    if not tss:
        return out
    for s, t in sliding_windows(tss, window):
        if t - s >= threshold:
            out.append(Finding(
                rule="error_spike", severity=SEV_WARN,
                title=f"Pico de errores 5xx del servidor",
                detail=f"{t - s} respuestas ≥500 en ≤{int(window)}s",
                first_ts=tss[s], last_ts=tss[t - 1], count=t - s))
    return out[:3]


def _suspicious_paths(events) -> list[Finding]:
    seen: dict[str, tuple[int, float, float]] = {}
    for e in events:
        if e.kind != "web":
            continue
        low = e.path.lower()
        frag = next((f for f in SUSPICIOUS_PATH_FRAGMENTS if f in low), None)
        if not frag:
            continue
        key = f"{frag} ← {e.ip}" if e.ip else frag
        c, first, last = seen.get(key, (0, e.ts, e.ts))
        seen[key] = (c + 1, min(first, e.ts), max(last, e.ts))
    return [
        Finding(rule="suspicious_path", severity=SEV_WARN,
                title=f"Sondeo de ruta sensible: {key.rsplit('←', 1)[0].strip()}",
                detail=f"{c} peticion(es) · origen: {key.rsplit('←', 1)[-1].strip() or '?'}",
                ip=key.rsplit("←", 1)[-1].strip(), first_ts=f, last_ts=l, count=c)
        for key, (c, f, l) in sorted(seen.items(), key=lambda kv: -kv[1][0])
    ]
