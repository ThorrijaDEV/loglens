from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------- events


@dataclass
class Event:
    ts: float                 # epoch seconds
    kind: str                 # "auth" | "web"
    raw: str
    ip: str = ""
    user: str = ""
    status: int = 0           # web only
    path: str = ""            # web only
    method: str = ""          # web only
    size: int = 0             # web only
    failed: bool = False      # auth failure / 4xx-5xx marker
    extra: dict = field(default_factory=dict)

    @property
    def ua(self) -> str:
        return self.extra.get("ua", "")


MONTHS = {m: i + 1 for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"))}


def _syslog_time(line: str, year_hint: Optional[int]):
    """'Aug 23 20:04:11' → epoch (assumes current year; rolls back if in future)."""
    import calendar
    import time as _t
    m = re.match(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})", line)
    if not m:
        return None
    mon, day, hh, mm, ss = MONTHS[m[1]], int(m[2]), int(m[3]), int(m[4]), int(m[5])
    year = year_hint or _t.localtime().tm_year
    epoch = calendar.timegm((year, mon, day, hh, mm, ss, 0, 0, 0))
    if year_hint is None and epoch > _t.time() + 86400 * 2:
        epoch = calendar.timegm((year - 1, mon, day, hh, mm, ss, 0, 0, 0))
    return epoch


# ------------------------------------------------------------ auth.log

_AUTH_PATTERNS = (
    # OpenSSH on Debian/Ubuntu
    (re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")
     , lambda e, m: (setattr(e, "user", m[1]), setattr(e, "ip", m[2]), setattr(e, "failed", True))),
    (re.compile(r"Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)")
     , lambda e, m: (setattr(e, "user", m[1]), setattr(e, "ip", m[2]))),
    (re.compile(r"Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)")
     , lambda e, m: (setattr(e, "user", m[1]), setattr(e, "ip", m[2]), setattr(e, "failed", True))),
    (re.compile(r"Disconnected from authenticating user (\S+) (\d+\.\d+\.\d+\.\d+)")
     , lambda e, m: (setattr(e, "user", m[1]), setattr(e, "ip", m[2]), setattr(e, "failed", True))),
    # sudo failures:  sudo: pam_unix(sudo:auth): auth failure ... user=pepe
    (re.compile(r"sudo:.+auth failure.+user=(\S+)")
     , lambda e, m: (setattr(e, "user", m[1]), setattr(e, "failed", True))),
)

AUTH_HOST_RE = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(\S+)\s")


def parse_auth_line(line: str, year_hint: Optional[int] = None) -> Optional[Event]:
    ts = _syslog_time(line, year_hint)
    if ts is None:
        return None
    ev = Event(ts=ts, kind="auth", raw=line.rstrip("\n"))
    hm = AUTH_HOST_RE.match(line)
    ev.extra["host"] = hm.group(1) if hm else ""
    for rx, apply_ in _AUTH_PATTERNS:
        m = rx.search(line)
        if m:
            apply_(ev, m)
            break
    else:
        return None  # unrelated syslog line (cron, systemd, …)
    return ev


# --------------------------------------------------- nginx/apache combined

_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<when>[^\]]+)\] "(?P<req>[^"]*)" '
    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)
_COMBINED_WHEN = re.compile(r"(\d{2})/([A-Z][a-z]{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})")
_REQ_RE = re.compile(r"(?P<method>[A-Z]+) (?P<path>\S+) HTTP/\S+")


def parse_web_line(line: str) -> Optional[Event]:
    m = _COMBINED_RE.match(line)
    if not m:
        return None
    w = _COMBINED_WHEN.match(m["when"])
    if not w:
        return None
    import calendar
    dd, mon, yy, hh, mi, ss, off = (
        int(w[1]), MONTHS[w[2]], int(w[3]), int(w[4]), int(w[5]), int(w[6]), w[7])
    epoch = calendar.timegm((yy, mon, dd, hh, mi, ss, 0, 0, 0))
    sign = 1 if off[0] == "+" else -1
    epoch -= sign * (int(off[1:3]) * 3600 + int(off[3:5]) * 60)

    req = _REQ_RE.match(m["req"])
    status = int(m["status"])
    ev = Event(
        ts=epoch, kind="web", raw=line.rstrip("\n"),
        ip=m["ip"], status=status,
        path=req["path"] if req else "",
        method=req["method"] if req else "",
        size=0 if m["size"] == "-" else int(m["size"]),
        failed=status >= 400,
        extra={"ua": m["ua"] or "", "ref": m["ref"] or ""},
    )
    return ev


# ---------------------------------------------------------------- files

def parse_file(path: Path, kind: str = "auto", year_hint: Optional[int] = None) -> list[Event]:
    events: list[Event] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                continue
            k = kind
            if k == "auto":
                k = "web" if 'HTTP/' in line and '"' in line else "auth"
            parser = parse_web_line if k == "web" else parse_auth_line
            try:
                ev = parser(line) if k == "web" else parser(line, year_hint)
            except Exception:
                continue
            if ev:
                events.append(ev)
    events.sort(key=lambda e: e.ts)
    return events
