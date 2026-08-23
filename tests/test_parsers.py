from __future__ import annotations

import time

import pytest

from loglens.parsers import Event, parse_auth_line, parse_web_line, parse_file


def syslog_now() -> str:
    return time.strftime("%b %e %H:%M:%S", time.gmtime()).replace("  ", " ")


class TestAuthParser:
    def test_failed_password(self):
        line = f"{syslog_now()} srv sshd[123]: Failed password for invalid user admin from 1.2.3.4 port 5555 ssh2"
        ev = parse_auth_line(line)
        assert ev and ev.failed and ev.user == "admin" and ev.ip == "1.2.3.4"
        assert ev.extra["host"] == "srv"

    def test_invalid_user_variant(self):
        line = f"{syslog_now()} srv sshd[9]: Invalid user oracle from 8.8.4.4 port 40022"
        ev = parse_auth_line(line)
        assert ev and ev.failed and ev.user == "oracle" and ev.ip == "8.8.4.4"

    def test_accepted_password_not_failure(self):
        line = f"{syslog_now()} srv sshd[7]: Accepted password for ana from 10.0.0.5 port 51234 ssh2"
        ev = parse_auth_line(line)
        assert ev and not ev.failed and ev.user == "ana"

    def test_sudo_failure(self):
        line = (f"{syslog_now()} srv sudo:   pepe : 3 incorrect password attempts ; "
                "TTY=pts/0 ; PWD=/home/pepe ; USER=root ; COMMAND=/bin/sh")
        # note: this format has no 'auth failure ... user=' — must NOT crash
        parse_auth_line(line)

    def test_unrelated_line_ignored(self):
        line = f"{syslog_now()} srv systemd[1]: Started Daily apt download."
        assert parse_auth_line(line) is None

    def test_year_hint(self):
        ev = parse_auth_line(
            "Jan  2 03:04:05 srv sshd[1]: Failed password for root from 1.1.1.1",
            year_hint=2020)
        assert ev is not None


COMBINED = ('203.0.113.7 - - [23/Aug/2026:20:15:30 +0200] "GET /.env HTTP/1.1" '
            '403 153 "-" "python-requests/2.31"')


class TestWebParser:
    def test_combined_format(self):
        ev = parse_web_line(COMBINED)
        assert ev and ev.ip == "203.0.113.7" and ev.status == 403
        assert ev.path == "/.env" and ev.method == "GET"
        assert ev.ua == "python-requests/2.31"
        assert ev.failed

    def test_epoch_is_utc_corrected(self):
        # 20:15:30 +0200 == 18:15:30 UTC
        ev = parse_web_line(COMBINED)
        import calendar
        expected = calendar.timegm((2026, 8, 23, 18, 15, 30, 0, 0, 0))
        assert ev.ts == expected

    def test_dash_size(self):
        line = COMBINED.replace("153", "-")
        ev = parse_web_line(line)
        assert ev.size == 0

    def test_garbage_ignored(self):
        assert parse_web_line("this is not a log") is None
        assert parse_web_line("") is None


class TestParseFile:
    def test_auto_kind_mixed(self, tmp_path):
        auth = f"{syslog_now()} s sshd[1]: Failed password for x from 1.2.3.4 port 1 ssh2\n"
        p = tmp_path / "mixed.log"
        p.write_text(auth + COMBINED + "\n")
        events = parse_file(p)
        kinds = {e.kind for e in events}
        assert kinds == {"auth", "web"}
