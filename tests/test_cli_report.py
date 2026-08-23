from __future__ import annotations

import time
from pathlib import Path

from loglens.cli import main
from loglens.parsers import Event
from loglens.report import render_report
from loglens.detect import Finding


def write_auth_log(path: Path, n=8):
    now = time.gmtime()
    stamp = time.strftime("%b %e %H:%M:%S", now).replace("  ", " ")
    lines = [
        f"{stamp} srv sshd[{100+i}]: Failed password for invalid user admin from 9.9.9.9 port {5000+i} ssh2"
        for i in range(n)
    ]
    path.write_text("\n".join(lines) + "\n")


class TestCli:
    def test_brute_force_exit_code_and_output(self, tmp_path, capsys):
        log = tmp_path / "auth.log"
        write_auth_log(log)
        rc = main([str(log)])
        out = capsys.readouterr().out
        assert rc == 1
        assert "Fuerza bruta" in out and "9.9.9.9" in out

    def test_clean_log_exits_zero(self, tmp_path, capsys):
        log = tmp_path / "clean.log"
        log.write_text("")
        assert main([str(log)]) == 0

    def test_missing_file_error(self, capsys):
        assert main(["/nonexistent/x.log"]) == 2
        err = capsys.readouterr().err
        assert "no existe" in err

    def test_report_written(self, tmp_path, capsys):
        log = tmp_path / "auth.log"
        write_auth_log(log)
        rep = tmp_path / "out.html"
        main([str(log), "--report", str(rep)], )
        assert rep.exists()
        html_text = rep.read_text()
        assert "Fuerza bruta" in html_text and "<!DOCTYPE html>" in html_text


class TestReport:
    def _events_findings(self):
        evs = [
            Event(ts=1755000000, kind="web", raw="", ip="1.1.1.1",
                  status=404, path="/.env", method="GET", failed=True),
            Event(ts=1755000100, kind="auth", raw="", ip="2.2.2.2",
                  user="root", failed=True),
        ]
        finds = [Finding("brute_force", "high", "Fuerza bruta SSH desde 2.2.2.2",
                         "5 fallos en ≤600s", ip="2.2.2.2",
                         first_ts=1755000100, last_ts=1755000100, count=5)]
        return evs, finds

    def test_renders_sections(self, tmp_path):
        evs, finds = self._events_findings()
        out = render_report(["a.log"], evs, finds, tmp_path / "r.html")
        text = out.read_text()
        for frag in ("Hallazgos", "Línea temporal", "Fuerza bruta",
                     "/.env", "404"):
            assert frag in text

    def test_empty_report_valid(self, tmp_path):
        out = render_report([], [], [], tmp_path / "e.html")
        text = out.read_text()
        assert text.startswith("<!DOCTYPE html>") and "Sin actividad sospechosa" in text
