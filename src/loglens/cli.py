from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

from loglens.detect import detect
from loglens.parsers import parse_file, parse_web_line, Event
from loglens.report import render_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="loglens",
        description="Analiza logs locales en busca de actividad sospechosa. "
                    "100%% offline: los logs no salen de tu máquina.",
        epilog="Ejemplo: loglens /var/log/auth.log --report informe.html",
    )
    parser.add_argument("logs", nargs="*", type=Path,
                        help="ficheros de log (auth.log, access.log combinado, …)")
    parser.add_argument("--kind", choices=("auto", "auth", "web"), default="auto")
    parser.add_argument("--year", type=int, default=None,
                        help="año para logs syslog sin año (por defecto: actual)")
    parser.add_argument("--report", type=Path, default=None,
                        metavar="FICHERO", help="escribe además un informe HTML")

    rules = parser.add_argument_group("umbrales de reglas")
    rules.add_argument("--brute-threshold", type=int, default=5,
                       help="fallos por IP para fuerza bruta (5)")
    rules.add_argument("--brute-window", type=int, default=600,
                       help="ventana de fuerza bruta en s (600)")
    rules.add_argument("--webscan-threshold", type=int, default=20,
                       help="4xx por IP para escaneo web (20)")
    rules.add_argument("--webscan-window", type=int, default=300)
    rules.add_argument("--spike-threshold", type=int, default=15,
                       help="errores 5xx para pico (15)")
    return parser


def read_stdin() -> list[Event]:
    events = []
    for line in sys.stdin:
        ev = None
        try:
            ev = parse_web_line(line)
            if not ev and line.strip():
                from loglens.parsers import parse_auth_line
                ev = parse_auth_line(line)
        except Exception:
            ev = None
        if ev:
            events.append(ev)
    events.sort(key=lambda e: e.ts)
    return events


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.logs:
        events: list[Event] = []
        for path in args.logs:
            if not path.exists():
                print(f"error: no existe {path}", file=sys.stderr)
                return 2
            events.extend(parse_file(path, kind=args.kind, year_hint=args.year))
    else:
        if sys.stdin.isatty():
            print("error: pasa ficheros de log o redirige stdin", file=sys.stderr)
            return 2
        events = read_stdin()

    findings = detect(
        events,
        brute_threshold=args.brute_threshold,
        brute_window=args.brute_window,
        webscan_threshold=args.webscan_threshold,
        spike_threshold=args.spike_threshold,
    )

    sev_icon = {"high": "✗", "warn": "!", "info": "·"}
    for f in sorted(findings, key=lambda f: {"high": 0, "warn": 1, "info": 2}[f.severity]):
        print(f"{sev_icon[f.severity]} [{f.severity:^4}] {f.title}")
        print(f"         {f.detail}")

    n_auth = sum(1 for e in events if e.kind == "auth")
    print(f"\n{len(events)} eventos ({n_auth} auth, {len(events)-n_auth} web) · "
          f"{len(findings)} hallazgo(s)")

    if args.report:
        out = render_report([str(p) for p in args.logs], events, findings, args.report)
        print(f"Informe HTML: {out}")

    return 1 if any(f.severity == "high" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
