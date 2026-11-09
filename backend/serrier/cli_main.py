"""Enhetlig Serrier-CLI. `serrier <kommando>`:

    serrier up | down | status       alltid-på Guardian (skyddar dina AI-verktyg)
    serrier run -- <kommando>        kör ETT kommando genom Guardian
    serrier scan <sökväg>            skanna ett repo lokalt (ingen server)
"""

from __future__ import annotations

import sys

from serrier import cli as scan_cli
from serrier.guardian import daemon, tray
from serrier.guardian import run as guard_run

_HJALP = (
    "serrier — AI-säkerhets-runtime\n"
    "  serrier up | down | status      alltid-på Guardian (skyddar AI-verktyg)\n"
    "  serrier tray                    tray-/menubar-klient (kräver display + --extra tray)\n"
    "  serrier run -- <kommando>       kör ett kommando genom Guardian\n"
    "  serrier scan <sökväg>           skanna ett repo lokalt\n"
)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    cmd = argv[0] if argv else ""
    if cmd in ("up", "down", "status"):
        return daemon.main([cmd])
    if cmd == "tray":
        return tray.kor()
    if cmd == "run":
        return guard_run.main(argv)          # förväntar ["run", "--", …]
    if cmd == "scan":
        return scan_cli.main(argv[1:])
    print(_HJALP, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
