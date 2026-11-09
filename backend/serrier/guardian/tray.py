"""Valfri tray-/menubar-klient (Design 0004, steg 2). TUNN klient ovanpå den headless kärnan
(daemonen): visar om Guardian är igång + en beslut-tally, och ger Start/Stopp/Öppna-dashboard.

Best practice (0004 §3): tray:en ÄGER aldrig daemonens livscykel och blockerar aldrig — den
bara styr och speglar. `tray_status()` är ren (ingen GUI) och testbar; `kor()` lazy-importerar
pystray/Pillow så modulen kan importeras även utan dem (de är en valfri extra: `--extra tray`).

Kräver en display för att faktiskt visas. Headless (server/WSL utan X) → kör dashboarden istället.
"""

from __future__ import annotations

import contextlib
import os
import sys
import time
import webbrowser

from serrier.db.store import Store
from serrier.guardian import daemon

_DASHBOARD = os.environ.get("SERRIER_DASHBOARD", "http://localhost:3000/guard")
_AKTIONER = ("block", "redact", "require_approval", "warn", "allow")


def tray_status() -> dict:
    """Ren statusdata för tray/menubar: igång? port? beslut-tally? Läser daemon-pid + events
    ur delade DB:n (samma som dashboarden). Inget GUI, inga nät-anrop → testbar."""
    pid = daemon.ar_igang()
    tally = dict.fromkeys(_AKTIONER, 0)
    antal = 0
    with contextlib.suppress(Exception):
        store = Store(os.environ.get("SERRIER_DB_URL", "sqlite:///serrier.db"))
        for e in store.lista_guard_events(store.dev_org(), limit=500):
            antal += 1
            if e["action"] in tally:
                tally[e["action"]] += 1
    return {"igang": pid is not None, "pid": pid, "port": daemon._port(),
            "tally": tally, "antal": antal}


def _titel(s: dict) -> str:
    if not s["igang"]:
        return "Serrier — avstängd"
    t = s["tally"]
    return f"Serrier — på · ⛔{t['block']} ✂{t['redact']} ✓{t['allow']}"


def kor() -> int:
    """Starta tray-klienten (kräver display + `--extra tray`). Blockerar tills Avsluta."""
    try:
        import pystray  # noqa: PLC0415 — valfri extra, lazy
        from PIL import Image, ImageDraw  # noqa: PLC0415
    except ImportError:
        print("serrier: tray kräver `uv sync --extra tray` och en display.")
        return 1

    def ikon(pa: bool) -> Image.Image:
        bild = Image.new("RGB", (64, 64), "white")
        d = ImageDraw.Draw(bild)
        d.ellipse((10, 10, 54, 54), fill=(16, 185, 129) if pa else (120, 120, 120))
        return bild

    def meny() -> pystray.Menu:
        s = tray_status()
        # pystray anropar callbacken med (icon, item) → alla tar (ic, it).
        return pystray.Menu(
            pystray.MenuItem(_titel(s), None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Starta skydd", lambda ic, it: daemon.up(), enabled=not s["igang"]),
            pystray.MenuItem("Stoppa skydd", lambda ic, it: daemon.down(), enabled=s["igang"]),
            pystray.MenuItem("Öppna dashboard", lambda ic, it: webbrowser.open(_DASHBOARD)),
            pystray.MenuItem("Avsluta", lambda ic, it: ic.stop()),
        )

    status = tray_status()
    app = pystray.Icon("serrier", ikon(status["igang"]), _titel(status), menu=meny())

    def uppdatera(ic: pystray.Icon) -> None:
        ic.visible = True
        while True:
            time.sleep(3)
            s = tray_status()
            ic.icon = ikon(s["igang"])
            ic.title = _titel(s)
            ic.menu = meny()
            ic.update_menu()

    app.run(setup=uppdatera)
    return 0


if __name__ == "__main__":
    sys.exit(kor())
