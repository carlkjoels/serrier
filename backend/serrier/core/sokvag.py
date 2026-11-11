"""Sökvägs-confinement (B) — håll skanningar inom en konfigurerad workspace-rot.

Hotet: en scan-begäran med godtycklig sökväg (``/etc``, ``../../hemligt``, eller en
symlänk som *pekar* ut ur workspace) läser filer utanför det tänkta arbetsområdet.

Försvaret är **kanonisk, symlänk-medveten** upplösning: vi löser upp både roten och
kandidaten med ``os.path.realpath`` (följer symlänkar hela vägen) och kräver att den
upplösta kandidaten ligger *under* den upplösta roten. Det stoppar både ``..``-traversal
och symlänk-escape, och prefix-förväxling (``/a/workspace-evil`` vs ``/a/workspace``)
eftersom vi jämför på sökvägs-komponentnivå, inte som strängprefix.

Confinement gäller bara när ``SERRIER_WORKSPACE_ROOT`` är satt. Är den osatt (dev) finns
ingen rot att begränsa mot — det dokumenteras som ett medvetet dev-läge, inte som ett
tyst "allt tillåtet som såg säkert ut".
"""

from __future__ import annotations

import os
from pathlib import Path

ENV_ROT = "SERRIER_WORKSPACE_ROOT"


def _kanonisk(p: str | os.PathLike[str]) -> Path:
    # realpath följer symlänkar och normaliserar .. / . — detta är confinementens kärna.
    return Path(os.path.realpath(p))


def inom_roten(kandidat: str | os.PathLike[str], rot: str | os.PathLike[str]) -> bool:
    """True om ``kandidat`` (symlänk-upplöst) ligger under ``rot`` (symlänk-upplöst).

    Komponentvis jämförelse via ``Path.is_relative_to`` — ``/a/workspace-evil`` räknas
    alltså INTE som under ``/a/workspace`` (ingen strängprefix-förväxling). Roten själv
    räknas som inom (``is_relative_to`` är reflexiv)."""
    kkan = _kanonisk(kandidat)
    rkan = _kanonisk(rot)
    return kkan == rkan or kkan.is_relative_to(rkan)


def workspace_rot() -> Path | None:
    """Den konfigurerade roten (kanonisk) eller None om confinement är avstängt (dev)."""
    rå = os.environ.get(ENV_ROT)
    return _kanonisk(rå) if rå and rå.strip() else None


class UtanforWorkspace(Exception):
    """Höjs när en sökväg ligger utanför den konfigurerade workspace-roten."""


def validera_scan_sokvag(sokvag: str | os.PathLike[str]) -> Path:
    """Returnera en säker, kanonisk sökväg att skanna — eller höj ``UtanforWorkspace``.

    Enforcas vid *både* API-gränsen och scannergränsen (defense in depth): även om en
    framtida anropsväg missar API-kontrollen stoppas den här."""
    rot = workspace_rot()
    kkan = _kanonisk(sokvag)
    if rot is not None and not inom_roten(kkan, rot):
        raise UtanforWorkspace(
            f"sökvägen ligger utanför workspace-roten ({ENV_ROT})")
    return kkan
