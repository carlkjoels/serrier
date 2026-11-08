"""Guardian-detektion & klassificering (Design 0001, steg 2). Lägger konservativ PII +
entropi ovanpå den delade hemlighets-kärnan (core/textdetect), och mappar varje träff till
en sensitivitetsnivå som policy-motorn (steg 3) fattar beslut på.

Konservativt med flit: kortnummer och personnummer Luhn-valideras så att slumpmässiga
sifferföljder inte flaggas (låg FPR). All detektion är LOKAL och deterministisk — rå text
lämnar aldrig maskinen. Resultatens råa träff (`Traff.text`) måste redakteras av anroparen.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
from collections import Counter
from dataclasses import replace
from enum import IntEnum

from serrier.core.findings import Category, Confidence, Severity
from serrier.core.textdetect import HEMLIGHETER, Monster, Traff, ar_placeholder, detektera_rad


class Sensitivity(IntEnum):
    """Hur känslig en träff är — grunden för policy-beslut. Härleds deterministiskt."""
    low = 1
    medium = 2
    high = 3
    critical = 4


# --- validatorer ----------------------------------------------------------
def _siffror(s: str) -> str:
    return re.sub(r"\D", "", s)


def luhn(nummer: str) -> bool:
    """Luhn-checksumma (kortnummer, svenska personnummer). Tom/kort → False."""
    d = [int(c) for c in _siffror(nummer)]
    if len(d) < 2:  # noqa: PLR2004 — minst två siffror för en checksumma
        return False
    summa = 0
    for i, siffra in enumerate(reversed(d)):
        v = siffra * 2 if i % 2 == 1 else siffra
        summa += v - 9 if v > 9 else v                # noqa: PLR2004 — Luhn: subtrahera 9
    return summa % 10 == 0


_PNR_MED_SEKEL = 12         # YYYYMMDDXXXX
_PNR_SIFFROR = 10          # YYMMDDXXXX (Luhn beräknas på dessa)


def _giltigt_personnummer(s: str) -> bool:
    """Svenskt personnummer: Luhn på de 10 signifikanta siffrorna (utan sekel)."""
    d = _siffror(s)
    if len(d) == _PNR_MED_SEKEL:        # droppa sekel
        d = d[2:]
    return len(d) == _PNR_SIFFROR and luhn(d)


# --- PII-mönster (komponeras över samma motor som hemligheter) ------------
PII: list[Monster] = [
    Monster("email", Category.pii, Severity.medium, Confidence.probable,
            re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    Monster("credit-card", Category.pii, Severity.high, Confidence.probable,
            re.compile(r"\b\d(?:[ \-]?\d){12,18}\b"), validator=luhn),
    Monster("swedish-personnummer", Category.pii, Severity.high, Confidence.probable,
            re.compile(r"\b(?:\d{2})?\d{6}[-+]?\d{4}\b"), validator=_giltigt_personnummer),
    Monster("internal-ip", Category.config, Severity.low, Confidence.probable,
            re.compile(r"\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}"
                       r"|192\.168\.\d{1,3}\.\d{1,3}"
                       r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b")),
]

_ALLA: list[Monster] = [*HEMLIGHETER, *PII]

# severity → sensitivitet (deterministiskt; hemligheter är redan critical/high).
_SENS: dict[Severity, Sensitivity] = {
    Severity.critical: Sensitivity.critical, Severity.high: Sensitivity.high,
    Severity.medium: Sensitivity.medium, Severity.low: Sensitivity.low,
    Severity.info: Sensitivity.low,
}


def sensitivitet(t: Traff) -> Sensitivity:
    return _SENS[t.severity]


# --- entropi (fångar hög-entropi-tokens specifika mönster missar) ----------
_TOKEN = re.compile(r"\S{20,}")
_ENTROPITRÖSKEL = 3.5          # bits/tecken — konservativt


def shannon(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


_MIN_TECKENKLASSER = 2


def _diversitet(tok: str) -> bool:
    """Minst två teckenklasser (gemener/versaler/siffror) → ser ut som en nyckel, inte
    ett ord eller en sifferföljd."""
    klasser = sum(bool(re.search(p, tok)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]"))
    return klasser >= _MIN_TECKENKLASSER


def _entropi_traffar(rad: str, klamda: list[tuple[int, int]]) -> list[Traff]:
    ut: list[Traff] = []
    for m in _TOKEN.finditer(rad):
        s, e = m.span()
        tok = m.group(0)
        if any(s < ce and cs < e for cs, ce in klamda):
            continue                              # redan fångad av ett mönster
        if ar_placeholder(tok) or not _diversitet(tok) or shannon(tok) < _ENTROPITRÖSKEL:
            continue
        ut.append(Traff("high-entropy-token", Category.secret, Severity.medium,
                        Confidence.heuristic, s, e, tok))
    return ut


# --- normalisering & evasion-motståndskraft (steg 5) ----------------------
_ZEROWIDTH = "\u200b‌‍⁠﻿"
# Vanliga homoglyfer (kyrilliska/grekiska/fullbredd) → ascii. 1:1 så offsets bevaras.
_HOMOGLYFER = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i",
    "ѕ": "s", "ԁ": "d", "ο": "o", "ⅼ": "l", "А": "A", "Е": "E", "О": "O", "Р": "P",
    "С": "C", "Х": "X", "І": "I",
})
_WS = re.compile(rf"[\s{_ZEROWIDTH}]")
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
# Evasion-kanalen jagar BARA specifika högvärda hemligheter (API-/privata nycklar). Att
# köra mejl/IP/generiskt/kort mot kollapsad text fuserar intilliggande tokens → falska
# block. De specifika formaten är entydiga och tål kollaps/avkodning utan FP.
_SPECIFIKA: list[Monster] = [m for m in HEMLIGHETER if m.regel != "generic-secret-assignment"]


def normalisera(text: str) -> str:
    """Radslut → \n och homoglyfer → ascii (1:1, offset-bevarande efter radslut-normal.).
    Gör homoglyf- och radbrytnings-evasion verkningslös MED bevarad redakterbarhet."""
    return text.replace("\r\n", "\n").replace("\r", "\n").translate(_HOMOGLYFER)


def _avkoda_b64(s: str) -> str | None:
    try:
        return base64.b64decode(s, validate=True).decode("utf-8", "ignore")
    except (binascii.Error, ValueError):
        return None


def _evasion_traffar(norm: str, redan: set[str]) -> list[Traff]:
    """Insmugna hemligheter som den offset-bevarande vägen missar: whitespace/zero-width-
    insprängda och base64-kodade. Dessa saknar exakt spann (-1) → tvingar BLOCK (kan ej
    redakteras säkert). `redan` = whitespace-strippade råträffar funna exakt (undvik dubblett)."""
    ut: list[Traff] = []
    for regel_prefix, kalla in (("evasion", _WS.sub("", norm)),
                                *[("evasion:base64", d) for m in _B64.finditer(norm)
                                  if (d := _avkoda_b64(m.group(0)))]):
        for t in detektera_rad(kalla, _SPECIFIKA):
            if _WS.sub("", t.text) in redan:
                continue
            ut.append(Traff(f"{regel_prefix}:{t.regel}", t.kategori, Severity.critical,
                            Confidence.heuristic, -1, -1, t.text))
    return ut


# --- kombinerad detektion över hel text (absoluta offsets för redaktion) ---
def detektera_kanslig(text: str, *, inkludera_evasion: bool = True) -> list[Traff]:
    """Alla känsliga träffar (hemligheter + PII + entropi + evasion) med ABSOLUTA offsets i
    den NORMALISERADE texten (anropare som vill redaktera måste maska mot normalisera(text)).
    Evasion-träffar har spann -1 (oredakterbara → BLOCK). Sorterat: exakta först."""
    norm = normalisera(text)
    ut: list[Traff] = []
    off = 0
    for rad in norm.split("\n"):
        mönstrade = detektera_rad(rad, _ALLA)
        klamda = [(t.start, t.slut) for t in mönstrade]
        for t in (*mönstrade, *_entropi_traffar(rad, klamda)):
            ut.append(replace(t, start=off + t.start, slut=off + t.slut))
        off += len(rad) + 1
    if inkludera_evasion:
        # Dedup mot EXAKTA mönsterträffar (ej entropi) — annars suppar en svag entropi-
        # träff den starka evasion-träffen för samma insmugna hemlighet.
        redan = {_WS.sub("", t.text) for t in ut if t.regel != "high-entropy-token"}
        ut.extend(_evasion_traffar(norm, redan))
    ut.sort(key=lambda t: (t.start < 0, t.start))      # exakta först, evasion (-1) sist
    return ut
