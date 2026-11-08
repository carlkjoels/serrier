"""Delad textdetektions-kärna. Yt-agnostisk: samma motor körs över en fils rader
(fil-skannern) och över utgående text (Pre-Send Guardian). Mönster-LISTAN är utbytbar så
olika ytor kan komponera olika detektorer (hemligheter delas; Guardian lägger till PII).

Säkerhet: `Traff.text` bär den RÅA träffen men lever bara i minnet under en skanning —
anropare måste redakta (Evidence.av / redact) innan något persisteras, loggas eller skickas.
Innehållet körs aldrig (otrodd data). Konservativ: placeholders flaggas inte.

Refaktorerad ur scanners/builtin.py (Design 0001, steg 1) — HEMLIGHETER + placeholder-filter
+ span-anspråk är oförändrade, så fil-skannerns beteende är identiskt (pinnat av tester).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from serrier.core.findings import Category, Confidence, Severity


@dataclass(frozen=True)
class Monster:
    """En detektionsregel: id, vad en träff betyder, mönstret, och en VALFRI validator.
    Validatorn bekräftar en regex-träff semantiskt (t.ex. Luhn på kortnummer) och skär
    falska positiva — None = varje regex-träff godtas."""
    regel: str
    kategori: Category
    severity: Severity
    confidence: Confidence
    monster: re.Pattern[str]
    validator: Callable[[str], bool] | None = None


@dataclass(frozen=True)
class Traff:
    """En träff i en textrad. `start`/`slut` är spann inom raden (för redaktion)."""
    regel: str
    kategori: Category
    severity: Severity
    confidence: Confidence
    start: int
    slut: int
    text: str                        # rå träff — redakta innan persistens/transit


# Hemlighets-mönster (flyttade oförändrade från builtin). Specifika nyckel-format = hög
# confidence; generisk "secret = ..." = heuristik (osäkrare, oftare falskt positiv).
HEMLIGHETER: list[Monster] = [
    Monster("anthropic-api-key", Category.secret, Severity.critical, Confidence.confirmed,
            re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    Monster("openai-api-key", Category.secret, Severity.critical, Confidence.probable,
            re.compile(r"sk-(?!ant-)[A-Za-z0-9]{20,}")),
    Monster("aws-access-key-id", Category.secret, Severity.critical, Confidence.confirmed,
            re.compile(r"AKIA[0-9A-Z]{16}")),
    Monster("private-key-block", Category.secret, Severity.critical, Confidence.confirmed,
            re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    Monster("generic-secret-assignment", Category.secret, Severity.high, Confidence.heuristic,
            re.compile(r"""(?i)(?:password|secret|token|api[_-]?key|passwd)\s*[=:]\s*['"]?([^\s'"]{8,})""")),
]

# Värden som nästan säkert INTE är en riktig hemlighet (reducerar falska positiva).
_PLACEHOLDER = re.compile(
    r"(?i)(your_|changeme|example|placeholder|dummy|xxx|\$\{|<[^>]+>|os\.environ|"
    r"process\.env|getenv|redacted|\*\*\*)")


def ar_placeholder(trafftext: str) -> bool:
    return bool(_PLACEHOLDER.search(trafftext))


def detektera_rad(rad: str, monster: list[Monster] = HEMLIGHETER) -> list[Traff]:
    """Alla träffar i en rad. Specifika mönster först (listordning); en senare träff som
    överlappar ett redan anspråkat spann hoppas (undviker dubbel-match av samma hemlighet).
    Placeholders filtreras bort."""
    klamda: list[tuple[int, int]] = []
    ut: list[Traff] = []
    for m in monster:
        for träff in m.monster.finditer(rad):
            s, e = träff.span()
            if ar_placeholder(träff.group(0)) or any(s < ce and cs < e for cs, ce in klamda):
                continue
            if m.validator and not m.validator(träff.group(0)):
                continue                     # regex matchade men validatorn underkände
            klamda.append((s, e))
            ut.append(Traff(regel=m.regel, kategori=m.kategori, severity=m.severity,
                            confidence=m.confidence, start=s, slut=e, text=träff.group(0)))
    return ut
