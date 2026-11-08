"""Modul B — Scraping-säkerhet (statisk analys av ett scraping-projekts kod/config).
Skrapat innehåll är OTRODD indata och får ALDRIG bli instruktioner till en agent — den
farligaste AI-native scraping-risken. Vi kör inget och skrapar inget; vi läser kod.

Flaggar: TLS-verifiering avstängd, proxy/URL med inbäddade credentials, och skrapat
innehåll som matas rakt in i en LLM-prompt (prompt injection via skrapad sida)."""

from __future__ import annotations

import re
from pathlib import Path

from serrier.core.findings import Category, Confidence, Evidence, Finding, Severity
from serrier.scanners.base import las_rader

# (regel, mönster, severity, confidence, kategori)
_MONSTER: list[tuple[str, re.Pattern[str], Severity, Confidence, Category]] = [
    ("tls-verification-disabled",
     re.compile(r"verify\s*=\s*False|_create_unverified_context|CERT_NONE|rejectUnauthorized\s*:\s*false"),
     Severity.high, Confidence.probable, Category.config),
    ("proxy-credentials-in-url",
     re.compile(r"(?:https?|socks\d?)://[^/\s:@'\"]+:[^/\s:@'\"]+@"),
     Severity.high, Confidence.probable, Category.secret),
    ("scraped-content-to-llm-prompt",
     re.compile(r"(?i)(?:prompt|messages|system|completion|content)\s*[=+].*"
                r"(?:\.text|\.content|\bresponse\b|scraped|\bhtml\b|soup|\.get_text)"),
     Severity.high, Confidence.heuristic, Category.injection),
]


class ScrapingSakerhetsskanner:
    namn = "scraping"

    def tillganglig(self) -> bool:
        return True

    def skanna(self, projekt_rot: Path, project_id: str) -> list[Finding]:
        ut: list[Finding] = []
        for rel, radnr, rad in las_rader(projekt_rot):
            for regel, monster, sev, konf, kat in _MONSTER:
                m = monster.search(rad)
                if not m:
                    continue
                plats = f"{rel}:{radnr}"
                ut.append(Finding(
                    project_id=project_id, category=kat, detector=self.namn, severity=sev,
                    confidence=konf, asset_ref=plats, title=f"scraping: {regel}", rule=regel,
                    evidence=[Evidence.av(source=self.namn, location=plats,
                                          detection_method=regel, confidence=konf,
                                          ra_innehall=m.group(0))]))
        return ut
