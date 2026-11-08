"""Inbyggd secret/.env-skanner. Kräver INGET externt verktyg (alltid tillgänglig) —
golvet som gör produkten användbar även utan gitleaks. Regex över textfiler; innehållet
körs aldrig (otrodd data). Redaktion sker vid detektion — rå hemlighet lämnar aldrig
den här modulen. Konservativ: placeholders/env-referenser flaggas inte (falskt-positiv-
reducering)."""

from __future__ import annotations

import re
from pathlib import Path

from serrier.core.findings import Category, Confidence, Evidence, Finding, Severity
from serrier.scanners.base import inom_roten

# (regel-id, mönster, severity, confidence). Specifika nyckel-format = hög confidence;
# generisk "secret = ..." = heuristik (osäkrare, oftare falskt positiv).
_MONSTER: list[tuple[str, re.Pattern[str], Severity, Confidence]] = [
    ("anthropic-api-key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"),
     Severity.critical, Confidence.confirmed),
    ("openai-api-key", re.compile(r"sk-(?!ant-)[A-Za-z0-9]{20,}"),
     Severity.critical, Confidence.probable),
    ("aws-access-key-id", re.compile(r"AKIA[0-9A-Z]{16}"),
     Severity.critical, Confidence.confirmed),
    ("private-key-block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
     Severity.critical, Confidence.confirmed),
    ("generic-secret-assignment",
     re.compile(r"""(?i)(?:password|secret|token|api[_-]?key|passwd)\s*[=:]\s*['"]?([^\s'"]{8,})"""),
     Severity.high, Confidence.heuristic),
]

# Värden som nästan säkert INTE är en riktig hemlighet (reducerar falska positiva).
_PLACEHOLDER = re.compile(
    r"(?i)(your_|changeme|example|placeholder|dummy|xxx|\$\{|<[^>]+>|os\.environ|"
    r"process\.env|getenv|redacted|\*\*\*)")

_HOPPA_KATALOG = {".git", "node_modules", ".venv", "venv", "__pycache__", ".next",
                  "dist", ".ruff_cache", ".pytest_cache", ".tools"}
_MAX_FIL = 1_000_000   # 1 MB — större filer hoppas (resursgräns, THREAT_MODEL T8)


def _ar_placeholder(trafftext: str) -> bool:
    return bool(_PLACEHOLDER.search(trafftext))


class InbyggdHemlighetsskanner:
    namn = "builtin"

    def tillganglig(self) -> bool:
        return True

    def skanna(self, projekt_rot: Path, project_id: str) -> list[Finding]:
        rot = projekt_rot
        fynd: list[Finding] = []
        for fil in rot.rglob("*"):
            if not fil.is_file() or any(d in fil.parts for d in _HOPPA_KATALOG):
                continue
            if not inom_roten(rot, fil) or fil.stat().st_size > _MAX_FIL:
                continue
            fynd.extend(self._skanna_fil(rot, fil, project_id))
        return fynd

    def _skanna_fil(self, rot: Path, fil: Path, project_id: str) -> list[Finding]:
        try:
            rader = fil.read_text(encoding="utf-8").splitlines()
        except (UnicodeDecodeError, OSError):
            return []                                    # binärt/oläsbart → hoppa
        rel = fil.relative_to(rot).as_posix()
        ut: list[Finding] = []
        for radnr, rad in enumerate(rader, 1):
            klamda: list[tuple[int, int]] = []       # redan täckta spann (specifika först)
            for regel, monster, sev, konf in _MONSTER:
                for m in monster.finditer(rad):
                    s, e = m.span()
                    if _ar_placeholder(m.group(0)) or any(s < ce and cs < e for cs, ce in klamda):
                        continue                     # placeholder, eller överlappar ett funnet
                    klamda.append((s, e))
                    ut.append(Finding(
                        project_id=project_id, category=Category.secret, detector=self.namn,
                        severity=sev, confidence=konf, asset_ref=f"{rel}:{radnr}",
                        title=f"Möjlig hemlighet: {regel}", rule=regel,
                        evidence=[Evidence.av(source=self.namn, location=f"{rel}:{radnr}",
                                              detection_method=regel, confidence=konf,
                                              ra_innehall=m.group(0))]))
        return ut
