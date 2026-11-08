"""Inbyggd secret/.env-skanner. Kräver INGET externt verktyg (alltid tillgänglig) —
golvet som gör produkten användbar även utan gitleaks. Innehållet körs aldrig (otrodd
data). Redaktion sker vid detektion — rå hemlighet lämnar aldrig den här modulen.

Mönstren + placeholder-filtret + span-anspråket bor nu i den delade kärnan
core/textdetect.py (Design 0001, steg 1), som också Pre-Send Guardian använder. Den här
skannern är tunn: vandra filträdet, mata varje rad genom kärnan, bygg Findings. Beteendet
är oförändrat (pinnat av tester)."""

from __future__ import annotations

from pathlib import Path

from serrier.core import textdetect
from serrier.core.findings import Evidence, Finding
from serrier.scanners.base import inom_roten

_HOPPA_KATALOG = {".git", "node_modules", ".venv", "venv", "__pycache__", ".next",
                  "dist", ".ruff_cache", ".pytest_cache", ".tools"}
_MAX_FIL = 1_000_000   # 1 MB — större filer hoppas (resursgräns, THREAT_MODEL T8)


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
            plats = f"{rel}:{radnr}"
            for t in textdetect.detektera_rad(rad):
                ut.append(Finding(
                    project_id=project_id, category=t.kategori, detector=self.namn,
                    severity=t.severity, confidence=t.confidence, asset_ref=plats,
                    title=f"Möjlig hemlighet: {t.regel}", rule=t.regel,
                    evidence=[Evidence.av(source=self.namn, location=plats,
                                          detection_method=t.regel, confidence=t.confidence,
                                          ra_innehall=t.text)]))
        return ut
