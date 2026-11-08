"""Scanner-registret — ett ställe som vet vilka skanners som finns och kör de
tillgängliga. Delas av CLI och API. Saknade verktyg hoppas (graceful degradation);
resultatet dedupliceras."""

from __future__ import annotations

from pathlib import Path

from serrier.core.findings import Finding
from serrier.ingest.dedup import deduplicera
from serrier.scanners.base import Scanner
from serrier.scanners.builtin import InbyggdHemlighetsskanner
from serrier.scanners.gitleaks_adapter import GitleaksAdapter

SKANNERS: list[Scanner] = [InbyggdHemlighetsskanner(), GitleaksAdapter()]


def tillgangliga() -> list[Scanner]:
    return [s for s in SKANNERS if s.tillganglig()]


def kor_skanners(rot: Path, project_id: str) -> list[Finding]:
    fynd: list[Finding] = []
    for s in tillgangliga():
        fynd.extend(s.skanna(rot, project_id))
    return deduplicera(fynd)
