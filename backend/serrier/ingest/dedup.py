"""Deduplicering: samma brist ur samma plats (samma stabila id) blir EN finding, med
evidensen sammanslagen. Det är grunden för att en omskanning inte dubblar allt och för
att historik ska gå att följa.

OBS (ärlig gräns): id:t innehåller detektorn, så dedup sker INOM en detektor (re-scan).
KORS-detektor-korrelation (samma hemlighet funnen av både builtin och gitleaks → en
finding) är en Fas 2-förfining, inte gjort här.
"""

from __future__ import annotations

from serrier.core.findings import Finding


def deduplicera(findings: list[Finding]) -> list[Finding]:
    per_id: dict[str, Finding] = {}
    for f in findings:
        if f.id in per_id:
            per_id[f.id].evidence.extend(f.evidence)   # samma finding → slå ihop evidens
        else:
            per_id[f.id] = f
    return list(per_id.values())
