"""Scanner-gränssnittet. Varje detektor (inbyggd, gitleaks, semgrep, osv) uppfyller
`Scanner`. `tillganglig()` ger graceful degradation — saknas verktyget rapporteras det
som en täckningsgräns, produkten kraschar inte.

Säkerhet (THREAT_MODEL T4): all filåtkomst confinas till projektroten. En plats som
försöker rymma (../, symlänk ut) avvisas — skannat innehåll är otrodd data.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from serrier.core.findings import Finding


@runtime_checkable
class Scanner(Protocol):
    namn: str

    def tillganglig(self) -> bool:
        """Finns verktyget? False → hoppas med en loggad täckningsgräns, ej krasch."""

    def skanna(self, projekt_rot: Path, project_id: str) -> list[Finding]:
        """Skanna ett projekt och returnera findings (evidens redaktad vid detektion)."""


def inom_roten(rot: Path, kandidat: Path) -> bool:
    """True om `kandidat` ligger inom `rot` efter full upplösning (skydd mot
    path traversal och symlänk-rymning)."""
    try:
        kandidat.resolve().relative_to(rot.resolve())
    except (ValueError, OSError):
        return False
    return True
