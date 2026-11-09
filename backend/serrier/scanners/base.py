"""Scanner-gränssnittet. Varje detektor (inbyggd, gitleaks, semgrep, osv) uppfyller
`Scanner`. `tillganglig()` ger graceful degradation — saknas verktyget rapporteras det
som en täckningsgräns, produkten kraschar inte.

Säkerhet (THREAT_MODEL T4): all filåtkomst confinas till projektroten. En plats som
försöker rymma (../, symlänk ut) avvisas — skannat innehåll är otrodd data.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Protocol, runtime_checkable

from serrier.core.findings import Finding

try:
    import resource
except ImportError:                                    # icke-POSIX
    resource = None

# Resurs-HÄGN för scanner-subprocesser (F6). OBS: en subprocess är INGEN säkerhetssandbox —
# detta begränsar resursåtgång (DoS av ett fientligt/enormt repo) men ger inte isolering.
# Full isolering (lägsta behörighet, nätverksspärr, namespaces) OCH ett pålitligt minnes-tak
# kräver cgroups/container/OS-sandbox; se ARCHITECTURE. Gränserna sätts via preexec_fn (POSIX).
_CPU_SEK = 120
_FIL_BYTES = 100 * 1024 ** 2        # 100 MB max outputfil
# RLIMIT_AS (adressrymd) sätts INTE som default: det begränsar VIRTUELLT minne, vilket
# moderna runtimes (t.ex. semgrep/OCaml) över-reserverar → svälter legitima scans. Äkta
# minnes-cap = cgroups (container). minne > 0 kan opt-in:as där det passar.
_MINNE_BYTES = 0


def resursgrans(*, cpu: int = _CPU_SEK, minne: int = _MINNE_BYTES,
                fstorlek: int = _FIL_BYTES) -> None:
    """preexec_fn: sätt CPU- och filstorleksgränser i scanner-barnprocessen (minne=0 →
    ingen adressrymdsgräns; se kommentar ovan)."""
    if resource is None:
        return
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
    if minne:
        resource.setrlimit(resource.RLIMIT_AS, (minne, minne))
    resource.setrlimit(resource.RLIMIT_FSIZE, (fstorlek, fstorlek))


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


_HOPPA_KATALOG = {".git", "node_modules", ".venv", "venv", "__pycache__", ".next",
                  "dist", ".ruff_cache", ".pytest_cache", ".tools"}
_MAX_FIL = 1_000_000   # 1 MB — resursgräns (THREAT_MODEL T8)


def las_rader(rot: Path) -> Iterator[tuple[str, int, str]]:
    """Generator över (rel_sökväg, radnr, rad) för textfiler under `rot`. Hoppar
    vendor/VCS-kataloger och stora filer; path-confinad; binärt hoppas. Delas av
    de regex-baserade skannerna (builtin, scraping). Innehållet körs aldrig."""
    for fil in rot.rglob("*"):
        if not fil.is_file() or any(d in fil.parts for d in _HOPPA_KATALOG):
            continue
        if not inom_roten(rot, fil) or fil.stat().st_size > _MAX_FIL:
            continue
        try:
            rader = fil.read_text(encoding="utf-8").splitlines()
        except (UnicodeDecodeError, OSError):
            continue
        rel = fil.relative_to(rot).as_posix()
        for radnr, rad in enumerate(rader, 1):
            yield rel, radnr, rad
