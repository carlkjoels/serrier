"""Tunn CLI-demo: kör alla TILLGÄNGLIGA skanners över ett lokalt projekt, deduplicera,
och skriv findings sorterade efter risk. Bevisar spinen end-to-end (scan → findings)
innan DB och API finns.

    uv run python -m serrier.cli <sökväg-till-projekt>
"""

from __future__ import annotations

import sys
from pathlib import Path

from serrier.core.findings import Finding
from serrier.core.risk import risk_score
from serrier.scanners.registry import SKANNERS, kor_skanners


def kor(rot: Path, project_id: str = "cli") -> list[Finding]:
    for s in SKANNERS:
        if not s.tillganglig():
            print(f"  [täckningsgräns] {s.namn} ej tillgänglig — hoppas", file=sys.stderr)
    return kor_skanners(rot, project_id)


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if not args:
        print("användning: python -m serrier.cli <sökväg>", file=sys.stderr)
        return 2
    rot = Path(args[0])
    if not rot.is_dir():
        print(f"ingen katalog: {rot}", file=sys.stderr)
        return 2
    fynd = sorted(kor(rot), key=risk_score, reverse=True)
    print(f"# Serrier — {len(fynd)} findings i {rot}\n")
    for f in fynd:
        print(f"[{risk_score(f):3d}] {f.severity.value:8} {f.confidence.value:9} "
              f"{f.detector:9} {f.asset_ref}")
        print(f"       {f.title}  ·  evidens: {f.evidence[0].redacted_content}")
    if not fynd:
        print("Inga findings. (Observera: detta bevisar inte att projektet är säkert — "
              "bara att de körda skannernas täckning inte fann något.)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
