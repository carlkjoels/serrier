"""Mätning: kör skannerna mot fixture-repot och jämför mot facit (ground truth).
Bevisar att vi MÄTER kvalitet, inte bara påstår den."""

import json
from pathlib import Path

from serrier.core.findings import Category, Confidence, Finding, Severity
from serrier.matning import matning
from serrier.scanners.builtin import InbyggdHemlighetsskanner
from serrier.scanners.semgrep_adapter import SemgrepAdapter

FIXTUR = Path(__file__).resolve().parents[1] / "scanfixtur" / "vulnprojekt"


def _facit() -> set[tuple[str, str]]:
    data = json.loads((FIXTUR / "FACIT.json").read_text())
    return {tuple(x) for x in data["facit"]}


def _f(fil: str, kat: Category) -> Finding:
    return Finding(project_id="p", category=kat, detector="d", severity=Severity.high,
                   confidence=Confidence.probable, asset_ref=f"{fil}:1", title="x", rule="r")


# --- matning-funktionen (enhet) ---

def test_matning_perfekt() -> None:
    facit = {("a.py", "secret"), ("b.py", "injection")}
    funna = [_f("a.py", Category.secret), _f("b.py", Category.injection)]
    m = matning(funna, facit)
    assert m["precision"] == 1.0
    assert m["recall"] == 1.0


def test_matning_falskt_positivt_och_missat() -> None:
    facit = {("a.py", "secret"), ("b.py", "injection")}
    funna = [_f("a.py", Category.secret), _f("c.py", Category.secret)]   # c = FP, b missad
    m = matning(funna, facit)
    assert m["recall"] == 0.5
    assert ("c.py", "secret") in m["falska_positiva"]
    assert ("b.py", "injection") in m["missade"]


# --- mätning mot fixture-repot (integration) ---

def test_skannerna_hittar_bada_utan_falska_positiva() -> None:
    funna: list[Finding] = []
    for s in (InbyggdHemlighetsskanner(), SemgrepAdapter()):
        if s.tillganglig():
            funna.extend(s.skanna(FIXTUR, "fix"))
    m = matning(funna, _facit())
    assert m["recall"] == 1.0, m["missade"]                  # båda planterade hittades
    assert m["precision"] == 1.0, m["falska_positiva"]       # os.environ-raden flaggas EJ
