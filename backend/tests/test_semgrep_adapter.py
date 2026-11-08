"""semgrep-adaptern: fångar osäker kod, graceful degradation. Syntetisk kod."""

from pathlib import Path

import pytest

from serrier.core.findings import Category, Severity
from serrier.scanners.base import Scanner
from serrier.scanners.semgrep_adapter import SemgrepAdapter


def test_uppfyller_protokollet() -> None:
    assert isinstance(SemgrepAdapter(), Scanner)


def test_graceful_degradation(tmp_path: Path) -> None:
    a = SemgrepAdapter(binar="/finns/inte/semgrep")
    assert a.tillganglig() is False
    assert a.skanna(tmp_path, "p1") == []


@pytest.mark.skipif(not SemgrepAdapter().tillganglig(), reason="semgrep ej installerad")
def test_fangar_osaker_kod(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import subprocess\n"
        "def run(cmd):\n"
        "    return subprocess.run(cmd, shell=True)\n"       # shell-true: ERROR → high
        "def calc(x):\n"
        "    return eval(x)\n")                              # eval: ERROR → high
    fynd = SemgrepAdapter().skanna(tmp_path, "p1")
    regler = {f.rule for f in fynd}
    assert "subprocess-shell-true" in regler
    assert "python-eval-untrusted" in regler
    assert all(f.detector == "semgrep" for f in fynd)
    assert all(f.category == Category.injection for f in fynd)
    assert all(f.severity == Severity.high for f in fynd)
