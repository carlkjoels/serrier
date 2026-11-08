"""semgrep-adaptern: fångar osäker kod, graceful degradation. Syntetisk kod."""

from pathlib import Path

import pytest

from serrier.core.findings import Category, Severity
from serrier.scanners.base import Scanner
from serrier.scanners.semgrep_adapter import SemgrepAdapter


def test_uppfyller_protokollet() -> None:
    assert isinstance(SemgrepAdapter(), Scanner)


def test_registry_ar_opt_in() -> None:
    # Default: bara lokala regler (ingen nät-/registry-config).
    default = SemgrepAdapter(binar="/x")._config_args()
    assert default.count("--config") == 1
    assert all(not v.startswith("p/") and v != "auto" for v in default)
    # Opt-in: registry-refs läggs till som extra --config.
    med = SemgrepAdapter(binar="/x", registry=["p/python", "auto"])._config_args()
    assert med.count("--config") == 3
    assert "p/python" in med
    assert "auto" in med


def test_registry_lases_fran_env(monkeypatch) -> None:
    monkeypatch.setenv("SERRIER_SEMGREP_REGISTRY", "p/security-audit, p/secrets")
    args = SemgrepAdapter(binar="/x")._config_args()
    assert "p/security-audit" in args
    assert "p/secrets" in args


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
