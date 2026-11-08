"""Inbyggd secret-skanner: hittar riktiga hemligheter, redaktar dem, och flaggar INTE
placeholders (falskt-positiv-testet). All data syntetisk."""

from pathlib import Path

from serrier.core.findings import Confidence, Severity
from serrier.scanners.base import Scanner
from serrier.scanners.builtin import InbyggdHemlighetsskanner

SK = InbyggdHemlighetsskanner()


def test_uppfyller_scanner_protokollet() -> None:
    assert isinstance(SK, Scanner)
    assert SK.tillganglig() is True                      # inbyggd = alltid tillgänglig


def test_hittar_anthropic_nyckel_och_redaktar(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("ANTHROPIC_API_KEY=sk-ant-api03-REALSECRET1234567890abc\n")
    fynd = SK.skanna(tmp_path, "p1")
    assert len(fynd) == 1
    f = fynd[0]
    assert f.severity == Severity.critical
    assert f.confidence == Confidence.confirmed
    assert f.asset_ref == ".env:1"
    # rå hemlighet lagras ALDRIG
    assert "sk-ant-api03-REALSECRET1234567890abc" not in f.evidence[0].redacted_content


def test_falskt_positivt_placeholder_flaggas_inte(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        'API_KEY = os.environ["API_KEY"]\n'
        'password = "your_password_here"\n'
        'token = "${TOKEN}"\n')
    assert SK.skanna(tmp_path, "p1") == []               # env-ref + placeholders → inget


def test_hoppar_git_och_stora_filer(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "secrets").write_text("AKIA0123456789ABCDEF\n")   # i .git → hoppas
    assert SK.skanna(tmp_path, "p1") == []


def test_privat_nyckel_block(tmp_path: Path) -> None:
    (tmp_path / "id_rsa").write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIabc...\n")
    fynd = SK.skanna(tmp_path, "p1")
    assert any(f.rule == "private-key-block" and f.severity == Severity.critical for f in fynd)
