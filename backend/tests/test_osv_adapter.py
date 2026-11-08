"""osv-scanner-adaptern: deterministisk parsning av en kanad rapport + graceful
degradation. Live-scan (nät) testas ej här. Syntetisk data."""

from pathlib import Path

from serrier.core.findings import Category, Confidence, Severity
from serrier.scanners.base import Scanner
from serrier.scanners.osv_adapter import OsvAdapter, findings_fran_json

KANAD = {
    "results": [{
        "source": {"path": "requirements.txt"},
        "packages": [{
            "package": {"name": "requests", "version": "2.19.0"},
            "vulnerabilities": [{
                "id": "GHSA-xxxx-yyyy-zzzz",
                "summary": "Information exposure in requests",
                "database_specific": {"severity": "HIGH"},
            }],
        }],
    }],
}


def test_uppfyller_protokollet() -> None:
    assert isinstance(OsvAdapter(), Scanner)


def test_parsar_kanad_rapport(tmp_path: Path) -> None:
    fynd = findings_fran_json(KANAD, tmp_path, "p1")
    assert len(fynd) == 1
    f = fynd[0]
    assert f.category == Category.dependency
    assert f.detector == "osv-scanner"
    assert f.severity == Severity.high
    assert f.confidence == Confidence.confirmed       # känd CVE-match
    assert f.asset_ref == "requirements.txt:requests@2.19.0"
    assert f.rule == "GHSA-xxxx-yyyy-zzzz"


def test_graceful_degradation(tmp_path: Path) -> None:
    a = OsvAdapter(binar="/finns/inte/osv")
    assert a.tillganglig() is False
    assert a.skanna(tmp_path, "p1") == []


def test_tom_rapport_ger_inga_findings(tmp_path: Path) -> None:
    assert findings_fran_json({"results": []}, tmp_path, "p1") == []


def test_live_vs_offline_argv(tmp_path: Path) -> None:
    # Default = live (nät mot osv.dev): inga offline-flaggor.
    live = OsvAdapter(binar="/x")._scan_args(tmp_path)
    assert "--offline-vulnerabilities" not in live
    assert live[:4] == ["/x", "scan", "source", "--format"]
    # Opt-in offline: lokal DB, ingen nät-fråga.
    off = OsvAdapter(binar="/x", offline=True)._scan_args(tmp_path)
    assert "--offline-vulnerabilities" in off


def test_offline_lases_fran_env(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SERRIER_OSV_OFFLINE", "1")
    assert "--offline-vulnerabilities" in OsvAdapter(binar="/x")._scan_args(tmp_path)
