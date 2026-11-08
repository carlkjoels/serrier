"""gitleaks-adaptern: fångar en planterad hemlighet (redaktad) och degraderar snällt
när binären saknas. All data syntetisk."""

from pathlib import Path

import pytest

from serrier.core.findings import Category
from serrier.scanners.base import Scanner
from serrier.scanners.gitleaks_adapter import GitleaksAdapter

PRIVATNYCKEL = ("-----BEGIN PRIVATE KEY-----\n"
                "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDummySYNTETISK\n"
                "-----END PRIVATE KEY-----\n")


def test_uppfyller_protokollet() -> None:
    assert isinstance(GitleaksAdapter(), Scanner)


def test_graceful_degradation_nar_binar_saknas(tmp_path: Path) -> None:
    a = GitleaksAdapter(binar="/finns/inte/gitleaks")
    assert a.tillganglig() is False
    assert a.skanna(tmp_path, "p1") == []            # ingen krasch, tom lista


@pytest.mark.skipif(not GitleaksAdapter().tillganglig(), reason="gitleaks ej installerad")
def test_fangar_planterad_hemlighet_redaktad(tmp_path: Path) -> None:
    (tmp_path / "id_key.pem").write_text(PRIVATNYCKEL)
    fynd = GitleaksAdapter().skanna(tmp_path, "p1")
    assert len(fynd) >= 1
    f = fynd[0]
    assert f.detector == "gitleaks"
    assert f.category == Category.secret
    assert f.asset_ref.startswith("id_key.pem:")
    assert "SYNTETISK" not in f.evidence[0].redacted_content   # rå hemlighet aldrig lagrad
