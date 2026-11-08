"""Remediation: hemlighet → kod-framtvingat rotationskrav; verifiering via utfall.
Claude fejkas."""

from serrier import remediation

SVAR = '{"forklaring":"f","impact":"i","prioritet":"hög","atgard":"a"}'


def _fynd(kat: str) -> dict:
    return {"id": "x1", "category": kat, "severity": "high", "confidence": "probable",
            "asset_ref": "a:1", "title": "t", "rule": "r", "evidence": []}


def test_hemlighet_kraver_rotation() -> None:
    f = remediation.foresla_atgard(_fynd("secret"), lambda d: SVAR)
    assert "obligatorisk_atgard" in f
    assert "rotera" in f["obligatorisk_atgard"].lower()
    assert f["kraver_godkannande"] is True        # inget auto-applas


def test_icke_hemlighet_har_inget_rotationskrav() -> None:
    f = remediation.foresla_atgard(_fynd("injection"), lambda d: SVAR)
    assert "obligatorisk_atgard" not in f


def test_verifiera_utfall() -> None:
    borta = remediation.verifiera_utfall(80, finns_kvar_efter_omskanning=False)
    assert borta["atgardat"] is True
    assert borta["risk_efter"] == 0
    kvar = remediation.verifiera_utfall(80, finns_kvar_efter_omskanning=True)
    assert kvar["atgardat"] is False
    assert kvar["risk_efter"] == 80               # inte löst → risken kvar
