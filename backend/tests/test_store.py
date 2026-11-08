"""Store: persistens, re-scan-upsert (ingen dubblering, status bevaras), tenant-isolering.
In-memory SQLite. All data syntetisk."""

from serrier.core.findings import Category, Confidence, Finding, Severity, Status
from serrier.db.store import Store


def _f(project_id: str, asset: str, status: Status = Status.detected) -> Finding:
    return Finding(project_id=project_id, category=Category.secret, detector="builtin",
                   severity=Severity.high, confidence=Confidence.probable,
                   asset_ref=asset, title="hemlighet", rule="r1", status=status)


def _store() -> Store:
    return Store("sqlite:///:memory:")


def _projekt(st: Store, namn: str = "demo") -> str:
    """Projekt under en färsk org (Fas 7: projekt är org-scopade)."""
    return st.skapa_projekt(namn, st.skapa_org("t"))


def test_spara_och_lista() -> None:
    st = _store()
    pid = _projekt(st)
    st.spara_scan(pid, [_f(pid, ".env:1"), _f(pid, ".env:2")], ["builtin"])
    fynd = st.lista_findings(pid)
    assert len(fynd) == 2
    assert all(0 <= d["risk"] <= 100 for d in fynd)


def test_omskanning_dubblar_inte() -> None:
    st = _store()
    pid = _projekt(st)
    st.spara_scan(pid, [_f(pid, ".env:1")], ["builtin"])
    st.spara_scan(pid, [_f(pid, ".env:1")], ["builtin"])     # samma brist igen
    assert len(st.lista_findings(pid)) == 1                  # upsert, inte dubblering


def test_tenant_isolering() -> None:
    st = _store()
    a = _projekt(st, "a")
    b = _projekt(st, "b")
    st.spara_scan(a, [_f(a, ".env:1")], ["builtin"])
    st.spara_scan(b, [_f(b, "secrets.py:9")], ["builtin"])
    fa = st.lista_findings(a)
    assert len(fa) == 1
    assert fa[0]["asset_ref"] == ".env:1"                    # a ser bara sitt eget
    assert all(d["asset_ref"] != "secrets.py:9" for d in fa)


def test_projekt_finns_och_org_scoping() -> None:
    st = _store()
    org = st.skapa_org("t")
    pid = st.skapa_projekt("x", org)
    assert st.projekt_finns(pid) is True
    assert st.projekt_finns(pid, org) is True
    assert st.projekt_finns(pid, "annan-org") is False      # fel org → finns inte
    assert st.projekt_finns("okänt") is False


def test_satt_status_explicit() -> None:
    st = _store()
    pid = _projekt(st)
    st.spara_scan(pid, [_f(pid, ".env:1")], ["builtin"])
    fid = st.lista_findings(pid)[0]["id"]
    assert st.satt_status(pid, fid, Status.remediation_approved) is True
    assert st.lista_findings(pid)[0]["status"] == "remediation_approved"
    assert st.satt_status(pid, "okänt", Status.verified) is False


def test_auto_verifiering_vid_omskanning() -> None:
    st = _store()
    pid = _projekt(st)
    st.spara_scan(pid, [_f(pid, ".env:1")], ["builtin"])          # fyndet finns
    fid = st.lista_findings(pid)[0]["id"]
    st.satt_status(pid, fid, Status.remediation_approved)         # användaren godkänner
    st.spara_scan(pid, [], ["builtin"])                           # omskanning: fyndet borta
    assert st.lista_findings(pid)[0]["status"] == "verified"      # risken sjönk → verified
