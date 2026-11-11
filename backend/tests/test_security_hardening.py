"""Regressionstester för säkerhetshärdningen (A–G) på `security-hardening`-branchen.

Ett test (minst) per fynd. Dessa bevisar att en *osäker* konfiguration faktiskt vägras
— inte bara att den säkra vägen fungerar. Negativa tester är poängen: vi testar att
Serrier failar closed, inte att den failar open tyst.

All data är syntetisk. Inga riktiga hemligheter, inga externa nätverksanrop.
"""

import asyncio
import gzip
import inspect as _inspect
import os
import resource
from collections import deque
from pathlib import Path
from urllib.parse import quote

import httpx
import pytest
from fastapi.testclient import TestClient
from upstream_harness import KontrolleradUpstream

import serrier.guardian.proxy as pmod
import serrier.scanners.resurser as rmod
from serrier import analyst
from serrier.api.app import app, get_store, krav_sakra_konfig
from serrier.core.sokvag import (
    UtanforWorkspace,
    validera_scan_sokvag,
    workspace_rot,
)
from serrier.db.store import Store
from serrier.guardian.policy import FailureMode
from serrier.guardian.proxy import _AUDIT_MAX, GuardProxy, Upstream, skriv_token
from serrier.scanners.gitleaks_adapter import GitleaksAdapter
from serrier.scanners.osv_adapter import OsvAdapter
from serrier.scanners.registry import kor_skanners
from serrier.scanners.resurser import resursgrans
from serrier.scanners.semgrep_adapter import SemgrepAdapter

REPO = Path(__file__).resolve().parents[2]


def _klient() -> TestClient:
    store = Store("sqlite:///:memory:")
    app.dependency_overrides[get_store] = lambda: store
    return TestClient(app)


# =========================================================================
# A — Säkra standardvärden: fail-closed konfig-grind + loopback + inga default-lösen
# =========================================================================

def test_A_konfig_vagrar_starta_nar_auth_kravs_utan_nycklar() -> None:
    """REQUIRE_AUTH satt men inga API-nycklar → RuntimeError (vägrar starta)."""
    with pytest.raises(RuntimeError, match="osäker konfiguration"):
        krav_sakra_konfig({"SERRIER_REQUIRE_AUTH": "1", "SERRIER_API_KEYS": ""})


def test_A_konfig_ok_nar_auth_kravs_med_nycklar() -> None:
    """REQUIRE_AUTH satt + minst en nyckel → startar (ingen exception)."""
    krav_sakra_konfig({"SERRIER_REQUIRE_AUTH": "1", "SERRIER_API_KEYS": "owner-key-123"})


@pytest.mark.parametrize("tomma", [",", " , ", "  ", ",,,", " ,\t,\n"])
def test_A_konfig_vagrar_nar_api_keys_saknar_giltig_nyckel(tomma: str) -> None:
    """Adversariell kant: en icke-tom men nyckel-LÖS sträng (',' / whitespace) seedar noll
    nycklar och skulle bricka API:t (auth krävs, ingen nyckel) — måste också vägras."""
    with pytest.raises(RuntimeError, match="osäker konfiguration"):
        krav_sakra_konfig({"SERRIER_REQUIRE_AUTH": "1", "SERRIER_API_KEYS": tomma})


def test_A_konfig_ok_med_nyckel_bland_tomma() -> None:
    """Minst en giltig nyckel bland separatorer räcker (matchar seed-parsningen)."""
    krav_sakra_konfig({"SERRIER_REQUIRE_AUTH": "1", "SERRIER_API_KEYS": " , owner-key , "})


def test_A_konfig_ror_inte_dev_lage() -> None:
    """REQUIRE_AUTH osatt → dev-läge, inget krav på nycklar (friktionsfritt lokalt)."""
    krav_sakra_konfig({"SERRIER_API_KEYS": ""})
    krav_sakra_konfig({})


@pytest.mark.parametrize("falskt", ["0", "false", "no", "off", "", "  "])
def test_A_konfig_falska_varden_ar_inte_require_auth(falskt: str) -> None:
    """Falsiga REQUIRE_AUTH-värden aktiverar inte kravet (ingen oavsiktlig låsning)."""
    krav_sakra_konfig({"SERRIER_REQUIRE_AUTH": falskt, "SERRIER_API_KEYS": ""})


def test_A_orgs_bootstrap_stangs_av_nar_auth_kravs(monkeypatch) -> None:
    """Tom prod-DB + REQUIRE_AUTH → /orgs får INTE bootstrappa en owner-nyckel öppet."""
    monkeypatch.setenv("SERRIER_REQUIRE_AUTH", "1")
    c = _klient()
    try:
        r = c.post("/orgs", json={"namn": "attacker"})
        assert r.status_code == 403
    finally:
        app.dependency_overrides.clear()


def test_A_orgs_bootstrap_oppen_i_dev(monkeypatch) -> None:
    """Dev-läge (ingen auth) → /orgs bootstrappar fortfarande (lokal friktionsfrihet)."""
    monkeypatch.delenv("SERRIER_REQUIRE_AUTH", raising=False)
    c = _klient()
    try:
        r = c.post("/orgs", json={"namn": "dev"})
        assert r.status_code == 200
        assert r.json()["api_key"]
    finally:
        app.dependency_overrides.clear()


@pytest.mark.parametrize("falskt", ["0", "false", "no", "off", "False", "OFF"])
def test_A_require_auth_tolkas_konsekvent_falsy(monkeypatch, falskt: str) -> None:
    """FYND 1 (fail-open): tidigare läste /orgs (_sant) och auth (rått) REQUIRE_AUTH olika,
    så 'false' lät /orgs minta en owner-nyckel medan /projects såg låst (401). Nu är det EN
    sanning: falsy → dev-läge ÖVERALLT (konsekvent), aldrig split-brain."""
    monkeypatch.setenv("SERRIER_REQUIRE_AUTH", falskt)
    # Separata färska stores: /orgs mintar en nyckel som annars skulle låsa /projects.
    c1 = _klient()
    try:
        assert c1.post("/projects", json={"namn": "p"}).status_code == 200   # dev-owner, ej 401
    finally:
        app.dependency_overrides.clear()
    c2 = _klient()
    try:
        assert c2.post("/orgs", json={"namn": "x"}).status_code == 200       # dev-bootstrap öppen
    finally:
        app.dependency_overrides.clear()


@pytest.mark.parametrize("sant", ["1", "true", "yes", "on"])
def test_A_require_auth_sant_laser_bade_orgs_och_projects(monkeypatch, sant: str) -> None:
    """Truthy REQUIRE_AUTH → BÅDE /orgs (403) och /projects (401) låsta, konsekvent."""
    monkeypatch.setenv("SERRIER_REQUIRE_AUTH", sant)
    c = _klient()
    try:
        assert c.post("/orgs", json={"namn": "x"}).status_code == 403
        assert c.post("/projects", json={"namn": "p"}).status_code == 401
    finally:
        app.dependency_overrides.clear()


def test_A_compose_binder_loopback_och_kraver_auth() -> None:
    """docker-compose: portar bundna till 127.0.0.1, auth krävs, inga default-lösen."""
    compose = (REPO / "docker-compose.yml").read_text()
    assert "127.0.0.1:8000:8000" in compose
    assert "127.0.0.1:3000:3000" in compose
    assert 'SERRIER_REQUIRE_AUTH: "1"' in compose
    assert ":-serrier}" not in compose          # ingen default-lösenords-fallback
    assert "POSTGRES_PASSWORD:?" in compose      # krävs explicit
    assert "SERRIER_API_KEYS:?" in compose       # owner-nyckel krävs explicit


def test_A_entrypoint_kor_konfig_grind() -> None:
    """Entrypoint kör fail-closed-grinden före migrering/start."""
    ep = (REPO / "backend" / "docker-entrypoint.sh").read_text()
    assert "krav_sakra_konfig" in ep


# =========================================================================
# B — Sökvägs-confinement: traversal + symlänk-escape + prefix-förväxling
# =========================================================================

def test_B_tillater_sokvag_inom_roten(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / "proj").mkdir()
    monkeypatch.setenv("SERRIER_WORKSPACE_ROOT", str(tmp_path))
    ut = validera_scan_sokvag(tmp_path / "proj")
    assert ut == (tmp_path / "proj").resolve()


def test_B_blockar_traversal_ut_ur_roten(monkeypatch, tmp_path: Path) -> None:
    rot = tmp_path / "ws"
    rot.mkdir()
    monkeypatch.setenv("SERRIER_WORKSPACE_ROOT", str(rot))
    with pytest.raises(UtanforWorkspace):
        validera_scan_sokvag(rot / ".." / ".." / "etc")


def test_B_blockar_symlank_escape(monkeypatch, tmp_path: Path) -> None:
    """En symlänk inne i workspace som pekar UT ur det får inte passera (realpath följer den)."""
    rot = tmp_path / "ws"
    rot.mkdir()
    utanfor = tmp_path / "hemligt"
    utanfor.mkdir()
    lank = rot / "escape"
    lank.symlink_to(utanfor)
    monkeypatch.setenv("SERRIER_WORKSPACE_ROOT", str(rot))
    with pytest.raises(UtanforWorkspace):
        validera_scan_sokvag(lank)


def test_B_blockar_prefix_forvaxling(monkeypatch, tmp_path: Path) -> None:
    """``/a/ws-evil`` är INTE under ``/a/ws`` (komponentvis jämförelse, ej strängprefix)."""
    (tmp_path / "ws").mkdir()
    granne = tmp_path / "ws-evil"
    granne.mkdir()
    monkeypatch.setenv("SERRIER_WORKSPACE_ROOT", str(tmp_path / "ws"))
    with pytest.raises(UtanforWorkspace):
        validera_scan_sokvag(granne)


def test_B_dev_utan_rot_tillater_allt_men_dokumenterat(monkeypatch, tmp_path: Path) -> None:
    """Osatt rot = dev-läge: ingen confinement (medvetet), returnerar kanonisk sökväg."""
    monkeypatch.delenv("SERRIER_WORKSPACE_ROOT", raising=False)
    assert workspace_rot() is None
    assert validera_scan_sokvag(tmp_path) == tmp_path.resolve()


def test_B_scan_endpoint_ger_403_utanfor_workspace(monkeypatch, tmp_path: Path) -> None:
    """Confinement enforcas vid API-gränsen: scan utanför roten → 403."""
    rot = tmp_path / "ws"
    rot.mkdir()
    monkeypatch.setenv("SERRIER_WORKSPACE_ROOT", str(rot))
    c = _klient()
    try:
        pid = c.post("/projects", json={"namn": "demo"}).json()["project_id"]
        r = c.post(f"/projects/{pid}/scan", json={"sokvag": str(tmp_path)})
        assert r.status_code == 403
    finally:
        app.dependency_overrides.clear()


def test_B_scanner_granssen_enforcar_ocksa(monkeypatch, tmp_path: Path) -> None:
    """Defense in depth: även kor_skanners() stoppar sökväg utanför roten."""
    rot = tmp_path / "ws"
    rot.mkdir()
    monkeypatch.setenv("SERRIER_WORKSPACE_ROOT", str(rot))
    with pytest.raises(UtanforWorkspace):
        kor_skanners(tmp_path, "proj")


# =========================================================================
# C — Strömmande body-gräns: enforcas under läsning, inte efter buffring
# =========================================================================

class _FakeStream:
    """Duck-typar Request: matar ut chunkar så vi kan verifiera att gränsen enforcas
    STRÖMMANDE (avbryter mitt i), oberoende av Content-Length."""

    def __init__(self, chunkar: list[bytes]) -> None:
        self._chunkar = chunkar
        self.levererade = 0

    async def stream(self):
        for c in self._chunkar:
            self.levererade += len(c)
            yield c


def _las(chunkar, grans):

    fake = _FakeStream(chunkar)
    res = asyncio.run(GuardProxy._las_begransad(fake, grans))
    return res, fake


def test_C_las_begransad_slapper_igenom_under_gransen() -> None:
    res, _ = _las([b"abc", b"def"], grans=100)
    assert res == b"abcdef"


def test_C_las_begransad_avbryter_over_gransen() -> None:
    """Gränsen 10, totalt 15 → None (413). Oberoende av om Content-Length fanns."""
    res, _ = _las([b"x" * 6, b"y" * 9], grans=10)
    assert res is None


def test_C_las_begransad_buffrar_inte_hela_vid_overskridande() -> None:
    """Bevis mot minnes-DoS: vi slutar dra chunkar så fort gränsen passeras —
    den sista (stora) chunken i strömmen hämtas aldrig."""
    stor = b"z" * 1000
    res, fake = _las([b"a" * 11, stor], grans=10)
    assert res is None
    assert fake.levererade == 11          # andra chunken (1000 B) drogs aldrig


def test_C_las_begransad_exakt_pa_gransen_passerar() -> None:
    res, _ = _las([b"x" * 10], grans=10)
    assert res == b"x" * 10


def _proxy_klient(max_body: int) -> TestClient:
    klient = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda r: httpx.Response(200, content=b"{}")))
    px = GuardProxy(klient=klient, allowlist=[Upstream("test", "https://upstream.test")],
                    validera_ip=False, max_body=max_body)
    return TestClient(px.app())


def test_C_oversize_utan_content_length_ger_413() -> None:
    """Chunked/strömmad body utan Content-Length > gräns → 413 (precheck räcker inte)."""
    c = _proxy_klient(max_body=100)

    def gen():
        for _ in range(50):
            yield b"x" * 10          # 500 B totalt, skickas chunkat (ingen CL)

    r = c.post("/test/v1/messages", content=gen())
    assert r.status_code == 413


# =========================================================================
# D/E — Request-coverage: query-inspektion + kodad body → UNKNOWN
# =========================================================================

RA = "sk-ant-api03-REALSECRET1234567890abcDEF"


def _de_rig(failure_mode):
    """Proxy mot KontrolleradUpstream (räknar exakt mottagna bytes → bevisar leak-through)."""

    up = KontrolleradUpstream()
    klient = httpx.AsyncClient(transport=httpx.ASGITransport(app=up.app()))
    px = GuardProxy(klient=klient, allowlist=[Upstream("test", "https://upstream.test")],
                    validera_ip=False, failure_mode=failure_mode)
    return TestClient(px.app()), up


def test_D_hemlighet_i_query_blockeras() -> None:
    c, up = _de_rig(FailureMode.balanced)
    r = c.post(f"/test/v1/messages?api_key={RA}", content=b'{"msg":"ren"}')
    assert r.status_code == 403
    assert not up.mottaget                        # nådde aldrig upstream (leak-through = 0)


def test_D_procentkodad_hemlighet_i_query_blockeras() -> None:
    """%-escaping får inte gömma hemligheten; unquote() avkodar innan inspektion."""

    c, up = _de_rig(FailureMode.balanced)
    r = c.post(f"/test/v1/messages?q={quote(RA)}", content=b'{"msg":"ren"}')
    assert r.status_code == 403
    assert not up.mottaget


def test_D_dubbelkodad_hemlighet_i_query_blockeras() -> None:
    """FYND 2: en DUBBELkodad hemlighet (?q=%2573k-…) gömmer sig bakom ett enda unquote.
    Vi avkodar till fixpunkt, så den fångas ändå."""
    c, up = _de_rig(FailureMode.balanced)
    dubbel = quote(quote(RA))                         # två lager %-escaping
    r = c.post(f"/test/v1/messages?q={dubbel}", content=b'{"msg":"ren"}')
    assert r.status_code == 403
    assert not up.mottaget


def test_D_ofarlig_query_slapps_igenom() -> None:
    c, up = _de_rig(FailureMode.balanced)
    r = c.post("/test/v1/messages?model=claude-opus-4&stream=true", content=b'{"msg":"ren"}')
    assert r.status_code == 200
    assert up.mottaget[0]["body"] == b'{"msg":"ren"}'   # oförändrad genomfart


def test_E_kodad_body_blockeras_i_balanced() -> None:
    """Content-Encoding: gzip → kan ej inspekteras → UNKNOWN → block i balanced.
    Avgörande: en hemlighet GÖMD i en gzip-body får INTE passera som 'inspekterad-säker'."""

    c, up = _de_rig(FailureMode.balanced)
    payload = gzip.compress(f'{{"p":"{RA}"}}'.encode())
    r = c.post("/test/v1/messages", content=payload,
               headers={"content-encoding": "gzip"})
    assert r.status_code == 403
    assert not up.mottaget                        # hemligheten nådde aldrig upstream


@pytest.mark.parametrize("enc", ["gzip", "deflate", "br", "GZIP"])
def test_E_alla_kodningar_blockeras_i_strict(enc: str) -> None:
    c, up = _de_rig(FailureMode.strict)
    r = c.post("/test/v1/messages", content=b"\x1f\x8b\x08rubbish",
               headers={"content-encoding": enc})
    assert r.status_code == 403
    assert not up.mottaget


def test_E_kodad_body_forwardas_orord_i_permissive() -> None:
    """Permissive: UNKNOWN → forwarda men OFÖRÄNDRAT (ingen trasig redact på bytes),
    loggat som unknown. Bevisar att vi inte tyst kallar det 'safe'."""

    c, up = _de_rig(FailureMode.permissive)
    payload = gzip.compress(b'{"p":"ofarlig"}')
    r = c.post("/test/v1/messages", content=payload,
               headers={"content-encoding": "gzip"})
    assert r.status_code == 200
    assert up.mottaget[0]["body"] == payload      # orörd, byte-identisk


def test_E_identity_encoding_inspekteras_som_vanligt() -> None:
    """content-encoding: identity är inte en kodning → vanlig inspektion gäller."""
    c, up = _de_rig(FailureMode.balanced)
    r = c.post("/test/v1/messages", content=f'{{"p":"{RA}"}}'.encode(),
               headers={"content-encoding": "identity"})
    assert r.status_code == 403                   # inspekteras → hemlighet fångas
    assert not up.mottaget


# =========================================================================
# F — Scanner-resursgränser (rlimit-preexec) — CPU/filstorlek, EJ adressrymd
# =========================================================================

def test_F_resursgrans_satter_cpu_och_filstorlek(monkeypatch) -> None:
    """preexec:n sätter RLIMIT_CPU + RLIMIT_FSIZE — och rör INTE RLIMIT_AS (svälter semgrep)."""

    satta = {}

    def _fanga(vilken, par):
        satta[vilken] = par

    monkeypatch.setattr(resource, "setrlimit", _fanga)
    fn = resursgrans(cpu=42, fstorlek=1234)
    fn()
    assert satta[resource.RLIMIT_CPU] == (42, 42)
    assert satta[resource.RLIMIT_FSIZE] == (1234, 1234)
    assert resource.RLIMIT_AS not in satta        # medvetet osatt


def test_F_resursgrans_no_op_utan_resource(monkeypatch) -> None:
    """Plattform utan `resource` (Windows) → None (timeout gäller fortfarande), ingen krasch."""
    monkeypatch.setattr(rmod, "resource", None)
    assert rmod.resursgrans() is None


def test_F_adaptrar_anvander_preexec() -> None:
    """Alla tre externa scanner-adaptrar binder resursgrans som preexec_fn på sitt scan-anrop."""

    for cls, metod in [(GitleaksAdapter, "_kor"), (SemgrepAdapter, "skanna"),
                       (OsvAdapter, "skanna")]:
        kall = _inspect.getsource(getattr(cls, metod))
        assert "preexec_fn=resursgrans()" in kall, f"{cls.__name__}.{metod} saknar rlimit"


def test_F_semgrep_svalts_inte_av_gransen(tmp_path: Path) -> None:
    """Regression: semgrep måste fortfarande KUNNA KÖRA med gränserna aktiva (RLIMIT_AS-fällan).
    Hoppas om semgrep inte är installerat — men kör på riktigt när det finns."""
    a = SemgrepAdapter()
    if not a.tillganglig():
        pytest.skip("semgrep ej installerat i miljön")
    (tmp_path / "x.py").write_text("import os\nos.system('echo hej')\n")
    fynd = a.skanna(tmp_path, "proj")              # ska returnera lista, inte krascha/svältas
    assert isinstance(fynd, list)


# =========================================================================
# G — Token aldrig i stdout, bunden audit, ingen cross-projekt-.env, supply chain
# =========================================================================

def test_G_skriv_token_skapar_0600_fil(tmp_path: Path) -> None:
    """Token skrivs till fil med behörighet 0600 (bara ägaren kan läsa)."""
    f = tmp_path / "sub" / "proxy-token"
    skriv_token("hemlig-token-abc", f)
    assert f.read_text() == "hemlig-token-abc"
    assert oct(f.stat().st_mode & 0o777) == "0o600"


def test_G_main_skriver_inte_token_till_stdout(monkeypatch, tmp_path: Path, capsys) -> None:
    """proxy.main(): en autogenererad token hamnar i en 0600-fil, ALDRIG i stdout."""
    monkeypatch.delenv("SERRIER_PROXY_TOKEN", raising=False)
    tokenfil = tmp_path / "proxy-token"
    monkeypatch.setenv("SERRIER_PROXY_TOKEN_FILE", str(tokenfil))
    monkeypatch.setattr(pmod.uvicorn, "run", lambda *a, **k: None)   # starta inte servern
    pmod.main()
    token = tokenfil.read_text()
    assert token                                   # token skrevs till fil
    assert token not in capsys.readouterr().out    # men syns ALDRIG i stdout


def test_G_audit_ar_bunden_ringbuffert() -> None:
    """Audit-loggen växer inte obegränsat: deque(maxlen) kastar äldsta vid taket."""

    px = GuardProxy(klient=httpx.AsyncClient(), allowlist=[Upstream("t", "https://x.test")])
    assert isinstance(px.audit, deque)
    assert px.audit.maxlen == _AUDIT_MAX
    for i in range(_AUDIT_MAX + 50):
        px.audit.append({"i": i})
    assert len(px.audit) == _AUDIT_MAX             # taket håller
    assert px.audit[-1]["i"] == _AUDIT_MAX + 49    # nyaste kvar
    assert px.audit[0]["i"] == 50                  # äldsta 50 utslängda


def test_G_analyst_laser_inte_cross_projekt_env(monkeypatch, tmp_path: Path) -> None:
    """ladda_nyckel() läser ENBART miljön — aldrig ~/selvra-analysis/.env el. annan katalog."""
    # Lägg en .env i ett fejk-hem; den får INTE plockas upp.
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    (tmp_path / "selvra-analysis").mkdir()
    (tmp_path / "selvra-analysis" / ".env").write_text("ANTHROPIC_API_KEY=sk-LACKT\n")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert analyst.ladda_nyckel() is False         # ingen fallback → False
    assert os.environ.get("ANTHROPIC_API_KEY") is None   # miljön förorenades inte
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-riktig")
    assert analyst.ladda_nyckel() is True


def test_G_analyst_kallkod_namner_inte_selvra_analysis() -> None:
    """Regression: källan får inte återinföra cross-projekt-sökvägen."""
    src = (REPO / "backend" / "serrier" / "analyst.py").read_text()
    assert "selvra-analysis" not in src


def test_G_dockerfile_pinnar_och_verifierar() -> None:
    """Dockerfile: pinnade versioner, SHA256-verifiering av scanners, uv ej :latest."""
    df = (REPO / "backend" / "Dockerfile").read_text()
    assert "sha256sum -c" in df                    # checksum-verifiering finns
    assert "GITLEAKS_SHA256=" in df                 # gitleaks-hash pinnad
    assert "OSV_SHA256=" in df                       # osv-hash pinnad
    assert "uv:latest" not in df                   # uv pinnad, inte latest
    assert "semgrep==" in df                        # semgrep pinnad

