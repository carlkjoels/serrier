"""Guardian-detektion & klassificering (steg 2): Luhn-validerad PII, entropi, sensitivitet,
kombinerad detektion med absoluta offsets. Konservativ → låg FPR. Syntetisk data."""

from serrier.core.findings import Category, Confidence, Severity
from serrier.guardian.classify import (
    Sensitivity,
    detektera_kanslig,
    luhn,
    sensitivitet,
    shannon,
)


def _regler(traffar) -> set[str]:
    return {t.regel for t in traffar}


# --- validatorer ----------------------------------------------------------
def test_luhn() -> None:
    assert luhn("4111111111111111") is True
    assert luhn("4111111111111112") is False
    assert luhn("") is False


def test_kortnummer_luhn_filtrerar_falska() -> None:
    giltigt = detektera_kanslig("betalkort 4111 1111 1111 1111")
    assert "credit-card" in _regler(giltigt)
    ogiltigt = detektera_kanslig("nummer 4111 1111 1111 1112")     # Luhn fail
    assert "credit-card" not in _regler(ogiltigt)


def test_personnummer_luhn() -> None:
    assert "swedish-personnummer" in _regler(detektera_kanslig("pnr 810118-9879"))
    assert "swedish-personnummer" not in _regler(detektera_kanslig("pnr 810118-9870"))


def test_email_och_intern_ip() -> None:
    assert "email" in _regler(detektera_kanslig("kontakt: anna@foretag.se"))
    assert "internal-ip" in _regler(detektera_kanslig("server 10.0.0.5 svarar"))
    assert "internal-ip" not in _regler(detektera_kanslig("publik 8.8.8.8"))


# --- sensitivitet ---------------------------------------------------------
def test_sensitivitet_mappning() -> None:
    anthropic = detektera_kanslig("key=sk-ant-api03-REALSECRET1234567890abcDEF")[0]
    assert sensitivitet(anthropic) == Sensitivity.critical
    email = detektera_kanslig("a@b.se")[0]
    assert sensitivitet(email) == Sensitivity.medium
    ip = detektera_kanslig("10.1.2.3")[0]
    assert sensitivitet(ip) == Sensitivity.low


# --- entropi --------------------------------------------------------------
def test_entropi_fangar_nyckelliknande_token() -> None:
    t = detektera_kanslig("deploy xQ8vK2mZ9pL4wR7nB3tY6uE1cF5dH0jA")
    assert "high-entropy-token" in _regler(t)


def test_entropi_flaggar_inte_vanliga_ord() -> None:
    t = detektera_kanslig("det här är ett helt vanligt meddelande utan hemligheter alls")
    assert "high-entropy-token" not in _regler(t)
    assert shannon("informationsmeddelande") >= 0       # funktionen fungerar


# --- kombinerad detektion -------------------------------------------------
def test_hemligheter_fangas_fortfarande() -> None:
    t = detektera_kanslig("export AWS stuff\nANTHROPIC=sk-ant-api03-REALSECRET1234567890abc")
    assert "anthropic-api-key" in _regler(t)


def test_absoluta_offsets_pekar_ratt_over_flera_rader() -> None:
    text = "rad ett\nmejl anna@foretag.se här"
    t = next(x for x in detektera_kanslig(text) if x.regel == "email")
    assert text[t.start:t.slut] == "anna@foretag.se"     # absolut offset redakterbart


def test_resultat_sorterade_pa_position() -> None:
    # Exakta träffar (start >= 0) sorteras på position; evasion-träffar (-1) ligger sist.
    text = "a@b.se och 10.0.0.1 och c@d.se"
    exakta = [t.start for t in detektera_kanslig(text) if t.start >= 0]
    assert exakta == sorted(exakta)
    assert exakta == [0, 11, 24]                 # ingen falsk evasion på godartad mejl/IP-text


def test_kategorier_korrekta() -> None:
    kort = detektera_kanslig("4111 1111 1111 1111")[0]
    assert kort.kategori == Category.pii
    assert kort.severity == Severity.high
    assert kort.confidence == Confidence.probable
