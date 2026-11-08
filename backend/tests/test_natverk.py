"""Modul C — nätverks-posture. Rena analysfunktioner över kanad data (ingen live-
insamling i testet). Syntetisk data."""

from serrier.scanners import natverk

SS = (
    "LISTEN 0 128 0.0.0.0:8000 0.0.0.0:*\n"      # exponerad
    "LISTEN 0 128 127.0.0.1:5432 0.0.0.0:*\n"    # bara lokalt
    "LISTEN 0 128 [::]:443 [::]:*\n"             # exponerad (IPv6)
)


def test_exponerade_portar() -> None:
    p = natverk.exponerade_portar(SS)
    exp = [x for x in p if x["exponerad"]]
    portar = {x["port"] for x in exp}
    assert portar == {"8000", "443"}            # 5432 (127.0.0.1) räknas EJ som exponerad


def test_vpn_aktiv() -> None:
    assert natverk.vpn_aktiv(["eth0", "wg0", "lo"]) is True
    assert natverk.vpn_aktiv(["eth0", "lo"]) is False


def test_dns_servrar() -> None:
    conf = "nameserver 10.255.255.254\nnameserver 1.1.1.1\n# kommentar\n"
    assert natverk.dns_servrar(conf) == ["10.255.255.254", "1.1.1.1"]


def test_posture_forklarar_och_friskriver() -> None:
    p = natverk.posture(SS, ["wg0", "eth0"], "nameserver 1.1.1.1\n")
    assert p["vpn_aktiv"] is True
    assert p["antal_exponerade"] == 2
    assert "anonymitet" in p["forklaringar"]["vpn"]        # VPN ≠ anonymitet
    assert "DENNA maskin" in p["ansvarsfriskrivning"]      # bedömer bara egen maskin
