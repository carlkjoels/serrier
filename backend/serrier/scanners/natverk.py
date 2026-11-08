"""Modul C — Nätverks-/VPN-posture för ANVÄNDARENS EGNA maskin (auktoriserad per
definition — det är deras dator). INGA externa prober, inget skanns av främmande
system. Rena analysfunktioner över lokalt insamlad data (ss, interfaces, resolv.conf)
+ en tunn insamlare. Varje fynd förklaras. VPN ≠ anonymitet."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

_VPN_IFACE = re.compile(r"^(tun|tap|wg|ppp|nordlynx|proton|mullvad)\d*")
_LOKALA = {"127.0.0.1", "::1", "[::1]"}
_MIN_SS_FALT = 4   # LISTEN Recv-Q Send-Q Local-Address:Port ...


def vpn_aktiv(interfaces: list[str]) -> bool:
    return any(_VPN_IFACE.match(i) for i in interfaces)


def exponerade_portar(ss_output: str) -> list[dict]:
    """Parsar `ss -tlnH`: lyssnande TCP-portar. Bundna till 0.0.0.0/:: = nåbara från
    NÄTVERKET (exponerade); 127.0.0.1/::1 = bara lokalt."""
    ut: list[dict] = []
    for rad in ss_output.splitlines():
        delar = rad.split()
        if len(delar) < _MIN_SS_FALT:
            continue
        adress, _, port = delar[3].rpartition(":")
        exponerad = adress not in _LOKALA and not adress.startswith("127.")
        ut.append({"port": port, "adress": adress, "exponerad": exponerad})
    return ut


def dns_servrar(resolv_conf: str) -> list[str]:
    return [r.split()[1] for r in resolv_conf.splitlines()
            if r.startswith("nameserver") and len(r.split()) > 1]


def posture(ss_output: str, interfaces: list[str], resolv_conf: str) -> dict:
    exp = [p for p in exponerade_portar(ss_output) if p["exponerad"]]
    return {
        "vpn_aktiv": vpn_aktiv(interfaces),
        "exponerade_portar": exp,
        "antal_exponerade": len(exp),
        "dns_servrar": dns_servrar(resolv_conf),
        "forklaringar": {
            "vpn": ("Ett aktivt VPN döljer din IP mot destinationen. Men VPN ≠ anonymitet: "
                    "DNS, inloggningar och trafikmönster kan ändå identifiera dig."),
            "exponerade_portar": ("Portar bundna till 0.0.0.0/:: är nåbara från nätverket, "
                                  "inte bara localhost. Minimera dem; bind till 127.0.0.1 "
                                  "om tjänsten bara behövs lokalt."),
            "dns": ("DNS-servrarna ser dina uppslag. Utanför VPN kan de läcka vilka "
                    "sajter du besöker."),
        },
        "ansvarsfriskrivning": "Bedömer endast DENNA maskin. Säger inget om fjärrsystem.",
    }


def samla() -> tuple[str, list[str], str]:
    """Tunn, live insamling av DENNA maskins data. Fel → tomt (graceful)."""
    try:
        ss = subprocess.run(["ss", "-tlnH"], capture_output=True,  # noqa: S607
                            text=True, timeout=10, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        ss = ""
    net = Path("/sys/class/net")
    interfaces = [p.name for p in net.iterdir()] if net.is_dir() else []
    resolv = Path("/etc/resolv.conf")
    return ss, interfaces, (resolv.read_text() if resolv.exists() else "")
