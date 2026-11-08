"""Auth-primitiver: rollhierarki, nyckelgenerering, hashning. Rena funktioner — ingen
DB, inget FastAPI — så behörighetslogiken kan testas isolerat.

Säkerhet: råa nycklar lagras aldrig (vi hashar med sha256; nycklarna är hög-entropi,
så ingen salt/KDF behövs — det här är inte lösenord). Jämförelse sker i konstant tid.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from enum import IntEnum

_NYCKELPREFIX = "srk_"   # serrier key — igenkännbart i loggar/leak-skanners


class Roll(IntEnum):
    """Hierarkisk: ett högre tal får allt ett lägre får. Lagras som namn i DB."""
    viewer = 1    # läsa findings/posture
    member = 2    # + köra scan, sätta status, be om åtgärdsförslag
    owner = 3     # + hantera nycklar och projekt

    @classmethod
    def fran_namn(cls, namn: str) -> Roll:
        try:
            return cls[namn]
        except KeyError as e:
            raise ValueError(f"okänd roll: {namn}") from e


def far(roll: Roll, kravd: Roll) -> bool:
    """Har `roll` minst behörigheten `kravd`?"""
    return roll >= kravd


def generera_nyckel() -> str:
    """Ny rå nyckel. Visas en gång; bara hashen sparas."""
    return _NYCKELPREFIX + secrets.token_urlsafe(32)


def hasha(rå_nyckel: str) -> str:
    return hashlib.sha256(rå_nyckel.encode()).hexdigest()


def hash_matchar(rå_nyckel: str, lagrad_hash: str) -> bool:
    return hmac.compare_digest(hasha(rå_nyckel), lagrad_hash)


@dataclass(frozen=True)
class Principal:
    """Den autentiserade anroparen: vilken org och vilken roll. Dev-läge ger en
    owner-principal i en dev-org så MVP-flödet funkar utan nycklar."""
    org_id: str
    roll: Roll
    dev: bool = False
