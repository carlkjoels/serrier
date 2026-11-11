"""Resursgränser för externa scanner-subprocesser (F).

Vad detta ÄR: en ``preexec_fn`` som sätter POSIX ``rlimit`` i barnet innan ``exec`` —
en CPU-tidsgräns och en max filstorlek barnet får skapa. Tillsammans med ``timeout`` (väggklocka)
och argv-arrayer (ingen shell) begränsar det en skenande eller fientlig scanner.

Vad detta INTE är: en sandbox. Det finns ingen namespace-isolering, inget seccomp-filter,
ingen cgroup, ingen filsystems-jail. En subprocess med samma uid kan fortfarande läsa det
den anropande processen kan läsa. Vi kallar det aldrig "sandboxad" i dokumentationen —
det är resurs-*begränsning*, inte isolering. Riktig isolering (cgroups v2 / seccomp /
container) är en medvetet uppskjuten uppgradering, dokumenterad i security-limitations.md.

RLIMIT_AS (adressrymd) sätts MEDVETET INTE: semgrep/osv mmap:ar stora regelträd och svälts
ihjäl av ett lågt AS-tak (observerat: testerna gick röda). CPU + FSIZE ger DoS-skydd utan
att strypa normal drift. Gränserna är konfigurerbara och dokumenteras ärligt.

Endast POSIX: på plattformar utan ``resource`` (Windows) blir preexec en no-op och vi
förlitar oss på ``timeout`` ensamt — dokumenterat, inte dolt.
"""

from __future__ import annotations

from collections.abc import Callable

try:
    import resource
except ImportError:                                # Windows: ingen rlimit-mekanism
    resource = None  # type: ignore[assignment]

CPU_SEKUNDER = 120            # väggklocks-timeout finns separat; detta är CPU-tid
FIL_BYTES = 100 * 1024 * 1024  # 100 MB — en scanner ska aldrig skriva en jättefil


def resursgrans(*, cpu: int = CPU_SEKUNDER, fstorlek: int = FIL_BYTES) -> Callable[[], None] | None:
    """Returnera en ``preexec_fn`` som sätter CPU- och filstorleksgränser i barnet.

    Returnerar ``None`` där ``resource`` saknas (→ subprocess körs utan preexec; timeout
    gäller fortfarande). ``RLIMIT_AS`` sätts avsiktligt inte (se modul-docstring)."""
    if resource is None:
        return None

    def _satt() -> None:                           # körs i barnet mellan fork och exec
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
        resource.setrlimit(resource.RLIMIT_FSIZE, (fstorlek, fstorlek))

    return _satt
