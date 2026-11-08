"""Latens-budget för Guardian (steg 5). inspect() ligger på den synkrona skicka-vägen —
för hög latens → användaren stänger av skyddet (hotmodell G4). Mäter medianlatens på en
representativ ~2 kB-text och håller den under budget. Siffran skrivs ut (syntetisk)."""

import statistics
import time

from serrier.guardian.inspect import inspect

_BUDGET_MS = 50.0        # typisk inspektion ska vara klart under detta


def _representativ_text() -> str:
    rader = [f"rad {i}: lite helt vanlig loggtext utan något känsligt alls här" for i in range(30)]
    rader.insert(10, "nyckel sk-ant-api03-REALSECRET1234567890abcDEF")
    rader.insert(20, "kund anna@foretag.se kort 4111 1111 1111 1111 pnr 810118-9879")
    return "\n".join(rader)


def test_median_latens_under_budget() -> None:
    text = _representativ_text()
    mätningar = []
    for _ in range(50):
        start = time.perf_counter()
        inspect(text)
        mätningar.append((time.perf_counter() - start) * 1000)
    median = statistics.median(mätningar)
    p95 = sorted(mätningar)[int(len(mätningar) * 0.95)]
    print(f"\n[syntetisk] inspect-latens median={median:.2f}ms p95={p95:.2f}ms "
          f"(~{len(text)} tecken, budget {_BUDGET_MS}ms)")
    assert median < _BUDGET_MS, f"median {median:.1f}ms över budget {_BUDGET_MS}ms"
