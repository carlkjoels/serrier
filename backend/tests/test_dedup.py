"""Dedup: samma id slås ihop (evidens), olika id behålls."""
from serrier.core.findings import Category, Confidence, Finding, Severity
from serrier.ingest.dedup import deduplicera


def _f(asset: str) -> Finding:
    return Finding(project_id="p1", category=Category.secret, detector="builtin",
                   severity=Severity.high, confidence=Confidence.probable,
                   asset_ref=asset, title="x", rule="r1")


def test_samma_id_slas_ihop() -> None:
    a, b, c = _f(".env:1"), _f(".env:1"), _f(".env:2")
    ut = deduplicera([a, b, c])
    assert len(ut) == 2                        # .env:1 slogs ihop, .env:2 separat
