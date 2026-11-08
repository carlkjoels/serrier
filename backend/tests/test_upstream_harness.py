"""Verifiera testharnessen SJÄLV innan proxyn byggs (Design 0002: harness före proxy).
Om bytes-räknaren inte är pålitlig är inget prevention-bevis pålitligt."""

from starlette.testclient import TestClient
from upstream_harness import KontrolleradUpstream


def test_registrerar_exakta_bytes() -> None:
    up = KontrolleradUpstream()
    c = TestClient(up.app())
    r = c.post("/v1/messages", content=b'{"secret":"sk-ant-XXX"}')
    assert r.status_code == 200
    assert up.antal_bytes == len(b'{"secret":"sk-ant-XXX"}')
    assert up.mottaget[0]["path"] == "/v1/messages"
    assert up.innehaller(b"sk-ant-XXX")


def test_tom_nar_inget_skickats() -> None:
    up = KontrolleradUpstream()
    assert up.antal_bytes == 0
    assert up.innehaller(b"any") is False
