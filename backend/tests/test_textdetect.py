"""Delad textdetektions-kärna (core/textdetect). Yt-agnostisk: pinnar hemlighets-
mönstren, placeholder-filtret och span-anspråket som både fil-skannern och Guardian
delar. Syntetisk data."""

import re

from serrier.core.findings import Category, Confidence, Severity
from serrier.core.textdetect import HEMLIGHETER, Monster, detektera_rad


def test_hittar_specifik_nyckel_hog_confidence() -> None:
    t = detektera_rad("ANTHROPIC_API_KEY=sk-ant-api03-REALSECRET1234567890abcDEF")
    assert len(t) == 1
    assert t[0].regel == "anthropic-api-key"
    assert t[0].kategori == Category.secret
    assert t[0].severity == Severity.critical
    assert t[0].confidence == Confidence.confirmed
    assert t[0].text.startswith("sk-ant-")


def test_placeholder_flaggas_inte() -> None:
    assert detektera_rad("api_key = your_api_key_here") == []
    assert detektera_rad("password = ${DB_PASSWORD}") == []
    assert detektera_rad("token = os.environ['TOKEN']") == []


def test_span_ansprak_ingen_dubbelmatch() -> None:
    # "api_key=sk-ant-…" matchar BÅDE anthropic-nyckel (specifik) och generic-secret-
    # assignment — överlappande spann. Specifik listas först, anspråkar; generisk hoppas.
    t = detektera_rad("api_key=sk-ant-api03-REALSECRET1234567890abcDEF")
    assert len(t) == 1
    assert t[0].regel == "anthropic-api-key"


def test_spann_pekar_pa_traffen() -> None:
    rad = "x = sk-ant-api03-REALSECRET1234567890abcDEF"
    t = detektera_rad(rad)[0]
    assert rad[t.start:t.slut] == t.text                     # spann redakterbart


def test_utbytbar_monsterlista() -> None:
    # Guardian komponerar egna mönster över samma motor.
    pii = [Monster("mejl", Category.info, Severity.medium, Confidence.probable,
                   re.compile(r"[\w.]+@[\w.]+\.\w+"))]
    t = detektera_rad("kontakt: a@b.se", pii)
    assert len(t) == 1
    assert t[0].regel == "mejl"
    assert t[0].text == "a@b.se"


def test_hemligheter_ar_default() -> None:
    assert all(isinstance(m, Monster) for m in HEMLIGHETER)
    assert any(m.regel == "aws-access-key-id" for m in HEMLIGHETER)
