"""Tray-klientens RENA logik (Design 0004, steg 2). GUI:t (pystray) kräver en display och
testas inte här; tray_status() + titeln är rena och testbara. Syntetisk data."""

import os

from serrier.db.store import Store
from serrier.guardian import daemon, tray
from serrier.guardian.tray import tray_status


def _flytta_hem(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(daemon, "_PID", tmp_path / "daemon.pid")


def test_status_avstangd_nar_ingen_daemon(monkeypatch, tmp_path) -> None:
    _flytta_hem(monkeypatch, tmp_path)
    monkeypatch.setenv("SERRIER_DB_URL", "sqlite:///:memory:")   # tom DB
    s = tray_status()
    assert s["igang"] is False
    assert s["antal"] == 0
    assert s["tally"]["block"] == 0
    assert "avstängd" in tray._titel(s)


def test_status_speglar_daemon_och_tally(monkeypatch, tmp_path) -> None:
    _flytta_hem(monkeypatch, tmp_path)
    (tmp_path / "daemon.pid").write_text(str(os.getpid()))        # "levande" daemon
    db = tmp_path / "ev.db"
    monkeypatch.setenv("SERRIER_DB_URL", f"sqlite:///{db}")
    st = Store(f"sqlite:///{db}")
    org = st.dev_org()
    st.spara_guard_event(org, action="block", analysis_status="ok")
    st.spara_guard_event(org, action="allow", analysis_status="ok")
    s = tray_status()
    assert s["igang"] is True
    assert s["antal"] == 2
    assert s["tally"]["block"] == 1
    assert s["tally"]["allow"] == 1
    assert "på" in tray._titel(s)
