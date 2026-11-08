"""Scraping-skannern (modul B): TLS-av, proxy-creds, skrapat-innehåll-till-LLM.
Syntetisk kod."""

from pathlib import Path

from serrier.core.findings import Category, Severity
from serrier.scanners.base import Scanner
from serrier.scanners.scraping import ScrapingSakerhetsskanner

SK = ScrapingSakerhetsskanner()


def test_uppfyller_protokollet() -> None:
    assert isinstance(SK, Scanner)
    assert SK.tillganglig() is True


def test_tls_av(tmp_path: Path) -> None:
    (tmp_path / "scrape.py").write_text("r = requests.get(url, verify=False)\n")
    f = SK.skanna(tmp_path, "p1")
    assert any(x.rule == "tls-verification-disabled" and x.category == Category.config
               and x.severity == Severity.high for x in f)


def test_proxy_med_credentials_redaktas(tmp_path: Path) -> None:
    (tmp_path / "cfg.py").write_text('PROXY = "http://scrapeuser:hemligt@proxy.example:8080"\n')
    f = SK.skanna(tmp_path, "p1")
    träff = [x for x in f if x.rule == "proxy-credentials-in-url"]
    assert träff
    assert träff[0].category == Category.secret
    assert "hemligt" not in träff[0].evidence[0].redacted_content   # creds redaktade


def test_skrapat_innehall_till_llm_prompt(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "html = requests.get(url).text\n"
        "messages = [{'role':'user','content': html}]\n")   # skrapat → prompt
    f = SK.skanna(tmp_path, "p1")
    assert any(x.rule == "scraped-content-to-llm-prompt" and x.category == Category.injection
               for x in f)


def test_ren_kod_ger_inget(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("r = requests.get(url, verify=True, timeout=10)\n")
    assert SK.skanna(tmp_path, "p1") == []
