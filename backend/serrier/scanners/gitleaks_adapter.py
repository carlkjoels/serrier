"""gitleaks-adapter. Kör gitleaks som subprocess (argv-array, ALDRIG shell → skydd mot
command injection, THREAT_MODEL T3), med timeout (T8) och `--redact` så den råa
hemligheten aldrig ens når Serrier (defense in depth). Saknas binären → tom lista +
täckningsgräns, ingen krasch (graceful degradation)."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from serrier.core.findings import Category, Confidence, Evidence, Finding, Severity
from serrier.scanners.base import inom_roten

_TIMEOUT = 180


class GitleaksAdapter:
    namn = "gitleaks"

    def __init__(self, binar: str | Path | None = None) -> None:
        self._binar = str(binar) if binar else self._hitta()

    @staticmethod
    def _hitta() -> str | None:
        lokal = Path(__file__).resolve().parents[2] / ".tools" / "gitleaks"
        return str(lokal) if lokal.exists() else shutil.which("gitleaks")

    def tillganglig(self) -> bool:
        if not self._binar:
            return False
        try:
            subprocess.run([self._binar, "version"], capture_output=True,  # noqa: S603
                           timeout=10, check=True)
        except (OSError, subprocess.SubprocessError):
            return False
        return True

    def skanna(self, projekt_rot: Path, project_id: str) -> list[Finding]:
        """Working tree (nuvarande filer)."""
        return self._kor(["dir", str(projekt_rot)], projekt_rot, project_id, self.namn)

    def skanna_historik(self, repo: Path, project_id: str) -> list[Finding]:
        """Git-HISTORIKEN: hemligheter som committats — även om de tagits bort ur working
        tree ligger de kvar i historiken och är fortfarande komprometterade."""
        return self._kor(["git", str(repo)], repo, project_id, "gitleaks-history")

    def _kor(self, delkommando: list[str], rot: Path, project_id: str,
             detektor: str) -> list[Finding]:
        if not self.tillganglig():
            return []
        with tempfile.TemporaryDirectory() as td:
            rapport = Path(td) / "gitleaks.json"
            try:
                subprocess.run(  # noqa: S603 — argv-array, ingen shell, binär vi kontrollerar
                    [self._binar, *delkommando, "--report-format", "json",
                     "--report-path", str(rapport), "--redact"],
                    capture_output=True, timeout=_TIMEOUT, check=False)
                data = json.loads(rapport.read_text()) if rapport.exists() else []
            except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
                return []
        return [self._till_finding(x, rot, project_id, detektor) for x in data]

    def _till_finding(self, x: dict, rot: Path, project_id: str, detektor: str) -> Finding:
        fil = Path(x.get("File", ""))
        rel = fil.resolve().relative_to(rot.resolve()).as_posix() if inom_roten(rot, fil) \
            else fil.name
        commit = str(x.get("Commit", ""))[:8]
        plats = f"{rel}:{x.get('StartLine', '?')}" + (f"@{commit}" if commit else "")
        regel = x.get("RuleID", "gitleaks")
        return Finding(
            project_id=project_id, category=Category.secret, detector=detektor,
            severity=Severity.high, confidence=Confidence.probable, asset_ref=plats,
            title=f"{detektor}: {regel}", rule=regel,
            evidence=[Evidence.av(source=detektor, location=plats, detection_method=regel,
                                  confidence=Confidence.probable,
                                  ra_innehall=str(x.get("Secret") or x.get("Match") or regel))])
