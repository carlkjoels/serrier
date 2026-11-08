"""semgrep-adapter — osäker (ofta AI-genererad) kod. Kör semgrep med en EGEN lokal
regeluppsättning (deterministiskt, offline; `--config auto` mot registret kan läggas
till som läge senare). Subprocess med argv (ingen shell), timeout, graceful degradation.
semgrep läser kod som text — ingenting körs (otrodd data)."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from serrier.core.findings import Category, Confidence, Evidence, Finding, Severity
from serrier.scanners.base import inom_roten

_TIMEOUT = 180
_REGLER = Path(__file__).parent / "semgrep_rules" / "serrier.yaml"
_SEV = {"ERROR": Severity.high, "WARNING": Severity.medium, "INFO": Severity.low}
# regel-prefix → kategori (resten = injection)
_KATEGORI = {"flask-debug": Category.config, "requests-verify": Category.config}


class SemgrepAdapter:
    namn = "semgrep"

    def __init__(self, regler: str | Path | None = None, binar: str | None = None) -> None:
        self._regler = str(regler or _REGLER)
        self._binar = binar or self._hitta()

    @staticmethod
    def _hitta() -> str | None:
        pa_path = shutil.which("semgrep")                      # extern (uv tool / system)
        if pa_path:
            return pa_path
        kandidat = Path(sys.executable).with_name("semgrep")   # fallback: samma venv
        return str(kandidat) if kandidat.exists() else None

    def tillganglig(self) -> bool:
        if not self._binar:
            return False
        try:
            subprocess.run([self._binar, "--version"], capture_output=True,  # noqa: S603
                           timeout=30, check=True)
        except (OSError, subprocess.SubprocessError):
            return False
        return True

    def skanna(self, projekt_rot: Path, project_id: str) -> list[Finding]:
        if not self.tillganglig():
            return []
        try:
            r = subprocess.run(  # noqa: S603 — argv, ingen shell, binär vi kontrollerar
                [self._binar, "scan", "--config", self._regler, "--json", "--quiet",
                 "--disable-version-check", str(projekt_rot)],
                capture_output=True, text=True, timeout=_TIMEOUT, check=False)
            data = json.loads(r.stdout) if r.stdout.strip() else {"results": []}
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
            return []
        return [self._till_finding(x, projekt_rot, project_id) for x in data.get("results", [])]

    def _till_finding(self, x: dict, rot: Path, project_id: str) -> Finding:
        fil = Path(x.get("path", ""))
        rel = fil.resolve().relative_to(rot.resolve()).as_posix() if inom_roten(rot, fil) \
            else fil.name
        rad = x.get("start", {}).get("line", "?")
        regel = x.get("check_id", "semgrep").split(".")[-1]
        extra = x.get("extra", {})
        sev = _SEV.get(extra.get("severity", "WARNING"), Severity.medium)
        kat = next((v for k, v in _KATEGORI.items() if regel.startswith(k)), Category.injection)
        plats = f"{rel}:{rad}"
        return Finding(
            project_id=project_id, category=kat, detector=self.namn, severity=sev,
            confidence=Confidence.probable, asset_ref=plats, title=f"semgrep: {regel}",
            rule=regel,
            evidence=[Evidence.av(source=self.namn, location=plats, detection_method=regel,
                                  confidence=Confidence.probable,
                                  ra_innehall=str(extra.get("message", regel)))])
