"""osv-scanner-adapter — kända sårbarheter i beroenden (lockfiler). Subprocess med argv,
timeout, graceful degradation. En känd CVE-match = hög confidence (confirmed). En live-
scan frågar osv.dev (nät); parsningen är fristående och deterministiskt testbar."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from serrier.core.findings import Category, Confidence, Evidence, Finding, Severity
from serrier.scanners.base import inom_roten
from serrier.scanners.resurser import resursgrans

_TIMEOUT = 180
_SEV = {"CRITICAL": Severity.critical, "HIGH": Severity.high, "MODERATE": Severity.medium,
        "MEDIUM": Severity.medium, "LOW": Severity.low}


def _sev_av(v: dict) -> Severity:
    s = (v.get("database_specific", {}) or {}).get("severity", "")
    return _SEV.get(str(s).upper(), Severity.high)        # känd sårbarhet → minst high


def findings_fran_json(data: dict, rot: Path, project_id: str) -> list[Finding]:
    """osv-scanner JSON → Findings. Fristående (ingen subprocess) → deterministiskt testbar."""
    ut: list[Finding] = []
    for res in data.get("results", []):
        kalla = Path(res.get("source", {}).get("path", "?"))
        rel = kalla.resolve().relative_to(rot.resolve()).as_posix() \
            if inom_roten(rot, kalla) else kalla.name
        for pkg in res.get("packages", []):
            namn = pkg.get("package", {}).get("name", "?")
            ver = pkg.get("package", {}).get("version", "?")
            for v in pkg.get("vulnerabilities", []):
                vid = v.get("id", "OSV")
                plats = f"{rel}:{namn}@{ver}"
                ut.append(Finding(
                    project_id=project_id, category=Category.dependency, detector="osv-scanner",
                    severity=_sev_av(v), confidence=Confidence.confirmed, asset_ref=plats,
                    title=f"{vid}: {namn} {ver}", rule=vid,
                    evidence=[Evidence.av(source="osv-scanner", location=plats,
                                          detection_method=vid, confidence=Confidence.confirmed,
                                          ra_innehall=str(v.get("summary") or vid))]))
    return ut


class OsvAdapter:
    namn = "osv-scanner"

    def __init__(self, binar: str | Path | None = None, *, offline: bool | None = None) -> None:
        self._binar = str(binar) if binar else self._hitta()
        # Live-läge frågar osv.dev (nät). Offline-läge använder en lokal DB — ingen nät-
        # fråga, deterministiskt i luftgapade miljöer. Opt-in via SERRIER_OSV_OFFLINE.
        self._offline = offline if offline is not None \
            else bool(os.environ.get("SERRIER_OSV_OFFLINE"))

    def _scan_args(self, rot: Path) -> list[str]:
        args = [self._binar, "scan", "source", "--format", "json", "-r"]
        if self._offline:
            args += ["--offline-vulnerabilities", "--no-resolve"]
        return [*args, str(rot)]

    @staticmethod
    def _hitta() -> str | None:
        lokal = Path(__file__).resolve().parents[2] / ".tools" / "osv-scanner"
        return str(lokal) if lokal.exists() else shutil.which("osv-scanner")

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
            r = subprocess.run(self._scan_args(projekt_rot),  # noqa: S603 — argv, ingen shell
                capture_output=True, text=True, timeout=_TIMEOUT, check=False,
                preexec_fn=resursgrans())  # F: CPU/filstorleks-rlimit i barnet
            data = json.loads(r.stdout) if r.stdout.strip() else {"results": []}
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
            return []
        return findings_fran_json(data, projekt_rot, project_id)
