"""Rapport-export. SARIF 2.1.0 (standarden kodläsare/CI/GitHub förstår) och ren JSON.
Rena funktioner över finding-dicts (store.lista_findings) → deterministiskt, testbart.

Säkerhet: exporten bär BARA redaktad evidens — råa hemligheter finns aldrig i dessa
dicts (de redaktades vid detektion), så en SARIF-fil kan delas utan att läcka något.
"""

from __future__ import annotations

_VERSION = "0.0.1"
_INFO_URI = "https://github.com/carlkjoels/serrier"

# severity → SARIF-nivå. SARIF har bara error/warning/note; vi mappar transparent.
_NIVA = {"critical": "error", "high": "error", "medium": "warning",
         "low": "note", "info": "note"}


def _uri_och_rad(asset_ref: str) -> tuple[str, int | None]:
    """Dela 'fil:rad' → (fil, rad). 'fil:pkg@ver' (osv) → (fil, None). Posix-sökvägar
    har inga kolon, så första segmentet är filen."""
    fil, _, svans = asset_ref.partition(":")
    return fil, int(svans) if svans.isdigit() else None


def _meddelande(f: dict) -> str:
    red = f.get("evidence") or []
    svans = f" [{red[0]['redacted_content']}]" if red else ""
    return f"{f['title']} ({f['detector']}, {f['confidence']}){svans}"


def till_sarif(findings: list[dict]) -> dict:
    """Findings → SARIF 2.1.0. Regler dedupas på rule-id; varje result pekar på en
    plats och bär severity/confidence/status som properties (aldrig ihopblandade)."""
    regler: dict[str, dict] = {}
    results: list[dict] = []
    for f in findings:
        rid = f["rule"] or f["category"]
        regler.setdefault(rid, {
            "id": rid,
            "name": rid,
            "shortDescription": {"text": f["title"]},
            "properties": {"category": f["category"]},
        })
        uri, rad = _uri_och_rad(f["asset_ref"])
        region = {"startLine": rad} if rad else {}
        results.append({
            "ruleId": rid,
            "level": _NIVA.get(f["severity"], "warning"),
            "message": {"text": _meddelande(f)},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": uri},
                **({"region": region} if region else {}),
            }}],
            "properties": {
                "serrierId": f["id"], "severity": f["severity"],
                "confidence": f["confidence"], "status": f["status"],
                "detector": f["detector"], "aterkomster": f.get("aterkomster", 0),
            },
        })
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "Serrier", "version": _VERSION, "informationUri": _INFO_URI,
                "rules": list(regler.values()),
            }},
            "results": results,
        }],
    }


def till_json(findings: list[dict]) -> dict:
    """Ren JSON-export: metadata + findings (redan redaktade)."""
    return {"tool": "serrier", "version": _VERSION,
            "antal": len(findings), "findings": findings}
