"""Mätning av detektionskvalitet mot ett facit (ground truth): precision, recall,
falska positiva. Briefen kräver att vi MÄTER detektionen, inte bara påstår att den
fungerar. Signaturen (fil, kategori) gör att flera detektorer som hittar samma problem
på samma ställe räknas en gång (inte som dubbel träff eller falskt positivt)."""

from __future__ import annotations

from serrier.core.findings import Finding


def _sig(f: Finding) -> tuple[str, str]:
    return (f.asset_ref.split(":")[0], str(f.category))


def matning(funna: list[Finding], facit: set[tuple[str, str]]) -> dict:
    """Jämför funna findings mot facit. precision = andel funna som är äkta; recall =
    andel av facit som hittades; falska_positiva/missade listas explicit."""
    funna_sig = {_sig(f) for f in funna}
    tp = funna_sig & facit
    return {
        "precision": len(tp) / len(funna_sig) if funna_sig else (1.0 if not facit else 0.0),
        "recall": len(tp) / len(facit) if facit else 1.0,
        "falska_positiva": sorted(funna_sig - facit),
        "missade": sorted(facit - funna_sig),
        "tp": len(tp), "antal_funna": len(funna_sig), "antal_facit": len(facit),
    }
