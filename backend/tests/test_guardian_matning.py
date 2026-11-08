"""Mätning av Guardian-detektionen mot en MÄRKT SYNTETISK fixtur (ej verkliga data).
Recall över positiva fall + falska positiva över rena fall. Resultat från artificiella
fixturer redovisas separat från verkliga (direktivets krav)."""

from serrier.guardian.classify import detektera_kanslig

# (text, förväntade regel-id). Positiva: ska fångas. Rena: ska ge inget.
POSITIVA: list[tuple[str, str]] = [
    ("ANTHROPIC_API_KEY=sk-ant-api03-REALSECRET1234567890abcDEF", "anthropic-api-key"),
    ("aws id AKIA1234567890ABCDEF i configen", "aws-access-key-id"),
    ("-----BEGIN RSA PRIVATE KEY-----", "private-key-block"),
    ("betalning med 4111 1111 1111 1111", "credit-card"),
    ("personnummer 810118-9879", "swedish-personnummer"),
    ("maila mig på anna@foretag.se", "email"),
    ("interna servern 10.0.0.5", "internal-ip"),
    ("token xQ8vK2mZ9pL4wR7nB3tY6uE1cF5dH0jA", "high-entropy-token"),
]

RENA: list[str] = [
    "det här är ett helt vanligt meddelande utan något känsligt alls",
    "jag gillar att skriva kod i python på kvällarna",
    "mötet är klockan fjorton på torsdag nästa vecka",
    "publika google-dns är 8.8.8.8 vilket är helt offentligt",
    "paketet uppdaterades till version 2.19.0 igår",
    "exempelnyckeln är your_api_key_here så den räknas inte",
]


def _regler(text: str) -> set[str]:
    return {t.regel for t in detektera_kanslig(text)}


def test_recall_och_falska_positiva_pa_syntetisk_fixtur() -> None:
    träffar = sum(1 for text, regel in POSITIVA if regel in _regler(text))
    recall = träffar / len(POSITIVA)

    falska = [text for text in RENA if _regler(text)]
    fpr = len(falska) / len(RENA)

    # SYNTETISK fixtur — inte ett verkligt recall-tal.
    print(f"\n[syntetisk] recall={recall:.2f} ({träffar}/{len(POSITIVA)}) "
          f"fpr={fpr:.2f} falska={falska}")

    assert recall == 1.0, [regel for text, regel in POSITIVA if regel not in _regler(text)]
    assert fpr == 0.0, falska
