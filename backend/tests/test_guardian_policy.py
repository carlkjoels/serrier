"""Guardian policy-motor (steg 3): deterministiska verdikt, strängast vinner, och UNKNOWN
som eget tillstånd över de tre fel-lägena. Syntetisk data."""

from serrier.guardian.classify import detektera_kanslig
from serrier.guardian.policy import (
    AnalysisStatus,
    FailureMode,
    GuardAction,
    besluta,
    strangast,
)


def test_strangast_vinner() -> None:
    assert strangast([GuardAction.warn, GuardAction.block, GuardAction.allow]) == GuardAction.block
    assert strangast([GuardAction.warn, GuardAction.redact]) == GuardAction.redact
    assert strangast([]) == GuardAction.allow


def test_hemlighet_blockeras() -> None:
    v = besluta(detektera_kanslig("key=sk-ant-api03-REALSECRET1234567890abcDEF"))
    assert v.action == GuardAction.block
    assert v.analysis_status == AnalysisStatus.ok
    assert any(r.regel == "anthropic-api-key" for r in v.reasons)


def test_kort_maskeras_mejl_varnar() -> None:
    assert besluta(detektera_kanslig("betalkort 4111 1111 1111 1111")).action == GuardAction.redact
    assert besluta(detektera_kanslig("maila anna@foretag.se")).action == GuardAction.warn


def test_strangaste_aktionen_bland_flera() -> None:
    # mejl (warn) + hemlighet (block) i samma text → block vinner
    v = besluta(detektera_kanslig("anna@foretag.se och sk-ant-api03-REALSECRET1234567890abc"))
    assert v.action == GuardAction.block
    assert len(v.reasons) >= 2


def test_ren_text_ar_allow_men_kontrollerad() -> None:
    v = besluta(detektera_kanslig("ett helt vanligt meddelande utan känsligt"))
    assert v.action == GuardAction.allow
    assert v.analysis_status == AnalysisStatus.ok       # 'kontrollerat och rent' ≠ unknown
    assert v.reasons == []


# --- UNKNOWN som eget tillstånd över fel-lägena ---------------------------
def test_unknown_strict_blockerar() -> None:
    v = besluta([], analysis_status=AnalysisStatus.unknown, failure_mode=FailureMode.strict)
    assert v.action == GuardAction.block
    assert v.analysis_status == AnalysisStatus.unknown
    assert v.failure_mode == FailureMode.strict


def test_unknown_balanced_kraver_godkannande_slapper_aldrig_tyst() -> None:
    v = besluta([], analysis_status=AnalysisStatus.unknown, failure_mode=FailureMode.balanced)
    assert v.action == GuardAction.require_approval     # aldrig allow
    assert v.analysis_status == AnalysisStatus.unknown


def test_unknown_permissive_tillater_men_markt_unknown() -> None:
    v = besluta([], analysis_status=AnalysisStatus.unknown, failure_mode=FailureMode.permissive)
    assert v.action == GuardAction.allow
    # Kritiskt: även när vi tillåter är status unknown — ALDRIG rapporterat som 'kontrollerat'
    assert v.analysis_status == AnalysisStatus.unknown
    assert "säkert" in v.reasons[0].forklaring or "Okänt" in v.reasons[0].forklaring


def test_unknown_aldrig_ok_status() -> None:
    for mode in FailureMode:
        v = besluta([], analysis_status=AnalysisStatus.unknown, failure_mode=mode)
        assert v.analysis_status == AnalysisStatus.unknown
        assert v.action != GuardAction.allow or mode == FailureMode.permissive
