import pytest

from app.domain.scoring_logic import (
    BUSINESS_IMPACT_QUESTIONS_CONFIG,
    PRIORITY_EMOJI_MAP,
    calculate_business_score,
    get_priority_emoji,
    get_risk_classification,
)

# ==========================================================
# get_priority_emoji
# ==========================================================


@pytest.mark.parametrize(
    "classification,expected",
    [
        ("P1 Crítico", "🔴"),
        ("P2 Alto", "🟠"),
        ("P3 Médio", "🟨"),
        ("P4 Baixo", "🟢"),
        ("P4 Informativa", "🔵"),
        ("Desconhecida", "⚪"),
        ("", "⚪"),
        (None, "⚪"),
    ],
)
def test_get_priority_emoji(classification, expected):
    assert get_priority_emoji(classification) == expected


def test_priority_emoji_map_completeness():
    """
    Todas as classificações oficiais devem possuir emoji definido.
    """
    expected_keys = {
        "P1 Crítico",
        "P2 Alto",
        "P3 Médio",
        "P4 Baixo",
        "P4 Informativa",
    }

    assert expected_keys.issubset(PRIORITY_EMOJI_MAP.keys())


# ==========================================================
# get_risk_classification
# ==========================================================


@pytest.mark.parametrize(
    "score,expected_classification,expected_sla",
    [
        (100, "P1 Crítico", "WAR ROOM, resolução imediata"),
        (95, "P1 Crítico", "WAR ROOM, resolução imediata"),
        (90, "P1 Crítico", "WAR ROOM, resolução imediata"),
        (89, "P2 Alto", "30 dias úteis"),
        (75, "P2 Alto", "30 dias úteis"),
        (70, "P2 Alto", "30 dias úteis"),
        (69, "P3 Médio", "60 dias úteis"),
        (50, "P3 Médio", "60 dias úteis"),
        (30, "P3 Médio", "60 dias úteis"),
        (29, "P4 Baixo", "90 dias úteis"),
        (15, "P4 Baixo", "90 dias úteis"),
        (10, "P4 Baixo", "90 dias úteis"),
        (9, "P4 Informativa", "Sem prazo definido"),
        (0, "P4 Informativa", "Sem prazo definido"),
    ],
)
def test_get_risk_classification(score, expected_classification, expected_sla):
    classification, sla = get_risk_classification(score)

    assert classification == expected_classification
    assert sla == expected_sla


def test_get_risk_classification_out_of_range():
    classification, sla = get_risk_classification(-1)
    assert classification == "Desconhecida"
    assert sla == "Não aplicável"

    classification, sla = get_risk_classification(101)
    assert classification == "Desconhecida"
    assert sla == "Não aplicável"


# ==========================================================
# calculate_business_score
# ==========================================================


def test_calculate_business_score_all_max_answers():
    """
    Todas as respostas mais críticas devem resultar
    no score máximo de negócio (40).
    """
    answers = ["A"] * len(BUSINESS_IMPACT_QUESTIONS_CONFIG)

    score, qualitative = calculate_business_score(answers)

    assert score == 40
    assert isinstance(qualitative, dict)
    assert len(qualitative) == len(BUSINESS_IMPACT_QUESTIONS_CONFIG)


def test_calculate_business_score_all_min_answers():
    """
    Todas as respostas de menor impacto devem resultar
    em score mínimo (>0, mas baixo).
    """
    answers = ["E", "E", "C", "C", "C"]

    score, qualitative = calculate_business_score(answers)

    assert score == 1
    assert isinstance(qualitative, dict)


def test_calculate_business_score_partial_answers():
    """
    Lista parcial de respostas não deve quebrar o cálculo.
    """
    answers = ["A", "B"]

    score, qualitative = calculate_business_score(answers)

    assert 0 < score <= 40
    assert len(qualitative) == 2


def test_calculate_business_score_extra_answers_ignored():
    """
    Respostas além do número de perguntas devem ser ignoradas.
    """
    answers = ["A"] * (len(BUSINESS_IMPACT_QUESTIONS_CONFIG) + 5)

    score, qualitative = calculate_business_score(answers)

    assert score == 40
    assert len(qualitative) == len(BUSINESS_IMPACT_QUESTIONS_CONFIG)


def test_calculate_business_score_invalid_answers_ignored():
    """
    Respostas inválidas não devem somar pontos.
    """
    answers = ["A", "INVALID", "B", None, "C"]

    score, qualitative = calculate_business_score(answers)

    assert 0 <= score <= 40
    assert isinstance(qualitative, dict)


def test_calculate_business_score_score_is_capped_at_40():
    """
    Mesmo que a soma ultrapasse 40, o score final
    deve ser limitado a 40.
    """
    answers = ["A", "A", "A", "A", "A"]

    score, _ = calculate_business_score(answers)

    assert score == 40


def test_calculate_business_score_preserves_display_map_values():
    """
    O retorno qualitativo deve usar display_map,
    não a letra da resposta.
    """
    answers = ["A"]

    score, qualitative = calculate_business_score(answers)

    first_question_name = BUSINESS_IMPACT_QUESTIONS_CONFIG[0]["name"]
    expected_display = BUSINESS_IMPACT_QUESTIONS_CONFIG[0]["display_map"]["A"]

    assert qualitative[first_question_name] == expected_display
