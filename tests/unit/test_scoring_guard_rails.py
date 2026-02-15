import pytest

from app.utils.scoring_guard_rails import ScoringGuardRails

# ==========================================================
# validate_score_range
# ==========================================================


@pytest.mark.parametrize("score", [0, 10, 30.5, 60])
def test_validate_score_range_valid(score):
    is_valid, error = ScoringGuardRails.validate_score_range(score)
    assert is_valid is True
    assert error is None


@pytest.mark.parametrize("score", [-1, 61, 100])
def test_validate_score_range_out_of_bounds(score):
    is_valid, error = ScoringGuardRails.validate_score_range(score)
    assert is_valid is False
    assert "fora do intervalo" in error.lower()


def test_validate_score_range_non_numeric():
    is_valid, error = ScoringGuardRails.validate_score_range("invalid")
    assert is_valid is False
    assert "numérico" in error.lower()


# ==========================================================
# validate_semantic_consistency
# ==========================================================


def test_semantic_consistency_rce_too_low():
    is_valid, suggested_score, warning = ScoringGuardRails.validate_semantic_consistency(
        score=10.0,
        description="Remote Code Execution without authentication",
    )

    assert is_valid is False
    assert suggested_score >= 45.0
    assert "remote code execution" in warning.lower()


def test_semantic_consistency_sql_injection_too_low():
    is_valid, suggested_score, warning = ScoringGuardRails.validate_semantic_consistency(
        score=15.0,
        description="SQL Injection vulnerability in login endpoint",
    )

    assert is_valid is False
    assert suggested_score >= 35.0
    assert "sql injection" in warning.lower()


def test_semantic_consistency_low_severity_too_high():
    is_valid, suggested_score, warning = ScoringGuardRails.validate_semantic_consistency(
        score=50.0,
        description="Cosmetic UI bug with no security impact",
    )

    assert is_valid is False
    assert suggested_score <= 10.0
    assert "cosmetic" in warning.lower()


def test_semantic_consistency_valid_case():
    is_valid, suggested_score, warning = ScoringGuardRails.validate_semantic_consistency(
        score=30.0,
        description="Authenticated access control misconfiguration",
    )

    assert is_valid is True
    assert suggested_score is None
    assert warning is None


def test_semantic_consistency_empty_description():
    is_valid, suggested_score, warning = ScoringGuardRails.validate_semantic_consistency(
        score=25.0,
        description="",
    )

    assert is_valid is True
    assert suggested_score is None
    assert warning is None


# ==========================================================
# validate_recalculation_variation
# ==========================================================


def test_recalculation_variation_within_limit():
    score, warning = ScoringGuardRails.validate_recalculation_variation(
        current_score=30.0,
        new_score=40.0,
    )

    assert score == 40.0
    assert warning is None


def test_recalculation_variation_exceeds_limit_upwards():
    score, warning = ScoringGuardRails.validate_recalculation_variation(
        current_score=20.0,
        new_score=55.0,
    )

    assert score == 40.0  # limitado a +20
    assert "variação" in warning.lower()


def test_recalculation_variation_exceeds_limit_downwards():
    score, warning = ScoringGuardRails.validate_recalculation_variation(
        current_score=40.0,
        new_score=5.0,
    )

    assert score == 20.0  # limitado a -20
    assert "variação" in warning.lower()


def test_recalculation_variation_decrease_not_allowed():
    score, warning = ScoringGuardRails.validate_recalculation_variation(
        current_score=40.0,
        new_score=30.0,
        allow_score_decrease=False,
    )

    assert score == 40.0
    assert "redução" in warning.lower()


# ==========================================================
# validate_initial_score
# ==========================================================


def test_validate_initial_score_out_of_range():
    score, warnings = ScoringGuardRails.validate_initial_score(
        score=100.0,
        description="SQL Injection vulnerability",
    )

    assert score == ScoringGuardRails.MAX_TECHNICAL_SCORE
    assert len(warnings) >= 1


def test_validate_initial_score_semantic_adjustment():
    score, warnings = ScoringGuardRails.validate_initial_score(
        score=10.0,
        description="Remote Code Execution vulnerability",
    )

    assert score >= 45.0
    assert len(warnings) >= 1


def test_validate_initial_score_no_adjustments():
    score, warnings = ScoringGuardRails.validate_initial_score(
        score=35.0,
        description="Authenticated privilege escalation",
    )

    assert score == 35.0
    assert warnings == []


# ==========================================================
# validate_recalculated_score
# ==========================================================


def test_validate_recalculated_score_full_flow():
    score, warnings = ScoringGuardRails.validate_recalculated_score(
        current_score=30.0,
        new_score=60.0,
        description="SQL Injection vulnerability",
        allow_score_decrease=True,
    )

    assert score == 50.0  # 30 + 20
    assert len(warnings) >= 1


def test_validate_recalculated_score_does_not_apply_semantic_rules():
    score, warnings = ScoringGuardRails.validate_recalculated_score(
        current_score=30.0,
        new_score=20.0,
        description="Remote Code Execution without authentication",
        allow_score_decrease=True,
    )

    assert score == 20.0
    assert warnings == []


def test_validate_recalculated_score_decrease_not_allowed():
    score, warnings = ScoringGuardRails.validate_recalculated_score(
        current_score=40.0,
        new_score=10.0,
        description="Cosmetic UI issue",
        allow_score_decrease=False,
    )

    assert score == 40.0
    assert len(warnings) >= 1
