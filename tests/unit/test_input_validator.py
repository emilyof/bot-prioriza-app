import pytest

from app.utils.input_validator import InputValidator

# ==========================================================
# VALIDATE_DESCRIPTION
# ==========================================================


def test_validate_description_valid():
    valid, error, sanitized = InputValidator.validate_description(
        "SQL Injection vulnerability in login form"
    )

    assert valid is True
    assert error is None
    assert sanitized == "SQL Injection vulnerability in login form"


def test_validate_description_empty():
    valid, error, sanitized = InputValidator.validate_description("   ")

    assert valid is False
    assert error == "Descrição não pode estar vazia"
    assert sanitized == ""


def test_validate_description_too_long():
    long_text = "A" * (InputValidator.MAX_DESCRIPTION_LENGTH + 1)

    valid, error, sanitized = InputValidator.validate_description(long_text)

    assert valid is False
    assert "Descrição muito longa" in error
    assert sanitized == ""


def test_validate_description_detects_script_injection():
    valid, error, sanitized = InputValidator.validate_description("<script>alert(1)</script>")

    assert valid is False
    assert "Padrão suspeito" in error
    assert sanitized == ""


def test_validate_description_detects_path_traversal():
    valid, error, sanitized = InputValidator.validate_description("../etc/passwd")

    assert valid is False
    assert "Padrão suspeito" in error
    assert sanitized == ""


# ==========================================================
# VALIDATE_JUSTIFICATION
# ==========================================================


def test_validate_justification_valid():
    valid, error, sanitized = InputValidator.validate_justification(
        "This vulnerability was exploited in production"
    )

    assert valid is True
    assert error is None
    assert sanitized == "This vulnerability was exploited in production"


def test_validate_justification_empty():
    valid, error, sanitized = InputValidator.validate_justification("")

    assert valid is False
    assert error == "Justificativa não pode estar vazia"
    assert sanitized == ""


def test_validate_justification_too_long():
    long_text = "B" * (InputValidator.MAX_JUSTIFICATION_LENGTH + 1)

    valid, error, sanitized = InputValidator.validate_justification(long_text)

    assert valid is False
    assert "Justificativa muito longa" in error
    assert sanitized == ""


def test_validate_justification_detects_template_injection():
    valid, error, sanitized = InputValidator.validate_justification("User input: {{7*7}}")

    assert valid is False
    assert "Padrão suspeito" in error
    assert sanitized == ""


# ==========================================================
# VALIDATE_IDENTIFIER
# ==========================================================


def test_validate_identifier_valid_cve():
    valid, error, sanitized = InputValidator.validate_identifier("CVE-2024-1234")

    assert valid is True
    assert error is None
    assert sanitized == "CVE-2024-1234"


def test_validate_identifier_trims_spaces():
    valid, error, sanitized = InputValidator.validate_identifier("  CVE-2024-9999  ")

    assert valid is True
    assert error is None
    assert sanitized == "CVE-2024-9999"


def test_validate_identifier_empty():
    valid, error, sanitized = InputValidator.validate_identifier("")

    assert valid is False
    assert error == "Identificador não pode estar vazio"
    assert sanitized == ""


def test_validate_identifier_too_long():
    long_id = "CVE-" + ("1" * (InputValidator.MAX_IDENTIFIER_LENGTH + 10))

    valid, error, sanitized = InputValidator.validate_identifier(long_id)

    assert valid is False
    assert "Identificador muito longa" in error
    assert sanitized == ""


# ==========================================================
# CVE / OWASP FORMAT VALIDATION
# ==========================================================


def test_validate_cve_format_valid():
    assert InputValidator.validate_cve_format("CVE-2023-12345") is True


def test_validate_cve_format_invalid():
    assert InputValidator.validate_cve_format("INVALID-CVE") is False


@pytest.mark.parametrize(
    "value",
    ["A01", "A10", "AI01", "AI10"],
)
def test_validate_owasp_format_valid(value):
    assert InputValidator.validate_owasp_format(value) is True


@pytest.mark.parametrize(
    "value",
    ["A00", "A11", "AI00", "AI11", "B01", "", None],
)
def test_validate_owasp_format_invalid(value):
    assert InputValidator.validate_owasp_format(value) is False


# ==========================================================
# SANITIZE_FOR_LOGGING
# ==========================================================


def test_sanitize_for_logging_removes_control_chars():
    text = "Malicious\nINFO: fake log\r\n"
    sanitized = InputValidator.sanitize_for_logging(text)

    assert "\n" not in sanitized
    assert "\r" not in sanitized
    assert "INFO" in sanitized


def test_sanitize_for_logging_truncates_long_text():
    text = "A" * 1000
    sanitized = InputValidator.sanitize_for_logging(text)

    assert len(sanitized) <= 203  # 200 + "..."
    assert sanitized.endswith("...")
