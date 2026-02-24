"""
Validação centralizada de entradas do usuário.

RESPONSABILIDADES:
- Validar tamanho de strings
- Sanitizar caracteres especiais
- Prevenir injection em logs
- Validar formatos específicos (CVE, OWASP)
"""

import logging
import re
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


class InputValidator:
    """
    Validador centralizado de entradas do usuário.
    """

    # ==========================================================
    # CONSTANTES DE VALIDAÇÃO
    # ==========================================================

    # Tamanhos máximos permitidos
    MAX_DESCRIPTION_LENGTH = 5000
    MAX_JUSTIFICATION_LENGTH = 2000
    MAX_IDENTIFIER_LENGTH = 500

    # Padrões de validação
    CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
    OWASP_PATTERN = re.compile(r"^A\d{2}:\d{4}$", re.IGNORECASE)

    # Caracteres perigosos para logs (OWASP Log Injection)
    DANGEROUS_LOG_CHARS = [
        "\n",  # Line Feed (LF)
        "\r",  # Carriage Return (CR)
        "\t",  # Tab
        "\x00",  # Null byte
        "\x1b",  # Escape (ANSI codes)
    ]

    # Padrões suspeitos (possível injection)
    SUSPICIOUS_PATTERNS = [
        r"<script",
        r"javascript:",
        r"onerror=",
        r"onload=",
        r"\$\{",  # Template injection
        r"{{",  # Template injection
        r"<%",  # Template injection
        r"../",  # Path traversal
        r"\.\.\\",  # Path traversal (Windows)
    ]

    # ==========================================================
    # VALIDAÇÃO DE TAMANHO
    # ==========================================================

    @classmethod
    def validate_length(
        cls, text: str, max_length: int, field_name: str = "campo"
    ) -> Tuple[bool, Optional[str]]:
        """
        Valida se o texto não excede o tamanho máximo.

        Args:
            text: Texto a validar
            max_length: Tamanho máximo permitido
            field_name: Nome do campo (para mensagem de erro)

        Returns:
            tuple: (is_valid, error_message)

        Examples:
            >>> InputValidator.validate_length("CVE-2024-1234", 100, "CVE ID")
            (True, None)

            >>> InputValidator.validate_length("A" * 6000, 5000, "descrição")
            (False, "descrição muito longa (máx. 5000 caracteres)")
        """
        if not text:
            return True, None

        if len(text) > max_length:
            error = (
                f"{field_name} muito longa "
                f"(máx. {max_length} caracteres, recebido: {len(text)})"
            )
            logger.warning(
                f"[VALIDATION] {error}. " f"Preview: {cls.sanitize_for_logging(text)[:50]}..."
            )
            return False, error

        return True, None

    # ==========================================================
    # SANITIZAÇÃO PARA LOGS (PREVINE LOG INJECTION)
    # ==========================================================

    @classmethod
    def sanitize_for_logging(cls, text: str) -> str:
        """
        Remove caracteres perigosos antes de logar.

        Previne:
        - Log Injection (CRLF injection)
        - Log Forging
        - ANSI escape code injection

        Args:
            text: Texto original

        Returns:
            str: Texto sanitizado para logs

        Examples:
            >>> InputValidator.sanitize_for_logging("Normal text")
            'Normal text'

            >>> InputValidator.sanitize_for_logging("Malicious\\nINFO: Fake log")
            'Malicious INFO: Fake log'
        """
        if not text:
            return ""

        # Remover caracteres perigosos
        sanitized = text
        for char in cls.DANGEROUS_LOG_CHARS:
            sanitized = sanitized.replace(char, " ")

        # Remover múltiplos espaços
        sanitized = re.sub(r"\s+", " ", sanitized)

        # Truncar se muito longo
        if len(sanitized) > 200:
            sanitized = sanitized[:200] + "..."

        return sanitized.strip()

    # ==========================================================
    # DETECÇÃO DE PADRÕES SUSPEITOS
    # ==========================================================

    @classmethod
    def detect_suspicious_patterns(
        cls, text: str, field_name: str = "campo"
    ) -> Tuple[bool, Optional[str]]:
        """
        Detecta padrões suspeitos de injection.

        Args:
            text: Texto a analisar
            field_name: Nome do campo (para mensagem de erro)

        Returns:
            tuple: (is_safe, warning_message)

        Examples:
            >>> InputValidator.detect_suspicious_patterns("Normal description")
            (True, None)

            >>> InputValidator.detect_suspicious_patterns("<script>alert(1)</script>")
            (False, "Padrão suspeito detectado em campo: <script")
        """
        if not text:
            return True, None

        text_lower = text.lower()

        for pattern in cls.SUSPICIOUS_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                warning = f"Padrão suspeito detectado em {field_name}: {pattern}"
                logger.warning(f"[SECURITY] {warning}. " f"Input: {cls.sanitize_for_logging(text)}")
                return False, warning

        return True, None

    # ==========================================================
    # VALIDAÇÃO DE DESCRIÇÃO DE VULNERABILIDADE
    # ==========================================================

    @classmethod
    def validate_description(cls, description: str) -> Tuple[bool, Optional[str], str]:
        """
        Validação completa de descrição de vulnerabilidade.

        Args:
            description: Descrição fornecida pelo usuário

        Returns:
            tuple: (is_valid, error_message, sanitized_description)

        Examples:
            >>> valid, err, clean = InputValidator.validate_description("SQL Injection")
            >>> valid
            True
        """
        if not description or not description.strip():
            return False, "Descrição não pode estar vazia", ""

        description = description.strip()

        # 1. Validar tamanho
        is_valid, error = cls.validate_length(description, cls.MAX_DESCRIPTION_LENGTH, "Descrição")
        if not is_valid:
            return False, error, ""

        # 2. Detectar padrões suspeitos
        is_safe, warning = cls.detect_suspicious_patterns(description, "descrição")
        if not is_safe:
            return False, warning, ""

        # 3. Sanitizar para uso seguro
        sanitized = cls._sanitize_text(description)

        return True, None, sanitized

    # ==========================================================
    # VALIDAÇÃO DE JUSTIFICATIVA DE RECÁLCULO
    # ==========================================================

    @classmethod
    def validate_justification(cls, justification: str) -> Tuple[bool, Optional[str], str]:
        """
        Validação completa de justificativa de recálculo.

        Args:
            justification: Justificativa fornecida pelo usuário

        Returns:
            tuple: (is_valid, error_message, sanitized_justification)
        """
        if not justification or not justification.strip():
            return False, "Justificativa não pode estar vazia", ""

        justification = justification.strip()

        # 1. Validar tamanho
        is_valid, error = cls.validate_length(
            justification, cls.MAX_JUSTIFICATION_LENGTH, "Justificativa"
        )
        if not is_valid:
            return False, error, ""

        # 2. Detectar padrões suspeitos
        is_safe, warning = cls.detect_suspicious_patterns(justification, "justificativa")
        if not is_safe:
            return False, warning, ""

        # 3. Sanitizar para uso seguro
        sanitized = cls._sanitize_text(justification)

        return True, None, sanitized

    # ==========================================================
    # VALIDAÇÃO DE IDENTIFICADORES (CVE, OWASP)
    # ==========================================================

    @classmethod
    def validate_identifier(cls, identifier: str) -> Tuple[bool, Optional[str], str]:
        """
        Validação de identificadores (CVE, OWASP, etc).

        Args:
            identifier: Identificador fornecido pelo usuário

        Returns:
            tuple: (is_valid, error_message, sanitized_identifier)
        """
        if not identifier or not identifier.strip():
            return False, "Identificador não pode estar vazio", ""

        identifier = identifier.strip()

        # 1. Validar tamanho
        is_valid, error = cls.validate_length(
            identifier, cls.MAX_IDENTIFIER_LENGTH, "Identificador"
        )
        if not is_valid:
            return False, error, ""

        # 2. Sanitizar para uso seguro
        sanitized = cls._sanitize_text(identifier)

        return True, None, sanitized

    # ==========================================================
    # SANITIZAÇÃO INTERNA
    # ==========================================================

    @classmethod
    def _sanitize_text(cls, text: str) -> str:
        """
        Sanitização básica de texto para uso interno.

        Remove:
        - Caracteres de controle
        - Espaços múltiplos
        - Whitespace no início/fim

        Args:
            text: Texto original

        Returns:
            str: Texto sanitizado
        """
        if not text:
            return ""

        # Remover caracteres de controle (exceto espaço, tab, newline)
        sanitized = re.sub(r"[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]", "", text)

        # Normalizar espaços
        sanitized = re.sub(r"[ \t]+", " ", sanitized)

        # Normalizar quebras de linha
        sanitized = re.sub(r"\n{3,}", "\n\n", sanitized)

        return sanitized.strip()

    # ==========================================================
    # VALIDAÇÃO DE FORMATO CVE
    # ==========================================================

    @classmethod
    def validate_cve_format(cls, cve_id: str) -> bool:
        """
        Valida formato CVE-YYYY-NNNNN.

        Args:
            cve_id: ID do CVE

        Returns:
            bool: True se válido

        Examples:
            >>> InputValidator.validate_cve_format("CVE-2024-1234")
            True

            >>> InputValidator.validate_cve_format("INVALID")
            False
        """
        if not cve_id:
            return False

        return bool(cls.CVE_PATTERN.match(cve_id.strip()))

    # ==========================================================
    # VALIDAÇÃO DE FORMATO OWASP
    # ==========================================================

    @staticmethod
    def validate_owasp_format(value: str) -> bool:
        """
        Valida apenas o FORMATO OWASP.
        Estar ou não no Top 10 é regra de DOMÍNIO.

        Formatos válidos:
        - A01, A10, A99
        - AI01, AI10, AI99
        """
        if not value:
            return False

        value = value.strip().upper()

        # A01–A99 ou AI01–AI99
        pattern = r"^(A|AI)(0[1-9]|10)$"
        return bool(re.match(pattern, value))
