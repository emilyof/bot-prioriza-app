"""
Guard-rails centralizados para validação de scores técnicos de vulnerabilidades.

RESPONSABILIDADES:
- Validar intervalos permitidos (0-60)
- Detectar scores semanticamente inconsistentes
- Aplicar correções automáticas quando possível
- Validar variações em recálculos
- Logar anomalias para análise posterior

REGRAS DE DESIGN:
- Todos os guard-rails de score devem estar NESTE módulo
- ai_service.py NÃO deve conter lógica de validação de score
- Apenas comunicação com IA deve estar em ai_service.py
- Cada validação deve retornar (score_validado, lista_de_warnings)

EXEMPLO DE USO:
    # Scoring inicial
    score, warnings = ScoringGuardRails.validate_initial_score(
        score=45.0,
        description="SQL Injection in login form"
    )

    # Recálculo
    score, warnings = ScoringGuardRails.validate_recalculated_score(
        current_score=30.0,
        new_score=55.0,
        description="SQL Injection",
        allow_score_decrease=True
    )
"""

import logging
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


class ScoringGuardRails:
    """
    Classe responsável por aplicar guard-rails em scores técnicos.

    Guard-rails implementados:
    1. Validação de intervalo (0-60)
    2. Validação semântica (coerência com descrição)
    3. Validação de variação máxima (recálculos)
    4. Detecção de keywords críticas
    5. Proteção contra scores absurdos
    6. Detecção de padrões suspeitos
    """

    # ==========================================================
    # CONSTANTES DE VALIDAÇÃO
    # ==========================================================

    # Intervalo válido para score técnico
    MIN_TECHNICAL_SCORE = 0.0
    MAX_TECHNICAL_SCORE = 60.0

    # Variação máxima permitida por recálculo
    MAX_VARIATION_PER_RECALCULATION = 20.0

    # Margem de tolerância para ajustes automáticos
    ADJUSTMENT_MARGIN = 5.0

    # ==========================================================
    # KEYWORDS PARA VALIDAÇÃO SEMÂNTICA
    # ==========================================================

    # Scores mínimos para keywords críticas
    CRITICAL_KEYWORDS = {
        "remote code execution": 45.0,
        "rce": 45.0,
        "arbitrary code execution": 45.0,
        "unauthenticated": 40.0,
        "authentication bypass": 40.0,
        "privilege escalation": 38.0,
        "sql injection": 35.0,
        "command injection": 40.0,
        "deserialization": 38.0,
        "buffer overflow": 35.0,
        "memory corruption": 35.0,
        "zero-day": 50.0,
        "0-day": 50.0,
        "wormable": 50.0,
        "ransomware": 45.0,
        "critical": 35.0,
        "path traversal": 30.0,
        "directory traversal": 30.0,
        "xxe": 35.0,
        "xml external entity": 35.0,
        "ssrf": 35.0,
        "server-side request forgery": 35.0,
        "ldap injection": 35.0,
        "code injection": 40.0,
        "os command injection": 40.0,
    }

    # Scores máximos para keywords de baixa severidade
    LOW_SEVERITY_KEYWORDS = {
        "information disclosure": 25.0,
        "log": 15.0,
        "typo": 10.0,
        "cosmetic": 5.0,
        "ui bug": 10.0,
        "deprecated": 20.0,
        "warning": 15.0,
        "informational": 10.0,
        "low": 20.0,
        "minor": 15.0,
        "documentation": 10.0,
        "style": 5.0,
        "formatting": 5.0,
        "whitespace": 5.0,
    }

    # Padrões que merecem atenção especial
    HIGH_ATTENTION_PATTERNS = [
        "zero-day",
        "0-day",
        "wormable",
        "ransomware",
        "actively exploited",
        "in the wild",
        "mass exploitation",
        "critical infrastructure",
        "no authentication required",
        "pre-auth",
        "pre-authentication",
    ]

    # ==========================================================
    # VALIDAÇÃO DE INTERVALO
    # ==========================================================

    @classmethod
    def validate_score_range(
        cls,
        score: float,
        context: str = "score",
    ) -> Tuple[bool, Optional[str]]:
        """
        Valida se o score está no intervalo permitido (0-60).

        Args:
            score: Pontuação técnica
            context: Contexto da validação (para log)

        Returns:
            tuple: (is_valid, error_message)

        Examples:
            >>> ScoringGuardRails.validate_score_range(45.0)
            (True, None)

            >>> ScoringGuardRails.validate_score_range(65.0)
            (False, "Score 65.0 fora do intervalo permitido (0-60)")
        """

        # Validar tipo
        if not isinstance(score, (int, float)):
            error = f"[{context}] Score deve ser numérico, recebido: {type(score).__name__}"
            logger.error(f"[GUARD-RAIL] {error}")
            return False, error

        # Validar intervalo
        if not cls.MIN_TECHNICAL_SCORE <= score <= cls.MAX_TECHNICAL_SCORE:
            error = (
                f"[{context}] Score {score:.1f} fora do intervalo permitido "
                f"({cls.MIN_TECHNICAL_SCORE:.0f}-{cls.MAX_TECHNICAL_SCORE:.0f})"
            )
            logger.error(f"[GUARD-RAIL] {error}")
            return False, error

        return True, None

    # ==========================================================
    # VALIDAÇÃO SEMÂNTICA
    # ==========================================================

    @classmethod
    def validate_semantic_consistency(
        cls,
        score: float,
        description: str,
    ) -> Tuple[bool, Optional[float], Optional[str]]:
        """
        Valida se o score é semanticamente consistente com a descrição.

        Detecta:
        - Scores muito baixos para vulnerabilidades críticas
        - Scores muito altos para problemas triviais

        Args:
            score: Pontuação técnica sugerida pela IA
            description: Descrição da vulnerabilidade

        Returns:
            tuple: (is_valid, suggested_score, warning_message)

        Examples:
            >>> ScoringGuardRails.validate_semantic_consistency(
            ...     score=10.0,
            ...     description="Remote Code Execution without authentication"
            ... )
            (False, 45.0, "Score muito baixo para 'remote code execution'...")
        """

        if not description:
            return True, None, None

        description_lower = description.lower()

        # ========== VERIFICAR KEYWORDS CRÍTICAS ==========
        for keyword, min_score in cls.CRITICAL_KEYWORDS.items():
            if keyword in description_lower:
                if score < min_score - cls.ADJUSTMENT_MARGIN:
                    warning = (
                        f"Score {score:.1f} muito baixo para '{keyword}' "
                        f"(mínimo esperado: {min_score:.0f}). "
                        f"Descrição: '{description[:100]}...'"
                    )
                    logger.warning(f"[GUARD-RAIL] {warning}")
                    return False, float(min_score), warning

        # ========== VERIFICAR KEYWORDS DE BAIXA SEVERIDADE ==========
        for keyword, max_score in cls.LOW_SEVERITY_KEYWORDS.items():
            if keyword in description_lower:
                if score > max_score + cls.ADJUSTMENT_MARGIN:
                    warning = (
                        f"Score {score:.1f} muito alto para '{keyword}' "
                        f"(máximo esperado: {max_score:.0f}). "
                        f"Descrição: '{description[:100]}...'"
                    )
                    logger.warning(f"[GUARD-RAIL] {warning}")
                    return False, float(max_score), warning

        # ========== VALIDAÇÃO PASSOU ==========
        return True, None, None

    # ==========================================================
    # VALIDAÇÃO DE VARIAÇÃO (RECÁLCULO)
    # ==========================================================

    @classmethod
    def validate_recalculation_variation(
        cls,
        current_score: float,
        new_score: float,
        allow_score_decrease: bool = True,
    ) -> Tuple[float, Optional[str]]:
        """
        Valida e ajusta variação de score em recálculos.

        Args:
            current_score: Score técnico atual
            new_score: Novo score sugerido pela IA
            allow_score_decrease: Se permite redução de score

        Returns:
            tuple: (adjusted_score, warning_message)

        Examples:
            >>> ScoringGuardRails.validate_recalculation_variation(
            ...     current_score=30.0,
            ...     new_score=55.0,
            ...     allow_score_decrease=True
            ... )
            (50.0, "Variação limitada a ±20 pontos...")
        """

        variation = abs(new_score - current_score)

        # ========== VARIAÇÃO DENTRO DO LIMITE ==========
        if variation <= cls.MAX_VARIATION_PER_RECALCULATION:
            # Verificar se redução é permitida
            if not allow_score_decrease and new_score < current_score:
                warning = (
                    f"Redução de score não permitida. "
                    f"Mantendo score original: {current_score:.1f}"
                )
                logger.info(f"[GUARD-RAIL] {warning}")
                return current_score, warning

            return new_score, None

        # ========== VARIAÇÃO EXCEDE LIMITE ==========
        if new_score > current_score:
            adjusted_score = min(new_score, current_score + cls.MAX_VARIATION_PER_RECALCULATION)
        else:
            adjusted_score = max(new_score, current_score - cls.MAX_VARIATION_PER_RECALCULATION)

        warning = (
            f"Variação muito grande detectada: {current_score:.1f} → {new_score:.1f}. "
            f"Limitando a ±{cls.MAX_VARIATION_PER_RECALCULATION:.0f} pontos. "
            f"Score ajustado: {adjusted_score:.1f}"
        )

        logger.warning(f"[GUARD-RAIL] {warning}")

        return adjusted_score, warning

    # ==========================================================
    # VALIDAÇÃO COMPLETA (SCORING INICIAL)
    # ==========================================================

    @classmethod
    def validate_initial_score(
        cls,
        score: float,
        description: str,
    ) -> Tuple[float, List[str]]:
        """
        Aplica TODAS as validações para scoring inicial.

        Args:
            score: Pontuação técnica sugerida pela IA
            description: Descrição da vulnerabilidade

        Returns:
            tuple: (validated_score, warnings_list)

        Examples:
            >>> score, warnings = ScoringGuardRails.validate_initial_score(
            ...     score=10.0,
            ...     description="Remote Code Execution"
            ... )
            >>> score
            45.0
            >>> len(warnings)
            1
        """

        warnings = []
        validated_score = score

        logger.info(
            f"[GUARD-RAIL] Validando score inicial: {score:.1f} "
            f"para descrição: '{description[:50]}...'"
        )

        # ========== 1. VALIDAR INTERVALO ==========
        is_valid, error = cls.validate_score_range(score, context="initial_scoring")

        if not is_valid:
            warnings.append(error)
            # Corrigir para valor mais próximo válido
            validated_score = max(cls.MIN_TECHNICAL_SCORE, min(cls.MAX_TECHNICAL_SCORE, score))
            logger.error(
                f"[GUARD-RAIL] Score fora do intervalo. "
                f"Ajustado: {score:.1f} → {validated_score:.1f}"
            )

        # ========== 2. VALIDAR SEMÂNTICA ==========
        is_consistent, suggested_score, warning = cls.validate_semantic_consistency(
            validated_score,
            description,
        )

        if not is_consistent and suggested_score is not None:
            warnings.append(warning)
            logger.warning(
                f"[GUARD-RAIL] Score semanticamente inconsistente. "
                f"Ajustado: {validated_score:.1f} → {suggested_score:.1f}"
            )
            validated_score = suggested_score

        # ========== 3. LOG FINAL ==========
        if warnings:
            logger.info(
                f"[GUARD-RAIL] Score inicial validado com ajustes: "
                f"{score:.1f} → {validated_score:.1f}"
            )
        else:
            logger.info(
                f"[GUARD-RAIL] Score inicial validado sem ajustes: {validated_score:.1f}"  # noqa: E501
            )

        return validated_score, warnings

    # ==========================================================
    # VALIDAÇÃO COMPLETA (RECÁLCULO)
    # ==========================================================

    @staticmethod
    def validate_recalculated_score(
        current_score: float,
        new_score: float,
        *,
        description: str,
        allow_score_decrease: bool = True,
    ) -> tuple[float, list[str]]:
        """
        Valida e ajusta o score técnico recalculado pela IA.

        Regras:
        - Score final entre 0 e 60
        - Variação máxima por recálculo: ±20
        - Redução pode ser bloqueada explicitamente
        - Retorna warnings quando ajustes automáticos ocorrem
        """

        warnings: list[str] = []

        # Normalização defensiva
        try:
            current_score = float(current_score)
        except Exception:
            current_score = 0.0
            warnings.append("Score atual inválido. Normalizado para 0.")

        try:
            new_score = float(new_score)
        except Exception:
            new_score = current_score
            warnings.append("Score sugerido inválido. Mantido score atual.")

        # Limites absolutos
        new_score = max(0.0, min(new_score, 60.0))

        # Variação máxima permitida
        delta = new_score - current_score
        if delta > 20:
            new_score = current_score + 20
            warnings.append("Aumento limitado a +20 pontos.")
        elif delta < -20:
            new_score = current_score - 20
            warnings.append("Redução limitada a -20 pontos.")

        # Controle explícito de redução
        if not allow_score_decrease and new_score < current_score:
            new_score = current_score
            warnings.append("Redução de score não permitida. Score mantido.")

        # Heurística mínima: evitar redução sem justificativa
        if new_score < current_score and not description:
            warnings.append("Ausência de contexto descritivo para justificar redução de score.")
            new_score = current_score

        return round(new_score, 1), warnings
