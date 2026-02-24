import json
import logging
import re
from typing import Dict, List, Optional

from app.core.vulnerability_types import VulnerabilityType
from app.ports.ai_provider import AIProvider
from app.prompts.ai_prompts import (
    build_cve_list_ranking_prompt,
    build_executive_report_prompt,
    build_owasp_category_description_prompt,
    build_suggest_owasp_prompt,
    build_technical_recalculation_prompt,
    build_technical_scoring_prompt,
)
from app.utils.ai_normalizer import AIMessageNormalizer
from app.utils.scoring_guard_rails import ScoringGuardRails

logger = logging.getLogger(__name__)


class AIService:
    """
    Serviço central de interação com IA.

    Responsabilidades:
    - Normalizar mensagens conforme o provider
    - Chamar o provider configurado
    - Padronizar parsing da resposta da IA
    - Aplicar guard-rails técnicos
    - Expor métodos de IA orientados ao domínio
    """

    def __init__(self, provider: AIProvider):
        self.provider = provider

    # ==========================================================
    # Chamada genérica de IA
    # ==========================================================

    def get_completion(
        self,
        *,
        user_id: str,
        message_content: Optional[str] = None,
        messages: Optional[List[Dict]] = None,
    ) -> Dict:
        """
        Retorna SEMPRE no formato:
        {
            "content": str,
            "raw": dict
        }
        """

        if not messages and not message_content:
            logger.error("Nenhuma mensagem fornecida para a IA.")
            return {
                "content": "",
                "raw": {"error": "Nenhuma mensagem fornecida."},
            }

        final_messages = messages or [{"role": "user", "content": message_content}]

        final_messages = AIMessageNormalizer.normalize_messages_for_provider(
            messages=final_messages,
            provider_name=self.provider.__class__.__name__,
        )

        try:
            response = self.provider.chat_completion(
                user_id=user_id,
                messages=final_messages,
            )

            return AIMessageNormalizer.normalize_response(provider_response=response)

        except Exception as e:
            logger.exception("Erro inesperado no serviço de IA.")
            return {
                "content": "",
                "raw": {"error": str(e)},
            }

    # ==========================================================
    # Utilitário: parsing robusto de JSON vindo da IA
    # ==========================================================

    @staticmethod
    def _parse_ai_json_response(text: str) -> dict:
        """
        Extrai o primeiro bloco JSON válido encontrado
        em uma resposta textual da IA.
        """

        if not text:
            raise ValueError("Resposta vazia da IA.")

        text = text.strip()

        # Tentativa direta
        try:
            return json.loads(text)
        except Exception:
            pass

        # Remove blocos ```json
        cleaned = text.replace("```json", "").replace("```", "").strip()

        try:
            return json.loads(cleaned)
        except Exception:
            pass

        # 3️⃣ Regex fallback
        match = re.search(r"\{[\s\S]*\}", text)
        if not match:
            raise ValueError("Nenhum JSON encontrado na resposta da IA.")

        return json.loads(match.group())

    # ==========================================================
    # SCORING TÉCNICO INICIAL (0–60) — POR DESCRIÇÃO
    # ==========================================================

    def calculate_technical_score_by_description(
        self,
        description: str,
    ) -> dict:
        """
        Calcula o score técnico inicial (0–60)
        a partir de uma descrição livre.

        ✅ Guard-rails aplicados:
        - Validação de intervalo (0-60)
        - Validação semântica (coerência com descrição)
        - Ajustes automáticos quando necessário
        """

        prompt = build_technical_scoring_prompt(description)

        response = self.get_completion(
            user_id="system-initial-scoring",
            message_content=prompt,
        )

        if not response or not response.get("content"):
            logger.warning("Resposta vazia da IA no scoring inicial.")
            return {
                "technical_subtotal": 0.0,
                "ai_justification": (
                    "Não foi possível calcular a pontuação técnica a partir da descrição."  # noqa: E501
                ),
                "description_ai": description,
            }

        try:
            data = self._parse_ai_json_response(response["content"])

            score = data.get("technical_subtotal")
            justification = data.get("justification")

            # VALIDAÇÃO BÁSICA DE TIPO
            if not isinstance(score, (int, float)):
                logger.error(f"[AI_SCORING] Score não numérico retornado pela IA: {score}")
                raise ValueError("Score técnico não numérico.")

            score = float(score)

            # APLICAR GUARD-RAILS COMPLETOS
            validated_score, warnings = ScoringGuardRails.validate_initial_score(
                score=score,
                description=description,
            )

            # LOG DE WARNINGS (se houver ajustes)
            if warnings:
                logger.warning(
                    f"[AI_SCORING] Guard-rails aplicaram ajustes no score inicial:\n"
                    f"  Score original: {score:.1f}\n"
                    f"  Score validado: {validated_score:.1f}\n"
                    f"  Warnings: {warnings}"
                )

            return {
                "technical_subtotal": validated_score,
                "ai_justification": (justification or "Justificativa não fornecida pela IA."),
                "description_ai": description,
            }

        except Exception as e:
            logger.warning(f"[AI_SCORING] Erro ao processar resposta da IA no scoring inicial: {e}")

            return {
                "technical_subtotal": 0.0,
                "ai_justification": ("Não foi possível interpretar corretamente a resposta da IA."),
                "description_ai": description,
            }

    # ==========================================================
    # SUGESTÃO DE OWASP TOP 10 (POR DESCRIÇÃO)
    # ==========================================================

    def suggest_owasp_from_description(self, description: str) -> List[dict]:
        """
        Usa IA para sugerir categorias OWASP a partir de uma descrição livre.

        Retorna lista de objetos no formato:
        {
            "type": str,
            "code": str,
            "title": str
        }

        ❗ Não valida se a categoria existe na versão atual.
        """
        prompt = build_suggest_owasp_prompt(description)

        response = self.get_completion(
            user_id="system-owasp-suggestion",
            message_content=prompt,
        )

        if not response or not response.get("content"):
            return []

        try:
            data = self._parse_ai_json_response(response["content"])
            categories = data.get("categories", [])

            valid_items = []

            for item in categories:
                if not isinstance(item, dict):
                    continue

                owasp_type = item.get("type")
                code = item.get("code")
                title = item.get("title")

                if not all([owasp_type, code, title]):
                    continue

                valid_items.append(
                    {
                        "type": owasp_type,
                        "code": code.upper(),
                        "title": title,
                    }
                )

            return valid_items

        except Exception as e:
            logger.warning(f"[AI_OWASP] Erro ao sugerir OWASP: {e}")
            return []

    # ==========================================================
    # VALIDAÇÃO DE CATEGORIA (OWASP / CWE)
    # ==========================================================

    def generate_owasp_category_description(
        self,
        owasp_code: str,
        owasp_title: str,
    ) -> str:
        """
        Gera uma descrição curta de uma categoria OWASP
        para uso em relatório executivo.
        """

        prompt = build_owasp_category_description_prompt(
            owasp_code=owasp_code,
            owasp_title=owasp_title,
        )

        response = self.get_completion(
            user_id="system-owasp-description",
            message_content=prompt,
        )

        if not response or not response.get("content"):
            return (
                f"Categoria OWASP {owasp_title} relacionada a falhas recorrentes "
                f"de segurança em aplicações."
            )

        return response["content"].strip()

    # ==========================================================
    # RECÁLCULO DE SCORE TÉCNICO (0–60)
    # ==========================================================

    def recalculate_technical_score(
        self,
        original_technical_data: dict,
        business_answers: dict,
        business_score: float,
        user_justification: str,
        recalculation_history: list,
        allow_score_decrease: bool = True,
    ) -> dict:
        """
        Recalcula APENAS o score técnico (0–60), considerando contexto de negócio.

        Guard-rails aplicados:
        - Intervalo válido (0–60)
        - Variação máxima permitida (±20)
        - Coerência semântica com a descrição
        - Controle explícito de redução de score
        """

        # Score atual e descrição base
        current_score = float(original_technical_data.get("technical_subtotal", 0.0))

        description = (
            original_technical_data.get("description_ai")
            or original_technical_data.get("description")
            or ""
        )

        # Prompt para IA
        prompt = build_technical_recalculation_prompt(
            original_technical_data=original_technical_data,
            business_answers=business_answers,
            business_score=business_score,
            user_justification=user_justification,
            recalculation_history=recalculation_history,
        )

        response = self.get_completion(
            user_id="system-recalculation",
            message_content=prompt,
        )

        # Falha de resposta da IA → manter score
        if not response or not response.get("content"):
            logger.warning("[RECALC] Resposta vazia da IA. Mantendo score atual.")
            return {
                "technical_subtotal": current_score,
                "justification": (
                    "Pontuação técnica mantida por ausência de resposta válida da IA."
                ),
            }

        try:
            # Parse da resposta
            data = self._parse_ai_json_response(response["content"])

            suggested_score = float(data.get("technical_subtotal", current_score))
            justification = data.get("justification", "").strip()

            # GUARD-RAILS — CHAMADA CORRETA (SEM DUPLICIDADE)
            validated_score, warnings = ScoringGuardRails.validate_recalculated_score(
                current_score,
                suggested_score,
                description=description,
                allow_score_decrease=allow_score_decrease,
            )

            # Log de ajustes aplicados
            if warnings:
                logger.warning(
                    "[RECALC] Guard-rails aplicaram ajustes no recálculo:\n"
                    f"  Score atual: {current_score:.1f}\n"
                    f"  Score sugerido pela IA: {suggested_score:.1f}\n"
                    f"  Score validado: {validated_score:.1f}\n"
                    f"  Warnings: {warnings}"
                )

                if validated_score != suggested_score:
                    justification = (
                        f"{justification}\n\n"
                        f"*Nota:* A sugestão da IA foi revisada pelos guard-rails. "
                        f"Score final mantido em {validated_score:.1f}/60."
                    )

            # ==========================================================
            # Retorno FINAL
            # ==========================================================
            return {
                "technical_subtotal": validated_score,
                "justification": (
                    justification or "Justificativa não fornecida explicitamente pela IA."
                ),
            }

        except Exception as e:
            logger.warning(f"[RECALC] Erro no recálculo técnico: {e}")

            return {
                "technical_subtotal": current_score,
                "justification": (
                    "A pontuação técnica foi mantida por inconsistência " "na resposta da IA."
                ),
            }

    # ==========================================================
    # Relatório executivo completo (recomendações de remediação, mitigação e considerações adicionais)  # noqa: E501
    # ==========================================================

    def generate_executive_recommendations(
        self,
        identifier: str,
        description: str,
        input_type: VulnerabilityType,
        technical_data: dict,
        business_answers: dict,
        final_score: float,
        classification: str,
    ) -> dict:
        """
        Gera recomendações executivas completas usando IA.

        Args:
            identifier: ID da vulnerabilidade (CVE, OWASP, etc.)
            description: Descrição da vulnerabilidade
            input_type: Tipo de entrada (CVE, OWASP, AI_SCORING_DESCRIPTION)
            technical_data: Dados técnicos calculados
            business_answers: Respostas de impacto no negócio
            final_score: Pontuação final (0-100)
            classification: Classificação de risco (P1-P4)

        Returns:
            dict: {
                "remediation_recommendations": str,
                "mitigation_measures": str,
                "additional_considerations": str,
            }
        """

        prompt = build_executive_report_prompt(
            identifier=identifier,
            description=description,
            input_type=input_type,
            technical_data=technical_data,
            business_answers=business_answers,
            final_score=final_score,
            classification=classification,
        )

        response = self.get_completion(
            user_id="system-executive-report",
            message_content=prompt,
        )

        if not response or not response.get("content"):
            logger.warning("Resposta vazia da IA ao gerar recomendações executivas")
            return {
                "remediation_recommendations": "Não foi possível gerar recomendações técnicas no momento.",  # noqa: E501
                "mitigation_measures": "Não foi possível gerar medidas de mitigação no momento.",  # noqa: E501
                "additional_considerations": "Não foi possível gerar considerações adicionais no momento.",  # noqa: E501
            }

        try:
            data = self._parse_ai_json_response(response["content"])

            return {
                "remediation_recommendations": data.get(
                    "remediation_recommendations", "Recomendações não disponíveis."
                ),
                "mitigation_measures": data.get("mitigation_measures", "Medidas não disponíveis."),
                "additional_considerations": data.get(
                    "additional_considerations", "Considerações não disponíveis."
                ),
            }

        except Exception as e:
            logger.warning(f"Erro ao processar recomendações executivas da IA: {e}")

            return {
                "remediation_recommendations": "Erro ao processar recomendações. Tente novamente.",  # noqa: E501
                "mitigation_measures": "Erro ao processar medidas. Tente novamente.",
                "additional_considerations": "Erro ao processar considerações. Tente novamente.",  # noqa: E501
            }

    # ==========================================================
    # Relatório executivo completo (LISTA DE CVEs)
    # ==========================================================

    def generate_executive_recommendations_for_list(
        self,
        cves: dict,
        business_context: dict,
        business_score: float,
    ) -> dict:
        """
        Gera recomendações executivas consolidadas para uma LISTA de CVEs.

        Retorna:
        {
            "remediation": "...",
            "mitigation": "...",
            "additional": "..."
        }
        """

        # ==========================================================
        # Preparar payload das CVEs para o prompt
        # ==========================================================
        cves_payload = []

        for cve_id, data in cves.items():
            technical = data["technical_data"]

            cves_payload.append(
                {
                    "cve": cve_id,
                    "description": (
                        technical.get("description") or technical.get("description_ai") or "N/A"
                    ),
                    "technical_score": f"{data['technical_score']:.1f}/60",
                    "final_score": f"{data['final_score']:.1f}/100",
                    "priority": data["priority"],
                }
            )

        # ==========================================================
        # Construir prompt
        # ==========================================================
        prompt = build_cve_list_ranking_prompt(
            business_context=business_context,
            business_score=business_score,
            cves=cves_payload,
        )

        # ==========================================================
        # Chamada ao modelo
        # ==========================================================
        response = self.get_completion(
            user_id="system-cve-list-report",
            message_content=prompt,
        )

        if not response or not response.get("content"):
            logger.warning("[AI] Resposta vazia para recomendações de lista")
            return {}

        # ==========================================================
        # Parse seguro do JSON
        # ==========================================================
        parsed = self._parse_ai_json_response(response["content"])

        if not parsed:
            logger.warning("[AI] Falha ao parsear JSON de recomendações de lista")
            return {}

        # ==========================================================
        # Normalizar saída para o handler
        # ==========================================================
        return {
            "remediation": parsed.get("remediation_recommendations", ""),
            "mitigation": parsed.get("mitigation_measures", ""),
            "additional": parsed.get("additional_considerations", ""),
        }
