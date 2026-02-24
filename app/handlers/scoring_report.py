import logging

from app.core.conversation_manager import ConversationManager
from app.core.vulnerability_types import VulnerabilityType
from app.domain.scoring_logic import (
    BUSINESS_IMPACT_QUESTIONS_CONFIG,
    calculate_business_score,
    format_executive_final_report,
    format_executive_final_report_for_cve_list,
    get_priority_emoji,
    get_risk_classification,
)
from app.handlers.base import BaseHandler
from app.messages.bot_messages import BotMessages
from app.services.ai_service import AIService
from app.services.vulnerability_service import VulnerabilityService

logger = logging.getLogger(__name__)


class ScoringAndReportHandler(BaseHandler):
    """
    Fluxo de priorização de vulnerabilidades.

    Responsabilidades:
    - iniciar análise técnica
    - coletar impacto de negócio
    - exibir preview + confirmação
    - executar recálculo técnico via IA

    Regras:
    - Para listas (cve_list): impacto de negócio é respondido uma única vez
    - Para modo individual: impacto de negócio é coletado por CVE
    """

    def __init__(
        self,
        app_client,
        bot_token,
        messages: BotMessages,
        conversation_manager: ConversationManager,
        vulnerability_service: VulnerabilityService,
        ai_service: AIService,
    ):
        super().__init__(app_client, bot_token, messages, conversation_manager)
        self.vulnerability_service = vulnerability_service
        self.ai_service = ai_service
        self.orchestrator = None

    # ==========================================================
    # Utilidades de UI
    # ==========================================================

    @staticmethod
    def _progress_bar(current: int, total: int) -> str:
        return f"{'█' * current}{'░' * (total - current)} ({current}/{total})"

    @staticmethod
    def _priority_action_blocks(text: str):
        return [
            {"type": "section", "text": {"type": "mrkdwn", "text": text}},
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "✅ Confirmar"},
                        "style": "primary",
                        "action_id": "confirm_priority",
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "✏️ Recalcular"},
                        "action_id": "recalculate_priority",
                    },
                ],
            },
        ]

    # ==========================================================
    # Início da análise
    # ==========================================================

    def start_vulnerability_analysis(
        self,
        user_id: str,
        identifier: str,
        input_type: VulnerabilityType,
        thread_ts: str,
        say,
    ):
        logger.info(f"Iniciando análise para {user_id}: {input_type.value} - {identifier}")

        previous_state = self.conversation_manager.get_state(user_id) or {}

        new_state = {
            "channel_id": previous_state.get("channel_id"),
            "thread_ts": previous_state.get("thread_ts", thread_ts),
            "identifier": identifier,
            "input_type": input_type,
            "technical_score_data": None,
            "technical_cache": {},
            "business_impact_answers": [],
            "question_index": 0,
            "awaiting_business_answer": False,
            "awaiting_confirmation": False,
            "awaiting_recalculation_justification": False,
            "recalculation_history": [],
        }

        # Preservar lista
        if "cve_list" in previous_state:
            new_state["cve_list"] = previous_state["cve_list"]

        self.conversation_manager.set_state(user_id, new_state)

        state = self.conversation_manager.get_state(user_id)

        if state.get("cve_list"):
            self._send_message(
                say,
                self.messages.START_CVE_LIST_ANALYSIS_MESSAGE,
                thread_ts,
            )

        elif input_type != VulnerabilityType.AI_SCORING_DESCRIPTION:
            self._send_message(
                say,
                self.messages.START_ANALYSIS_MESSAGE.format(
                    input_type=input_type.value,
                    identifier=identifier,
                ),
                thread_ts,
            )

        technical_data = self.vulnerability_service.calculate_technical_score(
            identifier, input_type
        )

        if not technical_data:
            self._send_message(
                say,
                self.messages.NO_DATA_FOUND.format(
                    input_type=input_type.value,
                    identifier=identifier,
                ),
                thread_ts,
            )
            self.conversation_manager.clear_state(user_id)
            return

        # CACHE PARA CVE ÚNICA
        new_state["technical_score_data"] = technical_data
        if input_type == VulnerabilityType.CVE:
            new_state["technical_cache"][identifier] = technical_data

        self.conversation_manager.update_state(
            user_id,
            new_state,
        )

        self._start_business_questions(user_id, thread_ts, say)

    # ==========================================================
    # CVE MODO LIST RANKING (PRIORITIZAÇÃO CONSOLIDADA)
    # ==========================================================

    def complete_cve_list_prioritization(
        self,
        user_id: str,
        thread_ts: str,
        say,
        preview_only: bool = False,
        override_results=None,
    ):
        state = self.conversation_manager.get_state(user_id)

        if not state or not state.get("cve_list"):
            return

        technical_cache = state.get("technical_cache", {})

        business_score, business_answers = calculate_business_score(
            state["business_impact_answers"]
        )

        cve_results = override_results or {}

        if not cve_results:
            for cve_id in state["cve_list"]:
                # USO DE CACHE
                if cve_id not in technical_cache:
                    technical_cache[cve_id] = self.vulnerability_service.calculate_technical_score(
                        cve_id, VulnerabilityType.CVE
                    )

                technical_data = technical_cache[cve_id]
                if not technical_data:
                    continue

                technical_score = technical_data["technical_subtotal"]
                final_score = technical_score + business_score
                classification, _ = get_risk_classification(final_score)

                cve_results[cve_id] = {
                    "technical_data": technical_data,
                    "technical_score": technical_score,
                    "final_score": final_score,
                    "priority": classification,
                }

            # Persistir cache
            self.conversation_manager.update_state(
                user_id,
                {"technical_cache": technical_cache},
            )

        # =====================================================
        # PREVIEW
        # =====================================================
        if preview_only:
            lines = ["*Resumo Consolidado da Lista:*", ""]

            for cve_id, data in cve_results.items():
                emoji = get_priority_emoji(data["priority"])
                lines.append(
                    f"• `{cve_id}` → {data['final_score']:.1f}/100 {emoji} {data['priority']}"  # noqa: E501
                )

            # Justificativa da IA (se houver recálculo)
            ai_justification = state.get("list_recalculation_justification")
            if ai_justification:
                lines.append("")
                lines.append("*Justificativa da IA:*")
                lines.append(f"_{ai_justification}_")

            lines.append("\nDeseja confirmar ou recalcular?")

            self.conversation_manager.update_state(
                user_id,
                {
                    "awaiting_confirmation": True,
                    "list_phase": "PREVIEW",
                },
            )

            preview_text = "\n".join(lines)

            self._send_message(
                say,
                text=preview_text,
                thread_ts=thread_ts,
                blocks=self._priority_action_blocks("\n".join(lines)),
            )
            return

    # ==========================================================
    # Perguntas de impacto no negócio
    # ==========================================================

    def _start_business_questions(self, user_id, thread_ts, say):
        self.conversation_manager.update_state(
            user_id,
            {"question_index": 0, "awaiting_business_answer": True},
        )

        state = self.conversation_manager.get_state(user_id)

        question_text = BUSINESS_IMPACT_QUESTIONS_CONFIG[0]["text"].replace(
            "{ID_OR_CATEGORY}",
            (
                state["identifier"]
                if state["input_type"] != VulnerabilityType.AI_SCORING_DESCRIPTION
                else "informada via descrição"
            ),
        )

        _ = self._progress_bar(1, len(BUSINESS_IMPACT_QUESTIONS_CONFIG))

        self._send_message(
            say,
            (
                f"{self.messages.FIRST_BUSINESS_QUESTION_INTRO.format(question_text=question_text)}"  # noqa: E501
            ),
            thread_ts,
        )

    def process_business_answer(self, user_id, message_text, thread_ts, say):
        state = self.conversation_manager.get_state(user_id)

        if (
            not state
            or not state.get("awaiting_business_answer")
            or state.get("thread_ts") != thread_ts
        ):
            return

        idx = state["question_index"]
        cfg = BUSINESS_IMPACT_QUESTIONS_CONFIG[idx]
        answer = message_text.strip().upper()

        # ---------------------------------------
        # Validação da resposta
        # ---------------------------------------
        if answer not in cfg["score_map"]:
            self._send_message(
                say,
                self.messages.INVALID_BUSINESS_ANSWER.format(
                    allowed_answers=", ".join(cfg["score_map"].keys())
                ),
                thread_ts,
            )
            return

        updated_answers = state["business_impact_answers"] + [answer]
        next_idx = idx + 1

        self.conversation_manager.update_state(
            user_id,
            {
                "business_impact_answers": updated_answers,
                "question_index": next_idx,
            },
        )

        # ---------------------------------------
        # Próxima pergunta
        # ---------------------------------------
        if next_idx < len(BUSINESS_IMPACT_QUESTIONS_CONFIG):
            next_question = BUSINESS_IMPACT_QUESTIONS_CONFIG[next_idx]["text"].replace(
                "{ID_OR_CATEGORY}",
                (
                    state["identifier"]
                    if state["input_type"] != VulnerabilityType.AI_SCORING_DESCRIPTION
                    else "informada via descrição"
                ),
            )

            progress = self._progress_bar(next_idx + 1, len(BUSINESS_IMPACT_QUESTIONS_CONFIG))

            self._send_message(
                say,
                f"*Etapa {next_idx + 1}*\n{progress}\n\n{next_question}",
                thread_ts,
            )

            return

        # ---------------------------------------
        # ÚLTIMA RESPOSTA
        # ---------------------------------------
        self.conversation_manager.update_state(
            user_id,
            {
                "awaiting_business_answer": False,
                "list_phase": "PREVIEW" if state.get("cve_list") else None,
            },
        )

        # ---------------------------------------
        # LISTA → PREVIEW CONSOLIDADO (OBRIGATÓRIO)
        # ---------------------------------------
        if state.get("cve_list"):
            self.complete_cve_list_prioritization(
                user_id=user_id,
                thread_ts=thread_ts,
                say=say,
                preview_only=True,
            )
            return

        # ---------------------------------------
        # INDIVIDUAL → preview normal
        # ---------------------------------------
        self._send_priority_preview(user_id, thread_ts, say)

    # ==========================================================
    # Preview + Confirmação
    # ==========================================================

    def _send_priority_preview(self, user_id, thread_ts, say):
        state = self.conversation_manager.get_state(user_id)

        # Nunca executar relatório individual em lista
        if state.get("cve_list"):
            logger.warning(
                "[REPORT] complete_prioritization_process chamado em modo lista. Ignorando."  # noqa: E501
            )
            return

        business_score, business_answers = calculate_business_score(
            state["business_impact_answers"]
        )

        # Captura dados da categoria do OWASP
        technical_data = state["technical_score_data"]
        technical_score = technical_data["technical_subtotal"]

        final_score = technical_score + business_score
        classification, sla = get_risk_classification(final_score)

        self.conversation_manager.update_state(
            user_id,
            {
                "business_score": business_score,
                "business_qualitative_answers": business_answers,
                "final_score": final_score,
                "classification": classification,
                "sla": sla,
                "awaiting_confirmation": True,
            },
        )

        emoji = get_priority_emoji(classification)

        preview_text = (
            f"*Resumo da Prioridade:*\n"
            f"🔷 Técnica: {technical_score:.1f}/60\n"
            f"🔷 Negócio: {business_score:.1f}/40\n"
            f"💡 *Total: {final_score:.1f}/100 → {emoji} {classification}*\n"
            f"SLA sugerido: {sla}\n\n"
            "Deseja confirmar ou recalcular?"
        )

        self._send_message(
            say,
            text=preview_text,
            thread_ts=thread_ts,
            blocks=self._priority_action_blocks(preview_text),
        )

    # ==========================================================
    # Recálculo técnico (IA)
    # ==========================================================

    def start_recalculation_flow(self, user_id, thread_ts, say):
        state = self.conversation_manager.get_state(user_id)

        updates = {
            "awaiting_recalculation_justification": True,
            "awaiting_confirmation": False,
        }

        if state.get("cve_list"):
            updates["list_phase"] = "RECALCULATION"

        self.conversation_manager.update_state(user_id, updates)

        self._send_message(
            say,
            self.messages.RECALCULATION_JUSTIFICATION_REQUEST,
            thread_ts,
        )

    def handle_recalculation_justification(self, user_id, message_text, thread_ts, say):
        state = self.conversation_manager.get_state(user_id)

        if not state or state.get("thread_ts") != thread_ts:
            return

        # LISTA
        if state.get("cve_list") and state.get("list_phase") == "RECALCULATION":
            self._handle_list_recalculation(user_id, message_text, thread_ts, say)
            return

        # INDIVIDUAL
        self._handle_single_recalculation(user_id, message_text, thread_ts, say)

    def _handle_list_recalculation(self, user_id, message_text, thread_ts, say):
        state = self.conversation_manager.get_state(user_id)
        justification = message_text.strip()

        technical_cache = state.get("technical_cache", {})

        # Impacto de negócio é ÚNICO no modo lista
        business_score, business_answers = calculate_business_score(
            state["business_impact_answers"]
        )

        updated_results = {}
        last_ai_justification = None

        for cve_id in state["cve_list"]:
            technical_data = technical_cache.get(cve_id)

            if not technical_data:
                continue

            ai_result = self.ai_service.recalculate_technical_score(
                original_technical_data=technical_data,
                business_answers=business_answers,
                business_score=business_score,
                user_justification=justification,
                recalculation_history=state.get("recalculation_history", []),
                allow_score_decrease=True,
            )

            if ai_result:
                previous_score = technical_data["technical_subtotal"]
                new_score = ai_result["technical_subtotal"]

                # Guard-rail: nunca permitir aumento em recálculo mitigador
                if new_score <= previous_score:
                    technical_data["technical_subtotal"] = new_score
                else:
                    logger.warning(
                        f"[LIST_RECALC_GUARDRAIL] Score aumentado ignorado para {cve_id}: "  # noqa: E501
                        f"{previous_score:.1f} → {new_score:.1f}"
                    )
                    technical_data["technical_subtotal"] = previous_score

                last_ai_justification = ai_result.get("justification")

            final_score = technical_data["technical_subtotal"] + business_score
            classification, _ = get_risk_classification(final_score)

            updated_results[cve_id] = {
                "technical_data": technical_data,
                "technical_score": technical_data["technical_subtotal"],
                "final_score": final_score,
                "priority": classification,
            }

        # Atualizar estado corretamente
        self.conversation_manager.update_state(
            user_id,
            {
                "technical_cache": technical_cache,
                "list_phase": "PREVIEW",
                "awaiting_recalculation_justification": False,
                "list_recalculation_justification": last_ai_justification,
            },
        )

        # Preview consolidado
        self.complete_cve_list_prioritization(
            user_id=user_id,
            thread_ts=thread_ts,
            say=say,
            preview_only=True,
            override_results=updated_results,
        )

    def _handle_single_recalculation(
        self,
        user_id,
        message_text,
        thread_ts,
        say,
    ):
        """
        Processa a justificativa do usuário para recálculo técnico
        (fluxo INDIVIDUAL apenas).
        """

        state = self.conversation_manager.get_state(user_id)
        if not state or state.get("thread_ts") != thread_ts:
            logger.warning(f"[RECALC] Estado inválido ou thread diferente para {user_id}")
            return

        justification = message_text.strip()

        logger.info(
            f"[RECALC] Processando recálculo individual para {user_id}. "
            f"Justificativa: {justification[:100]}..."
        )

        # CONTEXTO DE NEGÓCIO CORRETO
        business_answers = state.get("business_qualitative_answers", [])

        ai_result = self.ai_service.recalculate_technical_score(
            original_technical_data=state["technical_score_data"],
            business_answers=business_answers,
            business_score=state["business_score"],
            user_justification=justification,
            recalculation_history=state.get("recalculation_history", []),
            allow_score_decrease=True,
        )

        if not ai_result:
            logger.warning(f"[RECALC] IA não retornou resultado válido para {user_id}")
            self._send_message(
                say,
                "⚠️ Não foi possível recalcular a pontuação. Mantendo score original.",
                thread_ts,
            )
            self._send_priority_preview(user_id, thread_ts, say)
            return

        new_score = ai_result["technical_subtotal"]
        ai_justification = ai_result.get("justification", "")

        previous_score = state["technical_score_data"]["technical_subtotal"]

        logger.info(
            f"[RECALC] Score recalculado para {user_id}: " f"{previous_score:.1f} → {new_score:.1f}"
        )

        # Recalcular score final
        business_score = float(state.get("business_score", 0))
        final_score = max(0, min(new_score + business_score, 100))

        classification, sla = get_risk_classification(final_score)

        # Atualizar estado
        self.conversation_manager.update_state(
            user_id,
            {
                "technical_score_data": {
                    **state["technical_score_data"],
                    "technical_subtotal": new_score,
                    "ai_recalculation_justification": ai_justification,
                },
                "recalculation_history": state.get("recalculation_history", [])
                + [
                    {
                        "previous_technical_score": previous_score,
                        "user_justification": justification,
                        "ai_result": ai_result,
                    }
                ],
                "final_score": final_score,
                "classification": classification,
                "sla": sla,
                "awaiting_recalculation_justification": False,
                "awaiting_confirmation": True,
            },
        )

        emoji = get_priority_emoji(classification)

        preview_text = (
            "*Resumo da Prioridade (recalculado):*\n"
            f"🔹 Técnica (recalculada): {new_score:.1f}/60\n"
            f"🔹 Negócio: {business_score:.1f}/40\n"
            f"💡 *Total: {final_score:.1f}/100 → {emoji} {classification}*\n"
            f"SLA sugerido: {sla}\n\n"
            "*Justificativa da IA:*\n"
            f"_{ai_justification}_\n\n"
            "Deseja confirmar ou recalcular novamente?"
        )

        self._send_message(
            say,
            text=preview_text,
            thread_ts=thread_ts,
            blocks=self._priority_action_blocks(preview_text),
        )

        logger.info(f"[RECALC] Preview recalculado enviado para {user_id}")

    # ==========================================================
    # Finalização
    # ==========================================================

    def complete_prioritization_process(self, user_id, thread_ts, say):
        """
        Finaliza o processo de priorização gerando relatório executivo completo.

        ⚠️ EXCLUSIVO para:
        - CVE única
        - OWASP
        - Descrição livre
        """

        state = self.conversation_manager.get_state(user_id)
        if not state:
            return

        # Nunca rodar para lista
        if state.get("cve_list"):
            logger.warning(
                "[REPORT] complete_prioritization_process chamado em modo lista. Ignorando."  # noqa: E501
            )
            return

        # Garantir classificação e SLA (defensivo)
        if not state.get("classification") or not state.get("sla"):
            technical_score = state["technical_score_data"]["technical_subtotal"]
            business_score = state["business_score"]

            final_score = technical_score + business_score
            classification, sla = get_risk_classification(final_score)

            self.conversation_manager.update_state(
                user_id,
                {
                    "final_score": final_score,
                    "classification": classification,
                    "sla": sla,
                },
            )

            state = self.conversation_manager.get_state(user_id)

        # ==========================================================
        # Obter descrição
        # ==========================================================
        if state["input_type"] == VulnerabilityType.CVE:
            description = self.vulnerability_service.get_cve_description(state["identifier"])
        elif state["input_type"] == VulnerabilityType.OWASP:
            tech = state["technical_score_data"]
            owasp_code = state["identifier"]
            owasp_title = tech.get("description_ai", "OWASP Category")

            description = self.ai_service.generate_owasp_category_description(
                owasp_code=owasp_code,
                owasp_title=owasp_title,
            )
        elif state["input_type"] == VulnerabilityType.AI_SCORING_DESCRIPTION:
            description = state["technical_score_data"].get(
                "description_ai", "Descrição informada pelo usuário."
            )

        # ==========================================================
        # Gerar recomendações executivas (IA)
        # ==========================================================
        self._send_message(
            say,
            "🧠 Gerando recomendações de correção e mitigação...",
            thread_ts,
        )

        ai_recommendations = self.ai_service.generate_executive_recommendations(
            identifier=state["identifier"],
            description=description,
            input_type=state["input_type"],
            technical_data=state["technical_score_data"],
            business_answers=state["business_qualitative_answers"],
            final_score=state["final_score"],
            classification=state["classification"],
        )

        # ==========================================================
        # Relatório executivo final
        # ==========================================================
        report_text = format_executive_final_report(
            identifier=state["identifier"],
            description=description,
            input_type=state["input_type"],
            technical_data=state["technical_score_data"],
            business_score=state["business_score"],
            business_answers=state["business_qualitative_answers"],
            final_score=state["final_score"],
            classification=state["classification"],
            sla=state["sla"],
            ai_recommendations=ai_recommendations,
        )

        # ✅ Enviar relatório executivo
        self._send_message(
            say,
            report_text,
            thread_ts,
        )

        # ✅ Só depois encerrar a conversa
        self.conversation_manager.close_conversation(
            user_id,
            reason="completed",
        )
        self.conversation_manager.clear_state(user_id)

        logger.info(f"[REPORT] Fluxo finalizado para {user_id}")

    def complete_cve_list_executive_report(
        self,
        user_id: str,
        thread_ts: str,
        say,
    ):
        """
        Gera o RELATÓRIO EXECUTIVO FINAL para uma LISTA de CVEs.

        Regras:
        - Usa o MESMO padrão visual do relatório individual
        - Detalha completamente apenas a CVE mais crítica
        - As demais CVEs aparecem de forma resumida
        """

        state = self.conversation_manager.get_state(user_id)
        if not state or not state.get("cve_list"):
            logger.warning("[LIST_REPORT] Estado inválido ou não é lista")
            return

        technical_cache = state.get("technical_cache", {})

        # Impacto de negócio (UMA ÚNICA VEZ)
        business_score, business_answers = calculate_business_score(
            state.get("business_impact_answers", [])
        )

        # Consolidar resultados técnicos
        cve_results = {}

        for cve_id in state["cve_list"]:
            # Garantir cache técnico
            if cve_id not in technical_cache:
                technical_cache[cve_id] = self.vulnerability_service.calculate_technical_score(
                    cve_id, VulnerabilityType.CVE
                )

            technical_data = technical_cache.get(cve_id)
            if not technical_data:
                continue

            # Garantir descrição
            technical_data["description"] = self.vulnerability_service.get_cve_description(cve_id)

            technical_score = technical_data.get("technical_subtotal", 0.0)
            final_score = technical_score + business_score
            classification, sla = get_risk_classification(final_score)

            cve_results[cve_id] = {
                "technical_data": technical_data,
                "technical_score": technical_score,
                "final_score": final_score,
                "priority": classification,
                "sla": sla,
            }

        if not cve_results:
            self._send_message(
                say,
                "❌ Não foi possível gerar o relatório executivo da lista de CVEs.",
                thread_ts,
            )
            self.conversation_manager.clear_state(user_id)
            return

        # Persistir cache atualizado
        self.conversation_manager.update_state(
            user_id,
            {"technical_cache": technical_cache},
        )

        # Definir CVE mais crítica
        focus_cve = max(
            cve_results.items(),
            key=lambda item: item[1]["final_score"],
        )[0]

        focus_data = cve_results[focus_cve]

        # Recomendações executivas consolidadas (IA)
        self._send_message(
            say,
            "🧠 Gerando recomendações executivas consolidadas para a lista de CVEs...",
            thread_ts,
        )

        ai_recommendations = self.ai_service.generate_executive_recommendations_for_list(
            cves=cve_results,
            business_context=business_answers,
            business_score=business_score,
        )

        # Relatório final (DOMÍNIO)
        report_text = format_executive_final_report_for_cve_list(
            focus_cve=focus_cve,
            focus_data=focus_data,
            all_cves=cve_results,
            business_score=business_score,
            business_answers=business_answers,
            ai_recommendations=ai_recommendations,
            ai_recalculation_justification=state.get("list_recalculation_justification"),
        )

        # ENVIAR RELATÓRIO PARA O SLACK (PASSO QUE FALTAVA)
        self._send_message(
            say,
            report_text,
            thread_ts,
        )

        # Finalizar conversa APÓS envio
        self.conversation_manager.close_conversation(
            user_id,
            reason="completed",
        )
        self.conversation_manager.clear_state(user_id)

        logger.info(f"[LIST_REPORT] Relatório executivo de lista finalizado para {user_id}")
