import logging
from typing import TYPE_CHECKING, Optional

from app.core.conversation_manager import ConversationManager
from app.core.vulnerability_types import VulnerabilityType
from app.handlers.base import BaseHandler
from app.messages.bot_messages import BotMessages

if TYPE_CHECKING:
    from app.core.orchestrator import FlowOrchestrator

logger = logging.getLogger(__name__)


class ActionHandler(BaseHandler):
    """
    Lida exclusivamente com ações de botões do Slack.

    Responsabilidades:
    - ack imediato
    - evitar ações duplicadas (UI-level)
    - atualizar UI (desabilitar botões)
    - delegar fluxo ao orchestrator / handlers corretos

    NÃO contém lógica de negócio.
    """

    def __init__(
        self,
        app_client,
        bot_token,
        messages: BotMessages,
        conversation_manager: ConversationManager,
    ):
        super().__init__(app_client, bot_token, messages, conversation_manager)
        self.orchestrator: "FlowOrchestrator" | None = None
        self.processed_actions = set()

    # Integração com Orchestrator
    def set_orchestrator(self, orchestrator: "FlowOrchestrator"):
        self.orchestrator = orchestrator

    # Deduplicação (somente UI-level)
    def _is_duplicate_action(
        self,
        user_id: str,
        thread_ts: str,
        action_id: str,
        message_ts: Optional[str] = None,
    ) -> bool:
        message_ts = message_ts or thread_ts
        dedupe_key = f"{user_id}:{action_id}:{message_ts}"

        if dedupe_key in self.processed_actions:
            logger.info(f"[DUP ACTION] Ignorando ação duplicada: {dedupe_key}")
            return True

        self.processed_actions.add(dedupe_key)
        return False

    # ==========================================================
    # Utilitário: atualizar mensagem (remover botões)
    # ==========================================================

    def _update_message_status(self, body: dict, status_text: str):
        channel_id = body["channel"]["id"]
        message_ts = body["message"]["ts"]
        original_blocks = body.get("message", {}).get("blocks", [])

        updated_blocks = []
        for block in original_blocks:
            if block.get("type") == "actions":
                updated_blocks.append(
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": status_text},
                    }
                )
            else:
                updated_blocks.append(block)

        self.app_client.chat_update(
            channel=channel_id,
            ts=message_ts,
            text=status_text,
            blocks=updated_blocks,
        )

    # ==========================================================
    # CONFIRMAÇÃO FINAL DE PRIORIDADE
    # ==========================================================

    def handle_confirm_priority(self, ack, body, say):
        ack()

        user_id = body["user"]["id"]
        thread_ts = body["container"].get("thread_ts") or body["container"].get("message_ts")
        action_id = body["actions"][0]["action_id"]
        message_ts = body.get("message", {}).get("ts") or thread_ts

        if self._is_duplicate_action(user_id, thread_ts, action_id, message_ts):
            return

        state = self.conversation_manager.get_state(user_id)

        if not state or state.get("thread_ts") != thread_ts:
            self._send_message(
                say,
                self.messages.PREVIOUS_THREAD_CLOSED,
                thread_ts,
            )
            self.conversation_manager.clear_state(user_id)
            return

        # ✅ Atualiza UI
        self._update_message_status(
            body,
            "✅ *Prioridade confirmada pelo usuário.*",
        )

        # ✅ LISTA
        if state.get("cve_list"):
            self.orchestrator.scoring_and_report_handler.complete_cve_list_executive_report(  # noqa: E501
                user_id=user_id,
                thread_ts=thread_ts,
                say=say,
            )
            return

        # ✅ INDIVIDUAL
        self.orchestrator.scoring_and_report_handler.complete_prioritization_process(
            user_id=user_id,
            thread_ts=thread_ts,
            say=say,
        )

    # ==========================================================
    # RECÁLCULO
    # ==========================================================

    def handle_recalculate_priority(self, ack, body, say):
        ack()

        user_id = body["user"]["id"]
        thread_ts = body["container"].get("thread_ts") or body["container"].get("message_ts")
        action_id = body["actions"][0]["action_id"]
        message_ts = body.get("message", {}).get("ts") or thread_ts

        if self._is_duplicate_action(user_id, thread_ts, action_id, message_ts):
            return

        self._update_message_status(
            body,
            "🔄 *Usuário solicitou recálculo.*",
        )

        self.orchestrator.scoring_and_report_handler.start_recalculation_flow(
            user_id=user_id,
            thread_ts=thread_ts,
            say=say,
        )

    # ==========================================================
    # OWASP (seleção via botão)
    # ==========================================================

    # Selecionado o modo por OWASP Top 10

    def handle_select_calc_type_owasp(self, ack, body, say):
        """
        Processa seleção de OWASP sugerido pela IA.

        Regras:
        - NÃO adiciona ano (ex: :2021)
        - NÃO valida se é Top 10
        - Apenas extrai o código e delega ao domínio
        """
        ack()

        user_id = body["user"]["id"]
        thread_ts = body["container"].get("thread_ts") or body["container"].get("message_ts")
        action_id = body["actions"][0]["action_id"]

        # Extrai apenas o código OWASP (ex: A05, AI01)
        owasp_code = action_id.replace("select_calc_type_owasp_", "").upper()

        self._update_message_status(
            body,
            f"📊 *OWASP selecionado:* `{owasp_code}`",
        )

        self.orchestrator.start_vulnerability_analysis(
            user_id=user_id,
            identifier=owasp_code,
            input_type=VulnerabilityType.OWASP,
            thread_ts=thread_ts,
            say=say,
        )

    # ==========================================================
    # SELEÇÃO DE TIPO DE CÁLCULO (DESCRIÇÃO)
    # ==========================================================

    def handle_select_calc_type_description(self, ack, body, say):
        ack()

        user_id = body["user"]["id"]
        thread_ts = body["container"].get("thread_ts") or body["container"].get("message_ts")

        state = self.conversation_manager.get_state(user_id)
        description = state.get("original_description") if state else None

        if not description:
            self._send_message(
                say,
                "Não encontrei a descrição original da vulnerabilidade. Vamos reiniciar o fluxo.",  # noqa: E501
                thread_ts,
            )
            self.conversation_manager.clear_state(user_id)
            return

        self.conversation_manager.update_state(
            user_id,
            {"awaiting_calc_type_selection": False},
        )

        self._update_message_status(
            body,
            "📜 *Cálculo será realizado pela descrição.*",
        )

        self.orchestrator.start_vulnerability_analysis(
            user_id=user_id,
            identifier=description,
            input_type=VulnerabilityType.AI_SCORING_DESCRIPTION,
            thread_ts=thread_ts,
            say=say,
        )
