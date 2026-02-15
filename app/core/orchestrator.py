import logging
import re
from typing import TYPE_CHECKING

from slack_sdk.errors import SlackApiError

from app.core.vulnerability_types import VulnerabilityType
from app.handlers.action import ActionHandler
from app.handlers.conversation import ConversationHandler
from app.handlers.message_file import MessageAndFileHandler
from app.handlers.scoring_report import ScoringAndReportHandler
from app.messages.bot_messages import BotMessages

if TYPE_CHECKING:
    from slack_sdk import WebClient

logger = logging.getLogger(__name__)


class FlowOrchestrator:
    """
    Orquestra o fluxo de interação do bot Slack.

    Responsabilidades:
    - Receber mensagens, mentions e actions
    - Garantir idempotência por thread
    - Roteamento baseado em estado
    - Delegar lógica para handlers especializados

    NÃO contém lógica de cálculo técnico ou recálculo.
    """

    def __init__(
        self,
        ai_service,
        vulnerability_service,
        file_processing_service,
        conversation_manager,
        app_client: "WebClient",
        bot_token: str,
        messages: BotMessages,
    ):
        self.conversation_manager = conversation_manager
        self.app_client = app_client
        self.messages = messages
        self.bot_user_id = None

        # Handlers especializados
        self.message_and_file_handler = MessageAndFileHandler(
            app_client,
            bot_token,
            messages,
            conversation_manager,
            file_processing_service,
        )

        self.scoring_and_report_handler = ScoringAndReportHandler(
            app_client,
            bot_token,
            messages,
            conversation_manager,
            vulnerability_service,
            ai_service,
        )

        self.action_handler = ActionHandler(
            app_client,
            bot_token,
            messages,
            conversation_manager,
        )

        self.conversation_handler = ConversationHandler(
            app_client,
            bot_token,
            messages,
            conversation_manager,
            vulnerability_service,
            ai_service,
        )

        # Injeção do orchestrator
        self.message_and_file_handler.set_orchestrator(self)
        self.scoring_and_report_handler.orchestrator = self
        self.action_handler.set_orchestrator(self)
        self.conversation_handler.set_orchestrator(self)

        # Identificação do bot
        try:
            auth_test = self.app_client.auth_test()
            self.bot_user_id = auth_test.get("user_id")
            logger.info(f"Bot user ID obtido: {self.bot_user_id}")
        except SlackApiError as e:
            logger.error(f"Erro ao obter ID do bot: {e.response['error']}")
            self.bot_user_id = "UNKNOWN_BOT_ID"

        # Propaga bot_user_id para os handlers
        self.message_and_file_handler.bot_user_id = self.bot_user_id
        self.scoring_and_report_handler.bot_user_id = self.bot_user_id
        self.action_handler.bot_user_id = self.bot_user_id
        self.conversation_handler.bot_user_id = self.bot_user_id

    # ==========================================================
    # Entrada principal (mensagens e mentions)
    # ==========================================================

    def handle_app_mention_and_message(self, body, say, client):
        event = body["event"]
        user_id = event["user"]
        thread_ts = event.get("thread_ts", event["ts"])
        message_text = event.get("text", "").strip()

        is_bot_mentioned_or_im = (
            self.message_and_file_handler.is_bot_mentioned(message_text)
            or event.get("channel_type") == "im"
        )

        if is_bot_mentioned_or_im:
            message_text = message_text.replace(f"<@{self.bot_user_id}>", "").strip()

        state = self.conversation_manager.get_state(user_id)

        # Menção ao bot SEMPRE encerra fluxo anterior
        if self.message_and_file_handler.is_bot_mentioned(event.get("text", "")) and state:
            closed_state = self.conversation_manager.close_conversation(
                user_id,
                reason="new_mention",
            )

            if closed_state:
                self.message_and_file_handler._send_previous_thread_closed_message(closed_state)

            self.conversation_manager.clear_state(user_id)
            state = None

        # Criar estado somente quando iniciar novo fluxo
        if not state and is_bot_mentioned_or_im:
            self.conversation_manager.set_state(
                user_id,
                {
                    "channel_id": event["channel"],
                    "thread_ts": thread_ts,
                },
            )
            state = self.conversation_manager.get_state(user_id)

        # Upload de arquivos
        if event.get("files"):
            self.message_and_file_handler._handle_file_upload(
                event,
                user_id,
                thread_ts,
                say,
                client,
            )
            return

        # ======================================================
        # ROTEAMENTO POR ESTADO (ORDEM IMPORTA)
        # ======================================================

        # Recálculo técnico (prioridade máxima)
        if self.conversation_manager.is_awaiting_recalculation_justification(user_id, thread_ts):
            self.scoring_and_report_handler.handle_recalculation_justification(
                user_id,
                message_text,
                thread_ts,
                say,
            )
            return

        # Perguntas de impacto no negócio
        if self.conversation_manager.is_in_active_vulnerability_flow(user_id, thread_ts):
            self.scoring_and_report_handler.process_business_answer(
                user_id,
                message_text,
                thread_ts,
                say,
            )
            return

        # ======================================================
        # Fluxo inicial (idempotente por thread)
        # ======================================================

        if is_bot_mentioned_or_im and not state.get("flow_started"):
            self.conversation_manager.update_state(user_id, {"flow_started": True})
            self.process_initial_message_intent(
                user_id,
                message_text,
                thread_ts,
                say,
            )

    # ==========================================================
    # Intenção inicial
    # ==========================================================

    def process_initial_message_intent(self, user_id, message_text, thread_ts, say):
        if not message_text:
            self.message_and_file_handler._send_message(
                say, self.messages.WELCOME_MESSAGE, thread_ts
            )
            return

        input_type, identifier = self.detect_input_type(message_text)

        # CVE → fluxo direto
        if input_type == VulnerabilityType.CVE:
            self.start_vulnerability_analysis(user_id, identifier, input_type, thread_ts, say)
            return

        # OWASP explícito → fluxo OWASP
        if input_type == VulnerabilityType.OWASP:
            self.conversation_handler.handle_owasp_selection(user_id, identifier, thread_ts, say)
            return

        # DESCRIÇÃO → tentar identificar OWASP com IA
        self.conversation_handler.handle_description_input(
            user_id=user_id,
            description=identifier,
            thread_ts=thread_ts,
            say=say,
        )

    # ==========================================================
    # Actions (botões)
    # ==========================================================

    def handle_action(self, action_id, ack, body, say):
        logger.debug(f"[FLOW] Action recebida: {action_id}")

        action_map = {
            "confirm_priority": self.action_handler.handle_confirm_priority,
            "recalculate_priority": self.action_handler.handle_recalculate_priority,
        }

        if action_id.startswith("select_owasp_category_"):
            return self.action_handler.handle_select_owasp_category(ack, body, say)

        if action_id == "select_calc_type_description":
            return self.action_handler.handle_select_calc_type_description(ack, body, say)

        if action_id.startswith("select_calc_type_owasp_"):
            return self.action_handler.handle_select_calc_type_owasp(ack, body, say)

        if action_id in action_map:
            return action_map[action_id](ack, body, say)

        logger.warning(f"⚠️ Action ID '{action_id}' não mapeado.")
        ack()

    # ==========================================================
    # Delegações explícitas
    # ==========================================================

    def start_vulnerability_analysis(
        self,
        user_id,
        identifier,
        input_type,
        thread_ts,
        say,
    ):
        self.scoring_and_report_handler.start_vulnerability_analysis(
            user_id,
            identifier,
            input_type,
            thread_ts,
            say,
        )

    def complete_prioritization_process(self, user_id, thread_ts, say):
        self.scoring_and_report_handler.complete_prioritization_process(
            user_id,
            thread_ts,
            say,
        )

    # ==========================================================
    # Detecção de tipo de entrada
    # ==========================================================

    def detect_input_type(self, text):
        from app.utils.helpers import sanitize_text

        sanitized = sanitize_text(text).upper().strip()

        # CVE
        if re.match(r"^CVE-\d{4}-\d{4,}$", sanitized):
            return VulnerabilityType.CVE, sanitized

        # OWASP → NORMALIZA (remove :2021)
        legacy_match = re.match(r"^(A|AI)\d{2}:\d{4}$", sanitized)
        if legacy_match:
            normalized = sanitized.split(":")[0]
            return VulnerabilityType.OWASP, normalized

        # Descrição livre
        return VulnerabilityType.AI_SCORING_DESCRIPTION, sanitized
