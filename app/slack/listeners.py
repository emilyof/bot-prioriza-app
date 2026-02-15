import logging
import re

from slack_bolt import App

from app.core.conversation_manager import ConversationManager
from app.core.orchestrator import FlowOrchestrator

logger = logging.getLogger(__name__)


def register_listeners_function(
    app: App,
    orchestrator: FlowOrchestrator,
    conversation_manager: ConversationManager,
):
    """
    Registra os listeners do Slack.

    Responsabilidade deste arquivo:
    - Apenas escutar eventos do Slack
    - Encaminhar eventos para o FlowOrchestrator

    NÃO contém:
    - deduplicação
    - lógica de fluxo
    - leitura de estado
    """

    # ==========================================================
    # Messages (DMs e canais SEM menção)
    # ==========================================================

    @app.event("message")
    def handle_message(body, say):
        event = body.get("event", {})
        text = event.get("text", "")

        # Ignorar mensagens que NÃO devem ser processadas
        if (
            event.get("subtype") in ["bot_message", "message_changed"]
            or "bot_id" in event
            or not event.get("user")
            or event.get("user") == orchestrator.bot_user_id
        ):
            return

        # Se tiver menção ao bot, IGNORA
        if f"<@{orchestrator.bot_user_id}>" in text:
            return

        orchestrator.handle_app_mention_and_message(
            body=body,
            say=say,
            client=app.client,
        )

    # ==========================================================
    # Mentions ao bot (ÚNICO caminho para mensagens com menção)
    # ==========================================================

    @app.event("app_mention")
    def handle_app_mention(body, say):
        event = body.get("event", {})

        if (
            event.get("subtype") in ["bot_message", "message_changed"]
            or "bot_id" in event
            or not event.get("user")
            or event.get("user") == orchestrator.bot_user_id
        ):
            return

        orchestrator.handle_app_mention_and_message(
            body=body,
            say=say,
            client=app.client,
        )

    # ==========================================================
    # Actions (botões)
    # ==========================================================

    @app.action(re.compile(r".*"))
    def handle_actions(ack, body, say):
        """
        Encaminha actions para o FlowOrchestrator.
        O ack é obrigatório e sempre imediato.
        """
        ack()

        action = body.get("actions", [{}])[0]
        action_id = action.get("action_id")

        if not action_id:
            logger.warning("Action recebida sem action_id.")
            return

        orchestrator.handle_action(
            action_id=action_id,
            ack=lambda: None,  # ack já foi feito
            body=body,
            say=say,
        )

    # ==========================================================
    # Entrada do bot em canais
    # ==========================================================

    @app.event("member_joined_channel")
    def handle_channel_join(event, say):
        user_id = event.get("user")

        if user_id != orchestrator.bot_user_id:
            return

        channel_id = event.get("channel")

        orchestrator.message_and_file_handler._send_message(
            say,
            orchestrator.messages.WELCOME_MESSAGE,
            channel_id,
        )
