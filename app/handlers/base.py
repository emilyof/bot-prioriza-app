import logging

from slack_sdk.errors import SlackApiError

from app.core.conversation_manager import ConversationManager
from app.messages.bot_messages import BotMessages

logger = logging.getLogger(__name__)


class BaseHandler:
    """
    Classe base para todos os manipuladores de fluxo.
    Centraliza as dependências comuns e métodos auxiliares.
    """

    def __init__(
        self,
        app_client,
        bot_token,
        messages: BotMessages,
        conversation_manager: ConversationManager,
    ):
        self.app_client = app_client
        self.bot_token = bot_token
        self.messages = messages
        self.conversation_manager = conversation_manager

        # Cache para o ID do bot, para evitar chamadas repetitivas à API
        self.bot_user_id = None

    def _send_message(self, say, text=None, thread_ts=None, blocks=None):
        payload = {}

        if text is not None:
            payload["text"] = text

        if blocks is not None:
            payload["blocks"] = blocks

        if thread_ts is not None:
            payload["thread_ts"] = thread_ts

        say(**payload)

    def _delete_message(self, channel_id, message_ts):
        """Tenta deletar uma mensagem do Slack."""
        try:
            self.app_client.chat_delete(channel=channel_id, ts=message_ts)
            logger.info(f"Mensagem {message_ts} deletada do canal {channel_id}.")
        except SlackApiError as e:
            logger.error(
                f"Erro ao deletar mensagem {message_ts} do canal {channel_id}: {e.response['error']}"  # noqa: E501
            )
        except Exception as e:
            logger.error(f"Erro inesperado ao deletar mensagem: {e}")

    def is_bot_mentioned(self, text):
        """Verifica se o bot foi mencionado na mensagem."""
        if self.bot_user_id and f"<@{self.bot_user_id}>" in text:
            return True
        return False
