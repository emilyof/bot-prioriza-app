import logging
import os

from dotenv import load_dotenv
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

# Providers de IA
from app.adapters.groq_ai_provider import GroqAIProvider
from app.adapters.internal_ai_provider import InternalAIProvider
from app.core.conversation_manager import ConversationManager
from app.core.orchestrator import FlowOrchestrator
from app.messages.bot_messages import BotMessages

# Serviços e Core
from app.services.ai_service import AIService
from app.services.file_processing_service import FileProcessingService
from app.services.vulnerability_service import VulnerabilityService

# Slack
from app.slack.listeners import register_listeners_function

# ==========================================================
# Logging
# ==========================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# ==========================================================
# Função Principal
# ==========================================================


def main():
    load_dotenv()

    # ==========================================================
    # 2. VARIÁVEIS DE AMBIENTE
    # ==========================================================

    bot_token = os.getenv("SLACK_BOT_TOKEN")
    app_token = os.getenv("SLACK_APP_TOKEN")

    ai_provider_name = os.getenv("AI_PROVIDER", "internal").lower()
    ai_api_url = os.getenv("AI_API_URL")
    ai_api_token = os.getenv("AI_API_TOKEN")
    ai_model_override = os.getenv("AI_MODEL_OVERRIDE")

    vulncheck_token = os.getenv("VULNCHECK_TOKEN")

    # Validar variáveis obrigatórias
    if not all([bot_token, app_token, ai_api_url, ai_api_token, vulncheck_token]):
        logger.critical(
            "❌ Variáveis obrigatórias não configuradas: "
            "SLACK_BOT_TOKEN, SLACK_APP_TOKEN, AI_API_URL, AI_API_TOKEN, VULNCHECK_TOKEN"  # noqa: E501
        )
        raise RuntimeError("Variáveis obrigatórias não configuradas. Verifique o arquivo .env")

    logger.info("✅ Variáveis de ambiente validadas")

    # ==========================================================
    # 3. APP SLACK
    # ==========================================================

    app = App(token=bot_token)
    logger.info("✅ Slack App inicializado")

    # ==========================================================
    # 4. MENSAGENS
    # ==========================================================

    bot_messages = BotMessages()

    # ==========================================================
    # 5. PROVIDER DE IA
    # ==========================================================

    if ai_provider_name == "groq":
        logger.info("🤖 Usando Groq como provider de IA")
        ai_provider = GroqAIProvider(
            base_url=ai_api_url,
            token=ai_api_token,
            model_override=ai_model_override,
        )
    else:
        logger.info("🤖 Usando IA interna como provider")
        ai_provider = InternalAIProvider(
            base_url=ai_api_url,
            token=ai_api_token,
        )

    # ==========================================================
    # 6. SERVIÇOS
    # ==========================================================

    ai_service = AIService(ai_provider)
    logger.info("✅ AIService inicializado")

    vulnerability_service = VulnerabilityService(
        vulncheck_api_token=vulncheck_token,
        messages=bot_messages,
        ai_service=ai_service,
    )
    logger.info("✅ VulnerabilityService inicializado")

    file_processing_service = FileProcessingService()
    logger.info("✅ FileProcessingService inicializado")

    conversation_manager = ConversationManager()
    logger.info("✅ ConversationManager inicializado")

    # ==========================================================
    # 7. ORCHESTRATOR
    # ==========================================================

    flow_orchestrator = FlowOrchestrator(
        ai_service=ai_service,
        vulnerability_service=vulnerability_service,
        file_processing_service=file_processing_service,
        conversation_manager=conversation_manager,
        app_client=app.client,
        bot_token=bot_token,
        messages=bot_messages,
    )
    logger.info("✅ FlowOrchestrator inicializado")

    # ==========================================================
    # 8. LISTENERS
    # ==========================================================

    register_listeners_function(
        app=app,
        orchestrator=flow_orchestrator,
        conversation_manager=conversation_manager,
    )
    logger.info("✅ Listeners registrados")

    # ==========================================================
    # 10. START
    # ==========================================================

    logger.info("⚡️ Slack Bolt app iniciado com sucesso")
    SocketModeHandler(app, app_token).start()


# ==========================================================
# Entry point
# ==========================================================

if __name__ == "__main__":
    main()
