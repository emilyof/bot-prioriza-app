import logging
from typing import TYPE_CHECKING

from app.core.conversation_manager import ConversationManager
from app.core.vulnerability_types import VulnerabilityType
from app.handlers.base import BaseHandler
from app.messages.bot_messages import BotMessages
from app.services.owasp_service import OWASPService
from app.services.vulnerability_service import VulnerabilityService
from app.utils.text_normalizer import normalize_description_case

if TYPE_CHECKING:
    from app.core.orchestrator import FlowOrchestrator
    from app.services.ai_service import AIService

logger = logging.getLogger(__name__)


class ConversationHandler(BaseHandler):
    """
    Manipula fluxos conversacionais explícitos que NÃO dependem de botões.

    Responsabilidades:
    - Tratar entrada textual OWASP
    - Tratar descrição livre de vulnerabilidade
    - Solicitar escolha do tipo de cálculo (OWASP sugerido ou descrição)

    NÃO contém:
    - Lógica de cálculo
    - Lógica de scoring
    - Lógica de confirmação ou recálculo
    """

    def __init__(
        self,
        app_client,
        bot_token,
        messages: BotMessages,
        conversation_manager: ConversationManager,
        vulnerability_service: VulnerabilityService,
        ai_service: "AIService",
    ):
        super().__init__(app_client, bot_token, messages, conversation_manager)

        self.orchestrator: "FlowOrchestrator" | None = None
        self.vulnerability_service = vulnerability_service
        self.ai_service = ai_service
        self.owasp_service = OWASPService()

    # ==========================================================
    # Integração com Orchestrator
    # ==========================================================

    def set_orchestrator(self, orchestrator: "FlowOrchestrator"):
        self.orchestrator = orchestrator

    # ==========================================================
    # OWASP (entrada textual)
    # ==========================================================

    def handle_owasp_selection(self, user_id, original_text, thread_ts, say):
        """
        Trata entrada OWASP textual.
        - Sempre aceita OWASP informado
        - Validação e score ficam no domínio
        """

        logger.info(f"[OWASP] Entrada recebida: {original_text}")

        input_type, identifier = self.orchestrator.detect_input_type(original_text)

        if input_type != VulnerabilityType.OWASP:
            return

        logger.info(f"[OWASP] Categoria informada pelo usuário: {identifier}")

        # SEM validação de Top 10 aqui
        self.orchestrator.start_vulnerability_analysis(
            user_id=user_id,
            identifier=identifier,
            input_type=VulnerabilityType.OWASP,
            thread_ts=thread_ts,
            say=say,
        )

    # ==========================================================
    # Descrição → sugestão OWASP + escolha de cálculo
    # ==========================================================

    def handle_description_input(self, user_id, description, thread_ts, say):
        """
        Recebe uma descrição livre de vulnerabilidade, identifica possíveis
        categorias OWASP e permite ao usuário escolher o tipo de cálculo.

        Fluxo:
        1️⃣ Tentativa determinística via OWASPService
        2️⃣ Fallback semântico via IA (se domínio falhar)
        3️⃣ Usuário escolhe como calcular (OWASP ou descrição)
        """

        logger.info("[DESCRIPTION] Processando descrição para sugestão OWASP")

        # Normalização
        normalized_description = normalize_description_case(description)

        logger.debug(f"[DESCRIPTION] Original: {description[:80]}...")
        logger.debug(f"[DESCRIPTION] Normalizada: {normalized_description[:80]}...")

        identified_owasp: list[dict] = []

        # Match determinístico (prioritário)
        deterministic_matches = self.owasp_service.match_all_from_text(normalized_description)

        for category in deterministic_matches:
            identified_owasp.append(
                {
                    "code": category.code,
                    "title": category.title,
                }
            )

        # Fallback semântico via IA (APENAS se nada encontrado)
        if not identified_owasp and self.ai_service:
            logger.info(
                "[DESCRIPTION] Nenhum OWASP identificado pelo domínio. "
                "Usando IA como fallback semântico."
            )

            ai_suggestions = self.ai_service.suggest_owasp_from_description(normalized_description)

            for item in ai_suggestions or []:
                code = item.get("code")
                if not code:
                    continue

                category = self.owasp_service.resolve_by_code(code)
                if not category:
                    logger.info(f"[OWASP] IA sugeriu categoria fora do Top 10 atual: {code}")
                    continue

                identified_owasp.append(
                    {
                        "code": category.code,
                        "title": category.title,
                    }
                )

        # Atualiza estado da conversa
        self.conversation_manager.update_state(
            user_id,
            {
                "original_description": normalized_description,
                "identified_owasp": identified_owasp,
                "awaiting_calc_type_selection": True,
                "thread_ts": thread_ts,
            },
        )

        # UI — opções de cálculo
        self.send_calculation_type_options(
            say=say,
            thread_ts=thread_ts,
            identified_owasp=identified_owasp,
        )

    # ==========================================================
    # Opções de cálculo
    # ==========================================================

    def send_calculation_type_options(self, say, thread_ts, identified_owasp):
        elements = []
        description_lines = []

        # Só mostra OWASP se houver
        if identified_owasp:
            description_lines.append("Identifiquei possíveis formas de calcular a prioridade:")
            description_lines.append("")

            for item in identified_owasp:
                code = item.get("code")
                title = item.get("title")

                # Texto completo
                if title:
                    description_lines.append(f"• *{code}* — {title}")
                else:
                    description_lines.append(f"• *{code}*")

                # Botão curto (Slack‑safe)
                elements.append(
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": f"OWASP {code}",
                            "emoji": True,
                        },
                        "action_id": f"select_calc_type_owasp_{code}",
                    }
                )

            description_lines.append("")
            description_lines.append("*Ou, se preferir:*")

        else:
            # Caso IA falhe
            description_lines.append(
                "Não consegui identificar automaticamente uma categoria OWASP."
            )
            description_lines.append("")
            description_lines.append("*Você pode prosseguir assim:*")

        # Botão alternativo (sempre)
        elements.append(
            {
                "type": "button",
                "text": {
                    "type": "plain_text",
                    "text": "Calcular pela descrição",
                    "emoji": True,
                },
                "action_id": "select_calc_type_description",
            }
        )

        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "\n".join(description_lines),
                },
            },
            {
                "type": "actions",
                "elements": elements,
            },
        ]

        say(
            text="Selecione como deseja calcular a prioridade.",
            blocks=blocks,
            thread_ts=thread_ts,
        )
