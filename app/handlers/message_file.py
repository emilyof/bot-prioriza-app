import logging
from typing import TYPE_CHECKING

import requests
from slack_sdk.errors import SlackApiError

from app.core.conversation_manager import ConversationManager
from app.core.vulnerability_types import VulnerabilityType
from app.handlers.base import BaseHandler
from app.messages.bot_messages import BotMessages
from app.services.file_processing_service import FileProcessingService

if TYPE_CHECKING:
    from app.core.orchestrator import FlowOrchestrator

logger = logging.getLogger(__name__)


class MessageAndFileHandler(BaseHandler):
    """
    Lida com o processamento inicial de mensagens e upload de arquivos.

    Responsabilidades:
    - Detectar uploads
    - Extrair CVEs de arquivos
    - Inicializar corretamente o estado da conversa
    - Delegar o controle ao orchestrator correto

    NÃO contém lógica de priorização ou cálculo.
    """

    def __init__(
        self,
        app_client,
        bot_token,
        messages: BotMessages,
        conversation_manager: ConversationManager,
        file_processing_service: FileProcessingService,
    ):
        super().__init__(app_client, bot_token, messages, conversation_manager)
        self.file_processing_service = file_processing_service
        self.orchestrator: "FlowOrchestrator" | None = None

    # ==========================================================
    # Integração com Orchestrator
    # ==========================================================

    def set_orchestrator(self, orchestrator: "FlowOrchestrator"):
        self.orchestrator = orchestrator

    # ==========================================================
    # Upload de arquivos
    # ==========================================================

    def _handle_file_upload(self, event, user_id, thread_ts, say, client):
        """
        Processa upload de arquivos:
        - baixa arquivo
        - extrai CVEs
        - inicia o fluxo correto
        """
        logger.info(f"[FILE] Upload detectado de {user_id}")

        file_info = event["files"][0]
        file_name = file_info["name"]
        file_type = file_info["filetype"]

        self._send_message(
            say,
            self.messages.PROCESSING_FILE.format(file_name=file_name),
            thread_ts,
        )

        try:
            # --------------------------------------------------
            # Download do arquivo
            # --------------------------------------------------
            result = client.files_info(file=file_info["id"])
            file_url = result["file"]["url_private_download"]

            headers = {"Authorization": f"Bearer {self.bot_token}"}
            response = requests.get(file_url, headers=headers, timeout=30)
            response.raise_for_status()

            file_content = response.content
            logger.info(f"[FILE] Arquivo '{file_name}' baixado com sucesso")

            # --------------------------------------------------
            # Extração de CVEs
            # --------------------------------------------------
            cve_list = self.file_processing_service.extract_cves_from_file(file_content, file_type)

            if not cve_list:
                self._send_message(
                    say,
                    self.messages.NO_VALID_CVES_IN_FILE,
                    thread_ts,
                )
                logger.info(f"[FILE] Nenhum CVE válido encontrado em '{file_name}'")
                return

            logger.info(f"[FILE] {len(cve_list)} CVE(s) extraído(s)")

            # ==================================================
            # Caso 1: apenas 1 CVE → fluxo normal
            # ==================================================
            if len(cve_list) == 1:
                self.orchestrator.start_vulnerability_analysis(
                    user_id=user_id,
                    identifier=cve_list[0],
                    input_type=VulnerabilityType.CVE,
                    thread_ts=thread_ts,
                    say=say,
                )
                return

            # ==================================================
            # Caso 2: múltiplas CVEs → fluxo CONSOLIDADO
            # ==================================================

            # Inicializa estado consolidado
            self.conversation_manager.set_state(
                user_id,
                {
                    # CONTEXTO BASE (obrigatório)
                    "input_type": VulnerabilityType.CVE,
                    "identifier": "lista de CVEs",
                    "thread_ts": thread_ts,
                    # CONTEXTO DE LISTA
                    "cve_list": cve_list,
                    # CONTRATO DAS PERGUNTAS DE NEGÓCIO (CRÍTICO)
                    "business_impact_answers": [],
                    "question_index": 0,
                    "awaiting_business_answer": True,
                },
            )

            # Mensagem informativa inicial (SEM iniciar análise individual)
            self._send_message(
                say,
                (
                    f"📋 Encontrei **{len(cve_list)} CVEs**.\n\n"
                    "A priorização será feita de forma *consolidada*, "
                    "aplicando as mesmas respostas de impacto no negócio para todas.\n\n"  # noqa: E501
                    "Vamos começar com algumas perguntas de impacto no negócio."
                ),
                thread_ts,
            )

            # Dispara PRIMEIRA pergunta de negócio
            self.orchestrator.scoring_and_report_handler._start_business_questions(
                user_id=user_id,
                thread_ts=thread_ts,
                say=say,
            )

        except SlackApiError as e:
            logger.error(
                f"[FILE] Erro Slack ao acessar arquivo {file_info['id']}: " f"{e.response['error']}"
            )
            self._send_message(
                say,
                self.messages.FILE_ACCESS_ERROR.format(error_message=e.response["error"]),
                thread_ts,
            )

        except requests.exceptions.RequestException as e:
            logger.error(f"[FILE] Erro ao baixar arquivo '{file_name}': {e}")
            self._send_message(
                say,
                self.messages.FILE_DOWNLOAD_ERROR,
                thread_ts,
            )

        except Exception as e:
            logger.error(
                f"[FILE] Erro inesperado ao processar '{file_name}': {e}",
                exc_info=True,
            )
            self._send_message(
                say,
                self.messages.UNEXPECTED_FILE_ERROR,
                thread_ts,
            )

    # ==========================================================
    # Encerramento de thread anterior
    # ==========================================================

    def _send_previous_thread_closed_message(self, state: dict):
        """
        Envia mensagem informando que o fluxo anterior foi encerrado.

        ⚠️ IMPORTANTE:
        - NÃO usar `say()`
        - Deve usar `chat_postMessage`
        """
        channel_id = state.get("channel_id")
        thread_ts = state.get("thread_ts")

        if not channel_id or not thread_ts:
            logger.warning(
                "[FLOW] Não foi possível enviar mensagem de encerramento "
                "(channel_id ou thread_ts ausente)"
            )
            return

        try:
            self.app_client.chat_postMessage(
                channel=channel_id,
                thread_ts=thread_ts,
                text=self.messages.PREVIOUS_THREAD_CLOSED,
            )

            logger.info(
                f"[FLOW] Mensagem de encerramento enviada "
                f"(channel={channel_id}, thread={thread_ts})"
            )

        except Exception as e:
            logger.error(f"[FLOW] Falha ao enviar mensagem de encerramento: {e}")
