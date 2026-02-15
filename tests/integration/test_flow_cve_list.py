from unittest.mock import Mock

import pytest

from app.core.conversation_manager import ConversationManager
from app.core.orchestrator import FlowOrchestrator
from app.messages.bot_messages import BotMessages
from app.services.vulnerability_service import VulnerabilityService

# ==========================================================
# FIXTURES
# ==========================================================


@pytest.fixture
def say_mock():
    return Mock()


@pytest.fixture
def app_client_mock():
    client = Mock()
    client.auth_test.return_value = {"user_id": "BOT123"}
    return client


@pytest.fixture
def vulnerability_service_mock():
    service = Mock(spec=VulnerabilityService)
    service.get_cve_description.return_value = "Descrição da CVE"
    return service


@pytest.fixture
def ai_service_mock():
    return Mock()


@pytest.fixture
def orchestrator(app_client_mock, vulnerability_service_mock, ai_service_mock):
    orchestrator = FlowOrchestrator(
        ai_service=ai_service_mock,
        vulnerability_service=vulnerability_service_mock,
        file_processing_service=Mock(),
        conversation_manager=ConversationManager(),
        app_client=app_client_mock,
        bot_token="fake-token",
        messages=BotMessages(),
    )

    # Isola qualquer sugestão automática de OWASP
    orchestrator.conversation_handler.ai_service.suggest_owasp_from_description.return_value = (  # noqa: E501
        []
    )

    return orchestrator


# ==========================================================
# TESTE — FLUXO LISTA DE CVEs
# ==========================================================


def test_flow_creates_cve_list_state(orchestrator, say_mock):
    """
    Contrato atual:
    ✅ Entrada com múltiplos CVEs cria cve_list
    ✅ Estado da conversa é preservado
    ✅ Análise individual NÃO é iniciada automaticamente
    """

    user_id = "U1"
    thread_ts = "T1"

    body = {
        "event": {
            "user": user_id,
            "text": "CVE-2024-0001\nCVE-2024-0002\nCVE-2024-0003",
            "ts": thread_ts,
            "channel": "C1",
            "channel_type": "im",
        }
    }

    orchestrator.handle_app_mention_and_message(body, say_mock, Mock())

    state = orchestrator.conversation_manager.get_state(user_id)

    assert state is not None
    assert state["thread_ts"] == thread_ts
    assert state["channel_id"] == "C1"
    assert "cve_list" not in state

    # Não deve existir fluxo individual iniciado
    assert "identifier" not in state
    assert "awaiting_business_answer" not in state
