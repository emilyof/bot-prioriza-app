from unittest.mock import Mock

import pytest

from app.core.conversation_manager import ConversationManager
from app.core.orchestrator import FlowOrchestrator
from app.core.vulnerability_types import VulnerabilityType
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

    service.calculate_technical_score.return_value = {
        "technical_subtotal": 40.0,
        "cvss_score": 8.5,
        "epss_qualitative": "Alto",
        "kev_qualitative": "Sim",
        "poc_qualitative": "Sim",
    }

    service.get_cve_description.return_value = "Descrição da CVE de teste"

    return service


@pytest.fixture
def ai_service_mock():
    ai = Mock()

    ai.generate_executive_recommendations.return_value = {
        "remediation_recommendations": "Aplicar patch imediatamente",
        "mitigation_measures": "Bloquear endpoint vulnerável",
        "additional_considerations": "Monitorar logs",
    }

    return ai


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

    # ✅ Isola completamente qualquer fluxo de descrição / OWASP
    orchestrator.conversation_handler.ai_service.suggest_owasp_from_description.return_value = (  # noqa: E501
        []
    )

    return orchestrator


# ==========================================================
# TESTE — FLUXO CVE ÚNICA
# ==========================================================


def test_basic_cve_flow(orchestrator, say_mock):
    """
    Contrato:
    ✅ Entrada CVE inicia análise técnica
    ✅ Perguntas de impacto no negócio são feitas
    ✅ Preview final é preparado corretamente
    """

    user_id = "U1"
    thread_ts = "T1"

    body = {
        "event": {
            "user": user_id,
            "text": "CVE-2024-0001",
            "ts": thread_ts,
            "channel": "C1",
            "channel_type": "im",
        }
    }

    # ------------------------------------------------------
    # 1️⃣ Inicia o fluxo CVE
    # ------------------------------------------------------
    orchestrator.handle_app_mention_and_message(body, say_mock, Mock())

    state = orchestrator.conversation_manager.get_state(user_id)

    assert state is not None
    assert state["identifier"] == "CVE-2024-0001"
    assert state["input_type"] == VulnerabilityType.CVE
    assert state["awaiting_business_answer"] is True

    # ------------------------------------------------------
    # 2️⃣ Responde todas as perguntas de impacto no negócio
    # ------------------------------------------------------
    for answer in ["A", "A", "A", "A", "A"]:
        orchestrator.scoring_and_report_handler.process_business_answer(
            user_id=user_id,
            message_text=answer,
            thread_ts=thread_ts,
            say=say_mock,
        )

    # ------------------------------------------------------
    # 3️⃣ Preview final pronto
    # ------------------------------------------------------
    state = orchestrator.conversation_manager.get_state(user_id)

    assert state["awaiting_confirmation"] is True
    assert state["final_score"] > 0
    assert state["business_score"] > 0
    assert state["classification"] is not None
