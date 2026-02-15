from unittest.mock import Mock

import pytest

from app.core.conversation_manager import ConversationManager
from app.core.orchestrator import FlowOrchestrator
from app.core.vulnerability_types import VulnerabilityType
from app.messages.bot_messages import BotMessages

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
def orchestrator(app_client_mock):
    orchestrator = FlowOrchestrator(
        ai_service=Mock(),
        vulnerability_service=Mock(),
        file_processing_service=Mock(),
        conversation_manager=ConversationManager(),
        app_client=app_client_mock,
        bot_token="fake-token",
        messages=BotMessages(),
    )

    # ✅ Isolar completamente qualquer inferência automática
    orchestrator.conversation_handler.ai_service.suggest_owasp_from_description.return_value = (  # noqa: E501
        []
    )

    return orchestrator


# ==========================================================
# REGRESSÃO — iniciar análise preserva thread e lista
# ==========================================================


def test_start_analysis_preserves_thread_and_cve_list(orchestrator, say_mock):
    """
    Contrato:
    ✅ thread_ts não é sobrescrito
    ✅ cve_list não é apagada ao iniciar análise individual
    """

    orchestrator.conversation_manager.set_state(
        "U1",
        {
            "channel_id": "C1",
            "thread_ts": "T1",
            "cve_list": ["CVE-1", "CVE-2"],
        },
    )

    orchestrator.scoring_and_report_handler.vulnerability_service.calculate_technical_score.return_value = {  # noqa: E501
        "technical_subtotal": 30.0
    }

    orchestrator.start_vulnerability_analysis(
        user_id="U1",
        identifier="CVE-2",
        input_type=VulnerabilityType.CVE,
        thread_ts="T1",
        say=say_mock,
    )

    state = orchestrator.conversation_manager.get_state("U1")

    assert state["thread_ts"] == "T1"
    assert state["cve_list"] == ["CVE-1", "CVE-2"]
    assert state["identifier"] == "CVE-2"


# ==========================================================
# REGRESSÃO — resposta ignorada se thread divergir
# ==========================================================


def test_business_answer_ignored_if_thread_differs(orchestrator, say_mock):
    """
    Contrato:
    ✅ Respostas fora da thread ativa NÃO alteram estado
    """

    orchestrator.conversation_manager.set_state(
        "U1",
        {
            "thread_ts": "OLD_THREAD",
            "awaiting_business_answer": True,
            "question_index": 0,
            "business_impact_answers": [],
            "identifier": "CVE-2024-0001",
            "input_type": VulnerabilityType.CVE,
        },
    )

    orchestrator.scoring_and_report_handler.process_business_answer(
        user_id="U1",
        message_text="A",
        thread_ts="NEW_THREAD",
        say=say_mock,
    )

    state = orchestrator.conversation_manager.get_state("U1")

    assert state["business_impact_answers"] == []
    assert state["question_index"] == 0


# ==========================================================
# REGRESSÃO — estado limpo após finalização
# ==========================================================


def test_state_cleared_after_finalization(orchestrator, say_mock):
    """
    Contrato:
    ✅ Após finalizar priorização individual, estado deve ser limpo
    """

    orchestrator.scoring_and_report_handler.vulnerability_service.get_cve_description.return_value = (  # noqa: E501
        "Descrição da CVE"
    )

    orchestrator.scoring_and_report_handler.ai_service.generate_executive_recommendations.return_value = {  # noqa: E501
        "remediation_recommendations": "Aplicar patch",
        "mitigation_measures": "Mitigar temporariamente",
        "additional_considerations": "Monitorar logs",
    }

    orchestrator.conversation_manager.set_state(
        "U1",
        {
            "identifier": "CVE-2024-0001",
            "input_type": VulnerabilityType.CVE,
            "technical_score_data": {"technical_subtotal": 40.0},
            "business_score": 20.0,
            "business_qualitative_answers": {},
            "final_score": 60.0,
            "classification": "P2 Alto",
            "sla": "30 dias úteis",
        },
    )

    orchestrator.scoring_and_report_handler.complete_prioritization_process(
        user_id="U1",
        thread_ts="T1",
        say=say_mock,
    )

    assert orchestrator.conversation_manager.get_state("U1") is None
