from unittest.mock import Mock

import pytest

from app.core.orchestrator import FlowOrchestrator
from app.core.vulnerability_types import VulnerabilityType


@pytest.fixture
def conversation_manager_mock():
    cm = Mock()
    cm.get_state.return_value = None
    cm.is_awaiting_recalculation_justification.return_value = False
    cm.is_in_active_vulnerability_flow.return_value = False
    return cm


@pytest.fixture
def app_client_mock():
    client = Mock()
    client.auth_test.return_value = {"user_id": "BOT123"}
    return client


@pytest.fixture
def orchestrator(app_client_mock, conversation_manager_mock):
    return FlowOrchestrator(
        ai_service=Mock(),
        vulnerability_service=Mock(),
        file_processing_service=Mock(),
        conversation_manager=conversation_manager_mock,
        app_client=app_client_mock,
        bot_token="fake-token",
        messages=Mock(),
    )


def test_detect_input_type_cve(orchestrator):
    input_type, identifier = orchestrator.detect_input_type("CVE-2024-1234")

    assert input_type == VulnerabilityType.CVE
    assert identifier == "CVE-2024-1234"


def test_detect_input_type_owasp_legacy(orchestrator):
    input_type, identifier = orchestrator.detect_input_type("A02:2021")

    assert input_type == VulnerabilityType.OWASP
    assert identifier == "A02"


def test_detect_input_type_owasp_new_treated_as_description(orchestrator):
    input_type, identifier = orchestrator.detect_input_type("A01")

    assert input_type == VulnerabilityType.AI_SCORING_DESCRIPTION
    assert identifier == "A01"


def test_detect_input_type_description(orchestrator):
    input_type, identifier = orchestrator.detect_input_type("SQL Injection vulnerability")

    assert input_type == VulnerabilityType.AI_SCORING_DESCRIPTION
    assert "SQL INJECTION" in identifier


def test_process_initial_message_empty_message(orchestrator):
    say = Mock()

    orchestrator.message_and_file_handler._send_message = Mock()

    orchestrator.process_initial_message_intent(
        user_id="U1",
        message_text="",
        thread_ts="T1",
        say=say,
    )

    orchestrator.message_and_file_handler._send_message.assert_called_once()


def test_process_initial_message_cve(orchestrator):
    orchestrator.start_vulnerability_analysis = Mock()
    say = Mock()

    orchestrator.process_initial_message_intent(
        user_id="U1",
        message_text="CVE-2023-9999",
        thread_ts="T1",
        say=say,
    )

    orchestrator.start_vulnerability_analysis.assert_called_once_with(
        "U1",
        "CVE-2023-9999",
        VulnerabilityType.CVE,
        "T1",
        say,
    )


def test_process_initial_message_owasp_legacy(orchestrator):
    orchestrator.conversation_handler.handle_owasp_selection = Mock()

    orchestrator.process_initial_message_intent(
        user_id="U1",
        message_text="A02:2021",
        thread_ts="T1",
        say=Mock(),
    )

    orchestrator.conversation_handler.handle_owasp_selection.assert_called_once()


def test_process_initial_message_owasp_new_goes_to_description(orchestrator):
    orchestrator.conversation_handler.handle_description_input = Mock()

    orchestrator.process_initial_message_intent(
        user_id="U1",
        message_text="A02",
        thread_ts="T1",
        say=Mock(),
    )

    orchestrator.conversation_handler.handle_description_input.assert_called_once()


def test_process_initial_message_description(orchestrator):
    orchestrator.conversation_handler.handle_description_input = Mock()

    orchestrator.process_initial_message_intent(
        user_id="U1",
        message_text="Authentication bypass vulnerability",
        thread_ts="T1",
        say=Mock(),
    )

    orchestrator.conversation_handler.handle_description_input.assert_called_once()


def test_handle_message_recalculation_has_priority(orchestrator):
    say = Mock()
    client = Mock()

    orchestrator.conversation_manager.is_awaiting_recalculation_justification.return_value = (  # noqa: E501
        True
    )
    orchestrator.scoring_and_report_handler.handle_recalculation_justification = Mock()

    body = {
        "event": {
            "user": "U1",
            "text": "Justification text",
            "ts": "T1",
            "channel": "C1",
        }
    }

    orchestrator.handle_app_mention_and_message(body, say, client)

    orchestrator.scoring_and_report_handler.handle_recalculation_justification.assert_called_once()  # noqa: E501


def test_handle_message_business_flow_has_priority(orchestrator):
    say = Mock()
    client = Mock()

    orchestrator.conversation_manager.is_awaiting_recalculation_justification.return_value = (  # noqa: E501
        False
    )
    orchestrator.conversation_manager.is_in_active_vulnerability_flow.return_value = True
    orchestrator.scoring_and_report_handler.process_business_answer = Mock()

    body = {
        "event": {
            "user": "U1",
            "text": "A",
            "ts": "T1",
            "channel": "C1",
        }
    }

    orchestrator.handle_app_mention_and_message(body, say, client)

    orchestrator.scoring_and_report_handler.process_business_answer.assert_called_once()


def test_handle_message_initial_flow(orchestrator):
    say = Mock()
    client = Mock()

    orchestrator.conversation_manager.get_state.side_effect = [
        None,
        {"thread_ts": "T1"},
    ]

    orchestrator.conversation_manager.is_awaiting_recalculation_justification.return_value = (  # noqa: E501
        False
    )
    orchestrator.conversation_manager.is_in_active_vulnerability_flow.return_value = False

    orchestrator.process_initial_message_intent = Mock()

    body = {
        "event": {
            "user": "U1",
            "text": "CVE-2024-0001",
            "ts": "T1",
            "channel": "C1",
            "channel_type": "im",
        }
    }

    orchestrator.handle_app_mention_and_message(body, say, client)

    orchestrator.process_initial_message_intent.assert_called_once()


def test_new_mention_clears_previous_state(orchestrator):
    say = Mock()
    client = Mock()

    orchestrator.conversation_manager.get_state.return_value = {
        "thread_ts": "OLD_THREAD",
        "channel_id": "C1",
    }

    orchestrator.message_and_file_handler._send_previous_thread_closed_message = Mock()
    orchestrator.conversation_manager.clear_state = Mock()
    orchestrator.conversation_manager.set_state = Mock()

    orchestrator.conversation_handler.ai_service.suggest_owasp_from_description.return_value = (  # noqa: E501
        []
    )

    body = {
        "event": {
            "user": "U1",
            "text": "<@BOT123> Hello",
            "ts": "NEW_THREAD",
            "channel": "C1",
            "channel_type": "channel",
        }
    }

    orchestrator.handle_app_mention_and_message(body, say, client)

    orchestrator.message_and_file_handler._send_previous_thread_closed_message.assert_called_once()  # noqa: E501
    orchestrator.conversation_manager.clear_state.assert_called_once()
