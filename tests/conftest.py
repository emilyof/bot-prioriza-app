from unittest.mock import Mock

import pytest


@pytest.fixture
def say_mock():
    return Mock()


@pytest.fixture
def conversation_manager_mock():
    cm = Mock()
    cm.get_state.return_value = {}
    return cm
