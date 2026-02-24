import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class ConversationManager:
    """
    Gerencia exclusivamente o estado das conversas do usuário.

    Responsabilidades:
    - Armazenar estado por user_id
    - Validar thread ativa
    - Expor helpers simples de checagem de fluxo
    - Evitar envio duplicado de mensagens
    """

    def __init__(self):
        self.conversation_states: Dict[str, Dict] = {}

    # ==========================================================
    # Estado básico
    # ==========================================================

    def get_state(self, user_id: str) -> Optional[dict]:
        return self.conversation_states.get(user_id)

    def set_state(self, user_id: str, state: dict):
        self.conversation_states[user_id] = state

    def update_state(self, user_id: str, updates: dict):
        if user_id not in self.conversation_states:
            self.conversation_states[user_id] = {}
        self.conversation_states[user_id].update(updates)

    def clear_state(self, user_id: str):
        self.conversation_states.pop(user_id, None)

    def get_thread_ts(self, user_id: str) -> Optional[str]:
        state = self.get_state(user_id)
        return state.get("thread_ts") if state else None

    def close_conversation(self, user_id: str, reason: str = "new_mention"):
        state = self.get_state(user_id)
        if not state:
            return None

        if state.get("closed"):
            return None

        state["closed"] = True
        state["closed_reason"] = reason

        self.set_state(user_id, state)
        return state

    # ==========================================================
    # Checks de fluxo ativo (helpers simples)
    # ==========================================================

    def is_in_active_vulnerability_flow(self, user_id: str, thread_ts: str) -> bool:
        """
        Usuário está respondendo perguntas de impacto no negócio.
        """
        state = self.get_state(user_id)
        return bool(
            state
            and state.get("thread_ts") == thread_ts
            and state.get("awaiting_business_answer") is True
        )

    def is_awaiting_confirmation(self, user_id: str, thread_ts: str) -> bool:
        """
        Usuário está no preview final aguardando confirmar ou recalcular.
        """
        state = self.get_state(user_id)
        return bool(
            state
            and state.get("thread_ts") == thread_ts
            and state.get("awaiting_confirmation") is True
        )

    def is_awaiting_recalculation_justification(self, user_id: str, thread_ts: str) -> bool:
        """
        Usuário clicou em Recalcular e precisa enviar justificativa.
        """
        state = self.get_state(user_id)
        return bool(
            state
            and state.get("thread_ts") == thread_ts
            and state.get("awaiting_recalculation_justification") is True
        )

    # ==========================================================
    # Deduplicação de mensagens
    # ==========================================================

    def mark_as_sent(self, user_id: str, message_key: str):
        """
        Marca que uma mensagem identificada por `message_key`
        já foi enviada para este usuário.
        """
        state = self.get_state(user_id) or {}

        sent_messages = state.get("sent_messages", set())
        if not isinstance(sent_messages, set):
            sent_messages = set(sent_messages)

        sent_messages.add(message_key)
        state["sent_messages"] = sent_messages

        self.set_state(user_id, state)

        logger.debug(f"[ConversationManager] Mensagem marcada como enviada: {message_key}")

    def already_sent(self, user_id: str, message_key: str) -> bool:
        """
        Retorna True se a mensagem identificada por `message_key`
        já foi enviada para este usuário.
        """
        state = self.get_state(user_id)
        if not state:
            return False

        sent_messages = state.get("sent_messages", set())
        if not isinstance(sent_messages, set):
            sent_messages = set(sent_messages)

        return message_key in sent_messages

    def clear_list_context(self, user_id: str):
        """
        Remove do estado qualquer informação relacionada
        a processamento de LISTA de CVEs.
        """
        state = self.get_state(user_id)
        if not state:
            return

        for key in ("cve_list",):
            state.pop(key, None)

        self.set_state(user_id, state)
