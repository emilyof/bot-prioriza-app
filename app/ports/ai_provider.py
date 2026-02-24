from abc import ABC, abstractmethod
from typing import Dict, List, Optional


class AIProvider(ABC):
    """
    Contrato para qualquer engine de IA usada pelo sistema.
    """

    @abstractmethod
    def chat_completion(
        self,
        *,
        user_id: str,
        messages: List[Dict],
        model: Optional[str] = None,
    ) -> Dict:
        """
        Deve SEMPRE retornar no formato normalizado:
        {
            "content": str,
            "raw": dict
        }
        """
        raise NotImplementedError
