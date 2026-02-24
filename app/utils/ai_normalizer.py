from typing import Dict, List


class AIMessageNormalizer:
    """
    Normaliza mensagens e respostas de IA para evitar
    acoplamento com providers específicos.
    """

    @staticmethod
    def normalize_messages_for_provider(*, messages: List[Dict], provider_name: str) -> List[Dict]:
        """
        Ajusta mensagens conforme limitações do provider.
        """
        if provider_name == "groq":
            # Groq NÃO aceita role=assistant no input
            return [msg for msg in messages if msg.get("role") in ("system", "user")]

        # Default: retorna como está
        return messages

    @staticmethod
    def normalize_response(*, provider_response: Dict) -> Dict:
        """
        Garante formato único:
        {
            "content": str,
            "raw": dict
        }
        """
        if not provider_response:
            return {"content": "", "raw": provider_response}

        # Já normalizado (Groq / internal)
        if "content" in provider_response:
            return provider_response

        # OpenAI-style fallback
        if "choices" in provider_response:
            try:
                return {
                    "content": provider_response["choices"][0]["message"]["content"],
                    "raw": provider_response,
                }
            except Exception:
                pass

        # Último fallback seguro
        return {"content": "", "raw": provider_response}
