# app/adapters/groq_ai_provider.py
import logging
from typing import Dict, List, Optional

import requests

from app.ports.ai_provider import AIProvider

logger = logging.getLogger(__name__)


class GroqAIProvider(AIProvider):

    DEFAULT_MODEL = "llama-3.1-8b-instant"
    ALLOWED_MODELS = {
        "mixtral-8x7b-32768",
        "gemma-7b-it",
        "llama3-8b-8192",
        "llama3-70b-8192",
        "gemma-2b-it",
        "llama-3.1-8b-instant",
        "llama-3.1-70b-instant",
    }

    def __init__(self, *, base_url: str, token: str, model_override: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.token = token

        if model_override and model_override in self.ALLOWED_MODELS:
            self.model = model_override
            logger.info(f"[Groq] Usando modelo override: {self.model}")
        else:
            self.model = self.DEFAULT_MODEL
            if model_override:
                logger.warning(
                    f"[Groq] Modelo inválido '{model_override}', usando default '{self.DEFAULT_MODEL}'"  # noqa: E501
                )

    def chat_completion(
        self,
        *,
        user_id: str,  # ✅ CONTRATO OK (não usado)
        messages: List[Dict],
        model: Optional[str] = None,
    ) -> Dict:

        payload = {"model": model or self.model, "messages": messages}

        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

        url = f"{self.base_url}/chat/completions"

        response = requests.post(url, headers=headers, json=payload, timeout=30)

        if not response.ok:
            logger.error(f"[Groq] Erro {response.status_code}: {response.text}")

        response.raise_for_status()

        raw = response.json()
        content = raw["choices"][0]["message"]["content"]

        return {"content": content, "raw": raw}
