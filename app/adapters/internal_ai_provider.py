import os
import requests
import logging
import urllib3
from typing import List, Dict, Optional

from app.ports.ai_provider import AIProvider

# Desabilita warnings de SSL
if os.getenv("ENV") == "local":
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class InternalAIProvider(AIProvider):

    DEFAULT_MODEL = "gpt-4.1-mini"

    def __init__(self, *, base_url: str, token: str):
        self.base_url = base_url.rstrip("/")
        self.token = token

    def chat_completion(
        self, *, user_id: str, messages: List[Dict], model: Optional[str] = None
    ) -> Dict:

        payload = {
            "model": model or self.DEFAULT_MODEL,
            "messages": messages,
            "user": {"type": "consumer_id", "id": user_id},
        }

        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}

        url = f"{self.base_url}/chat/completions"

        # ✅ ADICIONAR verify=False
        response = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=30,
            verify=False,  # ⚠️ APENAS PARA DESENVOLVIMENTO LOCAL
        )
        response.raise_for_status()

        raw = response.json()
        content = raw["choices"][0]["message"]["content"]

        return {"content": content, "raw": raw}
