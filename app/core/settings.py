import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    # Slack
    slack_bot_token: str
    slack_app_token: str

    # AI
    ai_api_url: str
    ai_api_token: str

    # VulnCheck
    vulncheck_token: str

    @classmethod
    def from_env(cls) -> "Settings":
        """
        Carrega e valida todas as variáveis de ambiente necessárias.
        Falha rápido se algo estiver ausente.
        """
        missing = []

        def get(name: str) -> str:
            value = os.getenv(name)
            if not value:
                missing.append(name)
            return value

        settings = cls(
            slack_bot_token=get("SLACK_BOT_TOKEN"),
            slack_app_token=get("SLACK_APP_TOKEN"),
            ai_api_url=get("AI_API_URL"),
            ai_api_token=get("AI_API_TOKEN"),
            vulncheck_token=get("VULNCHECK_TOKEN"),
        )

        if missing:
            raise RuntimeError(f"Variáveis de ambiente ausentes: {', '.join(missing)}")

        return settings
