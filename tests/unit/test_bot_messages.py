def test_bot_messages_contract():
    """
    Garante que todas as mensagens referenciadas pelos handlers
    existem no catálogo BotMessages.
    """
    from app.messages.bot_messages import BotMessages

    required_messages = [
        # Arquivo / Upload
        "PROCESSING_FILE",
        "NO_VALID_CVES_IN_FILE",
        "FILE_ACCESS_ERROR",
        "FILE_DOWNLOAD_ERROR",
        "UNEXPECTED_FILE_ERROR",
        # Fluxo / Estado
        "PREVIOUS_THREAD_CLOSED",
        # IA
        "AI_SERVICE_ERROR",
    ]

    for message in required_messages:
        assert hasattr(BotMessages, message), f"Mensagem obrigatória ausente: BotMessages.{message}"
