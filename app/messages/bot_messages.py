class BotMessages:
    """
    Classe para centralizar todas as mensagens de texto do bot.
    Fluxo simplificado: CVE | OWASP | Descrição de vulnerabilidade.
    """

    # ==========================================================
    # Mensagem inicial
    # ==========================================================

    WELCOME_MESSAGE = (
        "Olá! Sou o bot de priorização de vulnerabilidades. 👋\n\n"
        "Posso te ajudar a calcular o risco de **vulnerabilidades de segurança** "
        "com base em impacto técnico e impacto no negócio.\n\n"
        "*Como iniciar uma análise:*\n"
        "• Envie um *ID de CVE* (ex: `CVE-2023-12345`).\n"
        "• Envie uma *categoria OWASP* (ex: `A03:2021`).\n"
        "• Ou descreva diretamente a *vulnerabilidade*.\n\n"
        "Após identificar a vulnerabilidade, farei algumas perguntas para calcular "
        "o impacto no negócio e gerar um relatório completo."
    )

    # ==========================================================
    # Mensagens gerais
    # ==========================================================

    START_ANALYSIS_MESSAGE = (
        "✅ Certo! Vou analisar **{input_type}** para *{identifier}*.\n"
        "Por favor, aguarde enquanto coleto os dados técnicos..."
    )

    START_CVE_LIST_ANALYSIS_MESSAGE = (
        "✅ Certo! Vou analisar **Lista de CVEs**.\n"
        "Por favor, aguarde enquanto coleto os dados técnicos..."
    )

    START_DESCRIPTION_ANALYSIS_MESSAGE = (
        "✅ Certo! Vou analisar a *descrição da vulnerabilidade*.\n"
        "Por favor, aguarde enquanto calculo a pontuação técnica..."
    )

    NO_DATA_FOUND = (
        "Não foi possível obter dados para **{input_type}** *{identifier}*.\n"
        "Verifique a informação e tente novamente."
    )

    PREVIOUS_THREAD_CLOSED = (
        "> ⚠️ Esta conversa foi encerrada porque você iniciou uma nova interação.\n"
        "> Por favor, continue no novo thread."
    )

    RECALCULATION_JUSTIFICATION_REQUEST = (
        "✏️ *Recalcular prioridade*\n\n"
        "Por favor, descreva abaixo as novas informações ou contexto "
        "que justificam o recálculo da prioridade."
    )

    # ==========================================================
    # Seleção inicial de cálculo
    # ==========================================================

    INITIAL_CALC_TYPE_SELECTION_TITLE = "Qual tipo de cálculo você gostaria de iniciar?"
    INITIAL_CALC_TYPE_SELECTION_TEXT = (
        "Selecione uma das opções abaixo para prosseguir com a priorização:"
    )

    CALC_TYPE_OWASP_BUTTON = "OWASP"
    CALC_TYPE_DESCRIPTION_BUTTON = "Descrição da vulnerabilidade"

    # ==========================================================
    # OWASP
    # ==========================================================

    SELECT_OWASP_CATEGORY_PROMPT = (
        "Por favor, selecione qual categoria **OWASP Top 10** você deseja calcular:"
    )

    SELECT_OWASP_CATEGORY_TEXT = "Selecione uma categoria OWASP Top 10:"

    SELECT_OLD_OWASP_CATEGORY_BUTTON = "Outra categoria OWASP (fora do Top 10)"

    OWASP_OUTSIDE_TOP10_PROMPT = (
        "Essa categoria OWASP não faz parte do Top 10 atual.\n"
        "Por favor, descreva a vulnerabilidade para que eu possa calcular "
        "a pontuação técnica com apoio da IA."
    )

    # ==========================================================
    # IA – descrição de vulnerabilidade
    # ==========================================================

    AI_SCORING_VULNERABILITY = (
        "🔍 Estou analisando a descrição da vulnerabilidade para definir "
        "a pontuação técnica (30 a 60)."
    )

    AI_SCORE_PRESENTATION = (
        "> *Pontuação Técnica sugerida pela IA*\n\n"
        "Com base na descrição:\n"
        "→ **{original_description}**\n\n"
        "Pontuação técnica: *{score:.1f} / 60*\n"
        "Justificativa: _{justification}_\n\n"
        "Você concorda com essa pontuação?"
    )

    CONFIRM_SCORE_BUTTON = "✅ Concordo"
    DISAGREE_SCORE_BUTTON = "❌ Discordo"

    USER_DISAGREES_PROMPT = (
        "Entendido. Por favor, explique brevemente por que você discorda "
        "da pontuação para que eu possa recalcular."
    )

    SCORE_RECALCULATED = (
        "> *Pontuação Técnica Recalculada*\n\n"
        "Justificativa do usuário:\n"
        "_{user_justification}_\n\n"
        "Nova pontuação técnica: *{new_score:.1f} / 60*\n"
        "Justificativa da IA:\n"
        "_{new_justification}_\n\n"
        "Agora vamos avaliar o impacto no negócio."
    )

    # ==========================================================
    # Impacto no negócio
    # ==========================================================

    FIRST_BUSINESS_QUESTION_INTRO = (
        "📊 Dados técnicos coletados!\n\n"
        "Agora preciso de algumas informações para calcular o impacto no negócio:\n"
        "{question_text}"
    )

    INVALID_BUSINESS_ANSWER = (
        "Resposta inválida. Por favor, utilize uma das opções permitidas: {allowed_answers}."
    )

    BUSINESS_ANSWERS_APPLIED_TO_ALL = (
        "Suas respostas de impacto no negócio serão aplicadas a todas as vulnerabilidades da lista."
    )

    # ==========================================================
    # Arquivo / Upload
    # ==========================================================

    PROCESSING_FILE = "📄 Processando o arquivo *{file_name}*… Aguarde um momento."

    NO_VALID_CVES_IN_FILE = (
        "⚠️ Não encontrei *nenhum CVE válido* no arquivo enviado.\n"
        "Verifique o conteúdo e tente novamente."
    )

    FILE_ACCESS_ERROR = (
        "❌ Não foi possível acessar o arquivo enviado.\n"
        "Verifique as permissões e tente novamente."
    )

    FILE_DOWNLOAD_ERROR = (
        "❌ Ocorreu um erro ao baixar o arquivo do Slack.\n" "Por favor, tente reenviar o arquivo."
    )

    UNEXPECTED_FILE_ERROR = (
        "❌ Ocorreu um erro inesperado ao processar o arquivo.\n"
        "Tente novamente ou envie os dados manualmente."
    )

    # ==========================================================
    # Resultado final
    # ==========================================================

    GENERATING_SUGGESTIONS = "🧠 Gerando recomendações de correção e mitigação..."

    ASK_RECALCULATE_SCORE_TITLE = "*Relatório concluído!*"
    ASK_RECALCULATE_SCORE_TEXT = (
        "Você gostaria de recalcular a pontuação técnica ou o impacto no negócio "
        "com base em novas informações?"
    )

    RECALCULATE_BUTTON = "✏️ Recalcular"
    DONT_RECALCULATE_BUTTON = "✅ Finalizar"

    RECALCULATING_SCORE = "🔄 Recalculando a pontuação com base nas novas informações..."

    RECALC_NOT_NEEDED = (
        "Perfeito! O relatório final está acima.\n" "Se precisar de algo mais, é só me chamar."
    )

    AI_SERVICE_ERROR = (
        "❌ Ocorreu um erro ao comunicar com o serviço de IA.\n" "Detalhes: {error_detail}"
    )

    NO_AI_SUGGESTIONS = "Não foi possível gerar recomendações automaticamente no momento."
