from typing import Optional

from app.core.vulnerability_types import VulnerabilityType

# ==========================================================
# CONSTANTES DE CLASSIFICAÇÃO (CENTRALIZADO)
# ==========================================================

# Mapeamento de classificação para emojis
PRIORITY_EMOJI_MAP = {
    "P1 Crítico": "🔴",
    "P2 Alto": "🟠",
    "P3 Médio": "🟨",
    "P4 Baixo": "🟢",
    "P4 Informativa": "🔵",
}

# ==========================================================
# FUNÇÃO AUXILIAR DE EMOJI (CENTRALIZADO)
# ==========================================================


def get_priority_emoji(classification: str) -> str:
    """
    Retorna o emoji correspondente à classificação de risco.

    Args:
        classification: Classificação de risco (ex: "P1 Crítico")

    Returns:
        str: Emoji correspondente (ex: "🔴")

    Examples:
        >>> get_priority_emoji("P1 Crítico")
        "🔴"
        >>> get_priority_emoji("P2 Alto")
        "🟠"
    """
    return PRIORITY_EMOJI_MAP.get(classification, "⚪")


# ==========================================================
# CLASSIFICAÇÃO FINAL E SLA
# ==========================================================


def get_risk_classification(total_score):
    """
    Retorna classificação de risco e SLA baseado na pontuação total.

    IMPORTANTE: Retorna classificação SEM emoji.
    Use get_priority_emoji() para adicionar emoji quando necessário.

    Args:
        total_score: Pontuação total (0-100)

    Returns:
        tuple: (classificação_sem_emoji, sla)

    Examples:
        >>> get_risk_classification(95)
        ("P1 Crítico", "WAR ROOM, resolução imediata")
        >>> get_risk_classification(75)
        ("P2 Alto", "30 dias úteis")
    """
    if 90 <= total_score <= 100:
        return "P1 Crítico", "WAR ROOM, resolução imediata"
    elif 70 <= total_score <= 89:
        return "P2 Alto", "30 dias úteis"
    elif 30 <= total_score <= 69:
        return "P3 Médio", "60 dias úteis"
    elif 10 <= total_score <= 29:
        return "P4 Baixo", "90 dias úteis"
    elif 0 <= total_score <= 9:
        return "P4 Informativa", "Sem prazo definido"

    return "Desconhecida", "Não aplicável"


# ==========================================================
# PERGUNTAS DE IMPACTO NO NEGÓCIO (ORIGINAL – NÃO ALTERAR FLUXO)
# ==========================================================

BUSINESS_IMPACT_QUESTIONS_CONFIG = [
    {
        "name": "Ambiente",
        "text": "\n:arrow_right: *Qual o ambiente do ativo afetado por esta vulnerabilidade/fraqueza {ID_OR_CATEGORY}? [máx. 10]*\n\n"
        "A) Produção Crítica / Exposto diretamente à Internet com dados sensíveis / Sistema Core do Negócio \n"
        "B) Produção / Interno com dados sensíveis / Suporte a Processos Críticos: \n"
        "C) Homologação / Desenvolvimento com acesso ou replicação de dados de produção: \n"
        "D) Desenvolvimento / Testes (sem dados sensíveis ou conexão com produção): \n"
        "E) Não se aplica / Desconhecido: ",
        "score_map": {"A": 10, "B": 7, "C": 4, "D": 1, "E": 0},
        "display_map": {
            "A": "Produção Crítica",
            "B": "Produção / Suporte Crítico",
            "C": "Homologação / Dev com dados",
            "D": "Desenvolvimento / Testes",
            "E": "Não se aplica / Desconhecido",
        },
    },
    {
        "name": "Criticidade",
        "text": "\n:arrow_right: *Qual a criticidade do ativo para o negócio (conforme Business Impact Analysis - BIA, classificação de ativos da instituição, ou sua melhor avaliação) em relação à vulnerabilidade/fraqueza {ID_OR_CATEGORY}? [máx. 8]*\n\n"
        "A) Crítico (parada/comprometimento gera impacto financeiro/reputacional severo, multas regulatórias altas, perda de dados irrecuperável ou altamente sensíveis): \n"
        "B) Alto (parada/comprometimento gera impacto significativo, perdas financeiras consideráveis, dano reputacional): \n"
        "C) Médio (parada/comprometimento gera impacto moderado, inconveniências operacionais): \n"
        "D) Baixo (parada/comprometimento gera impacto mínimo ou localizado): \n"
        "E) Não se aplica / Desconhecido: ",
        "score_map": {"A": 8, "B": 6, "C": 3, "D": 1, "E": 0},
        "display_map": {
            "A": "Crítico",
            "B": "Alto",
            "C": "Médio",
            "D": "Baixo",
            "E": "Não se aplica / Desconhecido",
        },
    },
    {
        "name": "Mitigações",
        "text": "\n:arrow_right: *Existem medidas de mitigação ou controles compensatórios efetivos já implementados ESPECIFICAMENTE para esta vulnerabilidade/fraqueza {ID_OR_CATEGORY} neste ativo (ex: patch virtual aplicado via WAF, segmentação de rede que impede o acesso ao serviço vulnerável, desativação da funcionalidade vulnerável)? [máx. 5]*\n\n"
        "A) Nenhuma medida específica implementada ou as medidas existentes não cobrem esta vulnerabilidade/fraqueza: \n"
        "B) Medidas parciais, não totalmente testadas, ou que reduzem mas não eliminam o risco: \n"
        "C) Medidas efetivas implementadas, testadas e validadas que impedem a exploração ou mitigam o impacto significativamente: ",
        "score_map": {"A": 5, "B": 2, "C": 0},
        "display_map": {"A": "Nenhuma", "B": "Parciais", "C": "Efetivas"},
    },
    {
        "name": "Acesso",
        "text": "\n:arrow_right: *Qual o nível de acesso ou privilégio que um atacante precisaria OBTER NO SISTEMA ALVO para explorar esta vulnerabilidade/fraqueza {ID_OR_CATEGORY} com sucesso no contexto deste ativo específico? [máx. 5]*\n\n"
        "A) Anônimo / Não autenticado / Acesso público (a vulnerabilidade/fraqueza pode ser explorada remotamente sem credenciais): \n"
        "B) Usuário comum autenticado (requer credenciais válidas de um usuário padrão): \n"
        "C) Usuário com privilégios elevados / Administrador (requer comprometimento prévio de conta com altos privilégios): ",
        "score_map": {"A": 5, "B": 3, "C": 1},
        "display_map": {
            "A": "Anônimo",
            "B": "Usuário comum autenticado",
            "C": "Usuário com privilégios elevados",
        },
    },
    {
        "name": "Dados Regulados",
        "text": "\n:arrow_right: *A vulnerabilidade/fraqueza {ID_OR_CATEGORY} afeta um sistema que armazena, processa ou transmite dados diretamente regulados por normativas críticas para a instituição (ex: LGPD para dados pessoais de clientes, Resoluções BACEN para dados financeiros/transacionais, PCI-DSS para dados de cartão)? [máx. 12]*\n\n"
        "A) Sim, diretamente e com alto volume/sensibilidade de dados regulados: \n"
        "B) Sim, mas de forma indireta, com baixo volume/sensibilidade, ou dados de menor impacto regulatório: \n"
        "C) Não, o sistema não lida com dados diretamente cobertos por essas normativas críticas ou o impacto é negligenciável: ",
        "score_map": {"A": 12, "B": 6, "C": 0},
        "display_map": {"A": "Sim, diretamente", "B": "Sim, indiretamente", "C": "Não"},
    },
]

# ==========================================================
# CÁLCULO DE IMPACTO NO NEGÓCIO (ORIGINAL)
# ==========================================================


def calculate_business_score(answers_list):
    """
    Calcula a pontuação de impacto no negócio (máx. 40)
    e retorna também as respostas qualitativas.
    """
    total_score = 0
    qualitative_answers = {}

    for i, ans_key in enumerate(answers_list):
        if i < len(BUSINESS_IMPACT_QUESTIONS_CONFIG):
            question = BUSINESS_IMPACT_QUESTIONS_CONFIG[i]
            score = question["score_map"].get(ans_key)

            if score is not None:
                total_score += score
                qualitative_answers[question["name"]] = question.get("display_map", {}).get(
                    ans_key, ans_key
                )

    return min(total_score, 40), qualitative_answers


# ==========================================================
# RELATÓRIO FINAL (VULNERABILIDADE ÚNICA)
# ==========================================================


def format_executive_final_report(
    identifier: str,
    description: str,
    input_type,
    technical_data: dict,
    business_score: float,
    business_answers: dict,
    final_score: float,
    classification: str,
    sla: str,
    ai_recommendations: dict,
) -> str:
    """
    Formata o relatório executivo COMPLETO com recomendações da IA.

    Baseado no formato do projeto original ms-prioriza-ai-infra.
    """

    report = []

    # CABEÇALHO
    report.append("*━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━*")
    report.append("*📊 RELATÓRIO EXECUTIVO DE PRIORIZAÇÃO*")
    report.append("*━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━*")
    report.append("")
    report.append(f"*Tipo de Entrada:* {input_type.value}")

    # Identificador inteligente
    if input_type == VulnerabilityType.AI_SCORING_DESCRIPTION:
        report.append("*Identificador:* Vulnerabilidade informada via descrição")
    else:
        report.append(f"*Identificador:* `{identifier}`")

    report.append("")

    # DESCRIÇÃO DA VULNERABILIDADE
    report.append("> *📋 Descrição da Vulnerabilidade:*")
    report.append(f"{description}")
    report.append("")

    # PONTUAÇÃO TÉCNICA (60)
    report.append("*━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━*")
    report.append("> *🔧 PONTUAÇÃO TÉCNICA (Máx. 60)*")
    report.append("")

    # Exibir detalhes técnicos para CVE, justificativa IA para descrição
    if input_type == VulnerabilityType.CVE:
        # DETALHES TÉCNICOS DE CVE (FORMATO ORIGINAL)
        # CVSS Score
        cvss_score = technical_data.get("cvss_score", 0)
        cvss_version = technical_data.get("cvss_version", "N/A")
        cvss_source = technical_data.get("cvss_source")
        cvss_type = technical_data.get("cvss_type")

        cvss_line = f"*CVSS ({cvss_version}):* {cvss_score:.1f}/10"

        # Fonte explícita (quando não é NVD oficial)
        if cvss_source:
            cvss_line += f" _(Fonte: {cvss_source}"
            if cvss_type:
                cvss_line += f", {cvss_type}"
            cvss_line += ")_"

        report.append(cvss_line)

        # EPSS
        epss_qualitative = technical_data.get("epss_qualitative", "Não disponível")
        report.append(f"*EPSS:* {epss_qualitative}")
        # KEV
        kev_qualitative = technical_data.get("kev_qualitative", "Não")
        report.append(f"*KEV:* {kev_qualitative}")
        # Ransomware (se disponível)
        ransomware = technical_data.get("ransomware_qualitative", "Não")
        report.append(f"*Ransomware:* {ransomware}")
        # POC
        poc_qualitative = technical_data.get("poc_qualitative", "Não")
        report.append(f"*POC:* {poc_qualitative}")
        # CWEs (se disponível)
        cwes = technical_data.get("cwes")
        if cwes:
            report.append(f"*CWEs:* {cwes}")

        report.append("")

        # Vetor de Ataque
        attack_vector = technical_data.get("attack_vector_string", "N/A")
        if attack_vector and attack_vector != "N/A":
            report.append(f"*Vetor de Ataque:* {attack_vector}")

            # Decodificar vetor de ataque com emojis
            vector_details = _decode_cvss_vector(attack_vector)
            for detail in vector_details:
                report.append(f"  - {detail}")

            report.append("")

    else:
        # JUSTIFICATIVA DA IA (PARA DESCRIÇÃO/OWASP)
        if input_type == VulnerabilityType.AI_SCORING_DESCRIPTION or technical_data.get(
            "ai_recalculation_justification"
        ):
            technical_justification = technical_data.get(
                "ai_recalculation_justification"
            ) or technical_data.get("ai_justification")

            report.append("*Justificativa da Pontuação (IA):*")
            report.append(f"_{technical_justification}_")
            report.append("")

    # Subtotal Técnico
    report.append(f"→ *Subtotal Técnico:* `{technical_data.get('technical_subtotal', 0):.1f} / 60`")
    report.append("")

    # IMPACTO NO NEGÓCIO (40)
    report.append("*━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━*")
    report.append("> *💼 IMPACTO NO NEGÓCIO (Máx. 40)*")
    report.append("")

    for key, value in business_answers.items():
        report.append(f"• *{key}:* {value}")

    report.append("")
    report.append(f"→ *Subtotal Negócio:* `{business_score:.1f} / 40`")
    report.append("")

    # CLASSIFICAÇÃO FINAL
    report.append("*━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━*")
    report.append("> *🎯 CLASSIFICAÇÃO FINAL*")
    report.append("")

    # USA FUNÇÃO CENTRALIZADA
    emoji = get_priority_emoji(classification)

    report.append(f"→ *Pontuação Final:* `{final_score:.1f} / 100`")
    report.append(f"→ *Classificação:* {emoji} *{classification}*")
    report.append(f"→ *SLA:* {sla}")
    report.append("")

    # Exibir justificativa de recálculo (se existir)
    recalc_justification = technical_data.get("ai_recalculation_justification")
    if recalc_justification:
        report.append("*📝 Justificativa do Recálculo (IA):*")
        report.append(f"_{recalc_justification}_")
        report.append("")

    # RESUMO EXECUTIVO
    report.append("*━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━*")
    report.append("> *📝 RESUMO EXECUTIVO*")
    report.append("")

    # Contexto de risco
    report.append(
        f"A vulnerabilidade identificada foi classificada como *{classification}* "
        f"com base em uma pontuação técnica de `{technical_data.get('technical_subtotal', 0):.1f}/60` "
        f"e impacto no negócio de `{business_score:.1f}/40`, totalizando `{final_score:.1f}/100`."
    )
    report.append("")

    # Adiciona contexto de negócio relevante
    if business_answers.get("Dados Regulados") == "Sim, diretamente":
        report.append(
            "⚠️ *Atenção:* Esta vulnerabilidade afeta sistemas que processam dados regulados, "
            "exigindo conformidade com normativas como LGPD, BACEN e PCI-DSS."
        )
        report.append("")

    if business_answers.get("Ambiente") == "Produção Crítica":
        report.append(
            "⚠️ *Atenção:* O ativo afetado está em ambiente de produção crítica, "
            "aumentando significativamente o risco de impacto ao negócio."
        )
        report.append("")

    # RECOMENDAÇÕES DE REMEDIAÇÃO
    report.append("*━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━*")
    report.append("> *🔧 RECOMENDAÇÕES DE REMEDIAÇÃO*")
    report.append("")
    report.append("*Ações técnicas para correção definitiva:*")
    report.append("")

    remediation = ai_recommendations.get(
        "remediation_recommendations", "Recomendações não disponíveis no momento."
    )
    report.append(remediation)
    report.append("")

    # MEDIDAS DE MITIGAÇÃO
    report.append("*━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━*")
    report.append("> *🛡️ MEDIDAS DE MITIGAÇÃO TEMPORÁRIAS*")
    report.append("")
    report.append("*Controles compensatórios enquanto a correção não é aplicada:*")
    report.append("")

    mitigation = ai_recommendations.get(
        "mitigation_measures", "Medidas não disponíveis no momento."
    )
    report.append(mitigation)
    report.append("")

    # CONSIDERAÇÕES ADICIONAIS
    report.append("*━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━*")
    report.append("> *💡 CONSIDERAÇÕES ADICIONAIS*")
    report.append("")

    considerations = ai_recommendations.get(
        "additional_considerations", "Considerações não disponíveis no momento."
    )
    report.append(considerations)
    report.append("")

    # RODAPÉ
    report.append("*━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━*")
    report.append("_Relatório gerado automaticamente pelo Bot de Priorização de Vulnerabilidades_")
    report.append("*━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━*")

    return "\n".join(report)


# ==========================================================
# RELATÓRIO FINAL (MODO LISTA)
# ==========================================================


def format_executive_final_report_for_cve_list(
    *,
    focus_cve: str,
    focus_data: dict,
    all_cves: dict,
    business_score: float,
    business_answers: dict,
    ai_recommendations: dict,
    ai_recalculation_justification: Optional[str] = None,
) -> str:
    """
    Relatório executivo para LISTA de CVEs
    - UX idêntico ao relatório de CVE única
    - Apenas a CVE mais crítica é detalhada tecnicamente
    """

    report = []

    # CABEÇALHO
    report.extend(
        [
            "*━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━*",
            "*📊 RELATÓRIO EXECUTIVO DE PRIORIZAÇÃO*",
            "*━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━*",
            "",
            "*Tipo de Entrada:* Lista CVE",
            "*Identificador:* " + " ".join(f"`{cve}`" for cve in all_cves.keys()),
            "",
        ]
    )

    # DESCRIÇÃO DAS VULNERABILIDADES
    report.append("> *📋 Descrição das Vulnerabilidades:*")

    for cve_id, data in all_cves.items():
        desc = (
            data["technical_data"].get("description")
            or data["technical_data"].get("description_ai")
            or "Descrição não disponível no NVD."
        )
        report.append(f"• `{cve_id}` — {desc}")

    report.append("")

    # PONTUAÇÃO TÉCNICA — CVE MAIS CRÍTICA
    tech = focus_data["technical_data"]

    cvss_score = tech.get("cvss_score", 0.0)
    cvss_version = tech.get("cvss_version", "N/A")
    cvss_source = tech.get("cvss_source")
    cvss_type = tech.get("cvss_type")

    cvss_line = f"*CVSS ({cvss_version}):* {cvss_score:.1f}/10"
    if cvss_source:
        cvss_line += f" _(Fonte: {cvss_source}"
        if cvss_type:
            cvss_line += f", {cvss_type}"
        cvss_line += ")_"

    report.extend(
        [
            "*━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━*",
            "> *🔧 PONTUAÇÃO TÉCNICA (Máx. 60)*",
            "",
            f"Abaixo a vulnerabilidade de maior criticidade `{focus_cve}`",
            "",
            cvss_line,
            f"*EPSS:* {tech.get('epss_qualitative', 'N/A')}",
            f"*KEV:* {tech.get('kev_qualitative', 'Não')}",
            f"*Ransomware:* {tech.get('ransomware_qualitative', 'Não')}",
            f"*POC:* {tech.get('poc_qualitative', 'Não')}",
            "",
        ]
    )

    # Vetor de ataque
    vector = tech.get("attack_vector_string")
    if vector:
        report.append(f"*Vetor de Ataque:* {vector}")
        for detail in _decode_cvss_vector(vector):
            report.append(f"  - {detail}")
        report.append("")

    report.append(f"→ *Subtotal Técnico:* `{focus_data['technical_score']:.1f} / 60`")
    report.append("")

    # IMPACTO NO NEGÓCIO
    report.extend(
        [
            "*━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━*",
            "> *💼 IMPACTO NO NEGÓCIO (Máx. 40)*",
            "",
        ]
    )

    for k, v in business_answers.items():
        report.append(f"• *{k}:* {v}")

    report.extend(
        [
            "",
            f"→ *Subtotal Negócio:* `{business_score:.1f} / 40`",
            "",
        ]
    )

    # CLASSIFICAÇÃO FINAL
    emoji = get_priority_emoji(focus_data["priority"])

    report.extend(
        [
            "*━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━*",
            "> *🎯 CLASSIFICAÇÃO FINAL*",
            "",
            "*CVE de maior criticidade:*",
            f"→ *Pontuação Final:* `{focus_data['final_score']:.1f} / 100`",
            f"→ *Classificação:* {emoji} *{focus_data['priority']}*",
            f"→ *SLA:* {focus_data.get('sla', 'Não definido')}",
            "",
            "*📌 Demais CVEs avaliadas:*",
        ]
    )

    # JUSTIFICATIVA DA IA (SE HOUVE RECÁLCULO)
    if ai_recalculation_justification:
        report.extend(
            [
                "*📝 Justificativa do Recálculo (IA):*",
                f"_{ai_recalculation_justification}_",
                "",
            ]
        )

    # Demais CVEs
    for cve_id, data in all_cves.items():
        if cve_id == focus_cve:
            continue
        emoji = get_priority_emoji(data["priority"])
        report.append(
            f"• `{cve_id}` — Técnica: {data['technical_score']:.1f}/60 | "
            f"Total: {data['final_score']:.1f}/100 → {emoji} {data['priority']}"
        )

    # RESUMO EXECUTIVO
    report.extend(
        [
            "",
            "*━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━*",
            "> *📝 RESUMO EXECUTIVO*",
            "",
            (
                f"A vulnerabilidade identificada `{focus_cve}` foi classificada como "
                f"*{focus_data['priority']}* com base em uma pontuação técnica de "
                f"`{focus_data['technical_score']:.1f}/60` e impacto no negócio de "
                f"`{business_score:.1f}/40`, totalizando "
                f"`{focus_data['final_score']:.1f}/100`."
            ),
            "",
        ]
    )

    # RECOMENDAÇÕES
    report.extend(
        [
            "*━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━*",
            "> *🔧 RECOMENDAÇÕES DE REMEDIAÇÃO*",
            "",
            ai_recommendations.get("remediation", "Não informado."),
            "",
            "*━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━*",
            "> *🛡️ MEDIDAS DE MITIGAÇÃO TEMPORÁRIAS*",
            "",
            ai_recommendations.get("mitigation", "Não informado."),
            "",
            "*━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━*",
            "> *💡 CONSIDERAÇÕES ADICIONAIS*",
            "",
            ai_recommendations.get("additional", "Não informado."),
            "",
            "*━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━*",
            "_Relatório gerado automaticamente pelo Bot de Priorização de Vulnerabilidades_",
            "*━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━*",
        ]
    )

    return "\n".join(report)


# ==========================================================
# FUNÇÃO AUXILIAR: Decodificar Vetor CVSS
# ==========================================================


def _decode_cvss_vector(vector_string: str) -> list:
    """
    Decodifica vetores CVSS 3.x e 4.0 em descrições legíveis.
    """

    details = []

    if not vector_string:
        return details

    # ===============================
    # CVSS 3.x
    # ===============================
    cvss3_map = {
        "AV:N": "🌐 Rede",
        "AV:A": "📡 Rede adjacente",
        "AV:L": "💻 Local",
        "AV:P": "🔌 Físico",
        "AC:L": "⚙️ Baixa complexidade",
        "AC:H": "⚙️ Alta complexidade",
        "PR:N": "🔓 Sem privilégios",
        "PR:L": "🔑 Privilégios baixos",
        "PR:H": "🔐 Privilégios altos",
        "UI:N": "👤 Sem interação do usuário",
        "UI:R": "👥 Requer interação do usuário",
        "S:U": "🔗 Escopo inalterado",
        "S:C": "🔗 Escopo alterado",
        "C:L": "🔓 Impacto baixo na confidencialidade",
        "C:H": "🔓 Impacto alto na confidencialidade",
        "I:L": "⚠️ Impacto baixo na integridade",
        "I:H": "❌ Impacto alto na integridade",
        "A:L": "⚠️ Impacto baixo na disponibilidade",
        "A:H": "❌ Impacto alto na disponibilidade",
    }

    # ===============================
    # CVSS 4.0 (parcial – seguro)
    # ===============================
    cvss4_map = {
        "AT:N": "🎯 Sem requisitos adicionais de ataque",
        "AT:P": "🎯 Requer pré-condições de ataque",
        "VC:L": "🔓 Impacto técnico baixo (Confidencialidade)",
        "VC:H": "🔓 Impacto técnico alto (Confidencialidade)",
        "VI:L": "⚠️ Impacto técnico baixo (Integridade)",
        "VI:H": "❌ Impacto técnico alto (Integridade)",
        "VA:L": "⚠️ Impacto técnico baixo (Disponibilidade)",
        "VA:H": "❌ Impacto técnico alto (Disponibilidade)",
    }

    # Escolher mapa
    metric_map = cvss4_map if vector_string.startswith("CVSS:4.0") else cvss3_map

    for component, description in metric_map.items():
        if component in vector_string:
            details.append(description)

    return details
