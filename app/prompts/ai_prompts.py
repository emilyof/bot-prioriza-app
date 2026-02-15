# app/prompts/ai_prompts.py

"""
Prompts centralizados de IA.

REGRAS GERAIS:
- Respostas devem ser APENAS JSON válido
- Nunca usar markdown
- Nunca retornar múltiplos objetos JSON
- Campos esperados DEVEM existir
"""

# ==========================================================
# 🔹 SCORING TÉCNICO POR DESCRIÇÃO (0–60)
# ==========================================================


def build_technical_scoring_prompt(description: str) -> str:
    return f"""
Você é um sistema automatizado de pontuação técnica de vulnerabilidades.

Analise a descrição abaixo e atribua UMA pontuação técnica TOTAL
entre 0 e 60.

Descrição:
\"\"\"{description}\"\"\"

REGRAS:
- Responda APENAS com JSON válido
- NÃO use markdown
- NÃO inclua texto fora do JSON
- Pontuação absoluta (0 a 60)

Formato EXATO da resposta:

{{
  "technical_subtotal": 0,
  "justification": "Justificativa técnica objetiva em uma única frase"
}}
""".strip()


# ==========================================================
# 🔹 SUGESTÃO DE OWASP TOP 10 (2021)
# ==========================================================


def build_suggest_owasp_prompt(description: str) -> str:
    """
    Prompt para sugerir categorias OWASP a partir de uma descrição livre.

    A IA deve:
    - Identificar categorias OWASP plausíveis
    - Informar o TIPO da lista OWASP
    - Informar código e título da categoria
    - NÃO assumir que a categoria está na versão mais recente
    """

    return f"""
Você é um especialista em segurança da informação.

Com base na descrição abaixo, identifique possíveis categorias OWASP
que representem corretamente o tipo de vulnerabilidade descrita.

DESCRIÇÃO:
\"\"\"{description}\"\"\"

LISTAS OWASP SUPORTADAS:
- OWASP_TOP_10 (aplicações web)
- OWASP_AI_TOP_10 (aplicações com IA / LLMs)

REGRAS OBRIGATÓRIAS:
- Retorne APENAS JSON válido
- NÃO use markdown
- NÃO inclua explicações fora do JSON
- NÃO invente códigos
- NÃO inclua ano (ex: NÃO use A01:2021)
- Se não tiver certeza absoluta, retorne lista vazia

FORMATO EXATO DA RESPOSTA:

{{
  "categories": [
    {{
      "type": "OWASP_TOP_10",
      "code": "A05",
      "title": "Security Misconfiguration"
    }}
  ]
}}

OBSERVAÇÕES IMPORTANTES:
- O sistema validará se a categoria pertence à versão mais recente
- Categorias podem estar desatualizadas ou fora do Top 10 atual
- Seu papel é APENAS sugerir com base na semântica
""".strip()


# ==========================================================
# 🔹 RECÁLCULO DE SCORE TÉCNICO (0–60)
# ==========================================================


def build_technical_recalculation_prompt(
    original_technical_data: dict,
    business_answers: dict,
    business_score: float,
    user_justification: str,
    recalculation_history: list,
) -> str:
    """
    Constrói prompt para recálculo técnico (0–60).

    OBJETIVO:
    - Recalcular APENAS o score técnico
    - Considerar dados técnicos já coletados
    - Considerar contexto e peso do negócio SEM misturar eixos
    """

    prompt_parts = []

    # ==========================================================
    # CONTEXTO GERAL
    # ==========================================================
    prompt_parts.append("# CONTEXTO DE RECÁLCULO DE VULNERABILIDADE")
    prompt_parts.append("")
    prompt_parts.append(
        "Você é um especialista em priorização de vulnerabilidades em ambientes corporativos."
    )
    prompt_parts.append(
        "Sua tarefa é RECALCULAR APENAS A PONTUAÇÃO TÉCNICA " "(intervalo absoluto de 0 a 60)."
    )
    prompt_parts.append(
        "O score técnico representa severidade técnica e probabilidade de exploração, "
        "considerando controles técnicos existentes."
    )
    prompt_parts.append("")

    # ==========================================================
    # SCORE TÉCNICO ORIGINAL
    # ==========================================================
    prompt_parts.append("## PONTUAÇÃO TÉCNICA ORIGINAL")
    prompt_parts.append(
        f"- Score técnico atual: {original_technical_data.get('technical_subtotal', 0):.1f}/60"
    )
    prompt_parts.append("")

    # ==========================================================
    # DADOS TÉCNICOS JÁ COLETADOS
    # ==========================================================
    prompt_parts.append("## DADOS TÉCNICOS DISPONÍVEIS")

    if "cvss_score" in original_technical_data:
        prompt_parts.append(f"- CVSS: {original_technical_data.get('cvss_score', 'N/A')}/10")
        prompt_parts.append(f"- EPSS: {original_technical_data.get('epss_qualitative', 'N/A')}")
        prompt_parts.append(
            f"- KEV (exploração conhecida): {original_technical_data.get('kev_qualitative', 'N/A')}"
        )
        prompt_parts.append(
            f"- POC público: {original_technical_data.get('poc_qualitative', 'N/A')}"
        )
        prompt_parts.append(
            f"- Ransomware: {original_technical_data.get('ransomware_qualitative', 'N/A')}"
        )

        attack_vector = original_technical_data.get("attack_vector_string")
        if attack_vector:
            prompt_parts.append(f"- Vetor de ataque: {attack_vector}")

        cwes = original_technical_data.get("cwes")
        if cwes:
            prompt_parts.append(f"- CWEs associadas: {cwes}")

    if original_technical_data.get("ai_justification"):
        prompt_parts.append("")
        prompt_parts.append("Justificativa técnica original:")
        prompt_parts.append(original_technical_data["ai_justification"])

    prompt_parts.append("")

    # ==========================================================
    # CONTEXTO DE NEGÓCIO (QUALITATIVO)
    # ==========================================================
    prompt_parts.append("## CONTEXTO DE NEGÓCIO (REFERÊNCIA)")
    prompt_parts.append("As informações abaixo servem APENAS para contextualizar o ambiente.")
    prompt_parts.append("Elas NÃO devem ser usadas para inflar artificialmente o score técnico.")
    prompt_parts.append("")

    for key, value in business_answers.items():
        prompt_parts.append(f"- {key}: {value}")

    prompt_parts.append("")

    # ==========================================================
    # PONTUAÇÃO DE NEGÓCIO (EXPLÍCITA)
    # ==========================================================
    prompt_parts.append("## IMPACTO DE NEGÓCIO (RESUMO NUMÉRICO)")
    prompt_parts.append(f"- Pontuação de negócio calculada: {business_score:.1f}/40")
    prompt_parts.append(
        "IMPORTANTE: esta pontuação JÁ é considerada no score final "
        "e NÃO deve ser compensada no score técnico."
    )
    prompt_parts.append("")

    # ==========================================================
    # JUSTIFICATIVA DO USUÁRIO
    # ==========================================================
    prompt_parts.append("## JUSTIFICATIVA DO USUÁRIO PARA RECÁLCULO")
    prompt_parts.append(user_justification)
    prompt_parts.append("")

    # ==========================================================
    # HISTÓRICO DE RECÁLCULOS
    # ==========================================================
    if recalculation_history:
        prompt_parts.append("## HISTÓRICO DE RECÁLCULOS ANTERIORES")
        for i, entry in enumerate(recalculation_history, 1):
            prompt_parts.append(f"### Recálculo #{i}")
            prompt_parts.append(f"- Score técnico anterior: {entry['previous_technical_score']}/60")
            prompt_parts.append(f"- Justificativa do usuário: {entry['user_justification']}")
            prompt_parts.append(
                f"- Score sugerido pela IA: {entry['ai_result']['technical_subtotal']}/60"
            )
            prompt_parts.append(f"- Justificativa da IA: {entry['ai_result']['justification']}")
            prompt_parts.append("")

    # ==========================================================
    # REGRAS DE DOMÍNIO (CRÍTICAS)
    # ==========================================================
    prompt_parts.append("## REGRAS DE DOMÍNIO OBRIGATÓRIAS")
    prompt_parts.append("- O score técnico reflete APENAS severidade técnica e exploração.")
    prompt_parts.append("- Impacto de negócio já é tratado separadamente (0–40).")
    prompt_parts.append("- NÃO aumente o score técnico apenas porque o impacto de negócio é alto.")
    prompt_parts.append("")
    prompt_parts.append(
        "- Se a justificativa indicar CONTROLE COMPENSATÓRIO "
        "(ex: WAF, firewall, IPS, segmentação, rate limiting):"
    )
    prompt_parts.append("  → O score técnico NÃO DEVE AUMENTAR")
    prompt_parts.append("  → Deve ser mantido ou reduzido")
    prompt_parts.append("")
    prompt_parts.append("- Se a justificativa indicar NOVA EXPOSIÇÃO técnica real:")
    prompt_parts.append("  → O score técnico PODE AUMENTAR")
    prompt_parts.append("")

    # ==========================================================
    # LIMITES NUMÉRICOS
    # ==========================================================
    prompt_parts.append("## LIMITES NUMÉRICOS")
    prompt_parts.append("- Intervalo absoluto: 0 a 60")
    prompt_parts.append("- Variação máxima por recálculo: ±20 pontos")
    prompt_parts.append("- Nunca contradiga sua própria justificativa textual")
    prompt_parts.append("")

    # ==========================================================
    # FORMATO DE SAÍDA
    # ==========================================================
    prompt_parts.append("## FORMATO DE RESPOSTA (OBRIGATÓRIO)")
    prompt_parts.append("Responda APENAS com JSON válido:")
    prompt_parts.append("```json")
    prompt_parts.append("{")
    prompt_parts.append('  "technical_subtotal": 22.0,')
    prompt_parts.append(
        '  "justification": "Reduzi o score técnico considerando a presença de WAF efetivo bloqueando tentativas de exploração, o que diminui significativamente a probabilidade de comprometimento, mantendo impacto técnico residual devido à natureza da vulnerabilidade."'
    )
    prompt_parts.append("}")
    prompt_parts.append("```")

    return "\n".join(prompt_parts)


# ==========================================================
# Relatório executivo completo (recomendações de remediação, mitigação e considerações adicionais)
# ==========================================================


def build_executive_report_prompt(
    identifier: str,
    description: str,
    input_type,
    technical_data: dict,
    business_answers: dict,
    final_score: float,
    classification: str,
) -> str:
    """
    Prompt para gerar relatório executivo completo com recomendações.

    Retorna prompt formatado para a IA gerar:
    - Recomendações de remediação
    - Medidas de mitigação
    - Considerações adicionais
    """

    return f"""
Você é um especialista em segurança da informação e gestão de vulnerabilidades em instituições financeiras.

**CONTEXTO DA VULNERABILIDADE:**
- Identificador: {identifier}
- Tipo: {input_type.value}
- Descrição: {description}
- Pontuação Final: {final_score:.1f}/100
- Classificação: {classification}

**IMPACTO TÉCNICO:**
- Pontuação Técnica: {technical_data.get('technical_subtotal', 0):.1f}/60
- Justificativa: {technical_data.get('ai_justification') or technical_data.get('ai_recalculation_justification', 'N/A')}

**IMPACTO NO NEGÓCIO:**
- Ambiente: {business_answers.get('Ambiente', 'N/A')}
- Criticidade: {business_answers.get('Criticidade', 'N/A')}
- Mitigações Existentes: {business_answers.get('Mitigações', 'N/A')}
- Acesso Necessário: {business_answers.get('Acesso', 'N/A')}
- Dados Regulados: {business_answers.get('Dados Regulados', 'N/A')}

**SUA TAREFA:**
Gere um relatório executivo completo em formato JSON com as seguintes seções:

1. **remediation_recommendations** (string):
   - Lista de 5-7 recomendações técnicas ESPECÍFICAS para CORRIGIR definitivamente esta vulnerabilidade
   - Cada recomendação deve ser acionável, técnica e detalhada
   - Priorize correções na raiz do problema
   - Formato: "- Recomendação técnica detalhada 1\\n- Recomendação técnica detalhada 2\\n..."

2. **mitigation_measures** (string):
   - Lista de 5-7 medidas de mitigação TEMPORÁRIAS enquanto a correção definitiva não é aplicada
   - Foco em controles compensatórios práticos e imediatos
   - Devem reduzir o risco significativamente
   - Formato: "- Medida de mitigação prática 1\\n- Medida de mitigação prática 2\\n..."

3. **additional_considerations** (string):
   - Lista de 4-5 considerações adicionais estratégicas
   - Incluir: monitoramento em tempo real, resposta a incidentes, treinamentos, avaliações de dependências, compliance
   - Formato: "- Consideração estratégica 1\\n- Consideração estratégica 2\\n..."

**DIRETRIZES IMPORTANTES:**
- Seja EXTREMAMENTE ESPECÍFICO para o contexto desta vulnerabilidade
- Use linguagem técnica mas acessível para gestores de segurança
- Priorize ações de maior impacto na redução de risco
- Considere o ambiente ({business_answers.get('Ambiente', 'N/A')}) e criticidade ({business_answers.get('Criticidade', 'N/A')}) informados
- Se for instituição financeira, considere conformidade regulatória (LGPD, BACEN, PCI-DSS)
- Mencione ferramentas e tecnologias específicas quando aplicável (WAF, IPS/IDS, SIEM, MFA, RBAC, etc.)
- Para vulnerabilidades críticas (P1/P2), enfatize urgência e impacto

**EXEMPLOS DE BOAS RECOMENDAÇÕES:**
✅ "Implementar validação de entrada com whitelist em todos os campos do formulário de login, utilizando biblioteca de sanitização como OWASP ESAPI"
✅ "Aplicar patch de segurança versão X.Y.Z disponibilizado pelo fabricante em [data]"
✅ "Revisar e restringir permissões de acesso ao banco de dados seguindo princípio de privilégio mínimo (POLP)"

**EXEMPLOS DE BOAS MITIGAÇÕES:**
✅ "Configurar WAF (Web Application Firewall) com regras específicas para bloquear padrões de SQL Injection"
✅ "Segmentar rede para isolar servidores críticos em VLAN separada com firewall stateful"
✅ "Ativar alertas em tempo real no SIEM para tentativas de exploração desta vulnerabilidade"

**FORMATO DE SAÍDA (JSON VÁLIDO):**
{{
  "remediation_recommendations": "- Implementar mecanismo X para Y\\n- Aplicar controle Z em W\\n- Revisar configuração A para B\\n- Atualizar biblioteca C para versão D\\n- Configurar E conforme padrão F\\n- Validar G utilizando H\\n- Documentar I no processo J",
  "mitigation_measures": "- Ativar ferramenta X para monitorar Y\\n- Segmentar rede Z com firewall W\\n- Configurar alerta A no SIEM B\\n- Restringir acesso C via D\\n- Implementar rate limiting E\\n- Habilitar logging F em G\\n- Aplicar regra H no WAF I",
  "additional_considerations": "- Monitorar logs de X em tempo real via Y\\n- Atualizar plano de resposta a incidentes incluindo Z\\n- Avaliar dependências W que possam ter vulnerabilidade similar\\n- Realizar treinamento A para equipe B\\n- Revisar política C de D"
}}

Responda APENAS com o JSON válido, sem markdown (```json), sem texto adicional.
"""


# ==========================================================
# CVE LIST RANKING (PRIORITIZAÇÃO CONSOLIDADA DE MÚLTIPLAS CVEs)
# ==========================================================


def build_cve_list_ranking_prompt(
    business_context: dict,
    business_score: float,
    cves: list,
) -> str:
    """
    Prompt para priorização consolidada de uma LISTA de CVEs.

    A IA deve:
    - Analisar todas as CVEs em conjunto
    - Considerar UMA pontuação de negócio compartilhada
    - Definir ranking de prioridade (maior → menor risco)
    - Escolher a CVE mais crítica (focus)
    - Gerar recomendações e mitigações consolidadas ou focadas
    """

    return f"""
Você é um especialista em gestão de vulnerabilidades em ambientes corporativos críticos.

Este relatório deve seguir o MESMO padrão de um Relatório Executivo
de Priorização para CVE única, com a diferença de que existe uma LISTA de CVEs.

==============================
CONTEXTO DE NEGÓCIO (ÚNICO)
==============================
Pontuação de negócio (0–40): {business_score}

Detalhes:
{business_context}

==============================
LISTA DE CVEs ANALISADAS
==============================
{cves}

==============================
SUAS TAREFAS
==============================

1. Analise TODAS as CVEs considerando:
   - Severidade técnica
   - Probabilidade de exploração
   - Impacto em ambiente de produção
   - Presença de exploit conhecido (KEV, ransomware, POC)

2. Defina um RANKING de priorização
   - Da CVE mais crítica para a menos crítica

3. Escolha UMA CVE principal (focus_cve)
   - Aquela que deve ser tratada com máxima urgência

4. Gere recomendações de:
   - Remediação (correção definitiva)
   - Mitigação (controles temporários)

⚠️ IMPORTANTE:
- Se as CVEs forem similares, gere recomendações ABRANGENTES
- Se uma CVE se destacar claramente, foque nela
- Use linguagem executiva, clara e acionável

==============================
FORMATO OBRIGATÓRIO DA RESPOSTA
==============================

Responda APENAS com JSON válido, sem markdown, sem texto adicional:

{{
  "ranking": ["CVE-XXXX-YYYY", "CVE-ZZZZ-WWWW"],
  "focus_cve": "CVE-XXXX-YYYY",
  "prioritization_justification": "Justificativa clara e objetiva do ranking",
  "remediation_recommendations": "- Recomendação 1\\n- Recomendação 2\\n- Recomendação 3",
  "mitigation_measures": "- Mitigação 1\\n- Mitigação 2\\n- Mitigação 3",
  "additional_considerations": "- Consideração 1\\n- Consideração 2"
}}
""".strip()


def build_owasp_category_description_prompt(
    owasp_code: str,
    owasp_title: str,
) -> str:
    """
    Prompt para gerar uma descrição curta e executiva
    de uma categoria OWASP.
    """

    return f"""
Você é um especialista em segurança da informação.

Explique de forma CLARA, OBJETIVA e CURTA (2 a 3 frases)
a seguinte categoria OWASP, para um público técnico-gerencial.

Categoria:
- Código: {owasp_code}
- Nome: {owasp_title}

REGRAS:
- Não mencione OWASP Top 10, ranking ou pontuação
- Não use markdown
- Não use listas
- Retorne APENAS texto corrido
""".strip()
