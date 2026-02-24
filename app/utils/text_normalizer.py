def normalize_description_case(text: str) -> str:
    """
    Normaliza texto em MAIÚSCULAS para capitalização adequada.

    Regras:
    - Se o texto estiver TODO EM MAIÚSCULAS, converte para sentence case
    - Preserva siglas conhecidas (CVE, API, CNPJ, PII, etc.)
    - Mantém texto já formatado corretamente

    Args:
        text: Texto original

    Returns:
        str: Texto normalizado
    """

    if not text or not isinstance(text, str):
        return text

    # Verifica se o texto está TODO em maiúsculas
    # (ignorando espaços e pontuação)
    words = text.split()
    uppercase_words = [w for w in words if w.isupper() and w.isalpha()]

    # Se menos de 70% das palavras estão em maiúsculas, não normaliza
    if len(uppercase_words) / len(words) < 0.7:
        return text

    # Lista de siglas/termos que devem permanecer em maiúsculas
    acronyms = {
        "CVE",
        "API",
        "CNPJ",
        "CPF",
        "PII",
        "SQL",
        "XSS",
        "CSRF",
        "JWT",
        "OWASP",
        "HTTPS",
        "HTTP",
        "SSL",
        "TLS",
        "DNS",
        "IP",
        "URL",
        "ID",
        "LGPD",
        "BACEN",
        "PCI",
        "DSS",
        "WAF",
        "IPS",
        "IDS",
        "SIEM",
        "MFA",
        "RBAC",
        "AWS",
        "GCP",
        "AZURE",
        "S3",
        "EC2",
        "RDS",
        "VPC",
        "IAM",
    }

    # Converte para lowercase e capitaliza primeira letra de cada sentença
    normalized = text.lower()

    # Capitaliza primeira letra após pontuação
    sentences = normalized.replace(". ", ".|||").replace("! ", "!|||").replace("? ", "?|||")
    sentences = [s.strip().capitalize() for s in sentences.split("|||")]
    normalized = ". ".join(sentences)

    # Restaura siglas conhecidas
    for acronym in acronyms:
        # Substitui versão lowercase pela versão uppercase
        normalized = normalized.replace(f" {acronym.lower()} ", f" {acronym} ")
        normalized = normalized.replace(f" {acronym.lower()}.", f" {acronym}.")
        normalized = normalized.replace(f" {acronym.lower()},", f" {acronym},")

        # Caso especial: início da frase
        if normalized.lower().startswith(acronym.lower()):
            normalized = acronym + normalized[len(acronym) :]

    return normalized
