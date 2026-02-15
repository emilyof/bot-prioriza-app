import logging
import re
import time
from functools import wraps

# Configura o logger para este módulo
logger = logging.getLogger(__name__)


def retry_with_backoff(
    tries: int = 3,
    delay: float = 1,
    backoff: float = 2,
    exceptions: tuple = (Exception,),
    logger_obj=None,
):
    """
    Decorator para retentar uma função com backoff exponencial.

    Args:
        tries (int): Número de tentativas.
        delay (float): Atraso inicial em segundos.
        backoff (float): Fator pelo qual o atraso aumentará a cada tentativa.
        exceptions (tuple): Tupla de exceções a serem capturadas e retentadas.
        logger_obj (logging.Logger, optional): Objeto logger para registrar tentativas.
    """
    if logger_obj is None:
        logger_obj = logger  # Usa o logger do módulo por padrão

    def deco_retry(f):
        @wraps(f)
        def f_retry(*args, **kwargs):
            mtries, mdelay = tries, delay
            while mtries > 1:
                try:
                    return f(*args, **kwargs)
                except exceptions as e:
                    logger_obj.warning(
                        f"Erro '{e}' ao executar {f.__name__}. Retentando em {mdelay:.1f} segundos..."  # noqa: E501
                    )
                    time.sleep(mdelay)
                    mtries -= 1
                    mdelay *= backoff
            return f(*args, **kwargs)  # Última tentativa sem try-except para propagar o erro

        return f_retry

    return deco_retry


def sanitize_text(text):
    """
    Remove caracteres de formatação Markdown do Slack antes de validar CVE/CWE/OWASP.

    Args:
        text (str): Texto bruto do usuário, possivelmente com formatação Markdown

    Returns:
        str: Texto limpo sem caracteres de formatação

    Examples:
        >>> sanitize_text("**CVE-2025-55182**")
        'CVE-2025-55182'
        >>> sanitize_text("*CWE-502*")
        'CWE-502'
        >>> sanitize_text("`CVE-2024-1234`")
        'CVE-2024-1234'
    """
    if not text:
        return text

    # Remove asteriscos (negrito/itálico)
    text = re.sub(r"\*+", "", text)

    # Remove underscores (itálico/sublinhado)
    text = re.sub(r"_+", "", text)

    # Remove backticks (código inline)
    text = re.sub(r"`+", "", text)

    # Remove tildes (tachado)
    text = re.sub(r"~+", "", text)

    # Remove espaços extras
    text = text.strip()

    return text


def validate_cve_format(cve_id: str) -> bool:
    """Valida formato CVE-YYYY-NNNNN"""
    return bool(re.match(r"^CVE-\d{4}-\d{4,}$", cve_id.upper()))


def validate_owasp_format(owasp_id: str) -> bool:
    """Valida formato A01:2021"""
    return bool(re.match(r"^A\d{2}:\d{4}$", owasp_id.upper()))
