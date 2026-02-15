from dataclasses import dataclass


@dataclass(frozen=True)
class OWASPCategory:
    """
    Representa uma categoria OWASP Top 10.

    Este é um objeto de domínio puro.
    NÃO contém lógica.
    """

    code: str
    title: str
    rank: int
