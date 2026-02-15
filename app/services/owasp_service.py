import logging
import re
from typing import List, Optional

from app.domain.owasp.catalog import OWASP_TOP_10
from app.domain.owasp.models import OWASPCategory

logger = logging.getLogger(__name__)


class OWASPService:
    """
    Serviço de domínio OWASP.

    Responsabilidades ÚNICAS:
    ✅ Resolver categoria OWASP por código (A01–A10)
    ✅ Identificar categoria OWASP a partir de texto livre (determinístico)
    ✅ Expor metadados oficiais (título, rank)

    """

    # A01–A10 | AI01–AI10 (sem ano)
    OWASP_CODE_PATTERN = re.compile(r"\b(A|AI)(0[1-9]|10)\b", re.IGNORECASE)

    # ==========================================================
    # Código → Categoria
    # ==========================================================

    def resolve_by_code(self, code: str) -> Optional[OWASPCategory]:
        """
        Resolve uma categoria OWASP a partir do código.

        Retorna:
        - OWASPCategory se existir no catálogo atual
        - None se não existir
        """

        if not code:
            return None

        normalized = code.strip().upper()
        data = OWASP_TOP_10.get(normalized)

        if not data:
            logger.info(f"[OWASP] Código fora do catálogo atual: {normalized}")
            return None

        return OWASPCategory(
            code=normalized,
            title=data["title"],
            rank=data["rank"],
        )

    # ==========================================================
    # Texto livre → Categoria OWASP
    # ==========================================================

    def match_from_text(self, text: str) -> Optional[OWASPCategory]:
        """
        Identifica UMA categoria OWASP a partir de texto livre.

        Ordem de decisão (determinística):
        1️⃣ Código explícito no texto (ex: A01)
        2️⃣ Match por keywords do catálogo

        Retorna:
        - OWASPCategory
        - None se não houver match confiável
        """

        if not text:
            return None

        text = text.lower()

        # 1️⃣ Código explícito
        explicit = self._match_explicit_code(text)
        if explicit:
            logger.info(f"[OWASP_MATCH] Código explícito identificado: {explicit.code}")
            return explicit

        # 2️⃣ Keywords
        keyword_match = self._match_by_keywords(text)
        if keyword_match:
            logger.info(f"[OWASP_MATCH] Match por keyword: {keyword_match.code}")
            return keyword_match

        logger.info("[OWASP_MATCH] Nenhuma categoria identificada")
        return None

    # ==========================================================
    # Utilitário: múltiplos matches (opcional)
    # ==========================================================

    def match_all_from_text(self, text: str) -> List[OWASPCategory]:
        """
        Identifica TODAS as categorias OWASP relevantes no texto.

        Usado quando:
        - queremos sugerir opções ao usuário
        - não para scoring direto
        """

        if not text:
            return []

        text = text.lower()
        matches = []
        seen_codes = set()

        # Código explícito
        explicit = self._match_explicit_code(text)
        if explicit:
            matches.append(explicit)
            seen_codes.add(explicit.code)

        # Keywords
        for code, data in OWASP_TOP_10.items():
            if code in seen_codes:
                continue

            for keyword in data.get("keywords", []):
                if keyword in text:
                    matches.append(
                        OWASPCategory(
                            code=code,
                            title=data["title"],
                            rank=data["rank"],
                        )
                    )
                    seen_codes.add(code)
                    break

        return matches

    # ==========================================================
    # Internals
    # ==========================================================

    def _match_explicit_code(self, text: str) -> Optional[OWASPCategory]:
        match = self.OWASP_CODE_PATTERN.search(text)
        if not match:
            return None

        return self.resolve_by_code(match.group(0).upper())

    def _match_by_keywords(self, text: str) -> Optional[OWASPCategory]:
        for code, data in OWASP_TOP_10.items():
            for keyword in data.get("keywords", []):
                if keyword in text:
                    return OWASPCategory(
                        code=code,
                        title=data["title"],
                        rank=data["rank"],
                    )
        return None
