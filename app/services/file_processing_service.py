import io
import logging
import re
from typing import List, Optional

import pandas as pd

logger = logging.getLogger(__name__)


class FileProcessingService:
    """
    Serviço responsável por extrair CVEs de texto e arquivos tabulares (CSV / XLSX).

    Estratégia:
    1. Normaliza nomes de colunas
    2. Detecta coluna de CVE por nome (heurística forte)
    3. Fallback: detecção por amostragem de conteúdo
    4. Extração final por regex padronizada
    """

    CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

    # Nomes normalizados aceitos como coluna de CVE
    NORMALIZED_CVE_COLUMNS = {
        "cve",
        "cveid",
        "cveidentifier",
        "vulnerability",
        "vulnerabilityid",
    }

    def extract_cves_from_text(self, text: str) -> List[str]:
        """
        Extrai CVEs de um texto livre.
        """
        if not text:
            return []

        found = self.CVE_REGEX.findall(text.upper())
        return sorted(set(found))

    # ==========================================================
    # Extração de arquivos
    # ==========================================================

    def extract_cves_from_file(self, file_content: bytes, file_type: str) -> List[str]:
        """
        Extrai CVEs de arquivos CSV ou Excel.

        Retorna:
        - Lista única de CVEs encontradas
        """
        try:
            df = self._load_dataframe(file_content, file_type)
            if df is None or df.empty:
                logger.warning("[FILE] DataFrame vazio ou não suportado")
                return []

            logger.debug(f"[FILE] Colunas detectadas: {df.columns.tolist()}")

            cve_column = self._detect_cve_column(df)

            if not cve_column:
                logger.warning(
                    "[FILE] Nenhuma coluna de CVE identificada "
                    "por nome ou amostragem de conteúdo."
                )
                return []

            logger.info(f"[FILE] Coluna de CVE identificada: '{cve_column}'")

            return self._extract_cves_from_column(df[cve_column])

        except Exception as exc:
            logger.error(
                f"[FILE] Erro ao processar arquivo: {exc}",
                exc_info=True,
            )
            return []

    # ==========================================================
    # Helpers internos
    # ==========================================================

    def _load_dataframe(self, file_content: bytes, file_type: str) -> Optional[pd.DataFrame]:
        """
        Carrega CSV ou XLSX em DataFrame.
        """
        try:
            if file_type == "csv":
                return pd.read_csv(io.BytesIO(file_content))
            if file_type in {"xlsx", "xls"}:
                return pd.read_excel(io.BytesIO(file_content))

            logger.debug(f"[FILE] Tipo de arquivo não suportado: {file_type}")
            return None

        except Exception as exc:
            logger.error(
                f"[FILE] Falha ao carregar arquivo ({file_type}): {exc}",
                exc_info=True,
            )
            return None

    def _detect_cve_column(self, df: pd.DataFrame) -> Optional[str]:
        """
        Detecta a coluna que contém CVEs.

        Prioridade:
        1. Nome da coluna normalizado
        2. Amostragem de conteúdo
        """
        # Detecção por nome
        for col in df.columns:
            normalized = self._normalize_column_name(col)
            if normalized in self.NORMALIZED_CVE_COLUMNS:
                return col

        # Fallback: amostragem de conteúdo
        for col in df.columns:
            if self._column_looks_like_cve(df[col]):
                logger.debug(f"[FILE] Coluna '{col}' identificada por amostragem")
                return col

        return None

    def _column_looks_like_cve(self, series: pd.Series) -> bool:
        """
        Verifica se uma coluna parece conter CVEs
        analisando uma amostra do conteúdo.
        """
        sample = series.dropna().astype(str).head(10).tolist()

        if not sample:
            return False

        matches = sum(1 for value in sample if self.CVE_REGEX.search(value.upper()))

        ratio = matches / len(sample)

        logger.debug(f"[FILE] Amostragem CVE: {matches}/{len(sample)} " f"({ratio:.0%})")

        # Pelo menos 50% da amostra deve conter CVE
        return ratio >= 0.5

    def _extract_cves_from_column(self, series: pd.Series) -> List[str]:
        """
        Extrai CVEs de uma coluna específica.
        """
        cves = set()

        for value in series.dropna().astype(str):
            match = self.CVE_REGEX.search(value.upper())
            if match:
                cves.add(match.group(0))

        return sorted(cves)

    @staticmethod
    def _normalize_column_name(col: str) -> str:
        """
        Normaliza nomes de colunas para comparação robusta.
        """
        return col.strip().lower().replace("_", "").replace("-", "").replace(" ", "")
