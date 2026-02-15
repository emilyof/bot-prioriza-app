import logging

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class SecureHTTPClient:
    """
    Cliente HTTP centralizado com:
    - timeout obrigatório
    - retry automático
    - backoff exponencial
    - proteção contra falhas transitórias
    """

    def __init__(
        self,
        timeout: int = 10,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
    ):
        self.timeout = timeout

        retry_strategy = Retry(
            total=max_retries,
            connect=max_retries,
            read=max_retries,
            status=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"],
            raise_on_status=False,
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)

        self.session = requests.Session()
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def get(self, url: str, **kwargs) -> requests.Response:
        logger.debug(f"[HTTP GET] {url}")
        return self.session.get(url, timeout=self.timeout, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        logger.debug(f"[HTTP POST] {url}")
        return self.session.post(url, timeout=self.timeout, **kwargs)
