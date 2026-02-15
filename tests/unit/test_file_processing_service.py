import io

import pandas as pd

from app.services.file_processing_service import FileProcessingService

# ==========================================================
# FIXTURE
# ==========================================================


def service():
    return FileProcessingService()


# ==========================================================
# extract_cves_from_text
# ==========================================================


def test_extract_cves_from_text_basic():
    text = """
    Encontramos as seguintes vulnerabilidades:
    - CVE-2024-1234
    - cve-2023-9999
    """

    result = FileProcessingService().extract_cves_from_text(text)

    assert result == ["CVE-2023-9999", "CVE-2024-1234"]


def test_extract_cves_from_text_duplicates_removed():
    text = "CVE-2024-0001 CVE-2024-0001 cve-2024-0001"

    result = FileProcessingService().extract_cves_from_text(text)

    assert result == ["CVE-2024-0001"]


def test_extract_cves_from_text_empty():
    assert FileProcessingService().extract_cves_from_text("") == []


def test_extract_cves_from_text_none():
    assert FileProcessingService().extract_cves_from_text(None) == []


# ==========================================================
# extract_cves_from_file — CSV
# ==========================================================


def test_extract_cves_from_csv_with_cve_column():
    df = pd.DataFrame(
        {
            "CVE": ["CVE-2024-1111", "CVE-2024-2222"],
            "Description": ["desc1", "desc2"],
        }
    )

    buffer = io.BytesIO()
    df.to_csv(buffer, index=False)

    result = FileProcessingService().extract_cves_from_file(buffer.getvalue(), "csv")

    assert result == ["CVE-2024-1111", "CVE-2024-2222"]


def test_extract_cves_from_csv_normalized_column_name():
    df = pd.DataFrame(
        {
            "vulnerability_id": ["cve-2023-0001", "CVE-2023-0002"],
        }
    )

    buffer = io.BytesIO()
    df.to_csv(buffer, index=False)

    result = FileProcessingService().extract_cves_from_file(buffer.getvalue(), "csv")

    assert result == ["CVE-2023-0001", "CVE-2023-0002"]


def test_extract_cves_from_csv_fallback_sampling():
    df = pd.DataFrame(
        {
            "random_col": [
                "CVE-2022-0001",
                "CVE-2022-0002",
                "not a cve",
                "CVE-2022-0003",
            ]
        }
    )

    buffer = io.BytesIO()
    df.to_csv(buffer, index=False)

    result = FileProcessingService().extract_cves_from_file(buffer.getvalue(), "csv")

    assert result == [
        "CVE-2022-0001",
        "CVE-2022-0002",
        "CVE-2022-0003",
    ]


def test_extract_cves_from_csv_fallback_below_threshold():
    df = pd.DataFrame(
        {
            "random_col": [
                "CVE-2022-0001",
                "not a cve",
                "not a cve",
                "not a cve",
            ]
        }
    )

    buffer = io.BytesIO()
    df.to_csv(buffer, index=False)

    result = FileProcessingService().extract_cves_from_file(buffer.getvalue(), "csv")

    assert result == []


# ==========================================================
# extract_cves_from_file — XLSX
# ==========================================================


def test_extract_cves_from_xlsx():
    df = pd.DataFrame(
        {
            "CVE Identifier": ["CVE-2021-1111", "CVE-2021-2222"],
        }
    )

    buffer = io.BytesIO()
    df.to_excel(buffer, index=False)

    result = FileProcessingService().extract_cves_from_file(buffer.getvalue(), "xlsx")

    assert result == ["CVE-2021-1111", "CVE-2021-2222"]


# ==========================================================
# extract_cves_from_file — DEFENSIVE
# ==========================================================


def test_extract_cves_from_unsupported_file_type():
    result = FileProcessingService().extract_cves_from_file(b"irrelevant content", "txt")

    assert result == []


def test_extract_cves_from_empty_file():
    result = FileProcessingService().extract_cves_from_file(b"", "csv")

    assert result == []


def test_extract_cves_from_corrupted_file():
    result = FileProcessingService().extract_cves_from_file(b"\x00\x01\x02\x03", "xlsx")

    assert result == []
