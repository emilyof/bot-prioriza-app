"""
Catálogo oficial OWASP Top 10 (2021).

Este arquivo é a FONTE ÚNICA DE VERDADE do domínio OWASP.
- Matcher
- Resolver
- Scoring
- UI

NÃO colocar lógica aqui.
"""

OWASP_TOP_10 = {
    "A01": {
        "title": "Broken Access Control",
        "rank": 1,
        "keywords": [
            "broken access control",
            "access control",
            "idor",
            "insecure direct object reference",
            "unauthorized access",
            "privilege escalation",
            "missing authorization",
        ],
    },
    "A02": {
        "title": "Cryptographic Failures",
        "rank": 2,
        "keywords": [
            "cryptographic failure",
            "weak encryption",
            "plaintext",
            "sensitive data exposure",
            "tls",
            "ssl",
            "encryption",
        ],
    },
    "A03": {
        "title": "Injection",
        "rank": 3,
        "keywords": [
            "injection",
            "sql injection",
            "sqli",
            "nosql injection",
            "command injection",
            "os injection",
            "ldap injection",
            "xpath injection",
        ],
    },
    "A04": {
        "title": "Insecure Design",
        "rank": 4,
        "keywords": [
            "insecure design",
            "missing security control",
            "design flaw",
            "threat modeling",
            "security design",
            "business logic flaw",
        ],
    },
    "A05": {
        "title": "Security Misconfiguration",
        "rank": 5,
        "keywords": [
            "security misconfiguration",
            "misconfiguration",
            "default configuration",
            "open bucket",
            "open s3",
            "debug enabled",
            "exposed admin",
        ],
    },
    "A06": {
        "title": "Vulnerable and Outdated Components",
        "rank": 6,
        "keywords": [
            "outdated component",
            "vulnerable component",
            "dependency vulnerability",
            "library vulnerability",
            "unpatched",
            "eol",
            "end of life",
        ],
    },
    "A07": {
        "title": "Identification and Authentication Failures",
        "rank": 7,
        "keywords": [
            "authentication failure",
            "weak authentication",
            "broken authentication",
            "session fixation",
            "credential stuffing",
            "password reuse",
            "missing authentication",
        ],
    },
    "A08": {
        "title": "Software and Data Integrity Failures",
        "rank": 8,
        "keywords": [
            "integrity failure",
            "software integrity",
            "data integrity",
            "insecure deserialization",
            "supply chain",
            "ci/cd",
            "pipeline tampering",
        ],
    },
    "A09": {
        "title": "Security Logging and Monitoring Failures",
        "rank": 9,
        "keywords": [
            "logging failure",
            "monitoring failure",
            "insufficient logging",
            "missing logs",
            "alerting failure",
            "incident detection",
        ],
    },
    "A10": {
        "title": "Server-Side Request Forgery (SSRF)",
        "rank": 10,
        "keywords": [
            "ssrf",
            "server side request forgery",
            "internal request",
            "metadata exposure",
            "aws metadata",
            "cloud metadata",
        ],
    },
}
