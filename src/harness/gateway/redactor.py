"""Outbound prompt redaction for secrets and PII.

Never logs or returns the redacted secret value itself, only the category.
"""

from __future__ import annotations

import re
from typing import List, Tuple

from pydantic import BaseModel, Field

SECRET_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    (
        "private_key",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.MULTILINE,
        ),
    ),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("aegis_token", re.compile(r"\baegis_[0-9a-fA-F]{16,}\b")),
    ("api_key", re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{16,}\b")),
    (
        "secret_assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|secret|token|password|passwd|client_secret)\s*[:=]\s*['\"]?([A-Za-z0-9_\-./+=]{12,})['\"]?"
        ),
    ),
]

PII_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("nric_fin", re.compile(r"\b[STFGM]\d{7}[A-Z]\b")),
    ("phone", re.compile(r"(?<!\w)(?:\+?\d{1,3}[\s-]?)?(?:\(?\d{3,4}\)?[\s-]?)\d{3,4}[\s-]?\d{4}(?!\w)")),
]


class RedactionResult(BaseModel):
    """Result of scanning and redacting an outbound prompt."""

    redacted_text: str
    categories: List[str] = Field(default_factory=list)
    redaction_count: int = 0


def redact_prompt(
    text: str,
    *,
    redact_secrets: bool = True,
    redact_pii: bool = True,
) -> RedactionResult:
    """Redact secrets and PII from `text`, returning only categories and safe text."""
    result = text
    categories: set[str] = set()
    count = 0

    patterns: List[Tuple[str, re.Pattern[str]]] = []
    if redact_secrets:
        patterns.extend(SECRET_PATTERNS)
    if redact_pii:
        patterns.extend(PII_PATTERNS)

    for category, pattern in patterns:
        if category == "secret_assignment":
            def _replace_assign(match: re.Match[str]) -> str:
                nonlocal count
                count += 1
                categories.add(category)
                return f"{match.group(1)}=[REDACTED:{category.upper()}]"

            result = pattern.sub(_replace_assign, result)
        else:
            matches = pattern.findall(result)
            if matches:
                count += len(matches)
                categories.add(category)
                result = pattern.sub(f"[REDACTED:{category.upper()}]", result)

    return RedactionResult(
        redacted_text=result,
        categories=sorted(categories),
        redaction_count=count,
    )
