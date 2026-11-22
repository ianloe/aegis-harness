"""Prompt-injection detection for repository content, issues, and dependencies."""

from __future__ import annotations

import re
from typing import List, Tuple

from pydantic import BaseModel, Field

from harness.audit.chain import AuditChain
from harness.config.schema import HarnessConfig

INJECTION_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("override_instructions", re.compile(r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b")),
    ("system_prompt_spoof", re.compile(r"(?i)(?:^|\n)\s*(?:system\s*prompt|developer\s*message)\s*:")),
    ("disable_guardrails", re.compile(r"(?i)\b(?:bypass|disable|skip)\s+(?:policy|security|gates|checks|sandbox)\b")),
    ("exfiltration_directive", re.compile(r"(?i)\b(?:exfiltrate|send|upload)\s+(?:secrets?|keys?|tokens?|\.env)\b")),
    ("hidden_html_directive", re.compile(r"(?is)<!--[\s\S]*?(?:ignore|system|execute|override|exfiltrate)[\s\S]*?-->")),
]


class InjectionFinding(BaseModel):
    """Single prompt-injection finding detected in untrusted content."""

    rule: str
    source: str
    excerpt: str


class InjectionScanResult(BaseModel):
    """Outcome of scanning untrusted text or repository content."""

    flagged: bool
    findings: List[InjectionFinding] = Field(default_factory=list)


def scan_for_prompt_injection(
    content: str,
    *,
    source: str = "repository",
    audit: AuditChain | None = None,
    config: HarnessConfig | None = None,
    task_id: str = "no-task",
) -> InjectionScanResult:
    """Detect prompt-injection attempts and log incidents to the audit chain."""
    findings: List[InjectionFinding] = []
    for rule, pattern in INJECTION_PATTERNS:
        match = pattern.search(content)
        if match:
            findings.append(
                InjectionFinding(
                    rule=rule,
                    source=source,
                    excerpt=match.group(0)[:120],
                )
            )

    flagged = len(findings) > 0
    if flagged and audit is not None:
        audit.append(
            event_type="incident",
            actor="agent:harness",
            outcome="blocked",
            task_id=task_id,
            repository=config.project.name if config else "local",
            policy_version=config.policy.version if config else "1.0.0",
            data_classification=config.project.data_classification.value if config else "internal",
            details={
                "violation_type": "PROMPT_INJECTION",
                "source": source,
                "rules": [f.rule for f in findings],
            },
        )
    return InjectionScanResult(flagged=flagged, findings=findings)
