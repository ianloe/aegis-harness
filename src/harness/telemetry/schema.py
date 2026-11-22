"""Pydantic v2 telemetry schemas aligned with Aegis ingestion contracts."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

import yaml
from pydantic import BaseModel, Field


class HarnessEventType(str, Enum):
    """Canonical Harness governance and engineering telemetry event types."""

    SESSION_START = "session_start"
    MODEL_CALL = "model_call"
    POLICY_DECISION = "policy_decision"
    TOOL_USE = "tool_use"
    FILE_CHANGE = "file_change"
    CHECK_PASS = "check_pass"
    CHECK_FAIL = "check_fail"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVAL_GRANTED = "approval_granted"
    COMMIT = "commit"
    PR_OPENED = "pr_opened"
    PR_MERGED = "pr_merged"
    OVERRIDE = "override"
    KILL_SWITCH = "kill_switch"
    INCIDENT = "incident"


class HarnessEvent(BaseModel):
    """Internal Pydantic + OpenTelemetry event emitted by Harness."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    session_id: str = "no-session"
    task_id: str = "no-task"
    actor: str = "agent:harness"
    event_type: HarnessEventType
    repository: str = "local"
    branch: str = "main"
    model: Optional[str] = None
    risk_tier: str = "medium"
    policy_version: str = "1.0.0"
    data_classification: str = "internal"
    outcome: str = "success"
    prev_hash: str = "0" * 64
    frame_controls: List[str] = Field(default_factory=list)
    aaef_dimensions: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)


class ControlMappingEntry(BaseModel):
    """Mapping entry from a Harness event type to FRAME and AAEF IDs."""

    frame_controls: List[str] = Field(default_factory=list)
    aaef_dimensions: List[str] = Field(default_factory=list)


def load_control_mapping(path: Optional[Path] = None) -> Dict[str, ControlMappingEntry]:
    """Load the editable FRAME/AAEF control mapping YAML."""
    target = path or (Path(__file__).resolve().parents[3] / "config" / "frame_aaef_mapping.yaml")
    if not target.exists():
        return {}
    raw = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    return {k: ControlMappingEntry.model_validate(v) for k, v in raw.items()}


# --- Exact Aegis Ingestion Contracts ---


class AegisBoundaryBreachPayload(BaseModel):
    """Matches Aegis POST /api/telemetry/ingest BOUNDARY_BREACH schema."""

    eventType: Literal["BOUNDARY_BREACH"] = "BOUNDARY_BREACH"
    assetCode: str = Field(min_length=1)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    description: str = Field(min_length=4)
    remediation: Optional[str] = None
    occurredAt: Optional[str] = None


class AegisRoiMetricPayload(BaseModel):
    """Matches Aegis POST /api/telemetry/ingest ROI_METRIC schema."""

    eventType: Literal["ROI_METRIC"] = "ROI_METRIC"
    assetCode: str = Field(min_length=1)
    metricType: Literal["COST", "BENEFIT"]
    category: str = Field(min_length=1)
    description: str = Field(min_length=2)
    amount: float = Field(ge=0)
    currency: Literal["SGD", "USD"] = "USD"
    quarter: str = Field(min_length=4)


class AegisGuardrailEventPayload(BaseModel):
    """Matches Aegis POST /api/telemetry/ingest GUARDRAIL_EVENT schema."""

    eventType: Literal["GUARDRAIL_EVENT"] = "GUARDRAIL_EVENT"
    assetCode: str = Field(min_length=1)
    gateway: str = Field(default="Aegis Harness", min_length=1)
    violationType: Literal[
        "PROMPT_INJECTION",
        "PII_LEAK",
        "TOXICITY",
        "DATA_EXFILTRATION",
        "OTHER",
    ] = "OTHER"
    blocked: bool = True
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "MEDIUM"
    description: str = Field(min_length=4)


class AegisMcpA2aPayload(BaseModel):
    """Matches Aegis POST /api/telemetry/mcp-a2a schema."""

    protocol: Literal["MCP", "A2A"] = "MCP"
    assetCode: str = Field(min_length=1)
    targetName: str = Field(min_length=1)
    operation: str = Field(min_length=1)
    hopDepth: int = Field(default=1, ge=1)
    traceId: Optional[str] = None
    durationMs: Optional[int] = Field(default=None, ge=0)
