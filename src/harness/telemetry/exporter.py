"""Telemetry exporter interface and Aegis adapter with offline SQLite queue and retry."""

from __future__ import annotations

import json
import os
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import httpx
from opentelemetry import trace

from harness.audit.chain import utc_now_iso
from harness.audit.store import StateStore
from harness.config.schema import HarnessConfig
from harness.telemetry.schema import (
    AegisBoundaryBreachPayload,
    AegisGuardrailEventPayload,
    AegisMcpA2aPayload,
    AegisRoiMetricPayload,
    ControlMappingEntry,
    HarnessEvent,
    HarnessEventType,
    load_control_mapping,
)

tracer = trace.get_tracer("aegis.harness")


def current_quarter(dt: Optional[datetime] = None) -> str:
    """Return quarter string such as '2026-Q4'."""
    now = dt or datetime.now(timezone.utc)
    q = (now.month - 1) // 3 + 1
    return f"{now.year}-Q{q}"


def build_otlp_payload(event: HarnessEvent, asset_code: str) -> Dict[str, Any]:
    """Convert a HarnessEvent into an OTLP JSON `resourceSpans` payload for Aegis `/api/telemetry/pydantic`."""
    now_ns = int(datetime.now(timezone.utc).timestamp() * 1_000_000_000)
    latency_ms = int(event.details.get("latency_ms", 0) or 0)
    end_ns = now_ns + (latency_ms * 1_000_000)

    attrs: List[Dict[str, Any]] = [
        {"key": "aegis.asset_code", "value": {"stringValue": asset_code}},
        {"key": "aegis.currency", "value": {"stringValue": "USD"}},
        {"key": "aegis.quarter", "value": {"stringValue": current_quarter()}},
        {"key": "harness.event_id", "value": {"stringValue": event.event_id}},
        {"key": "harness.event_type", "value": {"stringValue": event.event_type.value}},
        {"key": "harness.session_id", "value": {"stringValue": event.session_id}},
        {"key": "harness.task_id", "value": {"stringValue": event.task_id}},
        {"key": "harness.actor", "value": {"stringValue": event.actor}},
        {"key": "harness.repository", "value": {"stringValue": event.repository}},
        {"key": "harness.branch", "value": {"stringValue": event.branch}},
        {"key": "harness.risk_tier", "value": {"stringValue": event.risk_tier}},
        {"key": "harness.policy_version", "value": {"stringValue": event.policy_version}},
        {"key": "harness.data_classification", "value": {"stringValue": event.data_classification}},
        {"key": "harness.prev_hash", "value": {"stringValue": event.prev_hash}},
        {"key": "harness.outcome", "value": {"stringValue": event.outcome}},
    ]
    if event.model:
        attrs.append({"key": "gen_ai.request.model", "value": {"stringValue": event.model}})
    if "input_tokens" in event.details:
        attrs.append({"key": "gen_ai.usage.input_tokens", "value": {"intValue": int(event.details["input_tokens"])}})
    if "output_tokens" in event.details:
        attrs.append({"key": "gen_ai.usage.output_tokens", "value": {"intValue": int(event.details["output_tokens"])}})
    if "cost_usd" in event.details:
        attrs.append({"key": "aegis.cost", "value": {"doubleValue": float(event.details["cost_usd"])}})

    status_code = "ERROR" if event.outcome in ("deny", "fail", "halted", "breach") else "OK"
    span: Dict[str, Any] = {
        "traceId": event.event_id.replace("-", "")[:32],
        "spanId": event.event_id.replace("-", "")[:16],
        "name": f"harness.{event.event_type.value}",
        "startTimeUnixNano": str(now_ns),
        "endTimeUnixNano": str(end_ns),
        "attributes": attrs,
        "status": {"code": status_code},
    }
    if status_code == "ERROR":
        span["attributes"].append(
            {
                "key": "exception.message",
                "value": {"stringValue": str(event.details.get("reason") or event.outcome)},
            }
        )

    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "aegis-harness"}},
                        {"key": "aegis.asset_code", "value": {"stringValue": asset_code}},
                    ]
                },
                "scopeSpans": [{"spans": [span]}],
            }
        ]
    }


class TelemetryExporter(ABC):
    """Abstract interface for exporting Harness governance events."""

    @abstractmethod
    def emit(self, event: HarnessEvent) -> None:
        """Queue and attempt to export a single HarnessEvent."""

    @abstractmethod
    def flush(self) -> int:
        """Flush queued events and return count of newly delivered items."""


class AegisTelemetryExporter(TelemetryExporter):
    """Exports Harness events to Aegis endpoints with offline SQLite queue and backoff retry."""

    def __init__(
        self,
        config: HarnessConfig,
        store: StateStore,
        *,
        http_client: Optional[httpx.Client] = None,
        mapping_path: Optional[Path] = None,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        self.config = config
        self.store = store
        self._client = http_client or httpx.Client(timeout=config.aegis.timeout_seconds)
        self._sleep = sleep_fn
        self.control_mapping: Dict[str, ControlMappingEntry] = load_control_mapping(mapping_path)

    def _enrich_controls(self, event: HarnessEvent) -> HarnessEvent:
        mapping = self.control_mapping.get(event.event_type.value)
        if mapping:
            if not event.frame_controls:
                event.frame_controls = list(mapping.frame_controls)
            if not event.aaef_dimensions:
                event.aaef_dimensions = list(mapping.aaef_dimensions)
        return event

    def map_to_aegis_request(self, event: HarnessEvent) -> Tuple[str, Dict[str, Any]]:
        """Map a HarnessEvent to the closest Aegis endpoint and validated payload."""
        asset_code = self.config.project.asset_code

        if event.event_type == HarnessEventType.KILL_SWITCH:
            payload = AegisBoundaryBreachPayload(
                assetCode=asset_code,
                severity="CRITICAL",
                description=f"Harness kill switch triggered: {event.details.get('reason', 'Operator halt')}",
                remediation="All active agent sessions halted and task credentials revoked.",
                occurredAt=event.timestamp,
            )
            return "/api/telemetry/ingest", payload.model_dump(exclude_none=True)

        if event.event_type == HarnessEventType.INCIDENT:
            violation = str(event.details.get("violation_type", "PROMPT_INJECTION"))
            if violation not in ("PROMPT_INJECTION", "PII_LEAK", "TOXICITY", "DATA_EXFILTRATION", "OTHER"):
                violation = "OTHER"
            payload = AegisGuardrailEventPayload(
                assetCode=asset_code,
                gateway="Aegis Harness",
                violationType=violation,  # type: ignore[arg-type]
                blocked=bool(event.details.get("blocked", True)),
                severity=str(event.details.get("severity", "HIGH")).upper(),  # type: ignore[arg-type]
                description=str(event.details.get("description", "Security incident flagged by Harness")),
            )
            return "/api/telemetry/ingest", payload.model_dump(exclude_none=True)

        if event.event_type == HarnessEventType.CHECK_FAIL:
            payload = AegisGuardrailEventPayload(
                assetCode=asset_code,
                gateway="Aegis Harness Check-in Gate",
                violationType="DATA_EXFILTRATION" if "secrets" in str(event.details) else "OTHER",
                blocked=True,
                severity="HIGH",
                description=f"Check gate failed on task {event.task_id}: {event.details.get('summary', event.outcome)}",
            )
            return "/api/telemetry/ingest", payload.model_dump(exclude_none=True)

        if event.event_type == HarnessEventType.TOOL_USE:
            payload = AegisMcpA2aPayload(
                protocol="MCP",
                assetCode=asset_code,
                targetName=str(event.details.get("tool", "harness-sandbox")),
                operation=str(event.details.get("operation", "execute")),
                traceId=event.event_id,
                durationMs=event.details.get("duration_ms"),
            )
            return "/api/telemetry/mcp-a2a", payload.model_dump(exclude_none=True)

        if event.event_type == HarnessEventType.MODEL_CALL and float(event.details.get("cost_usd", 0) or 0) > 0:
            # Primary OTLP payload carries full model, token, cost, and governance attributes
            return "/api/telemetry/pydantic", build_otlp_payload(event, asset_code)

        if event.event_type == HarnessEventType.PR_MERGED and "cost_saved_usd" in event.details:
            payload = AegisRoiMetricPayload(
                assetCode=asset_code,
                metricType="BENEFIT",
                category="PRODUCTIVITY_HOURS",
                description=f"PR merged for task {event.task_id}",
                amount=float(event.details["cost_saved_usd"]),
                currency="USD",
                quarter=current_quarter(),
            )
            return "/api/telemetry/ingest", payload.model_dump(exclude_none=True)

        # Default: export as OpenTelemetry OTLP span to Aegis /api/telemetry/pydantic
        return "/api/telemetry/pydantic", build_otlp_payload(event, asset_code)

    def emit(self, event: HarnessEvent) -> None:
        """Record an OpenTelemetry span, enqueue idempotently, and attempt delivery."""
        enriched = self._enrich_controls(event)
        with tracer.start_as_current_span(f"harness.{enriched.event_type.value}") as span:
            span.set_attribute("harness.event_id", enriched.event_id)
            span.set_attribute("harness.task_id", enriched.task_id)
            span.set_attribute("harness.risk_tier", enriched.risk_tier)
            endpoint, payload = self.map_to_aegis_request(enriched)
            self.store.enqueue_telemetry(
                event_id=enriched.event_id,
                endpoint=endpoint,
                payload_json=json.dumps(payload),
                created_at=enriched.timestamp,
            )
        self.flush()

    def _send_one(self, event_id: str, endpoint: str, payload_json: str) -> None:
        token = os.environ.get(self.config.aegis.token_env_var, "")
        url = self.config.aegis.endpoint.rstrip("/") + endpoint
        headers = {
            "Content-Type": "application/json",
            "X-Idempotency-Key": event_id,
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"

        resp = self._client.post(url, headers=headers, content=payload_json)
        if resp.status_code >= 400:
            raise RuntimeError(f"Aegis returned {resp.status_code}: {resp.text[:200]}")

    def flush(self) -> int:
        """Deliver pending queued events in batches with exponential backoff."""
        delivered = 0
        pending = self.store.pending_telemetry(limit=self.config.aegis.batch_size)
        for item in pending:
            event_id = item["event_id"]
            last_err = ""
            sent = False
            max_attempts = max(1, self.config.aegis.max_retries)
            for attempt in range(max_attempts):
                try:
                    self._send_one(event_id, item["endpoint"], item["payload_json"])
                    self.store.mark_telemetry_delivered(event_id, utc_now_iso())
                    delivered += 1
                    sent = True
                    break
                except Exception as exc:
                    last_err = str(exc)
                    if attempt + 1 < max_attempts:
                        self._sleep(min(2.0**attempt * 0.05, 1.0))
            if not sent:
                self.store.mark_telemetry_failed(event_id, last_err)
        return delivered
