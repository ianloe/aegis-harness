"""Tests for Phase 5 Pydantic/OTLP telemetry, offline queue, metrics, and mock Aegis server."""

from pathlib import Path

import httpx
from fastapi.testclient import TestClient

from harness.audit.chain import AuditEntry
from harness.audit.store import StateStore
from harness.config import default_config
from harness.telemetry import (
    AegisTelemetryExporter,
    HarnessEvent,
    HarnessEventType,
    MockAegisState,
    compute_metrics,
    create_mock_aegis_app,
    load_control_mapping,
)


def test_control_mapping_covers_all_event_types() -> None:
    mapping = load_control_mapping()
    for ev_type in HarnessEventType:
        assert ev_type.value in mapping, f"Missing FRAME/AAEF mapping for {ev_type.value}"
        assert len(mapping[ev_type.value].frame_controls) >= 1
        assert len(mapping[ev_type.value].aaef_dimensions) >= 1


def _asgi_sync_client(app) -> httpx.Client:
    tc = TestClient(app)

    def handler(request: httpx.Request) -> httpx.Response:
        resp = tc.request(
            request.method,
            request.url.path,
            headers=dict(request.headers),
            content=request.content,
        )
        return httpx.Response(resp.status_code, json=resp.json())

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_events_validate_against_mock_aegis_server(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AEGIS_TELEMETRY_TOKEN", "aegis_test_token_1234567890abcdef")
    mock_state = MockAegisState()
    app = create_mock_aegis_app(mock_state)
    client = _asgi_sync_client(app)

    cfg = default_config("tel-demo", "HARNESS-001")
    cfg.aegis.endpoint = "http://mock-aegis.local"
    store = StateStore(tmp_path / "state.db")
    exporter = AegisTelemetryExporter(cfg, store, http_client=client, sleep_fn=lambda _: None)

    exporter.emit(HarnessEvent(event_type=HarnessEventType.SESSION_START, task_id="t1"))
    exporter.emit(
        HarnessEvent(
            event_type=HarnessEventType.MODEL_CALL,
            task_id="t1",
            model="agnes-coder",
            details={"input_tokens": 100, "output_tokens": 50, "cost_usd": 0.00045, "latency_ms": 120},
        )
    )
    exporter.emit(
        HarnessEvent(
            event_type=HarnessEventType.TOOL_USE,
            task_id="t1",
            details={"tool": "pytest", "operation": "run"},
        )
    )
    exporter.emit(
        HarnessEvent(
            event_type=HarnessEventType.INCIDENT,
            task_id="t1",
            outcome="breach",
            details={"violation_type": "PROMPT_INJECTION", "severity": "HIGH", "description": "Prompt injection flagged"},
        )
    )
    exporter.emit(
        HarnessEvent(
            event_type=HarnessEventType.KILL_SWITCH,
            task_id="t1",
            outcome="halted",
            details={"reason": "Operator halt test"},
        )
    )

    counts = store.telemetry_queue_counts()
    assert counts.get("delivered") == 5
    assert len(mock_state.pydantic_spans) == 2
    assert len(mock_state.mcp_a2a_events) == 1
    assert len(mock_state.ingested_events) == 2
    assert mock_state.registered_assets["HARNESS-001"] == "SUSPENDED"


def test_offline_queue_delivers_after_reconnection_without_loss_or_duplication(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("AEGIS_TELEMETRY_TOKEN", "aegis_test_token_1234567890abcdef")
    mock_state = MockAegisState()
    app = create_mock_aegis_app(mock_state)
    online_client = _asgi_sync_client(app)

    def offline_handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Aegis unreachable")

    offline_client = httpx.Client(transport=httpx.MockTransport(offline_handler))

    cfg = default_config("offline-demo", "HARNESS-001")
    cfg.aegis.endpoint = "http://mock-aegis.local"
    cfg.aegis.max_retries = 1
    store = StateStore(tmp_path / "state.db")

    # Emit 2 events while Aegis is unreachable
    exporter_offline = AegisTelemetryExporter(
        cfg, store, http_client=offline_client, sleep_fn=lambda _: None
    )
    ev1 = HarnessEvent(event_type=HarnessEventType.SESSION_START, task_id="t-off")
    ev2 = HarnessEvent(
        event_type=HarnessEventType.CHECK_FAIL,
        task_id="t-off",
        outcome="fail",
        details={"summary": "secrets found"},
    )
    exporter_offline.emit(ev1)
    exporter_offline.emit(ev2)

    assert store.telemetry_queue_counts().get("pending") == 2
    assert len(mock_state.pydantic_spans) == 0
    assert len(mock_state.ingested_events) == 0

    # Reconnect and flush
    exporter_online = AegisTelemetryExporter(
        cfg, store, http_client=online_client, sleep_fn=lambda _: None
    )
    delivered = exporter_online.flush()
    assert delivered == 2
    assert store.telemetry_queue_counts().get("delivered") == 2
    assert len(mock_state.pydantic_spans) == 1
    assert len(mock_state.ingested_events) == 1

    # Second flush must not duplicate
    assert exporter_online.flush() == 0
    assert len(mock_state.pydantic_spans) == 1


def test_compute_governance_metrics() -> None:
    entries = [
        AuditEntry(event_type="session_start", actor="human:alice", task_id="t1", timestamp="2026-11-22T10:00:00+00:00"),
        AuditEntry(
            event_type="model_call",
            actor="agent:harness",
            task_id="t1",
            details={"input_tokens": 500, "output_tokens": 200, "cost_usd": 0.05},
        ),
        AuditEntry(event_type="check_suite", actor="agent:harness", task_id="t1", outcome="fail"),
        AuditEntry(event_type="check_suite", actor="agent:harness", task_id="t1", outcome="pass"),
        AuditEntry(event_type="policy_decision", actor="agent:harness", task_id="t1", outcome="deny", details={"rule_id": "tool.allowlist"}),
        AuditEntry(event_type="approval_granted", actor="human:bob", task_id="t1"),
        AuditEntry(event_type="commit", actor="agent:harness", task_id="t1", details={"ai_lines": 80, "total_lines": 100}),
        AuditEntry(event_type="pr_merged", actor="human:bob", task_id="t1", timestamp="2026-11-22T10:05:00+00:00"),
    ]
    m = compute_metrics(entries)
    assert m.total_tasks == 1
    assert m.total_cost_usd == 0.05
    assert m.total_tokens == 700
    assert m.check_failure_rate == 0.5
    assert m.avg_time_to_merge_seconds == 300.0
    assert m.ai_authored_lines_pct == 80.0
    assert m.policy_denials_by_type == {"tool.allowlist": 1}
