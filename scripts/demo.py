"""End-to-end demonstration script for Aegis Harness."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

from harness.audit.chain import AuditChain, utc_now_iso
from harness.audit.store import StateStore
from harness.config import RiskTier, init_workspace
from harness.gateway import ModelGateway
from harness.gitops import GateRunner
from harness.policy import PolicyEngine
from harness.telemetry import (
    AegisTelemetryExporter,
    HarnessEvent,
    HarnessEventType,
    MockAegisState,
    create_mock_aegis_app,
)


def main() -> None:
    os.environ.setdefault("OPENAI_API_KEY", "demo-key")
    os.environ.setdefault("AGNES_API_KEY", "demo-agnes-key")
    os.environ.setdefault("AEGIS_TELEMETRY_TOKEN", "aegis_test_token_1234567890abcdef")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _cfg_path, cfg, _ = init_workspace(root=root, project_name="demo-service", asset_code="HARNESS-001")
        audit = AuditChain(root / cfg.audit.log_path, root / cfg.audit.checkpoint_dir)
        store = StateStore(root / cfg.audit.state_db_path)

        # 1. Mock Aegis server
        mock_state = MockAegisState()
        tc = TestClient(create_mock_aegis_app(mock_state))

        def aegis_handler(req: httpx.Request) -> httpx.Response:
            r = tc.request(req.method, req.url.path, headers=dict(req.headers), content=req.content)
            return httpx.Response(r.status_code, json=r.json())

        exporter = AegisTelemetryExporter(
            cfg, store, http_client=httpx.Client(transport=httpx.MockTransport(aegis_handler))
        )

        # 2. Mock model gateway (Agnes AI) with secret redaction
        def model_handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "model": "agnes-coder",
                    "choices": [{"message": {"content": "def ok(): return True"}}],
                    "usage": {"prompt_tokens": 42, "completion_tokens": 12},
                },
            )

        gw = ModelGateway(
            cfg, audit, workspace_root=root, http_client=httpx.Client(transport=httpx.MockTransport(model_handler))
        )
        res = gw.complete(
            prompt="Refactor helper using sk-proj-secret1234567890abcdef",
            model_override="agnes-coder",
            task_id="task-demo",
        )
        print("1. Model Gateway call:", res.record.model, "redacted:", res.record.redacted_categories)

        # 3. Check-in gate catches secret
        (root / "leaked.py").write_text('TOKEN = "ghp_1234567890abcdefghijklmnopqrstuv"\n', encoding="utf-8")
        report = GateRunner(cfg, audit, root).run_all(changed_paths=["leaked.py"], diff_lines=1, run_pytest=False)
        print("2. Gate passed with fake secret?:", report.passed)

        # 4. Second-person approval
        store.create_task(
            task_id="task-demo",
            title="Demo task",
            risk_tier=RiskTier.HIGH.value,
            branch="agent/task-demo",
            requester="alice@example.com",
            active_model="agnes-coder",
            now_iso=utc_now_iso(),
        )
        pol = PolicyEngine(cfg, audit, store)
        pol.record_approval(task_id="task-demo", approver="bob@example.com")
        pol.record_approval(task_id="task-demo", approver="carol@example.com")
        merge_dec = pol.evaluate_merge(
            task_id="task-demo", passed_checks=["secrets", "sast", "deps", "tests", "diff"]
        )
        print("3. High-risk merge decision:", merge_dec.outcome.value)

        # 5. Telemetry to mock Aegis + audit verification
        exporter.emit(
            HarnessEvent(
                event_type=HarnessEventType.MODEL_CALL,
                task_id="task-demo",
                model="agnes-coder",
                details={"input_tokens": 42, "output_tokens": 12, "cost_usd": 0.000135},
            )
        )
        print("4. Mock Aegis OTLP spans received:", len(mock_state.pydantic_spans))
        print("5. Audit chain valid:", audit.verify().valid)


if __name__ == "__main__":
    main()
