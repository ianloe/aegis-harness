"""Tests for Phase 7 local web dashboard, form-based config editor, and reporting."""

from pathlib import Path

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from harness.audit.chain import AuditChain, utc_now_iso
from harness.audit.store import StateStore
from harness.cli import app as cli_app
from harness.config import RiskTier, init_workspace, load_config
from harness.dashboard import create_dashboard_app


def test_dashboard_renders_sessions_approvals_and_feed(tmp_path: Path) -> None:
    cfg_path, cfg, _ = init_workspace(root=tmp_path, project_name="dash-demo", asset_code="AI-004")
    audit = AuditChain(tmp_path / cfg.audit.log_path, tmp_path / cfg.audit.checkpoint_dir)
    store = StateStore(tmp_path / cfg.audit.state_db_path)

    now = utc_now_iso()
    store.create_task(
        task_id="task-med",
        title="Refactor auth service",
        risk_tier="medium",
        branch="agent/task-med",
        requester="alice@example.com",
        active_model="agnes-coder",
        now_iso=now,
    )
    store.create_session(
        session_id="sess-1",
        task_id="task-med",
        actor="human:alice@example.com",
        model="agnes-coder",
        now_iso=now,
    )
    audit.append(
        event_type="model_call",
        actor="agent:harness",
        task_id="task-med",
        model="agnes-coder",
        details={"input_tokens": 200, "output_tokens": 100, "cost_usd": 0.0009},
    )

    client = TestClient(create_dashboard_app(cfg_path))
    resp = client.get("/")
    assert resp.status_code == 200
    assert "dash-demo" in resp.text
    assert "Refactor auth service" in resp.text
    assert "agnes-coder" in resp.text
    assert "sess-1" in resp.text

    # Approve via dashboard form
    app_resp = client.post("/approvals/task-med", data={"approver": "bob@example.com"}, follow_redirects=False)
    assert app_resp.status_code == 303
    assert len(store.list_approvals("task-med")) == 1


def test_config_webapp_uses_forms_with_explanations_and_persists_yaml(tmp_path: Path) -> None:
    cfg_path, _cfg, _ = init_workspace(root=tmp_path, project_name="cfg-ui", asset_code="AI-001")
    client = TestClient(create_dashboard_app(cfg_path))

    get_resp = client.get("/config")
    assert get_resp.status_code == 200
    assert "<form" in get_resp.text
    assert "Repository sensitivity tier" in get_resp.text
    assert "LOW Risk Tier" in get_resp.text
    assert "HIGH Risk Tier" in get_resp.text

    post_resp = client.post(
        "/config",
        data={
            "project_name": "updated-proj",
            "asset_code": "AI-009",
            "data_classification": "confidential",
            "repository_url": "https://github.com/ianloe/aegis-harness.git",
            "aegis_endpoint": "http://localhost:3000",
            "aegis_token_env_var": "AEGIS_TELEMETRY_TOKEN",
            "aegis_batch_size": "50",
            "poll_gate_before_call": "on",
            "default_model": "agnes-coder",
            "allowed_models": "agnes-coder, claude-3-7-sonnet",
            "restricted_allowed_models": "qwen2.5-coder:14b",
            "cost_ceiling_usd_per_task": "10.0",
            "redact_secrets": "on",
            "redact_pii": "on",
            "policy_version": "1.2.0",
            "default_risk_tier": "high",
            "restricted_paths": "infra/**, .env*",
            "allowed_tools": "read_file, pytest",
            "allowed_commands": "pytest, git status",
            "require_signed_commits": "on",
            "tier_low_approvals": "0",
            "tier_low_max_diff": "200",
            "tier_low_checks": "secrets, tests",
            "tier_medium_approvals": "1",
            "tier_medium_distinct": "on",
            "tier_medium_max_diff": "500",
            "tier_medium_checks": "secrets, sast, tests",
            "tier_high_approvals": "2",
            "tier_high_distinct": "on",
            "tier_high_max_diff": "900",
            "tier_high_checks": "secrets, sast, deps, tests, diff",
            "tier_high_gov_office": "on",
            "min_test_coverage_pct": "85.0",
            "sandbox_mode": "docker",
            "sandbox_timeout": "240",
        },
        follow_redirects=False,
    )
    assert post_resp.status_code == 303
    assert "saved=1" in post_resp.headers["location"]

    reloaded = load_config(cfg_path)
    assert reloaded.project.name == "updated-proj"
    assert reloaded.project.asset_code == "AI-009"
    assert reloaded.project.local_git_only is False
    assert reloaded.gateway.default_model == "agnes-coder"
    assert reloaded.policy.default_risk_tier == RiskTier.HIGH
    assert reloaded.policy.risk_tiers[RiskTier.HIGH].max_diff_lines == 900
    assert reloaded.sandbox.mode == "docker"
    assert reloaded.git.min_test_coverage_pct == 85.0


def test_cli_report_outputs_metrics(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    assert runner.invoke(cli_app, ["init", "--name", "rep-demo"]).exit_code == 0
    res = runner.invoke(cli_app, ["report"])
    assert res.exit_code == 0
    assert "Governance Report" in res.stdout
    assert "VERIFIED" in res.stdout


def test_user_manual_page_renders_guides(tmp_path: Path) -> None:
    cfg_path, _cfg, _ = init_workspace(root=tmp_path, project_name="manual-demo", asset_code="AI-001")
    client = TestClient(create_dashboard_app(cfg_path))
    resp = client.get("/manual")
    assert resp.status_code == 200
    assert "Aegis Harness User Manual" in resp.text
    assert "Agnes AI" in resp.text
    assert "CLI Command Reference" in resp.text
    assert "/assets/logo.png" in resp.text
    assert "id=\"theme-toggle\"" in resp.text
    assert "data-theme" in resp.text

    logo_resp = client.get("/assets/logo.png")
    assert logo_resp.status_code == 200
    assert logo_resp.headers["content-type"] == "image/png"
