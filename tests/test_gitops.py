"""Tests for Phase 4 Git integration, check-in gates, provenance trailers, and PR summaries."""

import subprocess
from pathlib import Path

import pytest

from harness.audit.chain import AuditChain
from harness.config import RiskTier, default_config
from harness.gitops import GateRunner, GitGovernanceError, GitWorkflow


def _init_repo(root: Path) -> None:
    subprocess.run(["git", "init", "-b", "main"], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "dev@example.com"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Dev User"], cwd=root, check=True)
    (root / "README.md").write_text("# Demo\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-m", "initial"], cwd=root, check=True, capture_output=True)


def test_secret_gate_blocks_fake_api_key_and_logs_audit(tmp_path: Path) -> None:
    cfg = default_config("sec-demo", "AI-001")
    audit = AuditChain(tmp_path / "audit.jsonl")
    (tmp_path / "app.py").write_text('API_KEY = "sk-proj-1234567890abcdefghijklmnop"\n', encoding="utf-8")

    runner = GateRunner(cfg, audit, tmp_path)
    report = runner.run_all(changed_paths=["app.py"], diff_lines=1, risk_tier=RiskTier.LOW, run_pytest=False)

    assert report.passed is False
    secrets_res = next(r for r in report.results if r.name == "secrets")
    assert secrets_res.passed is False
    entries = audit.read_all()
    assert any(e.event_type == "check_suite" and e.outcome == "fail" for e in entries)


def test_sast_deps_and_coverage_gates(tmp_path: Path) -> None:
    cfg = default_config("sast-demo", "AI-001")
    audit = AuditChain(tmp_path / "audit.jsonl")
    (tmp_path / "bad.py").write_text("eval('1+1')\n", encoding="utf-8")

    runner = GateRunner(cfg, audit, tmp_path)
    sast = runner.check_sast(["bad.py"])
    assert sast.passed is False

    deps = runner.check_deps_and_licences({"some-gpl-pkg": "GPL-3.0"})
    assert deps.passed is False

    cov = runner.check_tests(run_pytest=False, observed_coverage_pct=55.0)
    assert cov.passed is False


def test_branch_workflow_blocks_main_and_writes_provenance_trailers(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    cfg = default_config("git-demo", "AI-001")
    cfg.policy.require_signed_commits = False
    audit = AuditChain(tmp_path / "audit.jsonl")
    wf = GitWorkflow(cfg, audit, tmp_path)
    runner = GateRunner(cfg, audit, tmp_path)

    (tmp_path / "feature.py").write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")
    report = runner.run_all(changed_paths=["feature.py"], diff_lines=2, risk_tier=RiskTier.LOW, run_pytest=False)
    assert report.passed is True

    # Direct commit on main must be blocked
    with pytest.raises(GitGovernanceError, match="main"):
        wf.commit(
            message="Direct write",
            task_id="task-123",
            model="agnes-coder",
            provider="agnes",
            gate_report=report,
        )

    # Switch to agent/task-123 and commit
    branch = wf.ensure_task_branch("task-123")
    assert branch == "agent/task-123"
    sha = wf.commit(
        message="Add pure add helper",
        task_id="task-123",
        model="agnes-coder",
        provider="agnes",
        approver="bob@example.com",
        gate_report=report,
    )
    assert len(sha) == 40

    log_msg = subprocess.run(
        ["git", "log", "-1", "--pretty=%B"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert "Harness-Model: agnes-coder" in log_msg
    assert "Harness-Provider: agnes" in log_msg
    assert "Harness-Task-ID: task-123" in log_msg
    assert "Harness-Policy-Version: 1.0.0" in log_msg
    assert "Harness-Approver: bob@example.com" in log_msg

    pr_md = wf.generate_pr_summary(
        task_id="task-123",
        title="Add pure add helper",
        why="Needed for arithmetic module",
        model="agnes-coder",
        risk_tier="low",
        changed_files=["feature.py"],
        gate_report=report,
    )
    assert "Harness" not in ""  # sanity
    assert "agnes-coder" in pr_md
    assert "PASS" in pr_md

    hooks = wf.install_git_hooks()
    assert len(hooks) == 2
    assert all(h.exists() for h in hooks)
