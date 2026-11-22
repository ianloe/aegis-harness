"""Tests for the Policy Engine, risk tiers, sample policy profiles, and second-person approval."""

from pathlib import Path

import yaml

from harness.audit.chain import AuditChain, utc_now_iso
from harness.audit.store import StateStore
from harness.config import PolicyConfig, RiskTier, default_config
from harness.policy import PolicyEngine, PolicyOutcome


def test_sample_policy_files_validate_against_schema() -> None:
    policies_dir = Path(__file__).resolve().parent.parent / "policies"
    files = sorted(policies_dir.glob("*.yaml"))
    assert len(files) == 3
    for path in files:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        parsed = PolicyConfig.model_validate(raw)
        assert parsed.version


def test_model_tool_and_command_policies_logged(tmp_path: Path) -> None:
    cfg = default_config("pol-demo", "AI-001")
    audit = AuditChain(tmp_path / "audit.jsonl")
    engine = PolicyEngine(cfg, audit)

    d_model_ok = engine.evaluate_model("claude-4-sonnet", task_id="t1")
    d_model_bad = engine.evaluate_model("unapproved-model", task_id="t1")
    d_tool_bad = engine.evaluate_tool("curl_exfiltrate", task_id="t1")
    d_cmd_ok = engine.evaluate_command("pytest -v", task_id="t1")
    d_cmd_bad = engine.evaluate_command("rm -rf /", task_id="t1")

    assert d_model_ok.outcome == PolicyOutcome.ALLOW
    assert d_model_bad.outcome == PolicyOutcome.DENY
    assert d_tool_bad.outcome == PolicyOutcome.DENY
    assert d_cmd_ok.outcome == PolicyOutcome.ALLOW
    assert d_cmd_bad.outcome == PolicyOutcome.DENY

    entries = audit.read_all()
    assert len(entries) == 5
    assert all(e.policy_version == cfg.policy.version for e in entries)
    assert entries[1].details["reason"]


def test_restricted_paths_and_diff_size_require_approval(tmp_path: Path) -> None:
    cfg = default_config("path-demo", "AI-001")
    audit = AuditChain(tmp_path / "audit.jsonl")
    engine = PolicyEngine(cfg, audit)

    d_path = engine.evaluate_paths_and_diff(
        ["src/app.py", ".github/workflows/deploy.yml"],
        diff_lines=50,
        risk_tier=RiskTier.LOW,
    )
    assert d_path.outcome == PolicyOutcome.REQUIRE_APPROVAL
    assert d_path.rule_id == "paths.restricted"

    d_diff = engine.evaluate_paths_and_diff(
        ["src/app.py"],
        diff_lines=300,
        risk_tier=RiskTier.LOW,
    )
    assert d_diff.outcome == PolicyOutcome.REQUIRE_APPROVAL
    assert d_diff.rule_id == "diff.max_lines"


def test_high_risk_merge_requires_distinct_second_person_approvals(tmp_path: Path) -> None:
    cfg = default_config("merge-demo", "AI-001")
    audit = AuditChain(tmp_path / "audit.jsonl")
    store = StateStore(tmp_path / "state.db")
    engine = PolicyEngine(cfg, audit, store)

    store.create_task(
        task_id="task-hi",
        title="Modify payment settlement",
        risk_tier="high",
        branch="agent/task-hi",
        requester="alice@example.com",
        active_model="claude-4-sonnet",
        now_iso=utc_now_iso(),
    )

    # Self-approval must be denied
    self_dec = engine.record_approval(task_id="task-hi", approver="alice@example.com")
    assert self_dec.outcome == PolicyOutcome.DENY

    # Cannot merge yet
    m0 = engine.evaluate_merge(task_id="task-hi", passed_checks=["secrets", "sast", "deps", "tests", "diff"])
    assert m0.outcome == PolicyOutcome.REQUIRE_APPROVAL

    # First distinct approval (high tier requires 2)
    a1 = engine.record_approval(task_id="task-hi", approver="bob@example.com")
    assert a1.outcome == PolicyOutcome.ALLOW
    m1 = engine.evaluate_merge(task_id="task-hi", passed_checks=["secrets", "sast", "deps", "tests", "diff"])
    assert m1.outcome == PolicyOutcome.REQUIRE_APPROVAL

    # Second distinct approval
    a2 = engine.record_approval(task_id="task-hi", approver="carol@example.com")
    assert a2.outcome == PolicyOutcome.ALLOW
    m2 = engine.evaluate_merge(task_id="task-hi", passed_checks=["secrets", "sast", "deps", "tests", "diff"])
    assert m2.outcome == PolicyOutcome.ALLOW
