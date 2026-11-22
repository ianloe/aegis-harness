"""Tests for Pydantic configuration schema and YAML loader."""

from pathlib import Path

from harness.config import (
    HarnessConfig,
    RiskTier,
    default_config,
    init_workspace,
    load_config,
    save_config,
)


def test_default_config_has_three_risk_tiers() -> None:
    cfg = default_config("demo-repo", "AI-001")
    assert set(cfg.policy.risk_tiers.keys()) == {RiskTier.LOW, RiskTier.MEDIUM, RiskTier.HIGH}
    assert cfg.policy.risk_tiers[RiskTier.LOW].required_approvals == 0
    assert cfg.policy.risk_tiers[RiskTier.MEDIUM].required_approvals == 1
    assert cfg.policy.risk_tiers[RiskTier.HIGH].required_approvals == 2


def test_all_root_config_sections_have_descriptions() -> None:
    for name, field_info in HarnessConfig.model_fields.items():
        assert field_info.description, f"Config section {name} is missing a description"


def test_save_and_load_roundtrip(tmp_path: Path) -> None:
    cfg = default_config("roundtrip-app", "AI-009")
    cfg.gateway.cost_ceiling_usd_per_task = 12.5
    out_path = save_config(cfg, tmp_path / ".harness" / "config.yaml")

    loaded = load_config(out_path)
    assert loaded.project.name == "roundtrip-app"
    assert loaded.project.asset_code == "AI-009"
    assert loaded.gateway.cost_ceiling_usd_per_task == 12.5


def test_init_workspace_creates_config_and_local_git(tmp_path: Path) -> None:
    cfg_path, cfg, git_created = init_workspace(root=tmp_path, project_name="local-proj")
    assert cfg_path.exists()
    assert git_created is True
    assert (tmp_path / ".git").exists()
    assert cfg.project.local_git_only is True
