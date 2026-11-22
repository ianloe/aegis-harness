"""CLI smoke tests for Phase 1 commands."""

from pathlib import Path

from typer.testing import CliRunner

from harness.cli import app

runner = CliRunner()


def test_cli_init_task_model_audit_killswitch(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    res_init = runner.invoke(app, ["init", "--name", "cli-demo", "--asset-code", "AI-004"])
    assert res_init.exit_code == 0
    assert "Initialised Harness" in res_init.stdout

    res_task = runner.invoke(app, ["task", "start", "Implement auth middleware", "--risk", "high"])
    assert res_task.exit_code == 0
    assert "risk: high" in res_task.stdout

    res_models = runner.invoke(app, ["model", "list"])
    assert res_models.exit_code == 0
    assert "claude-4-sonnet" in res_models.stdout
    assert "gemini-4-hydrogen" in res_models.stdout

    res_verify = runner.invoke(app, ["audit", "verify"])
    assert res_verify.exit_code == 0
    assert "Audit log verified." in res_verify.stdout

    res_cp = runner.invoke(app, ["audit", "checkpoint"])
    assert res_cp.exit_code == 0
    assert "Checkpoint created" in res_cp.stdout

    res_ks = runner.invoke(app, ["killswitch", "--reason", "Test halt"])
    assert res_ks.exit_code == 0
    assert "Kill switch activated." in res_ks.stdout
