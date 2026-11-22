"""Command-line interface for Aegis Harness."""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from harness.audit.chain import AuditChain, utc_now_iso
from harness.audit.store import StateStore
from harness.config.loader import find_config_path, init_workspace, load_config
from harness.config.schema import RiskTier
from harness.gitops import GateRunner, GitGovernanceError, GitWorkflow
from harness.policy import PolicyEngine, PolicyOutcome
from harness.sandbox import SandboxManager

app = typer.Typer(
    name="harness",
    help="Security-first and governance-first wrapper for AI-assisted coding.",
    no_args_is_help=True,
)
task_app = typer.Typer(help="Manage governed coding tasks.")
model_app = typer.Typer(help="Inspect and switch coding models.")
audit_app = typer.Typer(help="Verify and checkpoint the tamper-evident audit log.")

app.add_typer(task_app, name="task")
app.add_typer(model_app, name="model")
app.add_typer(audit_app, name="audit")

console = Console()


def _resolve_root(config_path: Path) -> Path:
    # config_path is <root>/.harness/config.yaml
    if config_path.parent.name == ".harness":
        return config_path.parent.parent
    return config_path.parent


def _open_audit_and_store(config_path: Optional[Path] = None):
    cfg_path = config_path or find_config_path()
    cfg = load_config(cfg_path)
    root = _resolve_root(cfg_path)
    audit = AuditChain(root / cfg.audit.log_path, root / cfg.audit.checkpoint_dir)
    store = StateStore(root / cfg.audit.state_db_path)
    return cfg, root, audit, store


@app.command("init")
def cmd_init(
    project_name: Optional[str] = typer.Option(None, "--name", "-n", help="Project name."),
    asset_code: str = typer.Option("HARNESS-001", "--asset-code", help="Aegis AI Asset code."),
    repository_url: Optional[str] = typer.Option(None, "--remote", help="Optional GitHub remote URL."),
    force: bool = typer.Option(False, "--force", help="Overwrite existing .harness/config.yaml."),
) -> None:
    """Initialise Harness configuration, local SQLite state, audit chain, and local Git."""
    cfg_path, cfg, git_created = init_workspace(
        root=Path.cwd(),
        project_name=project_name,
        asset_code=asset_code,
        repository_url=repository_url,
        overwrite=force,
    )
    root = _resolve_root(cfg_path)
    audit = AuditChain(root / cfg.audit.log_path, root / cfg.audit.checkpoint_dir)
    StateStore(root / cfg.audit.state_db_path)
    entry = audit.append(
        event_type="harness_init",
        actor="human:cli",
        repository=cfg.project.name,
        branch=cfg.git.base_branch,
        policy_version=cfg.policy.version,
        data_classification=cfg.project.data_classification.value,
        details={"asset_code": cfg.project.asset_code, "git_initialised": git_created},
    )
    console.print(f"[green]Initialised Harness[/green] at {cfg_path}")
    console.print(f"Local Git initialised: {git_created} | Audit head: {entry.entry_hash[:12]}")


@task_app.command("start")
def cmd_task_start(
    title: str = typer.Argument(..., help="Short description of the coding task."),
    risk_tier: Optional[RiskTier] = typer.Option(None, "--risk", "-r", help="Risk tier (low, medium, high)."),
    requester: str = typer.Option("developer@local", "--requester", help="Human requester identifier."),
) -> None:
    """Start a new governed coding task and session."""
    cfg, _root, audit, store = _open_audit_and_store()
    tier = risk_tier or cfg.policy.default_risk_tier
    task_id = f"task-{uuid.uuid4().hex[:8]}"
    session_id = f"sess-{uuid.uuid4().hex[:8]}"
    branch = f"{cfg.git.branch_prefix}{task_id}"
    now = utc_now_iso()

    store.create_task(
        task_id=task_id,
        title=title,
        risk_tier=tier.value,
        branch=branch,
        requester=requester,
        active_model=cfg.gateway.default_model,
        now_iso=now,
    )
    store.create_session(
        session_id=session_id,
        task_id=task_id,
        actor=f"human:{requester}",
        model=cfg.gateway.default_model,
        now_iso=now,
    )
    audit.append(
        event_type="session_start",
        actor=f"human:{requester}",
        session_id=session_id,
        task_id=task_id,
        repository=cfg.project.name,
        branch=branch,
        model=cfg.gateway.default_model,
        risk_tier=tier.value,
        policy_version=cfg.policy.version,
        data_classification=cfg.project.data_classification.value,
        details={"title": title},
    )
    console.print(f"[green]Started[/green] {task_id} (branch: {branch}, risk: {tier.value}, session: {session_id})")


@model_app.command("list")
def cmd_model_list() -> None:
    """List configured models, providers, and whether they are permitted."""
    cfg, _root, _audit, _store = _open_audit_and_store()
    table = Table(title=f"Configured Models ({cfg.project.data_classification.value} repo)")
    table.add_column("Model")
    table.add_column("Provider")
    table.add_column("Local")
    table.add_column("Allowed")

    allowed_set = (
        set(cfg.gateway.restricted_allowed_models)
        if cfg.project.data_classification.value == "restricted"
        else set(cfg.gateway.allowed_models)
    )
    for provider in cfg.gateway.providers:
        for model in provider.models:
            table.add_row(
                model,
                provider.name,
                "yes" if provider.is_local else "no",
                "yes" if model in allowed_set else "no",
            )
    console.print(table)


@model_app.command("use")
def cmd_model_use(
    name: str = typer.Argument(..., help="Model identifier to activate."),
    task_id: Optional[str] = typer.Option(None, "--task", "-t", help="Task ID to update."),
) -> None:
    """Switch the active model for a task (full gateway routing added in Phase 2)."""
    cfg, _root, audit, store = _open_audit_and_store()
    if name not in cfg.gateway.allowed_models:
        console.print(f"[red]Denied:[/red] model '{name}' is not in gateway.allowed_models.")
        raise typer.Exit(code=1)
    if task_id:
        store.set_active_model(task_id, name, utc_now_iso())
    audit.append(
        event_type="model_switched",
        actor="human:cli",
        task_id=task_id or "no-task",
        repository=cfg.project.name,
        model=name,
        policy_version=cfg.policy.version,
        data_classification=cfg.project.data_classification.value,
    )
    console.print(f"[green]Active model set to[/green] {name}")


@audit_app.command("verify")
def cmd_audit_verify() -> None:
    """Verify the tamper-evident SHA-256 hash chain of the local audit log."""
    _cfg, _root, audit, _store = _open_audit_and_store()
    result = audit.verify()
    if result.valid:
        console.print(
            f"[green]Audit log verified.[/green] Entries checked: {result.entries_checked} | "
            f"Head hash: {result.head_hash[:16]}..."
        )
    else:
        console.print(f"[red]AUDIT VERIFICATION FAILED:[/red] {result.error}")
        raise typer.Exit(code=1)


@audit_app.command("checkpoint")
def cmd_audit_checkpoint() -> None:
    """Generate a daily signed checkpoint hash from the verified audit chain."""
    cfg, _root, audit, store = _open_audit_and_store()
    cp = audit.create_checkpoint(cfg.audit.signing_key_env_var)
    store.record_checkpoint(
        date_utc=cp.date_utc,
        entries_count=cp.entries_count,
        head_hash=cp.head_hash,
        signature=cp.signature,
        created_at=cp.created_at,
    )
    console.print(
        f"[green]Checkpoint created[/green] for {cp.date_utc} "
        f"(entries: {cp.entries_count}, head: {cp.head_hash[:12]}...)"
    )


@app.command("check")
def cmd_check(
    task_id: str = typer.Option("no-task", "--task", "-t", help="Task ID for audit attribution."),
    run_pytest: bool = typer.Option(True, "--run-tests/--skip-tests", help="Run pytest unit tests."),
) -> None:
    """Run pre-commit security, SAST, dependency, coverage, and diff-size checks."""
    cfg, root, audit, _store = _open_audit_and_store()
    wf = GitWorkflow(cfg, audit, root)
    runner = GateRunner(cfg, audit, root)
    report = runner.run_all(
        changed_paths=wf.changed_files(),
        diff_lines=wf.diff_line_count(),
        task_id=task_id,
        run_pytest=run_pytest,
    )
    for res in report.results:
        status = "[green]PASS[/green]" if res.passed else "[red]FAIL[/red]"
        console.print(f"{status} {res.name} ({res.scanner}): {res.summary}")
    if not report.passed:
        raise typer.Exit(code=1)


@app.command("commit")
def cmd_commit(
    message: str = typer.Option(..., "--message", "-m", help="Commit message."),
    task_id: str = typer.Option(..., "--task", "-t", help="Task ID for provenance trailers."),
    approver: str = typer.Option("none", "--approver", help="Approver identifier if approved."),
    run_pytest: bool = typer.Option(True, "--run-tests/--skip-tests", help="Run pytest during gates."),
) -> None:
    """Create a signed commit with AI provenance trailers after gates pass."""
    cfg, root, audit, store = _open_audit_and_store()
    task = store.get_task(task_id)
    model = (task.get("active_model") if task else None) or cfg.gateway.default_model
    provider = next((p.name for p in cfg.gateway.providers if model in p.models), "unknown")

    wf = GitWorkflow(cfg, audit, root)
    runner = GateRunner(cfg, audit, root)
    report = runner.run_all(
        changed_paths=wf.changed_files(),
        diff_lines=wf.diff_line_count(),
        task_id=task_id,
        run_pytest=run_pytest,
    )
    try:
        sha = wf.commit(
            message=message,
            task_id=task_id,
            model=model,
            provider=provider,
            approver=approver,
            gate_report=report,
        )
    except GitGovernanceError as exc:
        console.print(f"[red]Commit blocked:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    console.print(f"[green]Committed[/green] {sha[:12]} on {wf.current_branch()}")


@app.command("pr")
def cmd_pr(
    task_id: str = typer.Option(..., "--task", "-t", help="Task ID for the pull request."),
    why: str = typer.Option("Governed AI-assisted change.", "--why", help="Reason for change."),
) -> None:
    """Generate a governance summary and open or stage a pull request."""
    cfg, root, audit, store = _open_audit_and_store()
    task = store.get_task(task_id)
    if not task:
        console.print(f"[red]Task '{task_id}' not found.[/red]")
        raise typer.Exit(code=1)

    wf = GitWorkflow(cfg, audit, root)
    runner = GateRunner(cfg, audit, root)
    report = runner.run_all(
        changed_paths=wf.changed_files(),
        diff_lines=wf.diff_line_count(),
        risk_tier=RiskTier(task["risk_tier"]),
        task_id=task_id,
        run_pytest=False,
    )
    summary = wf.generate_pr_summary(
        task_id=task_id,
        title=task["title"],
        why=why,
        model=task["active_model"] or cfg.gateway.default_model,
        risk_tier=task["risk_tier"],
        changed_files=wf.changed_files(),
        gate_report=report,
    )
    out_file = root / ".harness" / f"pr-{task_id}.md"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(summary, encoding="utf-8")
    audit.append(
        event_type="pr_opened",
        actor="human:cli",
        task_id=task_id,
        repository=cfg.project.name,
        branch=task["branch"],
        risk_tier=task["risk_tier"],
        policy_version=cfg.policy.version,
        details={"summary_path": str(out_file), "local_git_only": cfg.project.local_git_only},
    )
    console.print(f"[green]PR summary generated[/green] at {out_file}")


@app.command("approve")
def cmd_approve(
    task_id: str = typer.Argument(..., help="Task ID awaiting approval."),
    approver: str = typer.Option(..., "--approver", help="Approver email or identifier."),
    notes: Optional[str] = typer.Option(None, "--notes", help="Optional approval notes."),
) -> None:
    """Record a second-person human approval for medium or high risk tasks."""
    cfg, _root, audit, store = _open_audit_and_store()
    engine = PolicyEngine(cfg, audit, store)
    decision = engine.record_approval(task_id=task_id, approver=approver, notes=notes)
    if decision.outcome == PolicyOutcome.DENY:
        console.print(f"[red]Approval denied:[/red] {decision.reason}")
        raise typer.Exit(code=1)
    console.print(f"[green]Approval recorded[/green] for {task_id} by {approver} (policy v{decision.policy_version}).")


@app.command("killswitch")
def cmd_killswitch(reason: str = typer.Option("Manual operator halt", "--reason", help="Reason for halt.")) -> None:
    """Immediately halt all active agent sessions and revoke task credentials."""
    cfg, root, audit, store = _open_audit_and_store()
    mgr = SandboxManager(cfg, audit, store, root)
    summary = mgr.activate_killswitch(reason=reason)
    console.print(
        f"[red]Kill switch activated.[/red] Halted {summary['halted_sessions']} session(s), "
        f"terminated {summary['terminated_processes']} process(es), "
        f"revoked {summary['revoked_tokens']} token(s)."
    )


@app.command("report")
def cmd_report() -> None:
    """Display governance, cost, and check-gate metrics (Phase 7)."""
    _cfg, _root, audit, store = _open_audit_and_store()
    entries = audit.read_all()
    tasks = store.list_tasks()
    console.print(f"Tasks recorded: {len(tasks)} | Audit entries: {len(entries)}")


if __name__ == "__main__":
    app()
