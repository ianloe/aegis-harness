"""Git branch workflow, signed commits, provenance trailers, PR summaries, and hooks."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import List, Optional

from harness.audit.chain import AuditChain
from harness.config.schema import HarnessConfig
from harness.gitops.gates import GateSuiteReport


class GitGovernanceError(RuntimeError):
    """Raised when a Git governance rule is violated."""


def format_provenance_trailers(
    *,
    model: str,
    provider: str,
    task_id: str,
    policy_version: str,
    approver: str = "pending",
) -> str:
    """Format standard Git commit trailers for AI-generated code provenance."""
    return "\n".join(
        [
            f"Harness-Model: {model}",
            f"Harness-Provider: {provider}",
            f"Harness-Task-ID: {task_id}",
            f"Harness-Policy-Version: {policy_version}",
            f"Harness-Approver: {approver}",
        ]
    )


class GitWorkflow:
    """Enforces branch isolation, commit signing, provenance trailers, and PR summaries."""

    def __init__(self, config: HarnessConfig, audit: AuditChain, root: Path) -> None:
        self.config = config
        self.audit = audit
        self.root = root.resolve()

    def _git(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *args],
            cwd=self.root,
            check=check,
            capture_output=True,
            text=True,
        )

    def current_branch(self) -> str:
        proc = self._git("rev-parse", "--abbrev-ref", "HEAD", check=False)
        if proc.returncode != 0:
            return self.config.git.base_branch
        return proc.stdout.strip()

    def ensure_task_branch(self, task_id: str) -> str:
        """Create or switch to `agent/<task-id>`, never allowing work directly on base_branch."""
        branch = f"{self.config.git.branch_prefix}{task_id}"
        existing = self._git("branch", "--list", branch).stdout.strip()
        if existing:
            self._git("checkout", branch)
        else:
            self._git("checkout", "-b", branch)
        return branch

    def changed_files(self) -> List[str]:
        """Return staged and unstaged modified file paths relative to repo root."""
        proc = self._git("status", "--porcelain", check=False)
        files: List[str] = []
        for line in proc.stdout.splitlines():
            if len(line) >= 4:
                files.append(line[3:].strip())
        return files

    def diff_line_count(self) -> int:
        """Return total added + removed lines in the working tree."""
        proc = self._git("diff", "--numstat", "HEAD", check=False)
        total = 0
        for line in proc.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
                total += int(parts[0]) + int(parts[1])
        return total

    def commit(
        self,
        *,
        message: str,
        task_id: str,
        model: str,
        provider: str,
        approver: str = "none",
        gate_report: GateSuiteReport,
        sign: Optional[bool] = None,
    ) -> str:
        """Stage and commit changes with AI provenance trailers after gates pass."""
        branch = self.current_branch()
        if branch == self.config.git.base_branch:
            raise GitGovernanceError(
                f"Direct commits to '{self.config.git.base_branch}' are forbidden. "
                f"Switch to '{self.config.git.branch_prefix}<task-id>' first."
            )

        if not gate_report.passed:
            failed = [r.name for r in gate_report.results if not r.passed]
            raise GitGovernanceError(f"Commit blocked by failed gate(s): {', '.join(failed)}")

        must_sign = self.config.policy.require_signed_commits if sign is None else sign
        trailers = format_provenance_trailers(
            model=model,
            provider=provider,
            task_id=task_id,
            policy_version=self.config.policy.version,
            approver=approver,
        )
        full_message = f"{message.strip()}\n\n{trailers}"

        self._git("add", "-A")
        commit_args = ["commit", "-m", full_message]
        if must_sign:
            commit_args.append("-S")
        proc = self._git(*commit_args, check=False)
        if proc.returncode != 0:
            raise GitGovernanceError(
                f"Git commit failed (signing required={must_sign}): {proc.stderr.strip()}"
            )

        sha = self._git("rev-parse", "HEAD").stdout.strip()
        self.audit.append(
            event_type="commit",
            actor="agent:harness",
            outcome="success",
            task_id=task_id,
            repository=self.config.project.name,
            branch=branch,
            model=model,
            policy_version=self.config.policy.version,
            data_classification=self.config.project.data_classification.value,
            details={"commit_sha": sha, "signed": must_sign, "provider": provider},
        )
        return sha

    def verify_commit_signed(self, rev: str = "HEAD") -> bool:
        """Verify that a commit carries a valid SSH or GPG signature."""
        proc = self._git("verify-commit", rev, check=False)
        return proc.returncode == 0

    def generate_pr_summary(
        self,
        *,
        task_id: str,
        title: str,
        why: str,
        model: str,
        risk_tier: str,
        changed_files: List[str],
        gate_report: GateSuiteReport,
    ) -> str:
        """Generate a structured Markdown PR summary with governance and scan evidence."""
        checks_lines = "\n".join(
            f"- **{r.name}** ({r.scanner}): {'PASS' if r.passed else 'FAIL'} - {r.summary}"
            for r in gate_report.results
        )
        files_lines = "\n".join(f"- `{f}`" for f in changed_files) or "- (no files listed)"
        return (
            f"## {title}\n\n"
            f"- **Task ID**: `{task_id}`\n"
            f"- **Risk Tier**: `{risk_tier}`\n"
            f"- **Model**: `{model}`\n"
            f"- **Policy Version**: `{self.config.policy.version}`\n\n"
            f"### Why\n{why}\n\n"
            f"### What Changed\n{files_lines}\n\n"
            f"### Security & Quality Gate Results\n{checks_lines}\n"
        )

    def install_git_hooks(self) -> List[Path]:
        """Install local pre-commit and pre-push hooks invoking `harness check`."""
        hooks_dir = self.root / ".git" / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)
        script = "#!/usr/bin/env sh\nset -e\nharness check\n"
        installed: List[Path] = []
        for hook_name in ("pre-commit", "pre-push"):
            hook_path = hooks_dir / hook_name
            hook_path.write_text(script, encoding="utf-8")
            hook_path.chmod(0o755)
            installed.append(hook_path)
        return installed
