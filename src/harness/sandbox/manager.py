"""Isolated agent sandbox (Git worktree or Docker) and rapid kill switch."""

from __future__ import annotations

import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional

from pydantic import BaseModel

from harness.audit.chain import AuditChain, utc_now_iso
from harness.audit.store import StateStore
from harness.config.schema import HarnessConfig, RiskTier
from harness.policy.engine import PolicyEngine, PolicyOutcome
from harness.sandbox.tokens import TaskTokenManager


class SandboxRunResult(BaseModel):
    """Result of executing an allow-listed command inside the sandbox."""

    exit_code: int
    stdout: str
    stderr: str
    halted: bool = False


class SandboxError(RuntimeError):
    """Raised when sandbox isolation or command policy fails."""


class SandboxManager:
    """Manages isolated task workspaces, command execution, and the kill switch."""

    def __init__(
        self,
        config: HarnessConfig,
        audit: AuditChain,
        store: StateStore,
        root: Path,
        token_manager: Optional[TaskTokenManager] = None,
    ) -> None:
        self.config = config
        self.audit = audit
        self.store = store
        self.root = root.resolve()
        self.policy = PolicyEngine(config, audit, store)
        self.tokens = token_manager or TaskTokenManager()
        self._active_procs: Dict[str, subprocess.Popen[str]] = {}
        self._active_containers: List[str] = []

    def prepare_worktree(self, task_id: str) -> Path:
        """Create or reuse an isolated Git worktree for `agent/<task-id>`."""
        branch = f"{self.config.git.branch_prefix}{task_id}"
        wt_path = self.root / ".harness" / "worktrees" / task_id
        if wt_path.exists():
            return wt_path
        wt_path.parent.mkdir(parents=True, exist_ok=True)
        existing_branch = subprocess.run(
            ["git", "branch", "--list", branch],
            cwd=self.root,
            capture_output=True,
            text=True,
        ).stdout.strip()
        cmd = (
            ["git", "worktree", "add", str(wt_path), branch]
            if existing_branch
            else ["git", "worktree", "add", "-b", branch, str(wt_path)]
        )
        subprocess.run(cmd, cwd=self.root, check=True, capture_output=True, text=True)
        return wt_path

    def start_background_command(
        self,
        *,
        session_id: str,
        task_id: str,
        command: List[str],
        cwd: Optional[Path] = None,
        risk_tier: Optional[RiskTier] = None,
    ) -> subprocess.Popen[str]:
        """Launch an allow-listed command in an isolated process group."""
        cmd_str = " ".join(command)
        decision = self.policy.evaluate_command(
            cmd_str,
            risk_tier=risk_tier or self.config.policy.default_risk_tier,
            task_id=task_id,
            session_id=session_id,
        )
        if decision.outcome != PolicyOutcome.ALLOW:
            raise SandboxError(decision.reason)

        work_dir = cwd or self.root
        if self.config.sandbox.mode == "docker":
            container_name = f"harness-{task_id}-{session_id}"[:48]
            docker_cmd = [
                "docker",
                "run",
                "--rm",
                "--name",
                container_name,
                "--cpus",
                str(self.config.sandbox.cpu_limit),
                "--memory",
                f"{self.config.sandbox.memory_limit_mb}m",
                *([] if self.config.sandbox.network_enabled else ["--network", "none"]),
                "-v",
                f"{work_dir}:/workspace",
                "-w",
                "/workspace",
                "python:3.12-slim",
                *command,
            ]
            self._active_containers.append(container_name)
            proc = subprocess.Popen(
                docker_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
        else:
            proc = subprocess.Popen(
                command,
                cwd=work_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )

        self._active_procs[session_id] = proc
        return proc

    def run_command(
        self,
        *,
        session_id: str,
        task_id: str,
        command: List[str],
        cwd: Optional[Path] = None,
        timeout_seconds: Optional[int] = None,
    ) -> SandboxRunResult:
        """Run an allow-listed command inside the sandbox and wait for completion."""
        proc = self.start_background_command(
            session_id=session_id,
            task_id=task_id,
            command=command,
            cwd=cwd,
        )
        timeout = timeout_seconds or self.config.sandbox.timeout_seconds
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            return SandboxRunResult(
                exit_code=proc.returncode or 0,
                stdout=stdout,
                stderr=stderr,
                halted=False,
            )
        except subprocess.TimeoutExpired:
            self._terminate_proc(proc)
            stdout, stderr = proc.communicate()
            return SandboxRunResult(exit_code=124, stdout=stdout, stderr=stderr, halted=True)
        finally:
            self._active_procs.pop(session_id, None)

    @staticmethod
    def _terminate_proc(proc: subprocess.Popen[str]) -> None:
        if proc.poll() is not None:
            return
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except OSError:
            proc.terminate()
        deadline = time.monotonic() + 1.5
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                return
            time.sleep(0.05)
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except OSError:
            proc.kill()
        proc.wait(timeout=1.0)

    def activate_killswitch(self, reason: str = "Operator kill switch") -> Dict[str, int]:
        """Halt all active sandbox processes/containers, revoke tokens, and log to audit."""
        terminated_procs = 0
        for proc in list(self._active_procs.values()):
            if proc.poll() is None:
                self._terminate_proc(proc)
                terminated_procs += 1
        self._active_procs.clear()

        for cname in list(self._active_containers):
            subprocess.run(["docker", "rm", "-f", cname], capture_output=True, text=True, check=False)
        self._active_containers.clear()

        revoked_tokens = self.tokens.revoke_all()
        halted_sessions = self.store.halt_all_sessions(utc_now_iso())

        self.audit.append(
            event_type="kill_switch",
            actor="human:operator",
            outcome="halted",
            repository=self.config.project.name,
            policy_version=self.config.policy.version,
            data_classification=self.config.project.data_classification.value,
            details={
                "reason": reason,
                "terminated_processes": terminated_procs,
                "revoked_tokens": revoked_tokens,
                "halted_sessions": halted_sessions,
            },
        )
        return {
            "terminated_processes": terminated_procs,
            "revoked_tokens": revoked_tokens,
            "halted_sessions": halted_sessions,
        }
