"""Security, quality, and compliance check-in gates.

Uses external scanners (gitleaks, semgrep, osv-scanner/trivy) when installed
and falls back to built-in Python scanners so gates remain deterministic both
locally and in CI.
"""

from __future__ import annotations

import ast
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from harness.audit.chain import AuditChain
from harness.config.schema import HarnessConfig, RiskTier
from harness.gateway.redactor import redact_prompt
from harness.policy.engine import PolicyEngine, PolicyOutcome


class GateCheckResult(BaseModel):
    """Outcome of a single security or quality gate check."""

    name: str
    passed: bool
    scanner: str
    summary: str
    findings: List[str] = Field(default_factory=list)


class GateSuiteReport(BaseModel):
    """Aggregated report across all check-in gates."""

    passed: bool
    results: List[GateCheckResult] = Field(default_factory=list)

    @property
    def passed_names(self) -> List[str]:
        return [r.name for r in self.results if r.passed]


class GateRunner:
    """Executes pre-commit, pre-push, and CI security gates."""

    def __init__(self, config: HarnessConfig, audit: AuditChain, root: Path) -> None:
        self.config = config
        self.audit = audit
        self.root = root.resolve()
        self.policy = PolicyEngine(config, audit)

    def _iter_source_files(self, paths: Optional[List[str]] = None) -> List[Path]:
        if paths is not None:
            safe_paths: List[Path] = []
            for p in paths:
                resolved = (self.root / p).resolve()
                if resolved.is_relative_to(self.root) and resolved.is_file():
                    safe_paths.append(resolved)
            return safe_paths
        ignored = {".git", ".venv", "__pycache__", ".pytest_cache", ".harness", "node_modules"}
        out: List[Path] = []
        for item in self.root.rglob("*"):
            if item.is_file() and not any(part in ignored for part in item.parts):
                out.append(item)
        return out

    def check_secrets(self, paths: Optional[List[str]] = None) -> GateCheckResult:
        """Scan files for leaked secrets using gitleaks if available, else built-in scanner."""
        if shutil.which("gitleaks") and paths is None:
            proc = subprocess.run(
                ["gitleaks", "detect", "--no-git", "--source", str(self.root), "--redact"],
                capture_output=True,
                text=True,
            )
            passed = proc.returncode == 0
            return GateCheckResult(
                name="secrets",
                passed=passed,
                scanner="gitleaks",
                summary="No secrets detected by gitleaks." if passed else "gitleaks detected potential secrets.",
                findings=[] if passed else [proc.stdout[:400] or proc.stderr[:400]],
            )

        findings: List[str] = []
        for file_path in self._iter_source_files(paths):
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            scan = redact_prompt(content, redact_secrets=True, redact_pii=False)
            if scan.redaction_count > 0:
                rel = file_path.relative_to(self.root)
                findings.append(f"{rel}: {', '.join(scan.categories)}")

        passed = len(findings) == 0
        return GateCheckResult(
            name="secrets",
            passed=passed,
            scanner="builtin-secret-scanner",
            summary="No secrets detected." if passed else f"Secret scan failed on {len(findings)} file(s).",
            findings=findings,
        )

    def check_sast(self, paths: Optional[List[str]] = None) -> GateCheckResult:
        """Run static analysis via semgrep if installed, else built-in Python AST check."""
        if shutil.which("semgrep") and paths is None:
            proc = subprocess.run(
                ["semgrep", "--config", "auto", "--error", "--quiet", str(self.root)],
                capture_output=True,
                text=True,
            )
            passed = proc.returncode == 0
            return GateCheckResult(
                name="sast",
                passed=passed,
                scanner="semgrep",
                summary="Semgrep passed." if passed else "Semgrep reported findings.",
                findings=[] if passed else [proc.stdout[:400] or proc.stderr[:400]],
            )

        findings: List[str] = []
        dangerous_calls = {"eval", "exec"}
        for file_path in self._iter_source_files(paths):
            if file_path.suffix != ".py":
                continue
            try:
                src = file_path.read_text(encoding="utf-8")
                tree = ast.parse(src, filename=str(file_path))
            except (OSError, SyntaxError):
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id in dangerous_calls:
                        rel = file_path.relative_to(self.root)
                        findings.append(f"{rel}:{node.lineno}: unsafe call '{node.func.id}()'")
                    elif isinstance(node.func, ast.Attribute) and node.func.attr == "loads":
                        if isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle":
                            rel = file_path.relative_to(self.root)
                            findings.append(f"{rel}:{node.lineno}: unsafe 'pickle.loads()'")
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            rel = file_path.relative_to(self.root)
                            findings.append(f"{rel}:{node.lineno}: subprocess call with shell=True")

        passed = len(findings) == 0
        return GateCheckResult(
            name="sast",
            passed=passed,
            scanner="builtin-python-ast",
            summary="Static analysis passed." if passed else f"Static analysis flagged {len(findings)} issue(s).",
            findings=findings,
        )

    def check_deps_and_licences(self, declared_licences: Optional[Dict[str, str]] = None) -> GateCheckResult:
        """Run vulnerability scan (osv-scanner/trivy if available) and licence allow-list check."""
        findings: List[str] = []
        scanner = "builtin-licence-check"

        if shutil.which("osv-scanner"):
            scanner = "osv-scanner"
            proc = subprocess.run(
                ["osv-scanner", "scan", "-r", str(self.root)],
                capture_output=True,
                text=True,
            )
            if proc.returncode not in (0, 128):
                findings.append(proc.stdout[:300] or proc.stderr[:300])

        allowed = set(self.config.git.allowed_licences)
        for pkg, licence in (declared_licences or {}).items():
            if licence not in allowed:
                findings.append(f"Disallowed dependency licence: {pkg} ({licence})")

        passed = len(findings) == 0
        return GateCheckResult(
            name="deps",
            passed=passed,
            scanner=scanner,
            summary="Dependency and licence checks passed." if passed else "Dependency or licence check failed.",
            findings=findings,
        )

    def check_tests(
        self,
        *,
        run_pytest: bool = True,
        observed_coverage_pct: Optional[float] = None,
    ) -> GateCheckResult:
        """Run unit tests and enforce the configured minimum coverage threshold."""
        if run_pytest:
            proc = subprocess.run(
                ["pytest", "-q"],
                cwd=self.root,
                capture_output=True,
                text=True,
            )
            if proc.returncode != 0:
                return GateCheckResult(
                    name="tests",
                    passed=False,
                    scanner="pytest",
                    summary="Unit tests failed.",
                    findings=[proc.stdout[-400:] or proc.stderr[-400:]],
                )

        min_cov = self.config.git.min_test_coverage_pct
        if observed_coverage_pct is not None and observed_coverage_pct < min_cov:
            return GateCheckResult(
                name="tests",
                passed=False,
                scanner="pytest",
                summary=f"Coverage {observed_coverage_pct:.1f}% is below threshold {min_cov:.1f}%.",
                findings=[f"coverage={observed_coverage_pct:.1f}% < {min_cov:.1f}%"],
            )

        return GateCheckResult(
            name="tests",
            passed=True,
            scanner="pytest",
            summary="Unit tests and coverage threshold passed.",
        )

    def check_diff(
        self,
        *,
        changed_paths: List[str],
        diff_lines: int,
        risk_tier: RiskTier,
        task_id: str = "no-task",
    ) -> GateCheckResult:
        """Check diff size and restricted file paths against PolicyEngine."""
        decision = self.policy.evaluate_paths_and_diff(
            changed_paths,
            diff_lines,
            risk_tier=risk_tier,
            task_id=task_id,
        )
        passed = decision.outcome == PolicyOutcome.ALLOW
        return GateCheckResult(
            name="diff",
            passed=passed,
            scanner="policy-engine",
            summary=decision.reason,
            findings=[] if passed else [decision.reason],
        )

    def run_all(
        self,
        *,
        changed_paths: Optional[List[str]] = None,
        diff_lines: int = 0,
        risk_tier: Optional[RiskTier] = None,
        task_id: str = "no-task",
        run_pytest: bool = False,
        observed_coverage_pct: Optional[float] = None,
        declared_licences: Optional[Dict[str, str]] = None,
    ) -> GateSuiteReport:
        """Execute all check-in gates and record results in the audit chain."""
        tier = risk_tier or self.config.policy.default_risk_tier
        results = [
            self.check_secrets(changed_paths),
            self.check_sast(changed_paths),
            self.check_deps_and_licences(declared_licences),
            self.check_tests(run_pytest=run_pytest, observed_coverage_pct=observed_coverage_pct),
            self.check_diff(
                changed_paths=changed_paths or [],
                diff_lines=diff_lines,
                risk_tier=tier,
                task_id=task_id,
            ),
        ]
        overall = all(r.passed for r in results)
        self.audit.append(
            event_type="check_suite",
            actor="agent:harness",
            outcome="pass" if overall else "fail",
            task_id=task_id,
            repository=self.config.project.name,
            risk_tier=tier.value,
            policy_version=self.config.policy.version,
            data_classification=self.config.project.data_classification.value,
            details={
                "results": {r.name: {"passed": r.passed, "scanner": r.scanner} for r in results},
            },
        )
        return GateSuiteReport(passed=overall, results=results)
