"""Declarative Policy Engine for Aegis Harness.

Evaluates models, tools, commands, file paths, diff sizes, and merge approvals
against the active HarnessConfig, recording every decision in the audit chain.
"""

from __future__ import annotations

import posixpath
import re
from enum import Enum
from fnmatch import fnmatch
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from harness.audit.chain import AuditChain, utc_now_iso
from harness.audit.store import StateStore
from harness.config.schema import DataClassification, HarnessConfig, RiskTier


class PolicyOutcome(str, Enum):
    """Possible outcomes of a policy evaluation."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class PolicyDecision(BaseModel):
    """Structured policy evaluation result recorded in the audit log."""

    outcome: PolicyOutcome
    policy_version: str
    rule_id: str
    reason: str
    risk_tier: RiskTier
    details: Dict[str, object] = Field(default_factory=dict)


class PolicyEngine:
    """Evaluates governance policies defined in HarnessConfig."""

    def __init__(
        self,
        config: HarnessConfig,
        audit: AuditChain,
        store: Optional[StateStore] = None,
    ) -> None:
        self.config = config
        self.audit = audit
        self.store = store

    def _record(
        self,
        decision: PolicyDecision,
        *,
        task_id: str = "no-task",
        session_id: str = "no-session",
        actor: str = "agent:harness",
        model: Optional[str] = None,
    ) -> PolicyDecision:
        self.audit.append(
            event_type="policy_decision",
            actor=actor,
            outcome=decision.outcome.value,
            session_id=session_id,
            task_id=task_id,
            repository=self.config.project.name,
            model=model,
            risk_tier=decision.risk_tier.value,
            policy_version=decision.policy_version,
            data_classification=self.config.project.data_classification.value,
            details={
                "rule_id": decision.rule_id,
                "reason": decision.reason,
                **decision.details,
            },
        )
        return decision

    def evaluate_model(
        self,
        model: str,
        *,
        risk_tier: Optional[RiskTier] = None,
        task_id: str = "no-task",
        session_id: str = "no-session",
        actor: str = "agent:harness",
    ) -> PolicyDecision:
        """Check whether `model` is permitted for the repository classification."""
        tier = risk_tier or self.config.policy.default_risk_tier
        version = self.config.policy.version
        classification = self.config.project.data_classification

        provider = next((p for p in self.config.gateway.providers if model in p.models), None)
        if classification == DataClassification.RESTRICTED:
            is_local = provider.is_local if provider else False
            if model not in self.config.gateway.restricted_allowed_models and not is_local:
                return self._record(
                    PolicyDecision(
                        outcome=PolicyOutcome.DENY,
                        policy_version=version,
                        rule_id="model.restricted_allowlist",
                        reason=f"Model '{model}' is not permitted in a 'restricted' repository.",
                        risk_tier=tier,
                        details={"model": model, "classification": classification.value},
                    ),
                    task_id=task_id,
                    session_id=session_id,
                    actor=actor,
                    model=model,
                )
        elif model not in self.config.gateway.allowed_models:
            return self._record(
                PolicyDecision(
                    outcome=PolicyOutcome.DENY,
                    policy_version=version,
                    rule_id="model.allowlist",
                    reason=f"Model '{model}' is not in gateway.allowed_models.",
                    risk_tier=tier,
                    details={"model": model},
                ),
                task_id=task_id,
                session_id=session_id,
                actor=actor,
                model=model,
            )

        return self._record(
            PolicyDecision(
                outcome=PolicyOutcome.ALLOW,
                policy_version=version,
                rule_id="model.allowlist",
                reason=f"Model '{model}' is permitted.",
                risk_tier=tier,
                details={"model": model},
            ),
            task_id=task_id,
            session_id=session_id,
            actor=actor,
            model=model,
        )

    def evaluate_tool(
        self,
        tool_name: str,
        *,
        risk_tier: Optional[RiskTier] = None,
        task_id: str = "no-task",
        session_id: str = "no-session",
        actor: str = "agent:harness",
    ) -> PolicyDecision:
        """Check whether an agent tool is in `policy.allowed_tools`."""
        tier = risk_tier or self.config.policy.default_risk_tier
        version = self.config.policy.version
        if tool_name not in self.config.policy.allowed_tools:
            return self._record(
                PolicyDecision(
                    outcome=PolicyOutcome.DENY,
                    policy_version=version,
                    rule_id="tool.allowlist",
                    reason=f"Tool '{tool_name}' is not in policy.allowed_tools.",
                    risk_tier=tier,
                    details={"tool": tool_name},
                ),
                task_id=task_id,
                session_id=session_id,
                actor=actor,
            )
        return self._record(
            PolicyDecision(
                outcome=PolicyOutcome.ALLOW,
                policy_version=version,
                rule_id="tool.allowlist",
                reason=f"Tool '{tool_name}' is permitted.",
                risk_tier=tier,
                details={"tool": tool_name},
            ),
            task_id=task_id,
            session_id=session_id,
            actor=actor,
        )

    def evaluate_command(
        self,
        command: str,
        *,
        risk_tier: Optional[RiskTier] = None,
        task_id: str = "no-task",
        session_id: str = "no-session",
        actor: str = "agent:harness",
    ) -> PolicyDecision:
        """Check whether a shell command is safe and matches an allow-listed command prefix."""
        tier = risk_tier or self.config.policy.default_risk_tier
        version = self.config.policy.version
        normalised = command.strip()

        if re.search(r"[;&|`><\r\n]|\$\(", normalised):
            return self._record(
                PolicyDecision(
                    outcome=PolicyOutcome.DENY,
                    policy_version=version,
                    rule_id="command.shell_metacharacter",
                    reason="Command contains disallowed shell metacharacters or chaining operators.",
                    risk_tier=tier,
                    details={"command": normalised},
                ),
                task_id=task_id,
                session_id=session_id,
                actor=actor,
            )

        allowed = any(
            normalised == prefix or normalised.startswith(f"{prefix} ")
            for prefix in self.config.policy.allowed_commands
        )
        if not allowed:
            return self._record(
                PolicyDecision(
                    outcome=PolicyOutcome.DENY,
                    policy_version=version,
                    rule_id="command.allowlist",
                    reason=f"Command '{normalised}' is not in policy.allowed_commands.",
                    risk_tier=tier,
                    details={"command": normalised},
                ),
                task_id=task_id,
                session_id=session_id,
                actor=actor,
            )
        return self._record(
            PolicyDecision(
                outcome=PolicyOutcome.ALLOW,
                policy_version=version,
                rule_id="command.allowlist",
                reason=f"Command '{normalised}' is permitted.",
                risk_tier=tier,
                details={"command": normalised},
            ),
            task_id=task_id,
            session_id=session_id,
            actor=actor,
        )

    def evaluate_paths_and_diff(
        self,
        changed_paths: List[str],
        diff_lines: int,
        *,
        risk_tier: Optional[RiskTier] = None,
        task_id: str = "no-task",
        session_id: str = "no-session",
        actor: str = "agent:harness",
    ) -> PolicyDecision:
        """Evaluate modified file paths and diff line count against tier limits."""
        tier = risk_tier or self.config.policy.default_risk_tier
        version = self.config.policy.version
        tier_cfg = self.config.policy.risk_tiers[tier]

        normalised_paths: List[str] = []
        for raw_path in changed_paths:
            cleaned = raw_path.replace("\\", "/").strip()
            norm = posixpath.normpath(cleaned)
            if posixpath.isabs(cleaned) or norm == ".." or norm.startswith("../"):
                return self._record(
                    PolicyDecision(
                        outcome=PolicyOutcome.DENY,
                        policy_version=version,
                        rule_id="paths.traversal_denied",
                        reason=f"Path traversal or absolute path is not permitted: '{raw_path}'.",
                        risk_tier=tier,
                        details={"path": raw_path},
                    ),
                    task_id=task_id,
                    session_id=session_id,
                    actor=actor,
                )
            normalised_paths.append(norm)

        matched_restricted = [
            path
            for path in normalised_paths
            if any(fnmatch(path, pattern) for pattern in self.config.policy.restricted_paths)
        ]
        if matched_restricted:
            return self._record(
                PolicyDecision(
                    outcome=PolicyOutcome.REQUIRE_APPROVAL,
                    policy_version=version,
                    rule_id="paths.restricted",
                    reason=(
                        "Modified restricted path(s) requiring elevated human approval: "
                        + ", ".join(matched_restricted)
                    ),
                    risk_tier=tier,
                    details={"restricted_paths": matched_restricted},
                ),
                task_id=task_id,
                session_id=session_id,
                actor=actor,
            )

        if diff_lines > tier_cfg.max_diff_lines:
            return self._record(
                PolicyDecision(
                    outcome=PolicyOutcome.REQUIRE_APPROVAL,
                    policy_version=version,
                    rule_id="diff.max_lines",
                    reason=(
                        f"Diff size ({diff_lines} lines) exceeds {tier.value} tier limit "
                        f"({tier_cfg.max_diff_lines} lines)."
                    ),
                    risk_tier=tier,
                    details={"diff_lines": diff_lines, "limit": tier_cfg.max_diff_lines},
                ),
                task_id=task_id,
                session_id=session_id,
                actor=actor,
            )

        return self._record(
            PolicyDecision(
                outcome=PolicyOutcome.ALLOW,
                policy_version=version,
                rule_id="paths_and_diff.ok",
                reason="Changed paths and diff size are within policy limits.",
                risk_tier=tier,
                details={"diff_lines": diff_lines, "changed_count": len(changed_paths)},
            ),
            task_id=task_id,
            session_id=session_id,
            actor=actor,
        )

    def record_approval(
        self,
        *,
        task_id: str,
        approver: str,
        notes: Optional[str] = None,
    ) -> PolicyDecision:
        """Record a human approval, enforcing separation of duties (approver != requester)."""
        if not self.store:
            raise RuntimeError("StateStore is required to record approvals.")
        task = self.store.get_task(task_id)
        if not task:
            raise ValueError(f"Task '{task_id}' not found.")

        tier = RiskTier(task["risk_tier"])
        tier_cfg = self.config.policy.risk_tiers[tier]
        requester = task["requester"]

        if tier_cfg.require_distinct_approver and approver.strip().lower() == requester.strip().lower():
            return self._record(
                PolicyDecision(
                    outcome=PolicyOutcome.DENY,
                    policy_version=self.config.policy.version,
                    rule_id="approval.distinct_approver",
                    reason="Approver must be a different person from the task requester.",
                    risk_tier=tier,
                    details={"requester": requester, "approver": approver},
                ),
                task_id=task_id,
                actor=f"human:{approver}",
            )

        now = utc_now_iso()
        self.store.record_approval(
            task_id=task_id,
            requester=requester,
            approver=approver,
            risk_tier=tier.value,
            decision="approved",
            notes=notes,
            now_iso=now,
        )
        self.audit.append(
            event_type="approval_granted",
            actor=f"human:{approver}",
            outcome="approved",
            task_id=task_id,
            repository=self.config.project.name,
            branch=task["branch"],
            risk_tier=tier.value,
            policy_version=self.config.policy.version,
            data_classification=self.config.project.data_classification.value,
            details={"requester": requester, "approver": approver, "notes": notes},
        )
        return self._record(
            PolicyDecision(
                outcome=PolicyOutcome.ALLOW,
                policy_version=self.config.policy.version,
                rule_id="approval.recorded",
                reason=f"Approval recorded by {approver}.",
                risk_tier=tier,
                details={"approver": approver},
            ),
            task_id=task_id,
            actor=f"human:{approver}",
        )

    def evaluate_merge(
        self,
        *,
        task_id: str,
        passed_checks: List[str],
    ) -> PolicyDecision:
        """Verify all required checks and human approvals for a task before merge."""
        if not self.store:
            raise RuntimeError("StateStore is required to evaluate merge readiness.")
        task = self.store.get_task(task_id)
        if not task:
            raise ValueError(f"Task '{task_id}' not found.")

        tier = RiskTier(task["risk_tier"])
        tier_cfg = self.config.policy.risk_tiers[tier]
        missing_checks = [c for c in tier_cfg.required_checks if c not in passed_checks]
        if missing_checks:
            return self._record(
                PolicyDecision(
                    outcome=PolicyOutcome.DENY,
                    policy_version=self.config.policy.version,
                    rule_id="merge.required_checks",
                    reason=f"Missing required check(s) for {tier.value} tier: {', '.join(missing_checks)}",
                    risk_tier=tier,
                    details={"missing_checks": missing_checks},
                ),
                task_id=task_id,
            )

        approvals = self.store.list_approvals(task_id)
        distinct_approvers = {
            a["approver"].strip().lower()
            for a in approvals
            if a["decision"] == "approved"
            and (
                not tier_cfg.require_distinct_approver
                or a["approver"].strip().lower() != task["requester"].strip().lower()
            )
        }
        if len(distinct_approvers) < tier_cfg.required_approvals:
            return self._record(
                PolicyDecision(
                    outcome=PolicyOutcome.REQUIRE_APPROVAL,
                    policy_version=self.config.policy.version,
                    rule_id="merge.human_approvals",
                    reason=(
                        f"{tier.value} tier requires {tier_cfg.required_approvals} distinct human approval(s); "
                        f"currently has {len(distinct_approvers)}."
                    ),
                    risk_tier=tier,
                    details={
                        "required": tier_cfg.required_approvals,
                        "received": len(distinct_approvers),
                    },
                ),
                task_id=task_id,
            )

        return self._record(
            PolicyDecision(
                outcome=PolicyOutcome.ALLOW,
                policy_version=self.config.policy.version,
                rule_id="merge.ready",
                reason="All required checks and approvals satisfied.",
                risk_tier=tier,
                details={"approvers": sorted(distinct_approvers)},
            ),
            task_id=task_id,
        )
