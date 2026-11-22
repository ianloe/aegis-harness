"""Governance and engineering metrics computed from Harness audit entries."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from harness.audit.chain import AuditEntry


class GovernanceMetrics(BaseModel):
    """Summary metrics surfaced by `harness report` and the web dashboard."""

    total_tasks: int = 0
    total_cost_usd: float = 0.0
    cost_per_task_usd: float = 0.0
    total_tokens: int = 0
    tokens_per_task: float = 0.0
    check_failure_rate: float = 0.0
    human_override_rate: float = 0.0
    avg_time_to_merge_seconds: Optional[float] = None
    ai_authored_lines_pct: float = 0.0
    policy_denials_by_type: Dict[str, int] = Field(default_factory=dict)


def _parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def compute_metrics(entries: List[AuditEntry]) -> GovernanceMetrics:
    """Calculate governance and cost metrics across recorded audit entries."""
    tasks: set[str] = set()
    total_cost = 0.0
    total_tokens = 0
    check_runs = 0
    check_failures = 0
    overrides = 0
    approvals = 0
    denials_by_type: Dict[str, int] = defaultdict(int)
    task_starts: Dict[str, datetime] = {}
    merge_durations: List[float] = []
    ai_lines = 0
    total_lines = 0

    for entry in entries:
        if entry.task_id and entry.task_id != "no-task":
            tasks.add(entry.task_id)

        if entry.event_type == "session_start" and entry.task_id not in task_starts:
            task_starts[entry.task_id] = _parse_iso(entry.timestamp)

        if entry.event_type == "model_call":
            total_cost += float(entry.details.get("cost_usd", 0.0) or 0.0)
            in_tok = int(entry.details.get("input_tokens", 0) or 0)
            out_tok = int(entry.details.get("output_tokens", 0) or 0)
            total_tokens += in_tok + out_tok

        if entry.event_type in ("check_suite", "check_pass", "check_fail"):
            check_runs += 1
            if entry.event_type == "check_fail" or entry.outcome == "fail":
                check_failures += 1

        if entry.event_type == "override":
            overrides += 1
        if entry.event_type == "approval_granted":
            approvals += 1

        if entry.event_type in ("policy_decision", "model_call_denied") and entry.outcome == "deny":
            rule_id = str(entry.details.get("rule_id", entry.event_type))
            denials_by_type[rule_id] += 1

        if entry.event_type == "commit":
            ai_l = int(entry.details.get("ai_lines", 0) or 0)
            tot_l = int(entry.details.get("total_lines", ai_l) or 0)
            ai_lines += ai_l
            total_lines += tot_l

        if entry.event_type == "pr_merged" and entry.task_id in task_starts:
            delta = (_parse_iso(entry.timestamp) - task_starts[entry.task_id]).total_seconds()
            if delta >= 0:
                merge_durations.append(delta)

    num_tasks = len(tasks)
    return GovernanceMetrics(
        total_tasks=num_tasks,
        total_cost_usd=round(total_cost, 6),
        cost_per_task_usd=round(total_cost / num_tasks, 6) if num_tasks else 0.0,
        total_tokens=total_tokens,
        tokens_per_task=round(total_tokens / num_tasks, 2) if num_tasks else 0.0,
        check_failure_rate=round(check_failures / check_runs, 4) if check_runs else 0.0,
        human_override_rate=round(overrides / max(1, approvals + overrides), 4) if (approvals + overrides) else 0.0,
        avg_time_to_merge_seconds=(
            round(sum(merge_durations) / len(merge_durations), 2) if merge_durations else None
        ),
        ai_authored_lines_pct=round((ai_lines / total_lines) * 100.0, 2) if total_lines else 0.0,
        policy_denials_by_type=dict(denials_by_type),
    )
