"""Pydantic v2 configuration schema for Aegis Harness.

Every field carries a human-readable description so that the configuration
webapp can render form controls with inline guidance rather than raw JSON.
"""

from __future__ import annotations

from enum import Enum
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class DataClassification(str, Enum):
    """Data sensitivity classification matching Aegis DataSensitivity."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class RiskTier(str, Enum):
    """Three-tier governance risk classification."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class TaskType(str, Enum):
    """Coding task types used for model routing."""

    PLAN = "plan"
    GENERATE = "generate"
    REFACTOR = "refactor"
    REVIEW = "review"
    TEST = "test"


class ProjectConfig(BaseModel):
    """Repository and Aegis asset identity settings."""

    name: str = Field(
        default="my-project",
        min_length=1,
        description="Human-readable project name shown in audit logs, PR summaries, and Aegis.",
    )
    asset_code: str = Field(
        default="HARNESS-001",
        min_length=1,
        description="Exact assetCode registered in Aegis (/assets) for telemetry attribution.",
    )
    data_classification: DataClassification = Field(
        default=DataClassification.INTERNAL,
        description="Repository sensitivity tier. Restricted repositories may only use approved or local models.",
    )
    local_git_only: bool = Field(
        default=True,
        description="Keep Git commits and branches local until the project is ready to publish to GitHub.",
    )
    repository_url: Optional[str] = Field(
        default=None,
        description="Optional remote Git URL (for example https://github.com/ianloe/aegis-harness.git) used when publishing.",
    )


class AegisConfig(BaseModel):
    """Connection and batching settings for Aegis telemetry."""

    endpoint: str = Field(
        default="https://aegisx.ianloehome.net",
        description="Base URL of the Aegis server (for example https://aegisx.ianloehome.net).",
    )
    token_env_var: str = Field(
        default="AEGIS_TELEMETRY_TOKEN",
        description="Name of the environment variable holding the Aegis Bearer token (aegis_...).",
    )
    timeout_seconds: float = Field(
        default=10.0,
        gt=0,
        description="HTTP timeout in seconds when sending telemetry batches to Aegis.",
    )
    batch_size: int = Field(
        default=25,
        ge=1,
        le=500,
        description="Maximum number of queued telemetry events sent per Aegis flush cycle.",
    )
    max_retries: int = Field(
        default=5,
        ge=0,
        description="Maximum retry attempts with exponential backoff when Aegis is unreachable.",
    )
    poll_gate_before_call: bool = Field(
        default=True,
        description="Check Aegis /api/assets/<assetCode>/gate before executing model calls.",
    )


class ProviderConfig(BaseModel):
    """Configuration for a single model provider endpoint."""

    name: str = Field(description="Logical provider identifier (anthropic, openai, gemini, ollama, vllm).")
    kind: Literal["anthropic", "openai", "gemini", "openai_compatible"] = Field(
        description="Adapter protocol used by the Model Gateway.",
    )
    base_url: Optional[str] = Field(
        default=None,
        description="Optional custom base URL for OpenAI-compatible or local endpoints such as Ollama.",
    )
    api_key_env_var: Optional[str] = Field(
        default=None,
        description="Environment variable holding the API key. Never store raw keys in config files.",
    )
    models: List[str] = Field(
        default_factory=list,
        description="Model identifiers served by this provider.",
    )
    is_local: bool = Field(
        default=False,
        description="Whether this provider runs locally without sending code or prompts externally.",
    )


class RoutingRule(BaseModel):
    """Declarative model routing rule evaluated by the Model Gateway."""

    task_type: TaskType = Field(description="Task type matched by this rule.")
    min_classification: DataClassification = Field(
        default=DataClassification.PUBLIC,
        description="Minimum data classification to which this rule applies.",
    )
    primary_model: str = Field(description="Preferred model identifier for matching requests.")
    fallback_models: List[str] = Field(
        default_factory=list,
        description="Ordered fallback models if the primary model fails or exceeds its cost ceiling.",
    )
    max_cost_usd: Optional[float] = Field(
        default=None,
        ge=0,
        description="Optional per-call USD cost ceiling for this rule.",
    )


class GatewayConfig(BaseModel):
    """Model Gateway controls, redaction, and routing configuration."""

    default_model: str = Field(
        default="claude-3-7-sonnet",
        description="Default model used when no task-specific routing rule matches.",
    )
    allowed_models: List[str] = Field(
        default_factory=lambda: [
            "claude-3-7-sonnet",
            "gpt-4o",
            "gemini-2.5-pro",
            "agnes-coder",
            "qwen2.5-coder:14b",
        ],
        description="Project-wide allow-list of approved models.",
    )
    restricted_allowed_models: List[str] = Field(
        default_factory=lambda: ["qwen2.5-coder:14b"],
        description="Strict allow-list enforced when the repository data classification is 'restricted'.",
    )
    cost_ceiling_usd_per_task: float = Field(
        default=5.0,
        ge=0,
        description="Maximum cumulative USD spend permitted per task before halting.",
    )
    redact_secrets: bool = Field(
        default=True,
        description="Automatically redact API keys, tokens, and private keys before prompts leave the gateway.",
    )
    redact_pii: bool = Field(
        default=True,
        description="Automatically redact email addresses, phone numbers, and national IDs from outbound prompts.",
    )
    store_prompt_bodies: bool = Field(
        default=False,
        description="Store encrypted prompt and response bodies locally when policy permits.",
    )
    providers: List[ProviderConfig] = Field(
        default_factory=lambda: [
            ProviderConfig(
                name="anthropic",
                kind="anthropic",
                api_key_env_var="ANTHROPIC_API_KEY",
                models=["claude-3-7-sonnet"],
                is_local=False,
            ),
            ProviderConfig(
                name="openai",
                kind="openai",
                api_key_env_var="OPENAI_API_KEY",
                models=["gpt-4o"],
                is_local=False,
            ),
            ProviderConfig(
                name="gemini",
                kind="gemini",
                api_key_env_var="GEMINI_API_KEY",
                models=["gemini-2.5-pro"],
                is_local=False,
            ),
            ProviderConfig(
                name="agnes",
                kind="openai_compatible",
                base_url="https://api.agnes.ai/v1",
                api_key_env_var="AGNES_API_KEY",
                models=["agnes-coder"],
                is_local=False,
            ),
            ProviderConfig(
                name="ollama",
                kind="openai_compatible",
                base_url="http://localhost:11434/v1",
                api_key_env_var=None,
                models=["qwen2.5-coder:14b"],
                is_local=True,
            ),
        ],
        description="Configured model providers and their environment variable key references.",
    )
    routing_rules: List[RoutingRule] = Field(
        default_factory=lambda: [
            RoutingRule(
                task_type=TaskType.PLAN,
                primary_model="claude-3-7-sonnet",
                fallback_models=["gemini-2.5-pro", "qwen2.5-coder:14b"],
                max_cost_usd=1.0,
            ),
            RoutingRule(
                task_type=TaskType.GENERATE,
                primary_model="claude-3-7-sonnet",
                fallback_models=["gpt-4o", "qwen2.5-coder:14b"],
                max_cost_usd=2.0,
            ),
            RoutingRule(
                task_type=TaskType.REVIEW,
                primary_model="gemini-2.5-pro",
                fallback_models=["claude-3-7-sonnet", "qwen2.5-coder:14b"],
                max_cost_usd=1.0,
            ),
        ],
        description="Task-based routing rules with cost ceilings and fallback order.",
    )


class RiskTierConfig(BaseModel):
    """Gate and approval requirements for a single risk tier."""

    required_approvals: int = Field(
        default=0,
        ge=0,
        description="Number of distinct human approvals required before merge.",
    )
    require_distinct_approver: bool = Field(
        default=True,
        description="Require approvers to be different individuals from the task requester.",
    )
    max_diff_lines: int = Field(
        default=400,
        ge=1,
        description="Maximum total added and removed lines allowed without elevated review.",
    )
    required_checks: List[str] = Field(
        default_factory=lambda: ["secrets", "sast", "deps", "tests", "diff"],
        description="Security and quality checks that must pass before commit or PR.",
    )
    require_governance_office: bool = Field(
        default=False,
        description="Require Governance Office sign-off in addition to peer approval.",
    )


class PolicyConfig(BaseModel):
    """Governance policy settings editable from config or the web UI."""

    version: str = Field(
        default="1.0.0",
        description="Semantic version of the active policy bundle recorded on every decision and commit.",
    )
    default_risk_tier: RiskTier = Field(
        default=RiskTier.MEDIUM,
        description="Default risk tier assigned to new tasks when not explicitly elevated.",
    )
    risk_tiers: Dict[RiskTier, RiskTierConfig] = Field(
        default_factory=lambda: {
            RiskTier.LOW: RiskTierConfig(
                required_approvals=0,
                require_distinct_approver=False,
                max_diff_lines=250,
                required_checks=["secrets", "sast", "tests", "diff"],
                require_governance_office=False,
            ),
            RiskTier.MEDIUM: RiskTierConfig(
                required_approvals=1,
                require_distinct_approver=True,
                max_diff_lines=600,
                required_checks=["secrets", "sast", "deps", "tests", "diff"],
                require_governance_office=False,
            ),
            RiskTier.HIGH: RiskTierConfig(
                required_approvals=2,
                require_distinct_approver=True,
                max_diff_lines=1000,
                required_checks=["secrets", "sast", "deps", "tests", "diff"],
                require_governance_office=True,
            ),
        },
        description="Per-tier approval, diff-size, and security check requirements.",
    )
    restricted_paths: List[str] = Field(
        default_factory=lambda: [
            ".github/workflows/**",
            ".gitlab-ci.yml",
            "infra/**",
            "terraform/**",
            ".env*",
            "*.pem",
            "*.key",
            ".harness/config.yaml",
        ],
        description="Glob patterns for sensitive paths that trigger elevated approval or block.",
    )
    allowed_tools: List[str] = Field(
        default_factory=lambda: ["read_file", "write_file", "search", "pytest", "ruff", "git"],
        description="Tools that AI agents are permitted to invoke inside the sandbox.",
    )
    allowed_commands: List[str] = Field(
        default_factory=lambda: ["pytest", "ruff", "mypy", "git status", "git diff", "python -m pytest"],
        description="Shell commands allow-listed for agent execution.",
    )
    require_signed_commits: bool = Field(
        default=True,
        description="Reject unsigned commits and require SSH or GPG commit signatures.",
    )


class GitConfig(BaseModel):
    """Git workflow, provenance trailer, and compliance thresholds."""

    base_branch: str = Field(
        default="main",
        description="Protected base branch that agents may never write to directly.",
    )
    branch_prefix: str = Field(
        default="agent/",
        description="Branch prefix used for isolated agent task branches (agent/<task-id>).",
    )
    commit_signing: Literal["ssh", "gpg"] = Field(
        default="ssh",
        description="Commit signing mechanism enforced by pre-commit and CI gates.",
    )
    min_test_coverage_pct: float = Field(
        default=80.0,
        ge=0.0,
        le=100.0,
        description="Minimum unit test coverage percentage required to pass check-in gates.",
    )
    allowed_licences: List[str] = Field(
        default_factory=lambda: ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "PSF-2.0"],
        description="SPDX licence identifiers permitted for project dependencies.",
    )


class SandboxConfig(BaseModel):
    """Execution isolation and resource limits for agent actions."""

    mode: Literal["docker", "worktree"] = Field(
        default="worktree",
        description="Isolation backend used for agent tasks (Docker container or Git worktree).",
    )
    network_enabled: bool = Field(
        default=False,
        description="Allow outbound network access inside the sandbox. Disabled by default for security.",
    )
    cpu_limit: float = Field(
        default=2.0,
        gt=0,
        description="CPU core limit allocated to sandboxed container runs.",
    )
    memory_limit_mb: int = Field(
        default=2048,
        ge=256,
        description="Memory cap in megabytes for sandboxed container runs.",
    )
    timeout_seconds: int = Field(
        default=300,
        ge=10,
        description="Maximum execution duration in seconds for a single sandboxed command.",
    )


class AuditConfig(BaseModel):
    """Paths and signing settings for the tamper-evident audit log."""

    log_path: str = Field(
        default=".harness/audit.jsonl",
        description="Path to the append-only SHA-256 hash-chained audit log.",
    )
    state_db_path: str = Field(
        default=".harness/state.db",
        description="Path to the local SQLite state database for tasks, approvals, and telemetry queue.",
    )
    checkpoint_dir: str = Field(
        default=".harness/checkpoints",
        description="Directory storing daily signed checkpoint hashes.",
    )
    signing_key_env_var: str = Field(
        default="HARNESS_AUDIT_SIGNING_KEY",
        description="Environment variable holding the HMAC signing key for daily checkpoints.",
    )


class DashboardConfig(BaseModel):
    """Local web dashboard and configuration UI settings."""

    host: str = Field(
        default="127.0.0.1",
        description="Bind address for the local web dashboard. Keep 127.0.0.1 for local-only access.",
    )
    port: int = Field(
        default=8787,
        ge=1024,
        le=65535,
        description="TCP port for the local web dashboard and configuration UI.",
    )
    auth_enabled: bool = Field(
        default=True,
        description="Require token authentication before accessing the dashboard, Coding Studio, and configuration UI.",
    )
    auth_token_env_var: str = Field(
        default="HARNESS_DASHBOARD_TOKEN",
        description="Environment variable holding the dashboard access token. Auto-generated in .harness/keys/dashboard.token if unset.",
    )
    session_ttl_minutes: int = Field(
        default=480,
        ge=5,
        description="Lifetime in minutes for signed browser session cookies.",
    )


class HarnessConfig(BaseModel):
    """Root configuration model for Aegis Harness."""

    project: ProjectConfig = Field(
        default_factory=ProjectConfig,
        description="Repository identity, data classification, and local or GitHub remote settings.",
    )
    aegis: AegisConfig = Field(
        default_factory=AegisConfig,
        description="Aegis telemetry endpoint, token variable, batching, and circuit-breaker settings.",
    )
    gateway: GatewayConfig = Field(
        default_factory=GatewayConfig,
        description="Model providers, allow-lists, routing rules, cost ceilings, and secret redaction.",
    )
    policy: PolicyConfig = Field(
        default_factory=PolicyConfig,
        description="Three-tier risk rules, restricted paths, allowed tools, and commit signing policy.",
    )
    git: GitConfig = Field(
        default_factory=GitConfig,
        description="Protected base branch, agent branch prefix, coverage threshold, and licence allow-list.",
    )
    sandbox: SandboxConfig = Field(
        default_factory=SandboxConfig,
        description="Execution isolation backend, network policy, and CPU, memory, and time limits.",
    )
    audit: AuditConfig = Field(
        default_factory=AuditConfig,
        description="Local tamper-evident audit log, SQLite state path, and checkpoint signing settings.",
    )
    dashboard: DashboardConfig = Field(
        default_factory=DashboardConfig,
        description="Host and port settings for the local web dashboard and configuration UI.",
    )
