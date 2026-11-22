"""Model Gateway router with allow-list enforcement, redaction, fallback, and cost capture."""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from pathlib import Path
from typing import Dict, List, Optional

import httpx
from cryptography.fernet import Fernet
from pydantic import BaseModel, Field

from harness.audit.chain import AuditChain
from harness.config.schema import DataClassification, HarnessConfig, ProviderConfig, TaskType
from harness.gateway.adapters import ModelAdapter, ModelRequest, ModelResponse, ProviderError, build_adapter
from harness.gateway.pricing import estimate_cost_usd
from harness.gateway.redactor import redact_prompt

CLASSIFICATION_ORDER = {
    DataClassification.PUBLIC: 0,
    DataClassification.INTERNAL: 1,
    DataClassification.CONFIDENTIAL: 2,
    DataClassification.RESTRICTED: 3,
}


class GatewayError(RuntimeError):
    """Raised when the Model Gateway denies a request or all fallbacks fail."""


class GatewayCallRecord(BaseModel):
    """Governance metadata captured for every Model Gateway call."""

    call_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    model: str
    provider: str
    version: str
    prompt_hash: str
    input_tokens: int
    output_tokens: int
    total_tokens: int
    latency_ms: int
    cost_usd: float
    policy_decision: str
    redacted_categories: List[str] = Field(default_factory=list)
    fallback_used: bool = False
    encrypted_body_path: Optional[str] = None


class GatewayResult(BaseModel):
    """Combined model response and governance call record."""

    response: ModelResponse
    record: GatewayCallRecord


class ModelGateway:
    """Routes prompts to approved providers with redaction, cost ceilings, and audit logging."""

    def __init__(
        self,
        config: HarnessConfig,
        audit: AuditChain,
        *,
        workspace_root: Optional[Path] = None,
        http_client: Optional[httpx.Client] = None,
        adapters: Optional[Dict[str, ModelAdapter]] = None,
    ) -> None:
        self.config = config
        self.audit = audit
        self.workspace_root = (workspace_root or Path.cwd()).resolve()
        self._http_client = http_client
        self._adapters = adapters or {}
        self._task_spend_usd: Dict[str, float] = {}

    def _find_provider_for_model(self, model: str) -> ProviderConfig:
        for provider in self.config.gateway.providers:
            if model in provider.models:
                return provider
        raise GatewayError(f"No configured provider serves model '{model}'.")

    def _get_adapter(self, provider: ProviderConfig) -> ModelAdapter:
        if provider.name in self._adapters:
            return self._adapters[provider.name]
        adapter = build_adapter(provider, client=self._http_client)
        self._adapters[provider.name] = adapter
        return adapter

    def _is_model_allowed(self, model: str, provider: ProviderConfig) -> tuple[bool, str]:
        classification = self.config.project.data_classification
        if classification == DataClassification.RESTRICTED:
            if model not in self.config.gateway.restricted_allowed_models and not provider.is_local:
                return (
                    False,
                    f"Model '{model}' is not permitted for 'restricted' repositories "
                    f"(must be local or in restricted_allowed_models).",
                )
        elif model not in self.config.gateway.allowed_models:
            return False, f"Model '{model}' is not in gateway.allowed_models."
        return True, "Model permitted by project allow-list."

    def resolve_candidates(
        self,
        task_type: TaskType,
        model_override: Optional[str] = None,
    ) -> List[str]:
        """Determine ordered candidate models from explicit override or YAML routing rules."""
        if model_override:
            return [model_override]

        repo_rank = CLASSIFICATION_ORDER[self.config.project.data_classification]
        for rule in self.config.gateway.routing_rules:
            if rule.task_type == task_type and repo_rank >= CLASSIFICATION_ORDER[rule.min_classification]:
                return [rule.primary_model, *rule.fallback_models]

        return [self.config.gateway.default_model]

    def _encrypt_body(self, call_id: str, prompt: str, response_text: str) -> str:
        key_env = os.environ.get("HARNESS_BODY_ENCRYPTION_KEY")
        if key_env:
            fernet_key = key_env.encode("utf-8")
        else:
            key_path = self.workspace_root / ".harness" / "keys" / "body.key"
            if key_path.exists():
                fernet_key = key_path.read_bytes().strip()
            else:
                key_path.parent.mkdir(parents=True, exist_ok=True)
                fernet_key = Fernet.generate_key()
                key_path.write_bytes(fernet_key)
                os.chmod(key_path, 0o600)

        fernet = Fernet(fernet_key)
        payload = json.dumps({"prompt": prompt, "response": response_text}).encode("utf-8")
        token = fernet.encrypt(payload)
        out_path = self.workspace_root / ".harness" / "bodies" / f"{call_id}.enc"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(token)
        return str(out_path)

    def complete(
        self,
        *,
        prompt: str,
        task_type: TaskType = TaskType.GENERATE,
        task_id: str = "no-task",
        session_id: str = "no-session",
        actor: str = "agent:harness",
        model_override: Optional[str] = None,
        system_prompt: Optional[str] = None,
        max_tokens: int = 1024,
    ) -> GatewayResult:
        """Route, redact, invoke, cost-track, and audit a coding model call."""
        spent = self._task_spend_usd.get(task_id, 0.0)
        if spent >= self.config.gateway.cost_ceiling_usd_per_task:
            self.audit.append(
                event_type="model_call_denied",
                actor=actor,
                outcome="deny",
                session_id=session_id,
                task_id=task_id,
                repository=self.config.project.name,
                policy_version=self.config.policy.version,
                data_classification=self.config.project.data_classification.value,
                details={"reason": "Task cost ceiling reached", "spent_usd": spent},
            )
            raise GatewayError(
                f"Task '{task_id}' has reached its USD cost ceiling "
                f"({spent:.4f} >= {self.config.gateway.cost_ceiling_usd_per_task:.4f})."
            )

        redaction = redact_prompt(
            prompt,
            redact_secrets=self.config.gateway.redact_secrets,
            redact_pii=self.config.gateway.redact_pii,
        )
        prompt_hash = hashlib.sha256(redaction.redacted_text.encode("utf-8")).hexdigest()

        candidates = self.resolve_candidates(task_type, model_override=model_override)
        last_error: Optional[str] = None

        for idx, candidate in enumerate(candidates):
            provider = self._find_provider_for_model(candidate)
            allowed, reason = self._is_model_allowed(candidate, provider)
            if not allowed:
                last_error = reason
                self.audit.append(
                    event_type="model_call_denied",
                    actor=actor,
                    outcome="deny",
                    session_id=session_id,
                    task_id=task_id,
                    repository=self.config.project.name,
                    model=candidate,
                    policy_version=self.config.policy.version,
                    data_classification=self.config.project.data_classification.value,
                    details={"reason": reason, "provider": provider.name},
                )
                continue

            adapter = self._get_adapter(provider)
            try:
                response = adapter.generate(
                    ModelRequest(
                        model=candidate,
                        prompt=redaction.redacted_text,
                        system_prompt=system_prompt,
                        max_tokens=max_tokens,
                    )
                )
            except ProviderError as exc:
                last_error = str(exc)
                continue

            cost_usd = estimate_cost_usd(
                response.model,
                response.input_tokens,
                response.output_tokens,
                is_local=provider.is_local,
            )
            self._task_spend_usd[task_id] = spent + cost_usd

            call_id = str(uuid.uuid4())
            encrypted_path = (
                self._encrypt_body(call_id, redaction.redacted_text, response.content)
                if self.config.gateway.store_prompt_bodies
                else None
            )

            record = GatewayCallRecord(
                call_id=call_id,
                model=response.model,
                provider=response.provider,
                version=response.version,
                prompt_hash=prompt_hash,
                input_tokens=response.input_tokens,
                output_tokens=response.output_tokens,
                total_tokens=response.input_tokens + response.output_tokens,
                latency_ms=response.latency_ms,
                cost_usd=cost_usd,
                policy_decision="allow",
                redacted_categories=redaction.categories,
                fallback_used=idx > 0,
                encrypted_body_path=encrypted_path,
            )
            self.audit.append(
                event_type="model_call",
                actor=actor,
                outcome="allow",
                session_id=session_id,
                task_id=task_id,
                repository=self.config.project.name,
                model=record.model,
                policy_version=self.config.policy.version,
                data_classification=self.config.project.data_classification.value,
                details={
                    "provider": record.provider,
                    "version": record.version,
                    "prompt_hash": record.prompt_hash,
                    "input_tokens": record.input_tokens,
                    "output_tokens": record.output_tokens,
                    "latency_ms": record.latency_ms,
                    "cost_usd": record.cost_usd,
                    "redacted_categories": record.redacted_categories,
                    "fallback_used": record.fallback_used,
                },
            )
            return GatewayResult(response=response, record=record)

        raise GatewayError(f"All candidate models failed or were denied. Last error: {last_error}")
