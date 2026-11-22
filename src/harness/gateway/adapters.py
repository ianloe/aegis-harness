"""Provider-agnostic model adapters for Anthropic, OpenAI, Gemini, and OpenAI-compatible endpoints."""

from __future__ import annotations

import os
import time
from abc import ABC, abstractmethod
from typing import Optional

import httpx
from pydantic import BaseModel, Field

from harness.config.schema import ProviderConfig


class ModelRequest(BaseModel):
    """Normalised outbound model request."""

    model: str
    prompt: str
    system_prompt: Optional[str] = None
    max_tokens: int = 1024
    temperature: float = 0.2


class ModelResponse(BaseModel):
    """Normalised inbound model response with usage and latency."""

    model: str
    provider: str
    version: str = "latest"
    content: str
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    latency_ms: int = Field(default=0, ge=0)


class ProviderError(RuntimeError):
    """Raised when a model provider returns an error or missing credential."""


class ModelAdapter(ABC):
    """Abstract base class for model provider adapters."""

    def __init__(
        self,
        provider: ProviderConfig,
        client: Optional[httpx.Client] = None,
        timeout: float = 30.0,
    ) -> None:
        self.provider = provider
        self._client = client or httpx.Client(timeout=timeout)

    def _resolve_api_key(self) -> Optional[str]:
        if not self.provider.api_key_env_var:
            return None
        key = os.environ.get(self.provider.api_key_env_var)
        if not key:
            raise ProviderError(
                f"Missing API key in environment variable '{self.provider.api_key_env_var}' "
                f"for provider '{self.provider.name}'."
            )
        return key

    @abstractmethod
    def generate(self, request: ModelRequest) -> ModelResponse:
        """Execute a completion request against the provider."""


class AnthropicAdapter(ModelAdapter):
    """Adapter for the Anthropic Messages API."""

    def generate(self, request: ModelRequest) -> ModelResponse:
        api_key = self._resolve_api_key()
        url = (self.provider.base_url or "https://api.anthropic.com").rstrip("/") + "/v1/messages"
        payload = {
            "model": request.model,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "messages": [{"role": "user", "content": request.prompt}],
        }
        if request.system_prompt:
            payload["system"] = request.system_prompt

        t0 = time.monotonic()
        resp = self._client.post(
            url,
            headers={
                "x-api-key": api_key or "",
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json=payload,
        )
        latency_ms = int((time.monotonic() - t0) * 1000)
        if resp.status_code >= 400:
            raise ProviderError(f"Anthropic error {resp.status_code}: {resp.text[:200]}")

        data = resp.json()
        blocks = data.get("content", [])
        text = "".join(b.get("text", "") for b in blocks if isinstance(b, dict))
        usage = data.get("usage", {})
        return ModelResponse(
            model=data.get("model", request.model),
            provider=self.provider.name,
            version=str(data.get("model", request.model)),
            content=text,
            input_tokens=int(usage.get("input_tokens", 0)),
            output_tokens=int(usage.get("output_tokens", 0)),
            latency_ms=latency_ms,
        )


class OpenAIAdapter(ModelAdapter):
    """Adapter for OpenAI and OpenAI-compatible Chat Completions APIs (Ollama, vLLM)."""

    def generate(self, request: ModelRequest) -> ModelResponse:
        api_key = self._resolve_api_key() if self.provider.api_key_env_var else None
        base = (self.provider.base_url or "https://api.openai.com/v1").rstrip("/")
        url = f"{base}/chat/completions"

        messages = []
        if request.system_prompt:
            messages.append({"role": "system", "content": request.system_prompt})
        messages.append({"role": "user", "content": request.prompt})

        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        t0 = time.monotonic()
        resp = self._client.post(
            url,
            headers=headers,
            json={
                "model": request.model,
                "messages": messages,
                "max_tokens": request.max_tokens,
                "temperature": request.temperature,
            },
        )
        latency_ms = int((time.monotonic() - t0) * 1000)
        if resp.status_code >= 400:
            raise ProviderError(f"{self.provider.name} error {resp.status_code}: {resp.text[:200]}")

        data = resp.json()
        choices = data.get("choices", [])
        text = choices[0].get("message", {}).get("content", "") if choices else ""
        usage = data.get("usage", {})
        return ModelResponse(
            model=data.get("model", request.model),
            provider=self.provider.name,
            version=str(data.get("model", request.model)),
            content=text,
            input_tokens=int(usage.get("prompt_tokens", 0)),
            output_tokens=int(usage.get("completion_tokens", 0)),
            latency_ms=latency_ms,
        )


class GeminiAdapter(ModelAdapter):
    """Adapter for the Google Gemini generateContent API."""

    def generate(self, request: ModelRequest) -> ModelResponse:
        api_key = self._resolve_api_key()
        base = (self.provider.base_url or "https://generativelanguage.googleapis.com/v1beta").rstrip("/")
        url = f"{base}/models/{request.model}:generateContent"

        payload: dict = {
            "contents": [{"role": "user", "parts": [{"text": request.prompt}]}],
            "generationConfig": {
                "maxOutputTokens": request.max_tokens,
                "temperature": request.temperature,
            },
        }
        if request.system_prompt:
            payload["systemInstruction"] = {"parts": [{"text": request.system_prompt}]}

        t0 = time.monotonic()
        resp = self._client.post(
            url,
            headers={"x-goog-api-key": api_key or "", "Content-Type": "application/json"},
            json=payload,
        )
        latency_ms = int((time.monotonic() - t0) * 1000)
        if resp.status_code >= 400:
            raise ProviderError(f"Gemini error {resp.status_code}: {resp.text[:200]}")

        data = resp.json()
        candidates = data.get("candidates", [])
        parts = candidates[0].get("content", {}).get("parts", []) if candidates else []
        text = "".join(p.get("text", "") for p in parts if isinstance(p, dict))
        meta = data.get("usageMetadata", {})
        return ModelResponse(
            model=request.model,
            provider=self.provider.name,
            version=str(data.get("modelVersion", request.model)),
            content=text,
            input_tokens=int(meta.get("promptTokenCount", 0)),
            output_tokens=int(meta.get("candidatesTokenCount", 0)),
            latency_ms=latency_ms,
        )


def build_adapter(provider: ProviderConfig, client: Optional[httpx.Client] = None) -> ModelAdapter:
    """Instantiate the matching ModelAdapter for a ProviderConfig."""
    if provider.kind == "anthropic":
        return AnthropicAdapter(provider, client=client)
    if provider.kind in ("openai", "openai_compatible"):
        return OpenAIAdapter(provider, client=client)
    if provider.kind == "gemini":
        return GeminiAdapter(provider, client=client)
    raise ValueError(f"Unsupported provider kind: {provider.kind}")
