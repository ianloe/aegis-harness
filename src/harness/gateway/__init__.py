"""Model Gateway module with provider adapters, redaction, routing, and cost capture."""

from harness.gateway.adapters import (
    AnthropicAdapter,
    GeminiAdapter,
    ModelAdapter,
    ModelRequest,
    ModelResponse,
    OpenAIAdapter,
    ProviderError,
    build_adapter,
)
from harness.gateway.pricing import estimate_cost_usd
from harness.gateway.redactor import RedactionResult, redact_prompt
from harness.gateway.router import GatewayCallRecord, GatewayError, GatewayResult, ModelGateway

__all__ = [
    "AnthropicAdapter",
    "GatewayCallRecord",
    "GatewayError",
    "GatewayResult",
    "GeminiAdapter",
    "ModelAdapter",
    "ModelGateway",
    "ModelRequest",
    "ModelResponse",
    "OpenAIAdapter",
    "ProviderError",
    "RedactionResult",
    "build_adapter",
    "estimate_cost_usd",
    "redact_prompt",
]
