"""Token pricing table and USD cost estimation for coding models."""

from __future__ import annotations

from typing import Dict, Tuple

# (input_usd_per_1m_tokens, output_usd_per_1m_tokens)
MODEL_PRICING_USD_PER_1M: Dict[str, Tuple[float, float]] = {
    "claude-3-7-sonnet": (3.00, 15.00),
    "claude-3-5-sonnet": (3.00, 15.00),
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-mini": (0.15, 0.60),
    "gemini-2.5-pro": (1.25, 10.00),
    "gemini-2.5-flash": (0.15, 0.60),
    "agnes-coder": (1.50, 6.00),
    "qwen2.5-coder:14b": (0.0, 0.0),
    "llama3.1:8b": (0.0, 0.0),
}


def estimate_cost_usd(
    model: str,
    input_tokens: int,
    output_tokens: int,
    *,
    is_local: bool = False,
) -> float:
    """Estimate USD cost for a single model invocation."""
    if is_local:
        return 0.0
    in_rate, out_rate = MODEL_PRICING_USD_PER_1M.get(model, (2.00, 8.00))
    cost = (input_tokens / 1_000_000.0) * in_rate + (output_tokens / 1_000_000.0) * out_rate
    return round(cost, 6)
