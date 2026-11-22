"""Tests for Model Gateway routing, adapters, redaction, fallback, and cost tracking."""

import json
from pathlib import Path

import httpx
import pytest

from harness.audit.chain import AuditChain
from harness.config import DataClassification, TaskType, default_config
from harness.gateway import GatewayError, ModelGateway, redact_prompt


def _mock_transport(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_secret_and_pii_redaction_never_leaks_value() -> None:
    fake_secret = "sk-proj-1234567890abcdefghijklmnop"
    fake_aws = "AKIAIOSFODNN7EXAMPLE"
    prompt = f"Deploy with key {fake_secret} and AWS {fake_aws} for alice@example.com"

    res = redact_prompt(prompt)
    assert fake_secret not in res.redacted_text
    assert fake_aws not in res.redacted_text
    assert "alice@example.com" not in res.redacted_text
    assert "api_key" in res.categories
    assert "aws_access_key" in res.categories
    assert "email" in res.categories


def test_switching_providers_with_no_code_change(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-anth-key")
    monkeypatch.setenv("OPENAI_API_KEY", "test-oai-key")
    monkeypatch.setenv("GEMINI_API_KEY", "test-gem-key")
    monkeypatch.setenv("AGNES_API_KEY", "test-agnes-key")

    seen_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_urls.append(str(request.url))
        url = str(request.url)
        if "anthropic.com" in url:
            return httpx.Response(
                200,
                json={
                    "model": "claude-4-sonnet",
                    "content": [{"type": "text", "text": "anthropic ok"}],
                    "usage": {"input_tokens": 100, "output_tokens": 50},
                },
            )
        if "openai.com" in url:
            return httpx.Response(
                200,
                json={
                    "model": "gpt-5",
                    "choices": [{"message": {"content": "openai ok"}}],
                    "usage": {"prompt_tokens": 120, "completion_tokens": 60},
                },
            )
        if "generativelanguage.googleapis.com" in url:
            return httpx.Response(
                200,
                json={
                    "modelVersion": "gemini-4-hydrogen",
                    "candidates": [{"content": {"parts": [{"text": "gemini ok"}]}}],
                    "usageMetadata": {"promptTokenCount": 80, "candidatesTokenCount": 40},
                },
            )
        if "agnes.ai" in url:
            return httpx.Response(
                200,
                json={
                    "model": "agnes-coder",
                    "choices": [{"message": {"content": "agnes ok"}}],
                    "usage": {"prompt_tokens": 100, "completion_tokens": 40},
                },
            )
        # Ollama local
        return httpx.Response(
            200,
            json={
                "model": "qwen3-coder:14b",
                "choices": [{"message": {"content": "ollama ok"}}],
                "usage": {"prompt_tokens": 90, "completion_tokens": 30},
            },
        )

    cfg = default_config("gw-demo", "AI-001")
    audit = AuditChain(tmp_path / "audit.jsonl")
    gw = ModelGateway(cfg, audit, workspace_root=tmp_path, http_client=_mock_transport(handler))

    r1 = gw.complete(prompt="Write hello world", model_override="claude-4-sonnet", task_id="t1")
    r2 = gw.complete(prompt="Write hello world", model_override="gpt-5", task_id="t1")
    r3 = gw.complete(prompt="Write hello world", model_override="gemini-4-hydrogen", task_id="t1")
    r4 = gw.complete(prompt="Write hello world", model_override="agnes-coder", task_id="t1")
    r5 = gw.complete(prompt="Write hello world", model_override="qwen3-coder:14b", task_id="t1")

    assert r1.record.provider == "anthropic"
    assert r2.record.provider == "openai"
    assert r3.record.provider == "gemini"
    assert r4.record.provider == "agnes"
    assert r5.record.provider == "ollama"
    assert r5.record.cost_usd == 0.0
    assert len(seen_urls) == 5


def test_prompt_secret_redacted_before_outbound_call_and_not_in_audit(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-oai-key")
    captured_body: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_body.update(json.loads(request.content.decode("utf-8")))
        return httpx.Response(
            200,
            json={
                "model": "gpt-5",
                "choices": [{"message": {"content": "done"}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            },
        )

    cfg = default_config("redact-demo", "AI-001")
    audit = AuditChain(tmp_path / "audit.jsonl")
    gw = ModelGateway(cfg, audit, workspace_root=tmp_path, http_client=_mock_transport(handler))

    fake_secret = "ghp_1234567890abcdefghijklmnopqrstuv"
    result = gw.complete(prompt=f"Use token {fake_secret}", model_override="gpt-5", task_id="t2")

    sent_content = captured_body["messages"][-1]["content"]
    assert fake_secret not in sent_content
    assert "[REDACTED:GITHUB_TOKEN]" in sent_content
    assert result.record.redacted_categories == ["github_token"]

    audit_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert fake_secret not in audit_text
    assert "github_token" in audit_text


def test_fallback_on_primary_failure(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-anth-key")
    monkeypatch.setenv("OPENAI_API_KEY", "test-oai-key")

    def handler(request: httpx.Request) -> httpx.Response:
        if "anthropic.com" in str(request.url):
            return httpx.Response(503, text="overloaded")
        return httpx.Response(
            200,
            json={
                "model": "gpt-5",
                "choices": [{"message": {"content": "fallback ok"}}],
                "usage": {"prompt_tokens": 20, "completion_tokens": 10},
            },
        )

    cfg = default_config("fallback-demo", "AI-001")
    audit = AuditChain(tmp_path / "audit.jsonl")
    gw = ModelGateway(cfg, audit, workspace_root=tmp_path, http_client=_mock_transport(handler))

    res = gw.complete(prompt="Generate tests", task_type=TaskType.GENERATE, task_id="t3")
    assert res.record.model == "gpt-5"
    assert res.record.fallback_used is True


def test_restricted_repo_blocks_cloud_models(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-oai-key")

    def handler(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("Network call should not be made for denied model")

    cfg = default_config("restricted-repo", "AI-001")
    cfg.project.data_classification = DataClassification.RESTRICTED
    audit = AuditChain(tmp_path / "audit.jsonl")
    gw = ModelGateway(cfg, audit, workspace_root=tmp_path, http_client=_mock_transport(handler))

    with pytest.raises(GatewayError, match="restricted"):
        gw.complete(prompt="Hello", model_override="gpt-5", task_id="t4")


def test_encrypted_body_storage_when_enabled(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-oai-key")

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "model": "gpt-5",
                "choices": [{"message": {"content": "secret response text"}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            },
        )

    cfg = default_config("enc-demo", "AI-001")
    cfg.gateway.store_prompt_bodies = True
    audit = AuditChain(tmp_path / "audit.jsonl")
    gw = ModelGateway(cfg, audit, workspace_root=tmp_path, http_client=_mock_transport(handler))

    res = gw.complete(prompt="sensitive prompt", model_override="gpt-5", task_id="t5")
    assert res.record.encrypted_body_path is not None
    enc_bytes = Path(res.record.encrypted_body_path).read_bytes()
    assert b"sensitive prompt" not in enc_bytes
    assert b"secret response text" not in enc_bytes
