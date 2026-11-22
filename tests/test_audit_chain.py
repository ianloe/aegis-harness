"""Tests for the tamper-evident SHA-256 audit hash chain."""

import json
from pathlib import Path

from harness.audit.chain import GENESIS_HASH, AuditChain


def test_hash_chain_links_and_verifies(tmp_path: Path) -> None:
    chain = AuditChain(tmp_path / "audit.jsonl", tmp_path / "checkpoints")
    e1 = chain.append(event_type="session_start", actor="human:alice", task_id="task-1")
    e2 = chain.append(event_type="model_call", actor="agent:harness", task_id="task-1", model="gpt-4o")
    e3 = chain.append(event_type="commit", actor="human:alice", task_id="task-1")

    assert e1.prev_hash == GENESIS_HASH
    assert e2.prev_hash == e1.entry_hash
    assert e3.prev_hash == e2.entry_hash

    res = chain.verify()
    assert res.valid is True
    assert res.entries_checked == 3
    assert res.head_hash == e3.entry_hash


def test_editing_past_audit_entry_fails_verify(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    chain = AuditChain(log_path, tmp_path / "checkpoints")
    chain.append(event_type="session_start", actor="human:alice", task_id="task-1")
    chain.append(event_type="policy_decision", actor="agent:harness", outcome="allow", task_id="task-1")
    chain.append(event_type="commit", actor="human:alice", task_id="task-1")

    # Tamper with line 2 outcome
    lines = log_path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[1])
    tampered["outcome"] = "deny"
    lines[1] = json.dumps(tampered)
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    res = chain.verify()
    assert res.valid is False
    assert res.tampered_line == 2
    assert res.error is not None


def test_create_daily_checkpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HARNESS_AUDIT_SIGNING_KEY", "test-signing-key-123")
    chain = AuditChain(tmp_path / "audit.jsonl", tmp_path / "checkpoints")
    e1 = chain.append(event_type="harness_init", actor="human:alice")

    cp = chain.create_checkpoint()
    assert cp.entries_count == 1
    assert cp.head_hash == e1.entry_hash
    assert len(cp.signature) == 64
    assert (tmp_path / "checkpoints" / f"{cp.date_utc}.json").exists()
