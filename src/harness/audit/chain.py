"""Append-only SHA-256 hash-chained audit log with verification and daily checkpoints."""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import secrets
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field

GENESIS_HASH = "0" * 64


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


class AuditEntry(BaseModel):
    """Single immutable entry in the Harness local audit hash chain."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=utc_now_iso)
    session_id: str = "no-session"
    task_id: str = "no-task"
    actor: str = "human:unknown"
    event_type: str
    repository: str = "local"
    branch: str = "main"
    model: Optional[str] = None
    risk_tier: str = "medium"
    policy_version: str = "1.0.0"
    data_classification: str = "internal"
    outcome: str = "success"
    details: Dict[str, Any] = Field(default_factory=dict)
    prev_hash: str = GENESIS_HASH
    entry_hash: str = ""

    def compute_hash(self) -> str:
        """Compute deterministic SHA-256 hash over all fields except `entry_hash`."""
        payload = self.model_dump(exclude={"entry_hash"})
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class VerifyResult(BaseModel):
    """Outcome of verifying the audit log hash chain."""

    valid: bool
    entries_checked: int
    head_hash: str
    tampered_line: Optional[int] = None
    error: Optional[str] = None


class DailyCheckpoint(BaseModel):
    """Signed daily checkpoint of the audit log head hash."""

    date_utc: str
    created_at: str
    entries_count: int
    head_hash: str
    signature_alg: str = "HMAC-SHA256"
    signature: str


class AuditChain:
    """Manages an append-only hash-chained JSONL audit log."""

    def __init__(self, log_path: Path, checkpoint_dir: Optional[Path] = None) -> None:
        self.log_path = log_path
        self.checkpoint_dir = checkpoint_dir or (log_path.parent / "checkpoints")

    def _read_tail_hash(self) -> str:
        if not self.log_path.exists() or self.log_path.stat().st_size == 0:
            return GENESIS_HASH
        last_line = ""
        with self.log_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped:
                    last_line = stripped
        if not last_line:
            return GENESIS_HASH
        data = json.loads(last_line)
        return str(data["entry_hash"])

    def append(
        self,
        *,
        event_type: str,
        actor: str,
        outcome: str = "success",
        session_id: str = "no-session",
        task_id: str = "no-task",
        repository: str = "local",
        branch: str = "main",
        model: Optional[str] = None,
        risk_tier: str = "medium",
        policy_version: str = "1.0.0",
        data_classification: str = "internal",
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditEntry:
        """Append a new hash-chained entry to the audit log."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.log_path.with_suffix(".lock")
        with lock_path.open("a+", encoding="utf-8") as lock_fh:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
            try:
                prev_hash = self._read_tail_hash()
                entry = AuditEntry(
                    event_type=event_type,
                    actor=actor,
                    outcome=outcome,
                    session_id=session_id,
                    task_id=task_id,
                    repository=repository,
                    branch=branch,
                    model=model,
                    risk_tier=risk_tier,
                    policy_version=policy_version,
                    data_classification=data_classification,
                    details=details or {},
                    prev_hash=prev_hash,
                )
                entry.entry_hash = entry.compute_hash()
                with self.log_path.open("a", encoding="utf-8") as fh:
                    fh.write(entry.model_dump_json() + "\n")
                return entry
            finally:
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)

    def read_all(self) -> list[AuditEntry]:
        """Read all audit entries from disk."""
        if not self.log_path.exists():
            return []
        entries: list[AuditEntry] = []
        with self.log_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped:
                    entries.append(AuditEntry.model_validate_json(stripped))
        return entries

    def verify(self) -> VerifyResult:
        """Verify the entire hash chain from genesis to the latest entry."""
        if not self.log_path.exists():
            return VerifyResult(valid=True, entries_checked=0, head_hash=GENESIS_HASH)

        expected_prev = GENESIS_HASH
        count = 0
        with self.log_path.open("r", encoding="utf-8") as fh:
            for line_no, raw_line in enumerate(fh, start=1):
                stripped = raw_line.strip()
                if not stripped:
                    continue
                try:
                    entry = AuditEntry.model_validate_json(stripped)
                except Exception as exc:
                    return VerifyResult(
                        valid=False,
                        entries_checked=count,
                        head_hash=expected_prev,
                        tampered_line=line_no,
                        error=f"Malformed audit entry at line {line_no}: {exc}",
                    )

                if entry.prev_hash != expected_prev:
                    return VerifyResult(
                        valid=False,
                        entries_checked=count,
                        head_hash=expected_prev,
                        tampered_line=line_no,
                        error=(
                            f"Broken hash chain at line {line_no}: "
                            f"expected prev_hash {expected_prev}, got {entry.prev_hash}"
                        ),
                    )

                recomputed = entry.compute_hash()
                if entry.entry_hash != recomputed:
                    return VerifyResult(
                        valid=False,
                        entries_checked=count,
                        head_hash=expected_prev,
                        tampered_line=line_no,
                        error=(
                            f"Entry hash mismatch at line {line_no}: "
                            f"stored {entry.entry_hash}, computed {recomputed}"
                        ),
                    )

                expected_prev = entry.entry_hash
                count += 1

        return VerifyResult(valid=True, entries_checked=count, head_hash=expected_prev)

    def _get_or_create_signing_key(self, env_var: str = "HARNESS_AUDIT_SIGNING_KEY") -> bytes:
        env_key = os.environ.get(env_var)
        if env_key:
            return env_key.encode("utf-8")

        key_file = self.log_path.parent / "keys" / "checkpoint.key"
        if key_file.exists():
            return key_file.read_bytes().strip()

        key_file.parent.mkdir(parents=True, exist_ok=True)
        generated = secrets.token_hex(32)
        key_file.write_text(generated, encoding="utf-8")
        os.chmod(key_file, 0o600)
        return generated.encode("utf-8")

    def create_checkpoint(self, signing_key_env_var: str = "HARNESS_AUDIT_SIGNING_KEY") -> DailyCheckpoint:
        """Verify the chain and write a daily HMAC-SHA256 signed checkpoint."""
        verification = self.verify()
        if not verification.valid:
            raise ValueError(f"Cannot checkpoint tampered audit log: {verification.error}")

        now = datetime.now(timezone.utc)
        date_utc = now.strftime("%Y-%m-%d")
        key = self._get_or_create_signing_key(signing_key_env_var)
        message = f"{date_utc}|{verification.entries_checked}|{verification.head_hash}".encode("utf-8")
        signature = hmac.new(key, message, hashlib.sha256).hexdigest()

        checkpoint = DailyCheckpoint(
            date_utc=date_utc,
            created_at=now.isoformat(),
            entries_count=verification.entries_checked,
            head_hash=verification.head_hash,
            signature=signature,
        )
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        out_path = self.checkpoint_dir / f"{date_utc}.json"
        out_path.write_text(checkpoint.model_dump_json(indent=2), encoding="utf-8")
        return checkpoint
