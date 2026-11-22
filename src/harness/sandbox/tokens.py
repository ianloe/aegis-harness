"""Short-lived, least-privilege per-task scoped tokens."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class ScopedTaskToken(BaseModel):
    """Short-lived token bound to a single task and explicit capability scopes."""

    token_id: str
    task_id: str
    scopes: List[str] = Field(default_factory=list)
    issued_at: str
    expires_at: str
    revoked: bool = False
    signature: str


class TaskTokenManager:
    """Mints, verifies, and revokes short-lived per-task tokens."""

    def __init__(self, signing_secret: Optional[bytes] = None) -> None:
        self._secret = signing_secret or secrets.token_bytes(32)
        self._tokens: Dict[str, ScopedTaskToken] = {}

    def _sign(self, token_id: str, task_id: str, scopes: List[str], expires_at: str) -> str:
        msg = f"{token_id}|{task_id}|{','.join(sorted(scopes))}|{expires_at}".encode("utf-8")
        return hmac.new(self._secret, msg, hashlib.sha256).hexdigest()

    def issue(
        self,
        *,
        task_id: str,
        scopes: List[str],
        ttl_seconds: int = 900,
    ) -> ScopedTaskToken:
        """Issue a least-privilege token valid for `ttl_seconds`."""
        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=ttl_seconds)
        token_id = f"htok_{secrets.token_hex(12)}"
        expires_iso = expires.isoformat()
        sig = self._sign(token_id, task_id, scopes, expires_iso)
        tok = ScopedTaskToken(
            token_id=token_id,
            task_id=task_id,
            scopes=list(scopes),
            issued_at=now.isoformat(),
            expires_at=expires_iso,
            signature=sig,
        )
        self._tokens[token_id] = tok
        return tok

    def verify(self, token_id: str, required_scope: str) -> bool:
        """Verify token signature, expiry, revocation status, and scope."""
        tok = self._tokens.get(token_id)
        if not tok or tok.revoked:
            return False
        if required_scope not in tok.scopes:
            return False
        if datetime.now(timezone.utc) >= datetime.fromisoformat(tok.expires_at):
            return False
        expected = self._sign(tok.token_id, tok.task_id, tok.scopes, tok.expires_at)
        return hmac.compare_digest(tok.signature, expected)

    def revoke_all(self) -> int:
        """Immediately revoke all issued tokens (called by kill switch)."""
        count = 0
        for tok in self._tokens.values():
            if not tok.revoked:
                tok.revoked = True
                count += 1
        return count
