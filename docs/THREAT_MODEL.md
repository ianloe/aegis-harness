# STRIDE Threat Model: Aegis Harness

This document analyses security threats to **Aegis Harness** using the STRIDE methodology and maps each threat to implemented controls and Aegis telemetry signals.

| Category | Threat | Impact | Harness Mitigation | Aegis Signal |
| :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | Forged telemetry or unauthorised agent identity | False governance records or bypass of Aegis controls | Bearer `aegis_...` tokens (SHA-256 hashed in Aegis); short-lived HMAC-signed per-task tokens (`TaskTokenManager`); SSH/GPG signed commits (`require_signed_commits`) | `401 Unauthorized` on invalid Bearer token; signed commit verification in CI |
| **Tampering** | Editing past audit logs or modifying restricted CI/infra files | Concealed policy violations or weakened security gates | Append-only SHA-256 hash chain (`AuditChain.verify()`); daily HMAC-SHA256 checkpoints; `restricted_paths` policy requiring elevated human approval; server-side branch protection | `TELEMETRY_BOUNDARY_BREACH` / `audit verify` failure |
| **Repudiation** | Developer or agent denies authorship or approval of a high-risk change | Lack of accountability during incident review | AI provenance Git trailers (`Harness-Model`, `Harness-Provider`, `Harness-Task-ID`, `Harness-Policy-Version`, `Harness-Approver`); separation of duties (`approver != requester`); immutable `AuditChain` | `AuditLogEntry` and OTLP spans with `harness.actor` |
| **Information Disclosure** | Secrets or PII sent to external LLMs or committed to Git; prompt bodies leaked | Credential compromise or data breach | Outbound redaction (`redact_prompt` scrubs keys, tokens, private keys, emails, phone, NRIC); `restricted` repos limited to local/approved models; optional Fernet-encrypted body storage; `gitleaks`/built-in secret gate | `GUARDRAIL_EVENT` (`PII_LEAK` / `DATA_EXFILTRATION`) |
| **Denial of Service** | Runaway agent loop exhausting LLM budget or sandbox CPU/memory | Financial overspend or host exhaustion | Per-call and per-task USD cost ceilings (`cost_ceiling_usd_per_task`); Docker CPU/memory/timeout limits; `harness killswitch` halting active sessions within 5 seconds | `ROI_METRIC` budget alerts (80% / 100%); `BOUNDARY_BREACH` (`CRITICAL`) |
| **Elevation of Privilege** | Prompt injection in repo files/comments alters agent behaviour to run arbitrary commands | Remote code execution or sandbox escape | Prompt-injection scanner (`scan_for_prompt_injection`); command and tool allow-lists (`PolicyEngine`); `--network none` Docker isolation and Git worktrees (`agent/<task-id>`); no direct writes to `main` | `GUARDRAIL_EVENT` (`PROMPT_INJECTION`); `MCP` violation alerts |

## Proposed Aegis Change Requests (No Direct Edits Made to Aegis)
1. Add a dedicated `HARNESS_EVENT` union member to Aegis `POST /api/telemetry/ingest` for coding-specific lifecycle events (`session_start`, `commit`, `pr_opened`, `pr_merged`, `override`).
2. Add an `idempotencyKey` / `eventId` unique column in Aegis telemetry tables to deduplicate retries server-side.
3. Add `previousHash` / `entryHash` columns to `AuditLogEntry` and a `POST /api/telemetry/checkpoint` endpoint to store Harness daily signed checkpoints.
4. Add an `INCIDENT` event type to `POST /api/telemetry/ingest` so prompt-injection detections map directly to Aegis `Incident` records.
