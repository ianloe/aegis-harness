# Aegis Harness Operator Runbook

## 1. Initialising a Project (Local-First Git)
```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"

export AEGIS_TELEMETRY_TOKEN="aegis_your_token_here"
harness init --name my-service --asset-code AI-004
```
By default, `harness init` keeps Git local (`local_git_only: true`). When ready to share or publish to GitHub:
1. Update `repository_url` and uncheck **Local Git Only** in `harness dashboard` (`/config`), or edit `.harness/config.yaml`.
2. Add the remote and push:
   ```bash
   git remote add origin https://github.com/ianloe/aegis-harness.git
   git push -u origin main
   ```

## 2. Daily Developer Workflow
1. Start a governed task: `harness task start "Implement rate limiter" --risk medium`
2. Switch model if needed: `harness model use agnes-coder --task <task-id>`
3. Run pre-commit security and quality gates: `harness check --task <task-id>`
4. Request second-person approval: `harness approve <task-id> --approver reviewer@company.com`
5. Create a signed commit with AI provenance trailers: `harness commit -m "Add rate limiter" --task <task-id> --approver reviewer@company.com`
6. Generate PR summary: `harness pr --task <task-id> --why "Protect public API endpoints"`

## 3. Incident Response & Kill Switch
If an agent behaves unexpectedly or a prompt-injection incident is flagged:
```bash
harness killswitch --reason "Suspected prompt injection in dependency"
harness audit verify
```
`harness killswitch` terminates active sandboxed processes/containers within 5 seconds, revokes all scoped task tokens, halts active sessions in SQLite, and logs the halt to `.harness/audit.jsonl`.

## 4. Audit Verification & Daily Checkpoints
```bash
harness audit verify
harness audit checkpoint
```
If `harness audit verify` reports `AUDIT VERIFICATION FAILED`, preserve `.harness/audit.jsonl` for forensic review and escalate to the Governance Office.

## 5. Offline Telemetry Recovery
When Aegis is unreachable, events remain in `.harness/state.db` (`telemetry_queue`, status `pending`). Once connectivity to Aegis is restored, call `AegisTelemetryExporter.flush()` or run a dashboard refresh; queued events are delivered idempotently with zero loss or duplication.
