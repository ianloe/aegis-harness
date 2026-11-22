# Getting Started: Building Your First AI Agent with Aegis Harness

This step-by-step guide walks a new user through setting up **Aegis Harness** and building an AI agent safely from scratch.

---

## Step 1: Install Aegis Harness

Open your terminal, clone the Harness repository, and install it into a Python virtual environment:

```bash
git clone https://github.com/ianloe/aegis-harness.git
cd aegis-harness
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Confirm the CLI works:

```bash
harness --help
```

---

## Step 2: Set Your Credentials in Environment Variables

Harness **never** stores API keys on disk or in configuration files. Export the keys for the coding models you want to use, plus your Aegis telemetry token (generated in Aegis under **API & Integrations > Generate Key**):

```bash
export AEGIS_TELEMETRY_TOKEN="aegis_your_token_here"

# Export one or more model provider keys (examples):
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
export GEMINI_API_KEY="AIza..."
export AGNES_API_KEY="your_agnes_key"
# (No key needed if using local Ollama)
```

---

## Step 3: Create and Initialise Your Agent Project

Create a folder for your new agent project and initialise Harness inside it. By default, Harness sets up a **local-only Git repository** so you can build privately before publishing to GitHub:

```bash
mkdir my-first-agent && cd my-first-agent
harness init --name my-first-agent --asset-code HARNESS-001
```

This creates:
- `.harness/config.yaml` (your project, model, policy, and Aegis settings)
- `.harness/audit.jsonl` (your tamper-evident SHA-256 audit log)
- `.harness/state.db` (local SQLite state and offline telemetry queue)
- A local `.git` repository on `main`

---

## Step 4: Review Your Settings in the Web Dashboard

Launch the local web UI (or use Docker Compose on port `8787`):

```bash
harness dashboard
```

Open **http://127.0.0.1:8787/** in your browser:
- **User Manual** (`/manual`): Built-in quick reference and workflow guide.
- **Configuration** (`/config`): Form-based editor with plain-English explanations for every setting. Here you can:
  - Confirm **Aegis Endpoint URL** is `https://aegisx.ianloehome.net`.
  - Set **Data Classification** (`public`, `internal`, `confidential`, or `restricted`; `restricted` limits you to local or approved models only).
  - Review **Risk Tiers** (`low`, `medium`, `high`), diff-size limits, and restricted file paths.
  - Switch between **Light Mode** and **Dark Mode** in the top-right corner.

---

## Step 5: Start a Governed Coding Task

Before writing agent code, start a task and choose its risk tier (`low`, `medium`, or `high`):

```bash
harness task start "Build customer triage agent" --risk medium --requester alice@company.com
```

This prints a `task_id` (for example `task-a1b2c3d4`) and creates an isolated branch `agent/task-a1b2c3d4`. Agents are never allowed to write directly to `main`.

Check which models are permitted and switch models at any time without changing your workflow:

```bash
harness model list
harness model use agnes-coder --task task-a1b2c3d4
```

---

## Step 6: Write Your Agent Code and Run Security Gates

Write your agent code on the `agent/<task-id>` branch (for example using PydanticAI or any Python framework). Whenever you are ready to check your work, run:

```bash
harness check --task task-a1b2c3d4
```

This runs five automated gates:
1. **Secrets**: Scans for leaked API keys, tokens, or private keys (`gitleaks` or built-in scanner).
2. **SAST**: Static analysis for unsafe patterns such as `eval()`, `exec()`, or `shell=True` (`semgrep` or built-in AST scanner).
3. **Dependencies & Licences**: Vulnerability scan and SPDX licence allow-list check.
4. **Tests**: Runs `pytest` and checks coverage thresholds.
5. **Diff & Path Policy**: Flags overly large diffs or edits to sensitive paths (such as `.env*`, `infra/**`, or CI workflows).

---

## Step 7: Get Second-Person Approval and Commit

For `medium` (1 approver) and `high` (2 approvers) risk tasks, a **different person** from the requester must approve the task before merging. They can approve via CLI or directly on the web dashboard (`/`):

```bash
harness approve task-a1b2c3d4 --approver bob@company.com
```

Then create a signed commit with AI provenance trailers (`Harness-Model`, `Harness-Provider`, `Harness-Task-ID`, `Harness-Policy-Version`, `Harness-Approver`):

```bash
harness commit -m "Add triage agent core logic" --task task-a1b2c3d4 --approver bob@company.com
```

---

## Step 8: Generate a PR Summary and Verify Your Audit Trail

Generate a governance-ready Pull Request summary (saved to `.harness/pr-<task-id>.md`):

```bash
harness pr --task task-a1b2c3d4 --why "Automate initial ticket triage"
```

At any time, you can check metrics, verify that no audit entries were tampered with, or halt everything in an emergency:

```bash
harness report            # View tasks, cost, tokens, and failure rates
harness audit verify      # Verify the SHA-256 hash chain
harness audit checkpoint  # Create a daily signed checkpoint
harness killswitch        # Immediately halt active agent sessions (< 5s)
```

---

## Step 9: Publish to GitHub When Ready

When your agent project is mature enough to share:
1. Open **http://127.0.0.1:8787/config**, uncheck **Local Git Only**, enter your GitHub repository URL, and click **Save Configuration**.
2. Add the remote and push:
   ```bash
   git remote add origin https://github.com/<your-org>/<your-repo>.git
   git push -u origin main
   ```
