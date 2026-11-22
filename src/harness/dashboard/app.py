"""Local web dashboard and form-based configuration UI for Aegis Harness."""

from __future__ import annotations

import html
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Form, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse

from harness.audit.chain import AuditChain
from harness.audit.store import StateStore
from harness.config.loader import load_config, save_config
from harness.config.schema import (
    AegisConfig,
    AuditConfig,
    DashboardConfig,
    DataClassification,
    GatewayConfig,
    GitConfig,
    HarnessConfig,
    PolicyConfig,
    ProjectConfig,
    RiskTier,
    SandboxConfig,
)
from harness.policy import PolicyEngine, PolicyOutcome
from harness.telemetry import compute_metrics

BASE_CSS = """
:root { --bg: #0f172a; --header-bg: #020617; --card: #1e293b; --input-bg: #0f172a; --border: #334155; --text: #f1f5f9; --muted: #94a3b8; --accent: #38bdf8; --ok: #22c55e; --warn: #f59e0b; --bad: #ef4444; --btn-text: #020617; }
[data-theme="light"] { --bg: #f8fafc; --header-bg: #ffffff; --card: #ffffff; --input-bg: #f8fafc; --border: #cbd5e1; --text: #0f172a; --muted: #475569; --accent: #0284c7; --ok: #15803d; --warn: #b45309; --bad: #b91c1c; --btn-text: #ffffff; }
* { box-sizing: border-box; }
body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); line-height: 1.5; }
header { background: var(--header-bg); border-bottom: 1px solid var(--border); padding: 14px 24px; display: flex; justify-content: space-between; align-items: center; }
header h1 { margin: 0; font-size: 1.15rem; letter-spacing: 0.02em; }
.brand-logo { background: #ffffff; padding: 6px 12px; border-radius: 8px; display: inline-flex; align-items: center; border: 1px solid var(--border); }
.brand-logo img { height: 36px; width: auto; display: block; }
nav { display: flex; align-items: center; gap: 18px; }
nav a { color: var(--muted); text-decoration: none; font-weight: 500; }
nav a.active, nav a:hover { color: var(--accent); }
main { max-width: 1180px; margin: 24px auto; padding: 0 20px 48px; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin-bottom: 24px; }
.card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 16px; margin-bottom: 20px; }
.stat-label { font-size: 0.78rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; }
.stat-val { font-size: 1.5rem; font-weight: 700; margin-top: 4px; }
h2 { margin: 0 0 12px; font-size: 1.05rem; color: var(--accent); }
h3 { margin: 16px 0 8px; font-size: 0.95rem; color: var(--text); }
table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
th, td { text-align: left; padding: 9px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
th { color: var(--muted); font-weight: 600; font-size: 0.78rem; text-transform: uppercase; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 0.75rem; font-weight: 600; }
.badge-ok { background: rgba(34,197,94,0.18); color: var(--ok); }
.badge-warn { background: rgba(245,158,11,0.18); color: var(--warn); }
.badge-bad { background: rgba(239,68,68,0.18); color: var(--bad); }
.form-row { margin-bottom: 14px; }
label { display: block; font-weight: 600; font-size: 0.9rem; margin-bottom: 4px; }
.help { font-size: 0.8rem; color: var(--muted); margin-top: 3px; }
input[type=text], input[type=number], select { width: 100%; max-width: 540px; padding: 8px 10px; border-radius: 6px; border: 1px solid var(--border); background: var(--input-bg); color: var(--text); font-size: 0.9rem; }
input[type=checkbox] { transform: scale(1.15); margin-right: 8px; }
button { background: var(--accent); color: var(--btn-text); border: 0; border-radius: 6px; padding: 9px 16px; font-weight: 700; cursor: pointer; font-size: 0.9rem; }
button.secondary { background: var(--border); color: var(--text); padding: 6px 10px; font-size: 0.8rem; }
.banner { padding: 10px 14px; border-radius: 8px; margin-bottom: 18px; background: rgba(34,197,94,0.15); border: 1px solid var(--ok); color: var(--ok); }
.banner-err { background: rgba(239,68,68,0.15); border: 1px solid var(--bad); color: var(--bad); }
.tier-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 14px; }
.tier-box { border: 1px solid var(--border); border-radius: 8px; padding: 12px; background: var(--input-bg); }
"""


def _page_shell(title: str, active: str, body: str) -> str:
    nav_dash = 'class="active"' if active == "dashboard" else ""
    nav_cfg = 'class="active"' if active == "config" else ""
    nav_man = 'class="active"' if active == "manual" else ""
    return f"""<!doctype html>
<html lang="en-GB">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>{html.escape(title)} - Aegis Harness</title>
<style>{BASE_CSS}</style>
<script>
(function() {{
  var saved = localStorage.getItem('harness-theme') || 'dark';
  if (saved === 'light') document.documentElement.setAttribute('data-theme', 'light');
}})();
</script>
</head>
<body>
<header>
  <a href="/" class="brand-logo" aria-label="Aegis Harness Home">
    <img src="/assets/logo.png" alt="Aegis Harness Logo" />
  </a>
  <nav>
    <a href="/" {nav_dash}>Dashboard</a>
    <a href="/config" {nav_cfg}>Configuration</a>
    <a href="/manual" {nav_man}>User Manual</a>
    <button type="button" id="theme-toggle" class="secondary">Light Mode</button>
  </nav>
</header>
<main>{body}</main>
<script>
(function() {{
  var btn = document.getElementById('theme-toggle');
  function sync() {{
    var isLight = document.documentElement.getAttribute('data-theme') === 'light';
    btn.textContent = isLight ? 'Dark Mode' : 'Light Mode';
  }}
  btn.addEventListener('click', function() {{
    var isLight = document.documentElement.getAttribute('data-theme') === 'light';
    if (isLight) {{
      document.documentElement.removeAttribute('data-theme');
      localStorage.setItem('harness-theme', 'dark');
    }} else {{
      document.documentElement.setAttribute('data-theme', 'light');
      localStorage.setItem('harness-theme', 'light');
    }}
    sync();
  }});
  sync();
}})();
</script>
</body>
</html>"""


def _outcome_badge(outcome: str) -> str:
    low = outcome.lower()
    if low in ("allow", "pass", "success", "approved", "active", "verified"):
        return f'<span class="badge badge-ok">{html.escape(outcome)}</span>'
    if low in ("require_approval", "pending", "restricted"):
        return f'<span class="badge badge-warn">{html.escape(outcome)}</span>'
    return f'<span class="badge badge-bad">{html.escape(outcome)}</span>'


def _desc(model_cls: Any, field_name: str) -> str:
    info = model_cls.model_fields.get(field_name)
    return html.escape(info.description or "") if info else ""


def create_dashboard_app(config_path: Path) -> FastAPI:
    """Create the FastAPI local dashboard and form-based configuration webapp."""
    app = FastAPI(title="Aegis Harness Dashboard", version="0.1.0")

    def _ctx():
        cfg = load_config(config_path)
        root = config_path.parent.parent if config_path.parent.name == ".harness" else config_path.parent
        audit = AuditChain(root / cfg.audit.log_path, root / cfg.audit.checkpoint_dir)
        store = StateStore(root / cfg.audit.state_db_path)
        return cfg, root, audit, store

    @app.get("/assets/logo.png")
    async def logo_asset() -> FileResponse:
        logo_path = Path(__file__).resolve().parent / "static" / "aegis-harness-logo.png"
        return FileResponse(logo_path, media_type="image/png")

    @app.get("/api/metrics")
    async def api_metrics() -> JSONResponse:
        _cfg, _root, audit, _store = _ctx()
        metrics = compute_metrics(audit.read_all())
        return JSONResponse(metrics.model_dump())

    @app.get("/api/audit")
    async def api_audit() -> JSONResponse:
        _cfg, _root, audit, _store = _ctx()
        return JSONResponse([e.model_dump() for e in audit.read_all()])

    @app.get("/", response_class=HTMLResponse)
    async def dashboard_home(msg: Optional[str] = None, err: Optional[str] = None) -> str:
        cfg, _root, audit, store = _ctx()
        entries = audit.read_all()
        verify = audit.verify()
        metrics = compute_metrics(entries)
        sessions = store.list_sessions()
        tasks = store.list_tasks()

        # Model usage aggregation
        model_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"calls": 0, "tokens": 0, "cost": 0.0})
        for e in entries:
            if e.event_type == "model_call":
                m = e.model or "unknown"
                model_stats[m]["calls"] += 1
                model_stats[m]["tokens"] += int(e.details.get("input_tokens", 0) or 0) + int(
                    e.details.get("output_tokens", 0) or 0
                )
                model_stats[m]["cost"] += float(e.details.get("cost_usd", 0.0) or 0.0)

        # Pending approvals (medium/high tasks with fewer approvals than required)
        pending_rows = []
        for t in tasks:
            tier = RiskTier(t["risk_tier"])
            req_count = cfg.policy.risk_tiers[tier].required_approvals
            approvals = [a for a in store.list_approvals(t["task_id"]) if a["decision"] == "approved"]
            if req_count > len(approvals) and t["status"] == "active":
                pending_rows.append(
                    f"<tr><td><code>{html.escape(t['task_id'])}</code></td>"
                    f"<td>{html.escape(t['title'])}</td>"
                    f"<td>{_outcome_badge(t['risk_tier'])}</td>"
                    f"<td>{len(approvals)} / {req_count}</td>"
                    f"<td><form method='post' action='/approvals/{html.escape(t['task_id'])}' style='display:flex;gap:6px;'>"
                    f"<input type='text' name='approver' placeholder='approver@company.com' required style='max-width:190px;padding:4px 8px;' />"
                    f"<button type='submit' class='secondary'>Approve</button></form></td></tr>"
                )

        session_rows = "".join(
            f"<tr><td><code>{html.escape(s['session_id'])}</code></td>"
            f"<td><code>{html.escape(s['task_id'])}</code></td>"
            f"<td>{html.escape(s['actor'])}</td>"
            f"<td>{html.escape(s['model'] or '-')}</td>"
            f"<td>{_outcome_badge(s['status'])}</td></tr>"
            for s in sessions[:12]
        ) or "<tr><td colspan='5'>No sessions recorded yet.</td></tr>"

        model_rows = "".join(
            f"<tr><td><code>{html.escape(m)}</code></td>"
            f"<td>{st['calls']}</td><td>{st['tokens']}</td>"
            f"<td>${st['cost']:.4f}</td></tr>"
            for m, st in sorted(model_stats.items())
        ) or "<tr><td colspan='4'>No model calls recorded yet.</td></tr>"

        gate_entries = [e for e in reversed(entries) if e.event_type in ("check_suite", "check_pass", "check_fail")][:10]
        gate_rows = "".join(
            f"<tr><td>{html.escape(e.timestamp[:19])}Z</td>"
            f"<td><code>{html.escape(e.task_id)}</code></td>"
            f"<td>{_outcome_badge(e.outcome)}</td>"
            f"<td><code>{html.escape(str(e.details))}</code></td></tr>"
            for e in gate_entries
        ) or "<tr><td colspan='4'>No gate checks run yet.</td></tr>"

        feed_entries = [
            e for e in reversed(entries) if e.event_type in ("policy_decision", "model_call_denied", "incident", "kill_switch", "approval_granted")
        ][:15]
        feed_rows = "".join(
            f"<tr><td>{html.escape(e.timestamp[:19])}Z</td>"
            f"<td>{html.escape(e.event_type)}</td>"
            f"<td>{_outcome_badge(e.outcome)}</td>"
            f"<td>v{html.escape(e.policy_version)}</td>"
            f"<td>{html.escape(str(e.details.get('reason') or e.details))}</td></tr>"
            for e in feed_entries
        ) or "<tr><td colspan='5'>No policy decisions recorded yet.</td></tr>"

        banner = ""
        if msg:
            banner = f'<div class="banner">{html.escape(msg)}</div>'
        elif err:
            banner = f'<div class="banner banner-err">{html.escape(err)}</div>'

        audit_badge = _outcome_badge("verified" if verify.valid else "tampered")
        body = f"""
        {banner}
        <div class="grid">
          <div class="card"><div class="stat-label">Project</div><div class="stat-val">{html.escape(cfg.project.name)}</div></div>
          <div class="card"><div class="stat-label">Tasks</div><div class="stat-val">{metrics.total_tasks}</div></div>
          <div class="card"><div class="stat-label">Total Cost</div><div class="stat-val">${metrics.total_cost_usd:.4f}</div></div>
          <div class="card"><div class="stat-label">Total Tokens</div><div class="stat-val">{metrics.total_tokens}</div></div>
          <div class="card"><div class="stat-label">Check Failure Rate</div><div class="stat-val">{metrics.check_failure_rate * 100:.1f}%</div></div>
          <div class="card"><div class="stat-label">Audit Chain</div><div class="stat-val">{audit_badge}</div></div>
        </div>

        <div class="card">
          <h2>Pending Human Approvals</h2>
          <table>
            <thead><tr><th>Task</th><th>Title</th><th>Risk Tier</th><th>Approvals</th><th>Action</th></tr></thead>
            <tbody>{"".join(pending_rows) or "<tr><td colspan='5'>No tasks awaiting approval.</td></tr>"}</tbody>
          </table>
        </div>

        <div class="card">
          <h2>Live &amp; Recent Sessions</h2>
          <table>
            <thead><tr><th>Session</th><th>Task</th><th>Actor</th><th>Model</th><th>Status</th></tr></thead>
            <tbody>{session_rows}</tbody>
          </table>
        </div>

        <div class="card">
          <h2>Model Usage &amp; Cost</h2>
          <table>
            <thead><tr><th>Model</th><th>Calls</th><th>Tokens</th><th>Cost (USD)</th></tr></thead>
            <tbody>{model_rows}</tbody>
          </table>
        </div>

        <div class="card">
          <h2>Recent Gate Results</h2>
          <table>
            <thead><tr><th>Timestamp</th><th>Task</th><th>Outcome</th><th>Details</th></tr></thead>
            <tbody>{gate_rows}</tbody>
          </table>
        </div>

        <div class="card">
          <h2>Policy Decision &amp; Governance Feed</h2>
          <table>
            <thead><tr><th>Timestamp</th><th>Event</th><th>Outcome</th><th>Policy</th><th>Reason / Details</th></tr></thead>
            <tbody>{feed_rows}</tbody>
          </table>
        </div>
        """
        return _page_shell("Dashboard", "dashboard", body)

    @app.post("/approvals/{task_id}")
    async def submit_approval(task_id: str, approver: str = Form(...)) -> RedirectResponse:
        cfg, _root, audit, store = _ctx()
        engine = PolicyEngine(cfg, audit, store)
        try:
            decision = engine.record_approval(task_id=task_id, approver=approver)
        except ValueError as exc:
            return RedirectResponse(url=f"/?err={html.escape(str(exc))}", status_code=303)
        if decision.outcome == PolicyOutcome.DENY:
            return RedirectResponse(url=f"/?err={decision.reason}", status_code=303)
        return RedirectResponse(url=f"/?msg=Approval+recorded+for+{task_id}", status_code=303)

    @app.get("/config", response_class=HTMLResponse)
    async def config_form(saved: Optional[str] = None, err: Optional[str] = None) -> str:
        cfg, _root, _audit, _store = _ctx()
        banner = ""
        if saved:
            banner = '<div class="banner">Configuration saved and validated. Audit entry recorded.</div>'
        elif err:
            banner = f'<div class="banner banner-err">{html.escape(err)}</div>'

        class_options = "".join(
            f'<option value="{dc.value}" {"selected" if cfg.project.data_classification == dc else ""}>{dc.value}</option>'
            for dc in DataClassification
        )
        tier_options = "".join(
            f'<option value="{rt.value}" {"selected" if cfg.policy.default_risk_tier == rt else ""}>{rt.value}</option>'
            for rt in RiskTier
        )
        sandbox_options = "".join(
            f'<option value="{m}" {"selected" if cfg.sandbox.mode == m else ""}>{m}</option>'
            for m in ("worktree", "docker")
        )

        tier_cards = ""
        for rt in (RiskTier.LOW, RiskTier.MEDIUM, RiskTier.HIGH):
            tc = cfg.policy.risk_tiers[rt]
            p = rt.value
            tier_cards += f"""
            <div class="tier-box">
              <h3>{p.upper()} Risk Tier</h3>
              <div class="form-row">
                <label>Required Approvals</label>
                <input type="number" min="0" name="tier_{p}_approvals" value="{tc.required_approvals}" />
                <div class="help">{_desc(type(tc), 'required_approvals')}</div>
              </div>
              <div class="form-row">
                <label><input type="checkbox" name="tier_{p}_distinct" {"checked" if tc.require_distinct_approver else ""} />Require Distinct Approver</label>
                <div class="help">{_desc(type(tc), 'require_distinct_approver')}</div>
              </div>
              <div class="form-row">
                <label>Max Diff Lines</label>
                <input type="number" min="1" name="tier_{p}_max_diff" value="{tc.max_diff_lines}" />
                <div class="help">{_desc(type(tc), 'max_diff_lines')}</div>
              </div>
              <div class="form-row">
                <label>Required Checks (comma-separated)</label>
                <input type="text" name="tier_{p}_checks" value="{html.escape(', '.join(tc.required_checks))}" />
                <div class="help">{_desc(type(tc), 'required_checks')}</div>
              </div>
              <div class="form-row">
                <label><input type="checkbox" name="tier_{p}_gov_office" {"checked" if tc.require_governance_office else ""} />Require Governance Office</label>
                <div class="help">{_desc(type(tc), 'require_governance_office')}</div>
              </div>
            </div>
            """

        body = f"""
        {banner}
        <form method="post" action="/config">
          <div class="card">
            <h2>1. Project &amp; Repository Settings</h2>
            <p class="help">{_desc(HarnessConfig, 'project')}</p>
            <div class="form-row">
              <label>Project Name</label>
              <input type="text" name="project_name" value="{html.escape(cfg.project.name)}" required />
              <div class="help">{_desc(ProjectConfig, 'name')}</div>
            </div>
            <div class="form-row">
              <label>Aegis Asset Code</label>
              <input type="text" name="asset_code" value="{html.escape(cfg.project.asset_code)}" required />
              <div class="help">{_desc(ProjectConfig, 'asset_code')}</div>
            </div>
            <div class="form-row">
              <label>Data Classification</label>
              <select name="data_classification">{class_options}</select>
              <div class="help">{_desc(ProjectConfig, 'data_classification')}</div>
            </div>
            <div class="form-row">
              <label><input type="checkbox" name="local_git_only" {"checked" if cfg.project.local_git_only else ""} />Local Git Only</label>
              <div class="help">{_desc(ProjectConfig, 'local_git_only')}</div>
            </div>
            <div class="form-row">
              <label>Repository Remote URL (optional)</label>
              <input type="text" name="repository_url" value="{html.escape(cfg.project.repository_url or '')}" placeholder="https://github.com/ianloe/aegis-harness.git" />
              <div class="help">{_desc(ProjectConfig, 'repository_url')}</div>
            </div>
          </div>

          <div class="card">
            <h2>2. Aegis Telemetry Connection</h2>
            <p class="help">{_desc(HarnessConfig, 'aegis')}</p>
            <div class="form-row">
              <label>Aegis Endpoint URL</label>
              <input type="text" name="aegis_endpoint" value="{html.escape(cfg.aegis.endpoint)}" required />
              <div class="help">{_desc(AegisConfig, 'endpoint')}</div>
            </div>
            <div class="form-row">
              <label>Bearer Token Env Var</label>
              <input type="text" name="aegis_token_env_var" value="{html.escape(cfg.aegis.token_env_var)}" required />
              <div class="help">{_desc(AegisConfig, 'token_env_var')}</div>
            </div>
            <div class="form-row">
              <label>Batch Size</label>
              <input type="number" min="1" max="500" name="aegis_batch_size" value="{cfg.aegis.batch_size}" />
              <div class="help">{_desc(AegisConfig, 'batch_size')}</div>
            </div>
            <div class="form-row">
              <label><input type="checkbox" name="poll_gate_before_call" {"checked" if cfg.aegis.poll_gate_before_call else ""} />Poll Aegis Runtime Gate Before Call</label>
              <div class="help">{_desc(AegisConfig, 'poll_gate_before_call')}</div>
            </div>
          </div>

          <div class="card">
            <h2>3. Model Gateway &amp; Redaction</h2>
            <p class="help">{_desc(HarnessConfig, 'gateway')}</p>
            <div class="form-row">
              <label>Default Model</label>
              <input type="text" name="default_model" value="{html.escape(cfg.gateway.default_model)}" required />
              <div class="help">{_desc(GatewayConfig, 'default_model')}</div>
            </div>
            <div class="form-row">
              <label>Allowed Models (comma-separated)</label>
              <input type="text" name="allowed_models" value="{html.escape(', '.join(cfg.gateway.allowed_models))}" />
              <div class="help">{_desc(GatewayConfig, 'allowed_models')}</div>
            </div>
            <div class="form-row">
              <label>Restricted Repository Allowed Models (comma-separated)</label>
              <input type="text" name="restricted_allowed_models" value="{html.escape(', '.join(cfg.gateway.restricted_allowed_models))}" />
              <div class="help">{_desc(GatewayConfig, 'restricted_allowed_models')}</div>
            </div>
            <div class="form-row">
              <label>Task Cost Ceiling (USD)</label>
              <input type="number" step="0.1" min="0" name="cost_ceiling_usd_per_task" value="{cfg.gateway.cost_ceiling_usd_per_task}" />
              <div class="help">{_desc(GatewayConfig, 'cost_ceiling_usd_per_task')}</div>
            </div>
            <div class="form-row">
              <label><input type="checkbox" name="redact_secrets" {"checked" if cfg.gateway.redact_secrets else ""} />Redact Secrets</label>
              <div class="help">{_desc(GatewayConfig, 'redact_secrets')}</div>
            </div>
            <div class="form-row">
              <label><input type="checkbox" name="redact_pii" {"checked" if cfg.gateway.redact_pii else ""} />Redact PII</label>
              <div class="help">{_desc(GatewayConfig, 'redact_pii')}</div>
            </div>
            <div class="form-row">
              <label><input type="checkbox" name="store_prompt_bodies" {"checked" if cfg.gateway.store_prompt_bodies else ""} />Store Encrypted Prompt Bodies</label>
              <div class="help">{_desc(GatewayConfig, 'store_prompt_bodies')}</div>
            </div>
          </div>

          <div class="card">
            <h2>4. Governance Policies &amp; Risk Tiers</h2>
            <p class="help">{_desc(HarnessConfig, 'policy')}</p>
            <div class="form-row">
              <label>Policy Version</label>
              <input type="text" name="policy_version" value="{html.escape(cfg.policy.version)}" required />
              <div class="help">{_desc(PolicyConfig, 'version')}</div>
            </div>
            <div class="form-row">
              <label>Default Risk Tier</label>
              <select name="default_risk_tier">{tier_options}</select>
              <div class="help">{_desc(PolicyConfig, 'default_risk_tier')}</div>
            </div>
            <div class="form-row">
              <label>Restricted Paths (comma-separated globs)</label>
              <input type="text" name="restricted_paths" value="{html.escape(', '.join(cfg.policy.restricted_paths))}" />
              <div class="help">{_desc(PolicyConfig, 'restricted_paths')}</div>
            </div>
            <div class="form-row">
              <label>Allowed Tools (comma-separated)</label>
              <input type="text" name="allowed_tools" value="{html.escape(', '.join(cfg.policy.allowed_tools))}" />
              <div class="help">{_desc(PolicyConfig, 'allowed_tools')}</div>
            </div>
            <div class="form-row">
              <label>Allowed Commands (comma-separated)</label>
              <input type="text" name="allowed_commands" value="{html.escape(', '.join(cfg.policy.allowed_commands))}" />
              <div class="help">{_desc(PolicyConfig, 'allowed_commands')}</div>
            </div>
            <div class="form-row">
              <label><input type="checkbox" name="require_signed_commits" {"checked" if cfg.policy.require_signed_commits else ""} />Require Signed Commits</label>
              <div class="help">{_desc(PolicyConfig, 'require_signed_commits')}</div>
            </div>
            <div class="tier-grid">{tier_cards}</div>
          </div>

          <div class="card">
            <h2>5. Git &amp; Sandbox Limits</h2>
            <p class="help">{_desc(HarnessConfig, 'git')} | {_desc(HarnessConfig, 'sandbox')}</p>
            <div class="form-row">
              <label>Minimum Test Coverage (%)</label>
              <input type="number" step="0.5" min="0" max="100" name="min_test_coverage_pct" value="{cfg.git.min_test_coverage_pct}" />
              <div class="help">{_desc(GitConfig, 'min_test_coverage_pct')}</div>
            </div>
            <div class="form-row">
              <label>Sandbox Backend</label>
              <select name="sandbox_mode">{sandbox_options}</select>
              <div class="help">{_desc(SandboxConfig, 'mode')}</div>
            </div>
            <div class="form-row">
              <label><input type="checkbox" name="sandbox_network" {"checked" if cfg.sandbox.network_enabled else ""} />Enable Sandbox Network (disabled recommended)</label>
              <div class="help">{_desc(SandboxConfig, 'network_enabled')}</div>
            </div>
            <div class="form-row">
              <label>Sandbox Timeout (seconds)</label>
              <input type="number" min="10" name="sandbox_timeout" value="{cfg.sandbox.timeout_seconds}" />
              <div class="help">{_desc(SandboxConfig, 'timeout_seconds')}</div>
            </div>
          </div>

          <button type="submit">Save Configuration</button>
        </form>
        """
        return _page_shell("Configuration", "config", body)

    @app.post("/config")
    async def save_config_form(request: Request) -> RedirectResponse:
        cfg, _root, audit, _store = _ctx()
        form = await request.form()

        def _csv(val: Any) -> List[str]:
            return [item.strip() for item in str(val or "").split(",") if item.strip()]

        try:
            cfg.project.name = str(form.get("project_name", cfg.project.name)).strip()
            cfg.project.asset_code = str(form.get("asset_code", cfg.project.asset_code)).strip()
            cfg.project.data_classification = DataClassification(str(form.get("data_classification")))
            cfg.project.local_git_only = "local_git_only" in form
            repo_url = str(form.get("repository_url", "")).strip()
            cfg.project.repository_url = repo_url or None

            cfg.aegis.endpoint = str(form.get("aegis_endpoint", cfg.aegis.endpoint)).strip()
            cfg.aegis.token_env_var = str(form.get("aegis_token_env_var", cfg.aegis.token_env_var)).strip()
            cfg.aegis.batch_size = int(form.get("aegis_batch_size", cfg.aegis.batch_size))
            cfg.aegis.poll_gate_before_call = "poll_gate_before_call" in form

            cfg.gateway.default_model = str(form.get("default_model", cfg.gateway.default_model)).strip()
            cfg.gateway.allowed_models = _csv(form.get("allowed_models"))
            cfg.gateway.restricted_allowed_models = _csv(form.get("restricted_allowed_models"))
            cfg.gateway.cost_ceiling_usd_per_task = float(form.get("cost_ceiling_usd_per_task", 5.0))
            cfg.gateway.redact_secrets = "redact_secrets" in form
            cfg.gateway.redact_pii = "redact_pii" in form
            cfg.gateway.store_prompt_bodies = "store_prompt_bodies" in form

            cfg.policy.version = str(form.get("policy_version", cfg.policy.version)).strip()
            cfg.policy.default_risk_tier = RiskTier(str(form.get("default_risk_tier")))
            cfg.policy.restricted_paths = _csv(form.get("restricted_paths"))
            cfg.policy.allowed_tools = _csv(form.get("allowed_tools"))
            cfg.policy.allowed_commands = _csv(form.get("allowed_commands"))
            cfg.policy.require_signed_commits = "require_signed_commits" in form

            for rt in (RiskTier.LOW, RiskTier.MEDIUM, RiskTier.HIGH):
                p = rt.value
                tc = cfg.policy.risk_tiers[rt]
                tc.required_approvals = int(form.get(f"tier_{p}_approvals", tc.required_approvals))
                tc.require_distinct_approver = f"tier_{p}_distinct" in form
                tc.max_diff_lines = int(form.get(f"tier_{p}_max_diff", tc.max_diff_lines))
                tc.required_checks = _csv(form.get(f"tier_{p}_checks"))
                tc.require_governance_office = f"tier_{p}_gov_office" in form

            cfg.git.min_test_coverage_pct = float(form.get("min_test_coverage_pct", cfg.git.min_test_coverage_pct))
            cfg.sandbox.mode = str(form.get("sandbox_mode", cfg.sandbox.mode))  # type: ignore[assignment]
            cfg.sandbox.network_enabled = "sandbox_network" in form
            cfg.sandbox.timeout_seconds = int(form.get("sandbox_timeout", cfg.sandbox.timeout_seconds))

            validated = HarnessConfig.model_validate(cfg.model_dump())
            save_config(validated, config_path)
            audit.append(
                event_type="config_updated",
                actor="human:webapp",
                repository=validated.project.name,
                policy_version=validated.policy.version,
                data_classification=validated.project.data_classification.value,
                details={"default_risk_tier": validated.policy.default_risk_tier.value},
            )
            return RedirectResponse(url="/config?saved=1", status_code=303)
        except Exception as exc:
            return RedirectResponse(url=f"/config?err={html.escape(str(exc))}", status_code=303)

    @app.get("/manual", response_class=HTMLResponse)
    async def user_manual() -> str:
        body = """
        <div class="card">
          <h2>Aegis Harness User Manual</h2>
          <p>Aegis Harness sits between developers, AI coding models, and Git. Every model call, file change, and commit is policy-checked, recorded in a tamper-evident audit chain, and streamed as telemetry to Aegis.</p>
        </div>

        <div class="card">
          <h2>1. Getting Started &amp; Local-First Git</h2>
          <p>Initialise Harness inside any project directory. By default, Harness creates a local Git repository so you can iterate privately and publish to GitHub only when ready.</p>
          <pre><code>export AEGIS_TELEMETRY_TOKEN="aegis_your_token_here"
harness init --name my-project --asset-code HARNESS-001</code></pre>
          <p>To publish a mature project to GitHub later, open <a href="/config">Configuration</a>, uncheck <strong>Local Git Only</strong>, set your <strong>Repository Remote URL</strong>, and push:</p>
          <pre><code>git remote add origin https://github.com/ianloe/aegis-harness.git
git push -u origin main</code></pre>
        </div>

        <div class="card">
          <h2>2. Model Providers &amp; Switching Models</h2>
          <p>Harness supports Anthropic, OpenAI, Google Gemini, <strong>Agnes AI</strong> (<code>agnes-coder</code>), and local OpenAI-compatible servers such as Ollama and vLLM. API keys are read from environment variables and are never written to disk.</p>
          <table>
            <thead><tr><th>Provider</th><th>Example Model</th><th>API Key Env Var</th><th>Notes</th></tr></thead>
            <tbody>
              <tr><td>Anthropic</td><td><code>claude-3-7-sonnet</code></td><td><code>ANTHROPIC_API_KEY</code></td><td>Cloud reasoning and coding</td></tr>
              <tr><td>OpenAI</td><td><code>gpt-4o</code></td><td><code>OPENAI_API_KEY</code></td><td>General coding</td></tr>
              <tr><td>Google Gemini</td><td><code>gemini-2.5-pro</code></td><td><code>GEMINI_API_KEY</code></td><td>Code review and analysis</td></tr>
              <tr><td>Agnes AI</td><td><code>agnes-coder</code></td><td><code>AGNES_API_KEY</code></td><td>OpenAI-compatible coding endpoint</td></tr>
              <tr><td>Ollama (Local)</td><td><code>qwen2.5-coder:14b</code></td><td>None</td><td>Required for <code>restricted</code> repositories</td></tr>
            </tbody>
          </table>
          <p>Use <code>harness model list</code> to view permitted models and <code>harness model use &lt;name&gt;</code> to switch models without changing your workflow.</p>
        </div>

        <div class="card">
          <h2>3. Risk Tiers &amp; Governance Policies</h2>
          <p>All policy rules are configured in <a href="/config">Configuration</a> (backed by <code>.harness/config.yaml</code>) and organised into three risk tiers:</p>
          <ul>
            <li><strong>Low Risk</strong>: Automated security and test checks only (0 human approvals by default).</li>
            <li><strong>Medium Risk</strong>: Automated checks plus 1 distinct human approver (must differ from the requester).</li>
            <li><strong>High Risk</strong>: Automated checks plus 2 distinct human approvers and Governance Office sign-off.</li>
          </ul>
          <p>Changes touching sensitive paths (such as <code>infra/**</code>, <code>.github/workflows/**</code>, or <code>.env*</code>) or exceeding the tier diff-line limit automatically require elevated approval.</p>
        </div>

        <div class="card">
          <h2>4. Daily Governed Coding Workflow</h2>
          <ol>
            <li><strong>Start a task</strong>: <code>harness task start "Implement login rate limit" --risk medium</code> (creates an isolated <code>agent/&lt;task-id&gt;</code> branch).</li>
            <li><strong>Run check-in gates</strong>: <code>harness check --task &lt;task-id&gt;</code> (runs secret scanning, SAST, dependency/licence checks, unit tests, and diff/path checks).</li>
            <li><strong>Obtain approval</strong>: <code>harness approve &lt;task-id&gt; --approver reviewer@company.com</code> (or approve directly on the <a href="/">Dashboard</a>).</li>
            <li><strong>Create a signed commit</strong>: <code>harness commit -m "Add rate limit" --task &lt;task-id&gt; --approver reviewer@company.com</code> (adds AI provenance trailers and SSH/GPG signature).</li>
            <li><strong>Generate PR summary</strong>: <code>harness pr --task &lt;task-id&gt; --why "Mitigate brute-force logins"</code>.</li>
          </ol>
        </div>

        <div class="card">
          <h2>5. Audit Verification, Sandbox &amp; Kill Switch</h2>
          <ul>
            <li><strong>Verify Audit Chain</strong>: Run <code>harness audit verify</code> at any time to confirm no past log entry has been altered.</li>
            <li><strong>Daily Signed Checkpoint</strong>: Run <code>harness audit checkpoint</code> to generate an HMAC-SHA256 signed daily digest.</li>
            <li><strong>Emergency Kill Switch</strong>: Run <code>harness killswitch --reason "Suspected prompt injection"</code> to halt all active agent processes within 5 seconds, revoke per-task tokens, and notify Aegis.</li>
          </ul>
        </div>

        <div class="card">
          <h2>6. CLI Command Reference</h2>
          <table>
            <thead><tr><th>Command</th><th>Purpose</th></tr></thead>
            <tbody>
              <tr><td><code>harness init</code></td><td>Initialise <code>.harness/config.yaml</code>, SQLite state, audit chain, and local Git.</td></tr>
              <tr><td><code>harness task start &lt;title&gt;</code></td><td>Start a new governed task and session with a risk tier.</td></tr>
              <tr><td><code>harness model list</code> / <code>use &lt;name&gt;</code></td><td>List permitted models or switch the active model.</td></tr>
              <tr><td><code>harness check</code></td><td>Run secret, SAST, dependency/licence, test, and diff gates.</td></tr>
              <tr><td><code>harness approve &lt;task-id&gt;</code></td><td>Record a distinct second-person human approval.</td></tr>
              <tr><td><code>harness commit -m ...</code></td><td>Create a signed commit with AI provenance trailers.</td></tr>
              <tr><td><code>harness pr --task &lt;id&gt;</code></td><td>Generate a Markdown pull request governance summary.</td></tr>
              <tr><td><code>harness audit verify</code> / <code>checkpoint</code></td><td>Verify hash-chain integrity or create a signed daily checkpoint.</td></tr>
              <tr><td><code>harness killswitch</code></td><td>Immediately halt active agent sessions and revoke task tokens.</td></tr>
              <tr><td><code>harness report</code></td><td>Display governance, cost, and check-gate metrics in the terminal.</td></tr>
              <tr><td><code>harness dashboard</code></td><td>Start this local web dashboard, configuration UI, and user manual.</td></tr>
            </tbody>
          </table>
        </div>
        """
        return _page_shell("User Manual", "manual", body)

    return app
