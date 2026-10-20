"""Self-contained, offline HTML report generator per context.md DEC-7 and flow.md §5 M6.

Produces runs/<id>/report.html with embedded CSS and zero external network dependencies.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from cairn.referee.evidence import EvidenceStore
from cairn.referee.validity import evaluate_certificate


def generate_html_report(
    run_id: str,
    store: EvidenceStore,
    out_path: Path | str,
) -> Path:
    """Generate offline HTML report from evidence store and write to out_path."""
    events = store.get_events()
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    # Extract manifest
    manifest: dict[str, Any] = {}
    for ev in events:
        if ev.kind == "manifest.frozen":
            manifest = ev.body
            break

    tier = manifest.get("tier", "t1").upper()
    is_simulated = manifest.get("model", {}).get("backend") == "sim_engine"
    host_class = "native-linux" if not manifest.get("env", {}).get("dev_only") else "dev-only"

    # Identify findings
    findings: set[str] = set()
    for ev in events:
        f = ev.body.get("finding")
        if f and not f.startswith("f_l") and f != "f_000":
            findings.add(f)

    # Evaluate certificate for each finding
    certs: list[dict[str, Any]] = []
    status_counts = {"VALID": 0, "VALID_WITH_WARNINGS": 0, "QUARANTINED": 0, "INCOMPLETE": 0}
    residual_risks: set[str] = set()

    for finding in sorted(findings):
        c = evaluate_certificate(events, finding=finding, manifest=manifest)
        c_dict = c.model_dump()
        certs.append(c_dict)
        st = c_dict["status"]
        status_counts[st] = status_counts.get(st, 0) + 1
        for r in c_dict.get("residual_risk", []):
            residual_risks.add(r)

    # Extract probe results
    l1_ev = next((e for e in events if e.kind == "probe.l1.result"), None)
    l3_ev = next((e for e in events if e.kind == "probe.l3.result"), None)
    l4_ev = next((e for e in events if e.kind == "probe.l4.result"), None)
    matrix_ev = next(
        (e for e in events if e.kind == "attestation.matrix" and e.body.get("phase") == "post"),
        None,
    )

    # Build HTML content
    tier_color = "#10b981" if tier == "T1" else "#ef4444"
    sim_badge = (
        '<span class="badge badge-warning">SIMULATED (SimEngine)</span>'
        if is_simulated
        else '<span class="badge badge-info">REAL ENGINE</span>'
    )

    table_rows = []
    for c in certs:
        invs = c.get("invariants", {})
        f_id = html.escape(c["finding"])
        st = c["status"]
        st_class = (
            "st-valid"
            if "VALID" in st
            else ("st-quarantined" if st == "QUARANTINED" else "st-incomplete")
        )

        inv_cells = []
        for i_num in range(1, 10):
            inv_key = f"I{i_num}"
            inv_res = invs.get(inv_key, {}).get("result", "missing")
            tag_class = f"inv-{inv_res}"
            char = inv_res[0].upper() if inv_res else "?"
            reason = invs.get(inv_key, {}).get("reason_code", "")
            inv_cells.append(f'<td class="{tag_class}" title="{reason}">{char}</td>')

        table_rows.append(
            f'<tr><td><code>{f_id}</code></td><td><span class="badge {st_class}">{st}</span></td>'
            + "".join(inv_cells)
            + "</tr>"
        )

    # Residual risk items
    risk_items = "".join(f"<li>{html.escape(r)}</li>" for r in sorted(residual_risks))

    valid_count = status_counts.get("VALID", 0) + status_counts.get("VALID_WITH_WARNINGS", 0)
    quar_count = status_counts.get("QUARANTINED", 0)
    incomp_count = status_counts.get("INCOMPLETE", 0)

    l1_status = l1_ev.body.get("status", "NOT_RUN") if l1_ev else "NOT_RUN"
    l1_badge = "badge-tier" if l1_status == "NO_SIGNAL_AT_POWER" else "st-quarantined"
    l1_details = json.dumps(l1_ev.body) if l1_ev else "N/A"

    l3_status = l3_ev.body.get("status", "NOT_RUN") if l3_ev else "NOT_RUN"
    l3_badge = "badge-tier" if l3_status == "NO_SIGNAL_AT_POWER" else "st-quarantined"
    l3_details = json.dumps(l3_ev.body) if l3_ev else "N/A"

    l4_clean = bool(l4_ev and l4_ev.body.get("canaries_found", 0) == 0)
    l4_status = "CLEAN" if l4_clean else "LEAK_DETECTED"
    l4_badge = "badge-tier" if l4_clean else "st-quarantined"
    l4_details = f"Canaries found: {l4_ev.body.get('canaries_found', 0)}" if l4_ev else "N/A"

    mat_enforced = bool(matrix_ev and matrix_ev.body.get("deviations", 0) == 0)
    mat_status = "ENFORCED" if mat_enforced else "DEVIATIONS"
    mat_badge = "badge-tier" if mat_enforced else "st-quarantined"
    mat_details = f"Deviations: {matrix_ev.body.get('deviations', 0)}" if matrix_ev else "N/A"

    run_escaped = html.escape(run_id)
    host_escaped = html.escape(host_class)
    tier_escaped = html.escape(tier)
    table_body = "".join(table_rows)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>CAIRN Assurance Report — {run_escaped}</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      margin: 0; padding: 2rem; background: #0f172a; color: #f8fafc; line-height: 1.5;
    }}
    .container {{ max-width: 1100px; margin: 0 auto; }}
    h1, h2 {{ color: #ffffff; margin-top: 1.5rem; }}
    .header {{
      display: flex; justify-content: space-between; align-items: center;
      border-bottom: 2px solid #334155; padding-bottom: 1rem; margin-bottom: 1.5rem;
    }}
    .badge {{
      display: inline-block; padding: 0.25rem 0.6rem; border-radius: 4px;
      font-weight: 600; font-size: 0.85rem; text-transform: uppercase;
    }}
    .badge-tier {{ background: {tier_color}; color: #ffffff; }}
    .badge-warning {{ background: #f59e0b; color: #000000; }}
    .badge-info {{ background: #3b82f6; color: #ffffff; }}
    .st-valid {{ background: #10b981; color: #ffffff; }}
    .st-quarantined {{ background: #ef4444; color: #ffffff; }}
    .st-incomplete {{ background: #64748b; color: #ffffff; }}
    .card-grid {{
      display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 2rem;
    }}
    .card {{
      background: #1e293b; padding: 1.25rem; border-radius: 8px; border: 1px solid #334155;
    }}
    .card-title {{
      font-size: 0.85rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em;
    }}
    .card-value {{
      font-size: 1.8rem; font-weight: 700; color: #ffffff; margin-top: 0.25rem;
    }}
    table {{
      width: 100%; border-collapse: collapse; margin-top: 1rem;
      background: #1e293b; border-radius: 8px; overflow: hidden;
    }}
    th, td {{ padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #334155; }}
    th {{ background: #0f172a; color: #cbd5e1; font-size: 0.85rem; text-transform: uppercase; }}
    .inv-pass {{ color: #10b981; font-weight: 700; text-align: center; }}
    .inv-fail {{ color: #ef4444; font-weight: 700; text-align: center; }}
    .inv-warn {{ color: #f59e0b; font-weight: 700; text-align: center; }}
    .inv-missing {{ color: #64748b; font-weight: 700; text-align: center; }}
    ul {{ padding-left: 1.5rem; }}
    li {{ margin-bottom: 0.5rem; color: #cbd5e1; }}
    code {{
      background: #020617; padding: 0.2rem 0.4rem; border-radius: 4px; font-family: monospace;
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h1>CAIRN Assurance Report</h1>
        <div style="color: #94a3b8;">
          Run ID: <code>{run_escaped}</code> · Host: <code>{host_escaped}</code>
        </div>
      </div>
      <div>
        <span class="badge badge-tier">{tier_escaped} TIER</span>
        {sim_badge}
      </div>
    </div>

    <div class="card-grid">
      <div class="card">
        <div class="card-title">Total Findings</div>
        <div class="card-value">{len(findings)}</div>
      </div>
      <div class="card">
        <div class="card-title">Valid (Clean)</div>
        <div class="card-value" style="color: #10b981;">{valid_count}</div>
      </div>
      <div class="card">
        <div class="card-title">Quarantined</div>
        <div class="card-value" style="color: #ef4444;">{quar_count}</div>
      </div>
      <div class="card">
        <div class="card-title">Incomplete</div>
        <div class="card-value" style="color: #64748b;">{incomp_count}</div>
      </div>
    </div>

    <h2>1. Finding Validity Certificates</h2>
    <table>
      <thead>
        <tr>
          <th>Finding</th><th>Status</th>
          <th>I1</th><th>I2</th><th>I3</th><th>I4</th><th>I5</th><th>I6</th><th>I7</th><th>I8</th><th>I9</th>
        </tr>
      </thead>
      <tbody>
        {table_body}
      </tbody>
    </table>

    <h2>2. Statistical Side-Channel Probes & Attestations</h2>
    <table>
      <thead><tr><th>Probe / Check</th><th>Scope</th><th>Outcome</th><th>Details</th></tr></thead>
      <tbody>
        <tr>
          <td><strong>L1 Prefix-Cache Timing</strong></td><td>Run</td>
          <td><span class="badge {l1_badge}">{l1_status}</span></td>
          <td>{l1_details}</td>
        </tr>
        <tr>
          <td><strong>L3 Verdict Fingerprinting</strong></td><td>Run</td>
          <td><span class="badge {l3_badge}">{l3_status}</span></td>
          <td>{l3_details}</td>
        </tr>
        <tr>
          <td><strong>L4 Filesystem & Shared Volumes</strong></td><td>Run</td>
          <td><span class="badge {l4_badge}">{l4_status}</span></td>
          <td>{l4_details}</td>
        </tr>
        <tr>
          <td><strong>C3 Topology Matrix Audit</strong></td><td>Run</td>
          <td><span class="badge {mat_badge}">{mat_status}</span></td>
          <td>{mat_details}</td>
        </tr>
      </tbody>
    </table>

    <h2>3. Residual-Risk Register</h2>
    <ul>
      {risk_items}
    </ul>
  </div>
</body>
</html>
"""
    out.write_text(html_content, encoding="utf-8")
    return out
