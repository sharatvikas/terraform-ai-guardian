"""CLI entry point for drift detection commands.

Usage (invoked via `python -m guardian.drift`):
    guardian.drift analyze      -- analyze drift artifacts and produce report
    guardian.drift open-issues  -- open GitHub Issues for HIGH/CRITICAL drift
    guardian.drift notify-slack -- post drift summary to Slack
    guardian.drift summary-markdown -- print GitHub step summary markdown
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
import argparse
import re
from datetime import datetime, timezone
from pathlib import Path

from guardian.drift.analyzer import (
    DriftFinding,
    DriftReport,
    SEVERITY_RANK,
    load_artifacts,
)


def cmd_analyze(args) -> None:
    """Load drift artifacts, enrich with AI analysis, write JSON report."""
    artifacts_dir = args.artifacts_dir
    output_path = args.output
    min_severity = args.min_severity or "LOW"
    min_rank = SEVERITY_RANK.get(min_severity, 1)

    findings_by_module = load_artifacts(artifacts_dir)

    all_findings: list[DriftFinding] = []
    for module, findings in findings_by_module.items():
        for f in findings:
            if SEVERITY_RANK.get(f.severity, 0) >= min_rank:
                all_findings.append(f)

    # AI enrichment — add root cause and remediation for HIGH/CRITICAL
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if api_key and all_findings:
        _enrich_with_ai(all_findings, api_key)

    modules_with_drift = list(findings_by_module.keys())
    report = DriftReport(
        modules_scanned=_discover_all_modules(artifacts_dir),
        modules_with_drift=modules_with_drift,
        findings=all_findings,
        scan_timestamp=datetime.now(timezone.utc).isoformat(),
    )

    if api_key and all_findings:
        report.ai_summary = _generate_summary(report, api_key)

    Path(output_path).write_text(json.dumps(report.to_dict(), indent=2))
    print(f"Drift report written to {output_path}")
    print(f"Total: {len(all_findings)} findings across {len(modules_with_drift)} modules")


def cmd_open_issues(args) -> None:
    """Open GitHub Issues for HIGH/CRITICAL drift findings."""
    report_data = json.loads(Path(args.report).read_text())
    repo = args.repo
    min_severity = args.min_severity or "HIGH"
    min_rank = SEVERITY_RANK.get(min_severity, 3)

    token = os.environ.get("GH_TOKEN", os.environ.get("GITHUB_TOKEN", ""))
    if not token:
        print("Error: GH_TOKEN or GITHUB_TOKEN not set", file=sys.stderr)
        sys.exit(1)

    findings = [
        f for f in report_data.get("findings", [])
        if SEVERITY_RANK.get(f["severity"], 0) >= min_rank
    ]

    if not findings:
        print(f"No findings at {min_severity}+ severity. No issues opened.")
        return

    opened = 0
    for finding in findings:
        title = (
            f"[Drift {finding['severity']}] {finding['action'].upper()} "
            f"{finding['resource']}"
        )

        changed_attrs = "\n".join(
            f"  - `{a['name']}`: `{a['before']}` → `{a['after']}`"
            for a in finding.get("changed_attributes", [])[:10]
        )

        body = f"""## Infrastructure Drift Detected

**Severity:** {finding['severity']}
**Module:** `{finding['module']}`
**Resource:** `{finding['resource']}`
**Action:** `{finding['action']}`
**Destructive:** {'Yes ⚠️' if finding.get('is_destructive') else 'No'}

### Changed Attributes

{changed_attrs or '_No attribute details available_'}

### Root Cause Analysis

{finding.get('root_cause') or '_Run with ANTHROPIC_API_KEY set for AI root cause analysis_'}

### Remediation

{finding.get('remediation') or '_Run the drift workflow with ANTHROPIC_API_KEY for remediation steps_'}

---

**To remediate:** Run `terraform apply` in the `{finding['module']}` directory to restore
declared state, or update your Terraform code to reflect the intended configuration.

**Detected at:** {report_data.get('scan_timestamp', 'unknown')}
**Workflow run:** https://github.com/{repo}/actions

_This issue was automatically opened by the Terraform Drift Detection workflow._
"""

        issue_data = {
            "title": title,
            "body": body,
            "labels": ["terraform-drift", f"severity:{finding['severity'].lower()}"],
        }

        try:
            url = f"https://api.github.com/repos/{repo}/issues"
            req = urllib.request.Request(
                url,
                data=json.dumps(issue_data).encode(),
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "Content-Type": "application/json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            with urllib.request.urlopen(req) as resp:
                issue = json.loads(resp.read())
                print(f"Opened issue #{issue['number']}: {title}")
                opened += 1
        except Exception as e:
            print(f"Warning: could not open issue for {finding['resource']}: {e}", file=sys.stderr)

    print(f"Opened {opened} GitHub issues")


def cmd_notify_slack(args) -> None:
    """Post drift summary to Slack webhook."""
    report_data = json.loads(Path(args.report).read_text())
    webhook_url = args.webhook_url or os.environ.get("SLACK_WEBHOOK_URL", "")
    run_url = args.run_url or ""

    if not webhook_url:
        print("No SLACK_WEBHOOK_URL set — skipping Slack notification")
        return

    summary = report_data.get("summary", {})
    critical = summary.get("critical_count", 0)
    high = summary.get("high_count", 0)
    total = summary.get("total_drift_resources", 0)
    modules_drifted = summary.get("modules_with_drift", 0)

    if total == 0:
        color = "good"
        title = "✅ Terraform Drift Check — No drift detected"
        text = "All Terraform state matches declared configuration."
    elif critical > 0:
        color = "danger"
        title = f"🔴 Terraform Drift — {critical} CRITICAL finding(s)"
        text = (
            f"*{total} total drift resource(s)* across {modules_drifted} module(s). "
            f"*{critical} CRITICAL* · {high} HIGH"
        )
    elif high > 0:
        color = "warning"
        title = f"🟠 Terraform Drift — {high} HIGH finding(s)"
        text = f"*{total} total drift resource(s)* across {modules_drifted} module(s)."
    else:
        color = "#FADE2A"
        title = f"🟡 Terraform Drift — {total} finding(s)"
        text = f"{total} drift resource(s) across {modules_drifted} module(s). No critical issues."

    # Top findings
    top_findings = sorted(
        report_data.get("findings", []),
        key=lambda f: SEVERITY_RANK.get(f["severity"], 0),
        reverse=True,
    )[:5]

    finding_lines = "\n".join(
        f"• [{f['severity']}] `{f['action'].upper()}` {f['resource']}"
        for f in top_findings
    )

    ai_summary = report_data.get("ai_summary", "")

    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": title}},
        {"type": "section", "text": {"type": "mrkdwn", "text": text}},
    ]

    if finding_lines:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Top Findings:*\n{finding_lines}"},
        })

    if ai_summary:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*AI Summary:*\n{ai_summary[:500]}"},
        })

    if run_url:
        blocks.append({
            "type": "actions",
            "elements": [{"type": "button", "text": {"type": "plain_text", "text": "View Workflow Run"}, "url": run_url}],
        })

    payload = json.dumps({"blocks": blocks, "attachments": [{"color": color, "fallback": title}]}).encode()
    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(req)
        print("Slack notification sent")
    except Exception as e:
        print(f"Warning: Slack notification failed: {e}", file=sys.stderr)


def cmd_summary_markdown(args) -> None:
    """Write GitHub Actions step summary markdown."""
    report_data = json.loads(Path(args.report).read_text())
    summary = report_data.get("summary", {})

    critical = summary.get("critical_count", 0)
    high = summary.get("high_count", 0)
    medium = summary.get("medium_count", 0)
    low = summary.get("low_count", 0)
    total = summary.get("total_drift_resources", 0)
    modules_drifted = summary.get("modules_with_drift", 0)
    modules_scanned = summary.get("modules_scanned", 0)

    status = "✅ Clean" if total == 0 else ("🔴 Critical Drift" if critical > 0 else "🟠 Drift Detected")

    print(f"## Terraform Drift Report — {status}\n")
    print("| | Count |")
    print("|---|---|")
    print(f"| Modules scanned | {modules_scanned} |")
    print(f"| Modules with drift | {modules_drifted} |")
    print(f"| 🔴 Critical | {critical} |")
    print(f"| 🟠 High | {high} |")
    print(f"| 🟡 Medium | {medium} |")
    print(f"| ⚪ Low | {low} |")
    print(f"| **Total** | **{total}** |")

    ai_summary = report_data.get("ai_summary", "")
    if ai_summary:
        print(f"\n### AI Summary\n\n{ai_summary}\n")

    findings = report_data.get("findings", [])
    high_plus = [f for f in findings if SEVERITY_RANK.get(f["severity"], 0) >= 3]
    if high_plus:
        print("\n### Critical & High Findings\n")
        print("| Severity | Resource | Action | Root Cause |")
        print("|----------|----------|--------|------------|")
        for f in high_plus[:10]:
            cause = (f.get("root_cause") or "—")[:80]
            print(f"| **{f['severity']}** | `{f['resource']}` | {f['action']} | {cause} |")


# ─── AI Enrichment ────────────────────────────────────────────────────────────

def _enrich_with_ai(findings: list[DriftFinding], api_key: str) -> None:
    """Call Claude to add root_cause and remediation to HIGH/CRITICAL findings."""
    try:
        import anthropic
    except ImportError:
        return

    client = anthropic.Anthropic(api_key=api_key)
    high_crit = [f for f in findings if f.severity in ("HIGH", "CRITICAL")]

    if not high_crit:
        return

    # Batch findings into a single prompt to minimize API calls
    findings_text = "\n\n".join(
        f"Finding {i + 1}: [{f.severity}] {f.change_action.upper()} {f.resource_address}\n"
        f"Resource type: {f.resource_type}\n"
        f"Changed attributes: {json.dumps([{'name': a.name, 'before': a.before, 'after': a.after} for a in f.changed_attributes[:5]])}"
        for i, f in enumerate(high_crit[:10])  # Cap at 10 to avoid token limits
    )

    prompt = f"""You are a Terraform and AWS infrastructure security expert.
Analyze these infrastructure drift findings and for each provide:
1. ROOT_CAUSE: One sentence explaining why this drift likely occurred (manual console change, automation, deployment, etc.)
2. REMEDIATION: One or two sentences on how to fix it (terraform apply, or update the code)

Format each finding as:
Finding N:
ROOT_CAUSE: <text>
REMEDIATION: <text>

Findings:
{findings_text}"""

    try:
        response = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=1000,
            messages=[{"role": "user", "content": prompt}],
        )
        text = response.content[0].text

        # Parse responses back to findings
        for i, finding in enumerate(high_crit[:10]):
            pattern = rf"Finding {i + 1}:\s*ROOT_CAUSE:\s*(.+?)\s*REMEDIATION:\s*(.+?)(?=Finding \d+:|$)"
            match = re.search(pattern, text, re.DOTALL)
            if match:
                finding.root_cause = match.group(1).strip()
                finding.remediation = match.group(2).strip()
    except Exception as e:
        print(f"Warning: AI enrichment failed: {e}", file=sys.stderr)


def _generate_summary(report: DriftReport, api_key: str) -> str:
    """Generate an executive summary of all drift findings."""
    try:
        import anthropic
    except ImportError:
        return ""

    client = anthropic.Anthropic(api_key=api_key)
    summary_data = {
        "total_findings": len(report.findings),
        "critical": len(report.critical_findings),
        "high": len(report.high_findings),
        "modules_drifted": len(report.modules_with_drift),
        "top_findings": [
            {"severity": f.severity, "resource": f.resource_address, "action": f.change_action}
            for f in report.findings[:5]
        ],
    }

    try:
        response = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=200,
            messages=[{
                "role": "user",
                "content": (
                    f"Write a 2-3 sentence executive summary of this Terraform drift report for an SRE team. "
                    f"Be specific about risks. Data: {json.dumps(summary_data)}"
                ),
            }],
        )
        return response.content[0].text.strip()
    except Exception:
        return ""


def _discover_all_modules(artifacts_dir: str) -> list[str]:
    """Infer the list of scanned modules from the artifacts directory structure."""
    base = Path(artifacts_dir)
    modules = set()
    for f in base.rglob("*.json"):
        modules.add(str(f.parent.relative_to(base)))
    return sorted(modules) or ["."]


# ─── Main Dispatcher ──────────────────────────────────────────────────────────



def main() -> None:
    parser = argparse.ArgumentParser(prog="guardian.drift")
    sub = parser.add_subparsers(dest="command")

    p_analyze = sub.add_parser("analyze")
    p_analyze.add_argument("--artifacts-dir", required=True)
    p_analyze.add_argument("--output", required=True)
    p_analyze.add_argument("--min-severity", default="LOW")

    p_issues = sub.add_parser("open-issues")
    p_issues.add_argument("--report", required=True)
    p_issues.add_argument("--repo", required=True)
    p_issues.add_argument("--min-severity", default="HIGH")

    p_slack = sub.add_parser("notify-slack")
    p_slack.add_argument("--report", required=True)
    p_slack.add_argument("--webhook-url", default=None)
    p_slack.add_argument("--run-url", default=None)

    p_md = sub.add_parser("summary-markdown")
    p_md.add_argument("--report", required=True)

    args = parser.parse_args()

    dispatch = {
        "analyze": cmd_analyze,
        "open-issues": cmd_open_issues,
        "notify-slack": cmd_notify_slack,
        "summary-markdown": cmd_summary_markdown,
    }

    if args.command not in dispatch:
        parser.print_help()
        sys.exit(1)

    dispatch[args.command](args)


if __name__ == "__main__":
    main()
