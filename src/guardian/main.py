"""terraform-ai-guardian entrypoint — called by the GitHub Action."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from guardian.ai.analyzer import analyze_with_ai
from guardian.parser import parse_plan
from guardian.reporter.github import build_pr_comment, compute_overall_risk, post_pr_comment
from guardian.reporter.slack import post_analysis_to_slack
from guardian.rules.cost import estimate_plan_cost, format_cost_summary
from guardian.rules.security import RiskLevel, run_security_checks
from guardian.rules.standards import StandardsLoader


def main() -> int:
    plan_file = os.environ.get("INPUT_PLAN-FILE", os.environ.get("PLAN_FILE", "tfplan.json"))
    fail_on_risk_str = os.environ.get("INPUT_FAIL-ON-RISK", "HIGH").upper()
    standards_file = os.environ.get("INPUT_STANDARDS-FILE", os.environ.get("STANDARDS_FILE", ""))
    max_tokens = int(os.environ.get("INPUT_MAX-TOKENS", "2000"))

    plan_path = Path(plan_file)
    if not plan_path.exists():
        print(f"::error::Plan file not found: {plan_file}", file=sys.stderr)
        return 1

    # ── Parse ────────────────────────────────────────────────────────────────
    print(f"Parsing Terraform plan: {plan_file}")
    try:
        plan = parse_plan(plan_path)
    except Exception as e:
        print(f"::error::Failed to parse plan: {e}", file=sys.stderr)
        return 1
    print(f"  {len(plan.changes)} resource changes")

    # ── Security rules ───────────────────────────────────────────────────────
    print("Running security checks...")
    findings = run_security_checks(plan.changes)
    print(f"  {len(findings)} security findings")

    # ── Org standards ────────────────────────────────────────────────────────
    if standards_file:
        sp = Path(standards_file)
        if sp.exists():
            print(f"Running standards from {standards_file}...")
            standards_violations = StandardsLoader(sp).evaluate(plan.changes)
            findings = findings + standards_violations
            print(f"  {len(standards_violations)} standards violations")
        else:
            print(f"::warning::Standards file not found: {standards_file}")

    # ── Cost estimation ──────────────────────────────────────────────────────
    cost_summary = ""
    if os.environ.get("INPUT_ESTIMATE-COST", "true").lower() != "false":
        try:
            cost_delta = estimate_plan_cost(plan.changes)
            cost_summary = format_cost_summary(cost_delta)
            _set_output("monthly-cost-delta", str(cost_delta.net_monthly_delta))
            print(f"  Estimated net monthly delta: ${cost_delta.net_monthly_delta:+,.2f}")
        except Exception as e:
            print(f"::warning::Cost estimation failed: {e}")

    # ── AI analysis ──────────────────────────────────────────────────────────
    ai_summary = ""
    if os.environ.get("INPUT_ANTHROPIC-API-KEY") or os.environ.get("ANTHROPIC_API_KEY"):
        print("Running AI analysis...")
        try:
            ai_summary = analyze_with_ai(plan, findings, max_tokens=max_tokens)
        except Exception as e:
            print(f"::warning::AI analysis failed: {e}")

    # ── Risk + reporting ─────────────────────────────────────────────────────
    overall_risk = compute_overall_risk(findings)
    print(f"Overall risk: {overall_risk.name}")

    comment = build_pr_comment(overall_risk, findings, ai_summary, plan_file, cost_summary=cost_summary)

    if os.environ.get("INPUT_GITHUB-TOKEN") or os.environ.get("GITHUB_TOKEN"):
        post_pr_comment(comment)

    if os.environ.get("SLACK_WEBHOOK_URL"):
        post_analysis_to_slack(
            overall_risk=overall_risk,
            findings=findings,
            ai_summary=ai_summary,
            plan_file=plan_file,
            pr_url=_pr_url(),
        )

    # ── GH Action outputs ────────────────────────────────────────────────────
    critical_count = sum(1 for f in findings if f.risk_level == RiskLevel.CRITICAL)
    warning_count = sum(1 for f in findings if f.risk_level in (RiskLevel.HIGH, RiskLevel.MEDIUM))
    _set_output("risk-level", overall_risk.name)
    _set_output("critical-count", str(critical_count))
    _set_output("warning-count", str(warning_count))
    _write_step_summary(comment)

    # ── Exit code ─────────────────────────────────────────────────────────────
    fail_threshold = RiskLevel.__members__.get(fail_on_risk_str, RiskLevel.HIGH)
    if overall_risk != RiskLevel.NONE and overall_risk.value >= fail_threshold.value:
        print(f"::error::Risk {overall_risk.name} >= threshold {fail_on_risk_str}")
        return 1
    return 0


def _set_output(name: str, value: str) -> None:
    f = os.environ.get("GITHUB_OUTPUT")
    if f:
        with open(f, "a") as fp:
            fp.write(f"{name}={value}\n")


def _write_step_summary(content: str) -> None:
    f = os.environ.get("GITHUB_STEP_SUMMARY")
    if f:
        with open(f, "a") as fp:
            fp.write(content)


def _pr_url() -> str | None:
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    pr = os.environ.get("PR_NUMBER", "")
    return f"https://github.com/{repo}/pull/{pr}" if repo and pr else None


if __name__ == "__main__":
    sys.exit(main())
