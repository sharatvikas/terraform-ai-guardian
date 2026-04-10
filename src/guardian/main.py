"""Terraform AI Guardian — main entrypoint for GitHub Action."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from guardian.parser import parse_plan
from guardian.rules.security import run_security_rules, RiskLevel
from guardian.ai.analyzer import analyze_with_ai
from guardian.reporter.github import (
    build_pr_comment,
    post_pr_comment,
    compute_overall_risk,
)


def main() -> None:
    plan_file = os.environ.get("PLAN_FILE", "plan.json")
    fail_on_risk = RiskLevel(os.environ.get("FAIL_ON_RISK", "CRITICAL"))
    max_tokens = int(os.environ.get("MAX_TOKENS", "4096"))
    post_comment = os.environ.get("POST_COMMENT", "true").lower() == "true"
    standards_file = os.environ.get("STANDARDS_FILE", ".guardian/standards.yaml")

    print(f"Parsing plan: {plan_file}")
    plan = parse_plan(plan_file)
    print(f"Plan: {plan.summary()}")

    # Rule-based analysis (fast, no API call)
    print("Running security rules...")
    findings = run_security_rules(plan)
    overall_risk = compute_overall_risk(findings)

    criticals = [f for f in findings if f.risk_level == RiskLevel.CRITICAL]
    highs = [f for f in findings if f.risk_level == RiskLevel.HIGH]
    print(f"Rule findings: {len(criticals)} critical, {len(highs)} high, {len(findings) - len(criticals) - len(highs)} other")

    # AI deep analysis
    ai_analysis = ""
    if os.environ.get("ANTHROPIC_API_KEY"):
        print("Running AI analysis...")
        standards_context = ""
        if Path(standards_file).exists():
            standards_context = Path(standards_file).read_text()

        try:
            ai_analysis = analyze_with_ai(plan, findings, max_tokens, standards_context)
        except Exception as e:
            print(f"AI analysis failed: {e}", file=sys.stderr)
            ai_analysis = f"AI analysis unavailable: {e}"
    else:
        print("ANTHROPIC_API_KEY not set, skipping AI analysis")

    # Build and post comment
    comment = build_pr_comment(plan, findings, ai_analysis, overall_risk)

    if post_comment:
        print("Posting PR comment...")
        post_pr_comment(comment)
    else:
        print(comment)

    # Set GitHub Action outputs
    _set_output("risk-level", overall_risk.value)
    _set_output("critical-count", str(len(criticals)))
    _set_output("warning-count", str(len(highs)))

    # Fail the action if risk level exceeds threshold
    risk_order = [RiskLevel.NONE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
    if risk_order.index(overall_risk) >= risk_order.index(fail_on_risk):
        print(f"\nFAILING: Risk level {overall_risk} meets or exceeds threshold {fail_on_risk}")
        sys.exit(1)

    print(f"\nComplete. Overall risk: {overall_risk}")


def _set_output(name: str, value: str) -> None:
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"{name}={value}\n")


if __name__ == "__main__":
    main()
