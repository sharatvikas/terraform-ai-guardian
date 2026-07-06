"""terraform-ai-guardian entrypoint — called by the GitHub Action."""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

from guardian.ai.analyzer import analyze_with_ai
from guardian.parser import parse_plan
from guardian.policy.opa import OPAEvaluator
from guardian.reporter.github import build_pr_comment, compute_overall_risk, post_pr_comment
from guardian.reporter.slack import ReviewSummary, SlackConfig, SlackReporter
from guardian.rules.cost import changes_to_cost_inputs, estimate_plan_cost, format_cost_summary
from guardian.rules.infracost import InfracostRunner
from guardian.rules.security import RiskLevel, run_security_rules
from guardian.rules.standards import StandardsError, StandardsEvaluator, load_standards

logging.basicConfig(level=os.environ.get("GUARDIAN_LOG_LEVEL", "INFO"))


def main() -> int:
    plan_file = os.environ.get("INPUT_PLAN-FILE", os.environ.get("PLAN_FILE", "tfplan.json"))
    fail_on_risk_str = os.environ.get("INPUT_FAIL-ON-RISK", os.environ.get("FAIL_ON_RISK", "HIGH")).upper()
    standards_file = os.environ.get("INPUT_STANDARDS-FILE", os.environ.get("STANDARDS_FILE", ""))
    max_tokens = int(os.environ.get("INPUT_MAX-TOKENS", os.environ.get("MAX_TOKENS", "2000")))

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
    print(f"  {len(plan.resource_changes)} resource changes ({plan.summary()})")

    # ── Security rules ───────────────────────────────────────────────────────
    print("Running security checks...")
    findings = run_security_rules(plan)
    print(f"  {len(findings)} security findings")

    # ── Org standards ────────────────────────────────────────────────────────
    standards_violations = []
    try:
        # Explicit file if provided; otherwise auto-discover .tf-guardian.yml etc.
        if standards_file and not Path(standards_file).exists():
            print(f"::warning::Standards file not found: {standards_file} — falling back to auto-discovery")
            standards_file = ""
        config = load_standards(standards_file or None)
        if not config.is_empty:
            print(f"Evaluating org standards from {config.source_file}...")
            standards_violations = StandardsEvaluator(config).evaluate(plan)
            findings = findings + [v.to_finding() for v in standards_violations]
            print(f"  {len(standards_violations)} standards violations")
    except StandardsError as e:
        print(f"::error::Invalid standards config: {e}", file=sys.stderr)
        return 1
    _set_output("standards-violations", str(len(standards_violations)))

    # ── Cost estimation ──────────────────────────────────────────────────────
    cost_summary = ""
    infracost_result = None
    if os.environ.get("INPUT_ESTIMATE-COST", "true").lower() != "false":
        print("Running cost estimation...")
        runner = InfracostRunner()
        if runner.is_available:
            print("  Using Infracost CLI (accurate pricing)")
        else:
            print("  Using built-in estimator (approximate on-demand rates)")
        try:
            infracost_result = runner.estimate(plan_path)
            cost_summary = infracost_result.format_github_section()
            _set_output("monthly-cost-delta", str(infracost_result.diff_total_monthly_cost))
            _set_output("cost-source", infracost_result.source)
            print(f"  Net monthly delta: ${infracost_result.diff_total_monthly_cost:+,.2f} ({infracost_result.source})")
            if infracost_result.exceeds_threshold:
                threshold = float(os.environ.get("GUARDIAN_COST_THRESHOLD", "0"))
                print(f"::warning::Cost delta ${infracost_result.diff_total_monthly_cost:+,.2f}/mo exceeds budget threshold ${threshold:,.0f}/mo")
        except Exception:
            # Fallback to old estimator
            try:
                cost_delta = estimate_plan_cost(changes_to_cost_inputs(plan.resource_changes))
                cost_summary = format_cost_summary(cost_delta)
                _set_output("monthly-cost-delta", str(cost_delta.net_monthly_delta))
                print(f"  Estimated net monthly delta: ${cost_delta.net_monthly_delta:+,.2f} (fallback)")
            except Exception as e2:
                print(f"::warning::Cost estimation failed: {e2}")

    # ── OPA policy enforcement ───────────────────────────────────────────────
    opa_result = None
    if os.environ.get("INPUT_OPA-ENABLED", "true").lower() != "false":
        print("Running OPA policy checks...")
        try:
            evaluator = OPAEvaluator(
                bundle_path=os.environ.get("INPUT_OPA-BUNDLE", "policies"),
                opa_url=os.environ.get("INPUT_OPA-URL", ""),
            )
            opa_result = evaluator.evaluate(str(plan_path))
            print(f"  {len(opa_result.violations)} violations, {len(opa_result.warnings)} warnings")
            _set_output("opa-violations", str(len(opa_result.violations)))
            _set_output("opa-warnings", str(len(opa_result.warnings)))
            if opa_result.violations:
                print(f"::error::OPA policy violations detected:\n{opa_result.summary()}")
        except Exception as e:
            print(f"::warning::OPA evaluation failed: {e}")

    # ── Cost threshold gate ──────────────────────────────────────────────────
    if infracost_result and infracost_result.exceeds_threshold:
        threshold = float(os.environ.get("GUARDIAN_COST_THRESHOLD", "0"))
        fail_on_cost = os.environ.get("GUARDIAN_FAIL_ON_COST_THRESHOLD", "false").lower() == "true"
        if fail_on_cost:
            print(
                f"::error::Cost threshold exceeded: ${infracost_result.diff_total_monthly_cost:+,.2f}/mo > ${threshold:,.0f}/mo. "
                "Set GUARDIAN_FAIL_ON_COST_THRESHOLD=false to downgrade to a warning.",
                file=sys.stderr,
            )
            return 1

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

    slack_config = SlackConfig.from_env()
    if slack_config.enabled or slack_config.dry_run:
        print("Posting review to Slack...")
        SlackReporter(slack_config).post_review(ReviewSummary(
            overall_risk=overall_risk,
            findings=findings,
            violations=standards_violations,
            plan_file=plan_file,
            pr_url=_pr_url() or "",
            pr_key=_pr_key(),
            ai_summary=ai_summary,
            cost_delta_monthly=(
                infracost_result.diff_total_monthly_cost if infracost_result else None
            ),
            cost_source=infracost_result.source if infracost_result else "",
        ))

    # ── GH Action outputs ────────────────────────────────────────────────────
    critical_count = sum(1 for f in findings if f.risk_level == RiskLevel.CRITICAL)
    warning_count = sum(1 for f in findings if f.risk_level in (RiskLevel.HIGH, RiskLevel.MEDIUM))
    _set_output("risk-level", overall_risk.name)
    _set_output("critical-count", str(critical_count))
    _set_output("warning-count", str(warning_count))
    _write_step_summary(comment)

    # ── Exit code ─────────────────────────────────────────────────────────────
    fail_threshold = RiskLevel.__members__.get(fail_on_risk_str, RiskLevel.HIGH)
    if overall_risk != RiskLevel.NONE and (
        overall_risk == fail_threshold or overall_risk > fail_threshold
    ):
        print(f"::error::Risk {overall_risk.name} >= threshold {fail_on_risk_str}")
        return 1
    # OPA violations always block (they represent hard policy constraints)
    if opa_result and opa_result.has_violations():
        print("::error::OPA policy violations block apply")
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
    pr = os.environ.get("GITHUB_PR_NUMBER", os.environ.get("PR_NUMBER", ""))
    return f"https://github.com/{repo}/pull/{pr}" if repo and pr else None


def _pr_key() -> str:
    """Stable per-PR identity used for Slack thread-per-PR grouping."""
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    pr = os.environ.get("GITHUB_PR_NUMBER", os.environ.get("PR_NUMBER", ""))
    return f"{repo}#{pr}" if repo and pr else ""


if __name__ == "__main__":
    sys.exit(main())
