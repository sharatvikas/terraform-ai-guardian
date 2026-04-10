"""Format findings into a GitHub PR comment."""

from __future__ import annotations

import os
import httpx

from guardian.parser import TerraformPlan
from guardian.rules.security import Finding, RiskLevel


_RISK_EMOJI = {
    RiskLevel.CRITICAL: "🔴",
    RiskLevel.HIGH: "🟠",
    RiskLevel.MEDIUM: "🟡",
    RiskLevel.LOW: "🔵",
    RiskLevel.NONE: "✅",
}

_COMMENT_HEADER = "<!-- terraform-ai-guardian -->"


def build_pr_comment(
    plan: TerraformPlan,
    findings: list[Finding],
    ai_analysis: str,
    overall_risk: RiskLevel,
) -> str:
    emoji = _RISK_EMOJI[overall_risk]
    criticals = [f for f in findings if f.risk_level == RiskLevel.CRITICAL]
    highs = [f for f in findings if f.risk_level == RiskLevel.HIGH]
    mediums = [f for f in findings if f.risk_level == RiskLevel.MEDIUM]

    lines = [
        _COMMENT_HEADER,
        f"## {emoji} Terraform AI Guardian — Risk: **{overall_risk}**",
        "",
        f"**Plan:** {plan.summary()}  |  "
        f"**Issues:** {len(criticals)} critical, {len(highs)} high, {len(mediums)} medium",
        "",
        "---",
    ]

    if criticals:
        lines.append("\n### 🔴 Critical Issues (must fix before merge)\n")
        for f in criticals:
            lines.extend(_format_finding(f))

    if highs:
        lines.append("\n### 🟠 High — Review Carefully\n")
        for f in highs:
            lines.extend(_format_finding(f))

    if mediums:
        lines.append("\n### 🟡 Medium — Informational\n")
        for f in mediums:
            lines.extend(_format_finding(f))

    if not findings:
        lines.append("\n### ✅ No automated rule violations found\n")

    if ai_analysis:
        lines.append("\n### 🤖 AI Deep Analysis\n")
        lines.append(ai_analysis)

    lines.extend([
        "",
        "---",
        f"*Analysis by [terraform-ai-guardian](https://github.com/sharatvikas/terraform-ai-guardian) "
        f"using Claude API*",
    ])

    return "\n".join(lines)


def _format_finding(f: Finding) -> list[str]:
    return [
        f"**{f.title}**",
        f"- **Resource:** `{f.resource_address}`",
        f"- {f.description}",
        f"- **Fix:** {f.recommendation}",
        "",
    ]


def post_pr_comment(comment_body: str) -> None:
    """Post or update the guardian comment on the PR."""
    token = os.environ["GITHUB_TOKEN"]
    repo = os.environ["GITHUB_REPOSITORY"]
    pr_number = os.environ.get("GITHUB_PR_NUMBER")

    if not pr_number:
        print("Not a PR context, skipping comment.")
        return

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    base = f"https://api.github.com/repos/{repo}"

    with httpx.Client(headers=headers, timeout=30) as client:
        # Find existing guardian comment to update
        existing_id = _find_existing_comment(client, base, pr_number)

        if existing_id:
            client.patch(
                f"{base}/issues/comments/{existing_id}",
                json={"body": comment_body},
            ).raise_for_status()
            print(f"Updated existing PR comment {existing_id}")
        else:
            client.post(
                f"{base}/issues/{pr_number}/comments",
                json={"body": comment_body},
            ).raise_for_status()
            print("Posted new PR comment")


def _find_existing_comment(client: httpx.Client, base: str, pr_number: str) -> int | None:
    resp = client.get(f"{base}/issues/{pr_number}/comments", params={"per_page": 100})
    resp.raise_for_status()
    for comment in resp.json():
        if _COMMENT_HEADER in comment.get("body", ""):
            return comment["id"]
    return None


def compute_overall_risk(findings: list[Finding]) -> RiskLevel:
    if any(f.risk_level == RiskLevel.CRITICAL for f in findings):
        return RiskLevel.CRITICAL
    if any(f.risk_level == RiskLevel.HIGH for f in findings):
        return RiskLevel.HIGH
    if any(f.risk_level == RiskLevel.MEDIUM for f in findings):
        return RiskLevel.MEDIUM
    if findings:
        return RiskLevel.LOW
    return RiskLevel.NONE
