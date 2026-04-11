"""Slack reporter for terraform-ai-guardian — post analysis results to Slack."""

from __future__ import annotations

import json
import os
from typing import Any

import httpx

from guardian.rules.security import Finding, RiskLevel


_RISK_EMOJI = {
    RiskLevel.CRITICAL: ":red_circle:",
    RiskLevel.HIGH: ":large_orange_circle:",
    RiskLevel.MEDIUM: ":large_yellow_circle:",
    RiskLevel.LOW: ":white_circle:",
    RiskLevel.NONE: ":large_green_circle:",
}

_RISK_COLOR = {
    RiskLevel.CRITICAL: "#e01e5a",
    RiskLevel.HIGH: "#ff4500",
    RiskLevel.MEDIUM: "#ecb22e",
    RiskLevel.LOW: "#2eb886",
    RiskLevel.NONE: "#2eb886",
}


def post_analysis_to_slack(
    overall_risk: RiskLevel,
    findings: list[Finding],
    ai_summary: str,
    plan_file: str,
    pr_url: str | None = None,
    webhook_url: str | None = None,
) -> bool:
    """
    Post terraform plan analysis results to Slack.

    Returns True on success. Does nothing if SLACK_WEBHOOK_URL is not configured.
    """
    webhook = webhook_url or os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook:
        return False

    emoji = _RISK_EMOJI.get(overall_risk, ":question:")
    color = _RISK_COLOR.get(overall_risk, "#cccccc")

    critical = [f for f in findings if f.risk_level == RiskLevel.CRITICAL]
    high = [f for f in findings if f.risk_level == RiskLevel.HIGH]
    medium = [f for f in findings if f.risk_level == RiskLevel.MEDIUM]

    header_text = f"{emoji} Terraform Plan Review — *{overall_risk.name}* risk"
    if pr_url:
        header_text += f" | <{pr_url}|View PR>"

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"Terraform AI Guardian — {overall_risk.name}"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Plan File*\n`{plan_file}`"},
                {"type": "mrkdwn", "text": f"*Risk Level*\n{emoji} {overall_risk.name}"},
                {"type": "mrkdwn", "text": f"*Critical*\n{len(critical)}"},
                {"type": "mrkdwn", "text": f"*High / Medium*\n{len(high)} / {len(medium)}"},
            ],
        },
        {"type": "divider"},
    ]

    # AI summary section
    if ai_summary:
        # Truncate for Slack's 3000 char limit per block
        truncated = ai_summary[:2800] + "..." if len(ai_summary) > 2800 else ai_summary
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*AI Analysis*\n{truncated}"},
        })

    # Top findings
    top_findings = sorted(findings, key=lambda f: f.risk_level.value, reverse=True)[:5]
    if top_findings:
        finding_lines = []
        for f in top_findings:
            risk_emoji = _RISK_EMOJI.get(f.risk_level, "")
            finding_lines.append(f"{risk_emoji} *{f.rule_id}* — `{f.resource_address}`\n  {f.message}")
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Top Findings*\n" + "\n".join(finding_lines),
            },
        })

    blocks.append({
        "type": "context",
        "elements": [
            {"type": "mrkdwn", "text": "terraform-ai-guardian • Powered by Claude claude-opus-4-6"}
        ],
    })

    payload: dict[str, Any] = {
        "blocks": blocks,
        "attachments": [{"color": color, "blocks": []}],
    }

    resp = httpx.post(webhook, json=payload, timeout=10.0)
    return resp.is_success
