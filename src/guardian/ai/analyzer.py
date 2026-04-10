"""Claude API integration for deep Terraform plan analysis."""

from __future__ import annotations

import os
import json
from dataclasses import asdict

import anthropic

from guardian.parser import TerraformPlan
from guardian.rules.security import Finding, RiskLevel


_SYSTEM_PROMPT = """You are a senior Site Reliability Engineer and AWS security architect reviewing
a Terraform plan before it is applied to production infrastructure.

Your job is to:
1. Identify security risks not caught by automated rules
2. Assess blast radius — what breaks if this plan fails mid-apply?
3. Flag cost implications of new or changed resources
4. Spot configuration drift from best practices
5. Check for things that look wrong given the resource names and context

Be specific and actionable. Reference exact resource addresses. Distinguish between
critical blockers (must fix), warnings (should discuss), and informational notes.

Format your response as:
- ADDITIONAL CRITICAL ISSUES (if any)
- ADDITIONAL WARNINGS (if any)
- COST IMPLICATIONS (if any)
- OVERALL ASSESSMENT: one paragraph summary with risk level (CRITICAL/HIGH/MEDIUM/LOW)

If the plan looks clean, say so clearly. Do not manufacture issues."""


def analyze_with_ai(
    plan: TerraformPlan,
    existing_findings: list[Finding],
    max_tokens: int = 4096,
    standards_context: str = "",
) -> str:
    """Send plan summary to Claude for deep analysis beyond rule-based checks."""
    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

    plan_summary = _build_plan_summary(plan, existing_findings)

    user_message = f"""Review this Terraform plan and provide additional security and reliability analysis.

PLAN SUMMARY:
{plan_summary}

AUTOMATED RULE FINDINGS:
{_format_findings(existing_findings)}
"""

    if standards_context:
        user_message += f"\nORG STANDARDS CONTEXT:\n{standards_context}\n"

    user_message += "\nProvide your additional analysis:"

    response = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=max_tokens,
        system=_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
    )

    return response.content[0].text


def _build_plan_summary(plan: TerraformPlan, findings: list[Finding]) -> str:
    lines = [
        f"Terraform {plan.terraform_version}",
        f"Changes: {plan.summary()}",
        "",
        "RESOURCES BEING CREATED:",
    ]

    for r in plan.creates[:20]:
        after = r.after or {}
        # Pull key attributes per resource type
        attrs = _key_attributes(r.resource_type, after)
        attr_str = f" ({', '.join(f'{k}={v}' for k, v in attrs.items())})" if attrs else ""
        lines.append(f"  + {r.address}{attr_str}")

    if len(plan.creates) > 20:
        lines.append(f"  ... and {len(plan.creates) - 20} more")

    if plan.updates:
        lines.append("\nRESOURCES BEING MODIFIED:")
        for r in plan.updates[:10]:
            lines.append(f"  ~ {r.address}")

    if plan.destroys:
        lines.append("\nRESOURCES BEING DESTROYED:")
        for r in plan.destroys:
            lines.append(f"  - {r.address}  ⚠ DESTROY")

    if plan.replaces:
        lines.append("\nRESOURCES BEING REPLACED (destroy + create):")
        for r in plan.replaces:
            lines.append(f"  ± {r.address}  ⚠ REPLACE")

    return "\n".join(lines)


def _key_attributes(resource_type: str, after: dict) -> dict:
    """Extract the most relevant attributes per resource type for the AI summary."""
    attr_map = {
        "aws_instance": ["instance_type", "ami", "subnet_id"],
        "aws_db_instance": ["instance_class", "engine", "engine_version", "multi_az", "publicly_accessible"],
        "aws_security_group": ["name", "vpc_id"],
        "aws_s3_bucket": ["bucket"],
        "aws_iam_role": ["name"],
        "aws_iam_policy": ["name"],
        "aws_lambda_function": ["function_name", "runtime", "memory_size"],
        "aws_eks_cluster": ["name", "version"],
    }
    keys = attr_map.get(resource_type, [])
    return {k: after[k] for k in keys if k in after and after[k] is not None}


def _format_findings(findings: list[Finding]) -> str:
    if not findings:
        return "No automated rule findings."

    lines = []
    for f in findings:
        lines.append(f"[{f.risk_level}] {f.title}")
        lines.append(f"  Resource: {f.resource_address}")
        lines.append(f"  {f.description}")
        lines.append("")

    return "\n".join(lines)
