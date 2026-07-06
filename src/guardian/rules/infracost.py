"""Infracost integration for accurate Terraform cost estimation.

Provides a 3-tier cost estimation strategy:
  1. Infracost CLI (if installed) — accurate, real AWS pricing
  2. Built-in approximate pricing (guardian.rules.cost) — offline fallback
  3. Skip — if neither available and GUARDIAN_REQUIRE_COST=false

Infracost docs: https://www.infracost.io/docs/
To install: brew install infracost / curl -fsSL https://raw.githubusercontent.com/infracost/infracost/master/scripts/install.sh | sh

Environment variables:
    INFRACOST_API_KEY         — Infracost Cloud API key (required for CLI)
    INFRACOST_PATH            — path to infracost binary (default: infracost)
    GUARDIAN_COST_THRESHOLD   — monthly cost delta threshold in USD (PR fails if exceeded)
    GUARDIAN_REQUIRE_COST     — if "true", fail if cost estimation is unavailable
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

INFRACOST_BIN = os.environ.get("INFRACOST_PATH", "infracost")
COST_THRESHOLD = float(os.environ.get("GUARDIAN_COST_THRESHOLD", "0"))  # 0 = disabled


@dataclass
class InfracostResource:
    """Cost breakdown for a single Terraform resource."""
    name: str
    resource_type: str
    monthly_cost: float
    hourly_cost: float
    cost_components: list[dict[str, Any]] = field(default_factory=list)

    @property
    def is_free(self) -> bool:
        return self.monthly_cost == 0.0


@dataclass
class InfracostResult:
    """Result from running infracost on a Terraform plan."""
    total_monthly_cost: float
    total_hourly_cost: float
    past_total_monthly_cost: float        # cost before changes
    diff_total_monthly_cost: float        # net delta
    resources: list[InfracostResource]
    currency: str = "USD"
    source: str = "infracost"            # "infracost" | "builtin" | "skipped"
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_cost_increase(self) -> bool:
        return self.diff_total_monthly_cost > 0

    @property
    def exceeds_threshold(self) -> bool:
        if COST_THRESHOLD <= 0:
            return False
        return self.diff_total_monthly_cost > COST_THRESHOLD

    def format_summary(self) -> str:
        lines = [
            f"💰 Cost estimate ({self.source}):",
            f"   Before: ${self.past_total_monthly_cost:+,.2f}/mo",
            f"   After:  ${self.total_monthly_cost:+,.2f}/mo",
            f"   Delta:  ${self.diff_total_monthly_cost:+,.2f}/mo",
        ]
        if COST_THRESHOLD > 0:
            status = "⚠️  EXCEEDS THRESHOLD" if self.exceeds_threshold else "✓ within threshold"
            lines.append(f"   Budget: ${COST_THRESHOLD:,.0f}/mo threshold — {status}")

        if self.resources:
            lines.append("\n   Top 5 resources by cost:")
            top = sorted(self.resources, key=lambda r: r.monthly_cost, reverse=True)[:5]
            for r in top:
                lines.append(f"     ${r.monthly_cost:>10,.2f}/mo  {r.name}")

        return "\n".join(lines)

    def format_github_section(self) -> str:
        """Formatted block for GitHub PR comment."""
        sign = "+" if self.diff_total_monthly_cost >= 0 else ""
        delta_str = f"{sign}${self.diff_total_monthly_cost:,.2f}/mo"
        threshold_note = ""
        if COST_THRESHOLD > 0 and self.exceeds_threshold:
            threshold_note = f" ⚠️  exceeds ${COST_THRESHOLD:,.0f}/mo budget"

        lines = [
            "### 💰 Cost Estimate",
            "",
            "| | Before | After | Delta |",
            "|---|---|---|---|",
            f"| Monthly | ${self.past_total_monthly_cost:,.2f} | ${self.total_monthly_cost:,.2f} | **{delta_str}**{threshold_note} |",
            f"| Hourly  | ${self.past_total_monthly_cost/730:,.4f} | ${self.total_monthly_cost/730:,.4f} | — |",
            "",
            f"*Source: {self.source}*",
        ]

        if self.resources:
            top = sorted(self.resources, key=lambda r: r.monthly_cost, reverse=True)[:5]
            lines += [
                "",
                "<details><summary>Top resources by cost</summary>",
                "",
                "| Resource | Monthly |",
                "|---|---|",
            ]
            for r in top:
                lines.append(f"| `{r.name}` | ${r.monthly_cost:,.2f} |")
            lines.append("</details>")

        return "\n".join(lines)


class InfracostRunner:
    """Run infracost CLI or fall back to built-in estimator."""

    def __init__(self) -> None:
        self._has_infracost = bool(shutil.which(INFRACOST_BIN))
        self._api_key = os.environ.get("INFRACOST_API_KEY", "")

    @property
    def is_available(self) -> bool:
        return self._has_infracost and bool(self._api_key)

    def estimate(self, plan_json_path: Path) -> InfracostResult:
        """Estimate costs for a Terraform plan JSON file.

        Tries infracost CLI first, falls back to built-in estimator.
        """
        if self.is_available:
            try:
                return self._run_infracost_cli(plan_json_path)
            except Exception as exc:
                log.warning("infracost CLI failed, falling back to built-in: %s", exc)

        return self._run_builtin(plan_json_path)

    def _run_infracost_cli(self, plan_json_path: Path) -> InfracostResult:
        """Call `infracost breakdown --path <plan.json> --format json`."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out_path = tmp.name

        env = {**os.environ, "INFRACOST_API_KEY": self._api_key}
        result = subprocess.run(
            [
                INFRACOST_BIN,
                "breakdown",
                "--path", str(plan_json_path),
                "--format", "json",
                "--out-file", out_path,
                "--no-color",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
        )

        if result.returncode != 0:
            raise RuntimeError(f"infracost exited {result.returncode}: {result.stderr[:500]}")

        with open(out_path) as f:
            data = json.load(f)

        return self._parse_infracost_json(data)

    def _parse_infracost_json(self, data: dict[str, Any]) -> InfracostResult:
        """Parse infracost JSON output format."""
        projects = data.get("projects", [])

        total_monthly = float(data.get("totalMonthlyCost", 0) or 0)
        total_hourly = float(data.get("totalHourlyCost", 0) or 0)
        past_monthly = float(data.get("pastTotalMonthlyCost", 0) or 0)
        diff_monthly = float(data.get("diffTotalMonthlyCost", 0) or (total_monthly - past_monthly))

        resources: list[InfracostResource] = []
        for project in projects:
            for breakdown in project.get("breakdown", {}).get("resources", []):
                monthly = float(breakdown.get("monthlyCost", 0) or 0)
                hourly = float(breakdown.get("hourlyCost", 0) or 0)
                resources.append(InfracostResource(
                    name=breakdown.get("name", ""),
                    resource_type=breakdown.get("resourceType", ""),
                    monthly_cost=monthly,
                    hourly_cost=hourly,
                    cost_components=breakdown.get("costComponents", []),
                ))

        return InfracostResult(
            total_monthly_cost=total_monthly,
            total_hourly_cost=total_hourly,
            past_total_monthly_cost=past_monthly,
            diff_total_monthly_cost=diff_monthly,
            resources=resources,
            currency=data.get("currency", "USD"),
            source="infracost",
            raw=data,
        )

    def _run_builtin(self, plan_json_path: Path) -> InfracostResult:
        """Fall back to the built-in approximate estimator."""
        from guardian.parser import parse_plan
        from guardian.rules.cost import changes_to_cost_inputs, estimate_plan_cost

        try:
            plan = parse_plan(plan_json_path)
            delta = estimate_plan_cost(changes_to_cost_inputs(plan.resource_changes))

            return InfracostResult(
                total_monthly_cost=max(0.0, delta.net_monthly_delta),
                total_hourly_cost=max(0.0, delta.net_monthly_delta) / 730,
                past_total_monthly_cost=0.0,
                diff_total_monthly_cost=delta.net_monthly_delta,
                resources=[
                    InfracostResource(
                        name=r.resource_address,
                        resource_type=r.resource_address.split(".")[0],
                        monthly_cost=r.monthly_delta,
                        hourly_cost=r.monthly_delta / 730,
                    )
                    for r in (delta.additions + delta.modifications)
                    if hasattr(r, "resource_address")
                ],
                source="builtin",
            )
        except Exception as exc:
            log.warning("built-in cost estimation failed: %s", exc)
            return InfracostResult(
                total_monthly_cost=0.0,
                total_hourly_cost=0.0,
                past_total_monthly_cost=0.0,
                diff_total_monthly_cost=0.0,
                resources=[],
                source="skipped",
            )
