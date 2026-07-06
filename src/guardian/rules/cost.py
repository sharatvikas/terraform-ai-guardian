"""Cost estimation rules — estimate monthly AWS cost delta from a Terraform plan.

Pricing is approximate and uses on-demand us-east-1 rates hardcoded here.
For production use, integrate with the AWS Pricing API or Infracost.
This module is intentionally self-contained with no external dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from guardian.parser import ResourceChange


# ─── Pricing tables (on-demand, us-east-1, USD/hr unless noted) ─────────────

_EC2_HOURLY: dict[str, float] = {
    "t3.nano": 0.0052, "t3.micro": 0.0104, "t3.small": 0.0208,
    "t3.medium": 0.0416, "t3.large": 0.0832, "t3.xlarge": 0.1664,
    "t3.2xlarge": 0.3328,
    "m5.large": 0.096, "m5.xlarge": 0.192, "m5.2xlarge": 0.384,
    "m5.4xlarge": 0.768, "m5.8xlarge": 1.536,
    "m6i.large": 0.096, "m6i.xlarge": 0.192, "m6i.2xlarge": 0.384,
    "c5.large": 0.085, "c5.xlarge": 0.17, "c5.2xlarge": 0.34,
    "c6i.large": 0.085, "c6i.xlarge": 0.17,
    "r5.large": 0.126, "r5.xlarge": 0.252, "r5.2xlarge": 0.504,
    "p3.2xlarge": 3.06, "p3.8xlarge": 12.24,
    "g4dn.xlarge": 0.526, "g4dn.2xlarge": 0.752,
}

_RDS_HOURLY: dict[str, float] = {
    "db.t3.micro": 0.017, "db.t3.small": 0.034, "db.t3.medium": 0.068,
    "db.t3.large": 0.136,
    "db.m5.large": 0.171, "db.m5.xlarge": 0.342, "db.m5.2xlarge": 0.684,
    "db.m6g.large": 0.163, "db.m6g.xlarge": 0.325,
    "db.r5.large": 0.24, "db.r5.xlarge": 0.48, "db.r5.2xlarge": 0.96,
}

_EBS_MONTHLY_PER_GB: dict[str, float] = {
    "gp2": 0.10,
    "gp3": 0.08,
    "io1": 0.125,
    "io2": 0.125,
    "st1": 0.045,
    "sc1": 0.025,
    "standard": 0.05,
}

_EKS_CLUSTER_HOURLY = 0.10
_NAT_GATEWAY_HOURLY = 0.045
_ALB_HOURLY = 0.008
_ELASTICACHE_HOURLY = 0.068  # cache.m6g.large
_HOURS_PER_MONTH = 730


@dataclass
class ResourceCostEstimate:
    resource_type: str
    resource_address: str
    action: str  # create | update | delete | no-op
    monthly_cost_usd: float
    details: str
    assumptions: list[str] = field(default_factory=list)


@dataclass
class CostDelta:
    new_monthly_cost: float
    removed_monthly_cost: float
    net_monthly_delta: float
    estimates: list[ResourceCostEstimate]
    warnings: list[str]


def changes_to_cost_inputs(changes: list["ResourceChange"]) -> list[dict[str, Any]]:
    """Adapt parsed ResourceChange objects to the dict shape estimate_plan_cost expects."""
    inputs: list[dict[str, Any]] = []
    for c in changes:
        if c.is_create:
            action = "create"
        elif c.is_destroy:
            action = "delete"
        elif c.is_update:
            action = "update"
        else:
            action = "no-op"
        inputs.append({
            "type": c.resource_type,
            "address": c.address,
            "action": action,
            "config": (c.after if action != "delete" else c.before) or {},
        })
    return inputs


def estimate_plan_cost(resources: list[dict[str, Any]]) -> CostDelta:
    """
    Estimate monthly cost delta from a list of Terraform resource changes.

    Args:
        resources: List of resource dicts from the parsed Terraform plan
                   (type, address, action, config).

    Returns:
        CostDelta with per-resource estimates and net monthly delta.
    """
    estimates: list[ResourceCostEstimate] = []
    warnings: list[str] = []

    for resource in resources:
        est = _estimate_resource(resource)
        if est is not None:
            estimates.append(est)

    # Only count create/update as new cost; delete removes cost
    new_cost = sum(
        e.monthly_cost_usd
        for e in estimates
        if e.action in ("create", "update")
    )
    removed_cost = sum(
        e.monthly_cost_usd
        for e in estimates
        if e.action == "delete"
    )

    return CostDelta(
        new_monthly_cost=round(new_cost, 2),
        removed_monthly_cost=round(removed_cost, 2),
        net_monthly_delta=round(new_cost - removed_cost, 2),
        estimates=estimates,
        warnings=warnings,
    )


def _estimate_resource(resource: dict[str, Any]) -> ResourceCostEstimate | None:
    rtype = resource.get("type", "")
    address = resource.get("address", "")
    action = resource.get("action", "create")
    config = resource.get("config", {})

    if action == "no-op":
        return None

    estimators = {
        "aws_instance": _estimate_ec2,
        "aws_db_instance": _estimate_rds,
        "aws_ebs_volume": _estimate_ebs,
        "aws_eks_cluster": _estimate_eks,
        "aws_nat_gateway": _estimate_nat,
        "aws_lb": _estimate_alb,
        "aws_alb": _estimate_alb,
        "aws_elasticache_cluster": _estimate_elasticache,
    }

    estimator = estimators.get(rtype)
    if estimator is None:
        return None

    monthly, details, assumptions = estimator(config)
    return ResourceCostEstimate(
        resource_type=rtype,
        resource_address=address,
        action=action,
        monthly_cost_usd=round(monthly, 2),
        details=details,
        assumptions=assumptions,
    )


def _estimate_ec2(config: dict) -> tuple[float, str, list[str]]:
    instance_type = config.get("instance_type", "t3.micro")
    hourly = _EC2_HOURLY.get(instance_type, 0.10)  # default $0.10/hr unknown types
    monthly = hourly * _HOURS_PER_MONTH

    # Count attached EBS root volume
    root_block = config.get("root_block_device", [{}])
    if isinstance(root_block, list) and root_block:
        root_block = root_block[0]
    root_gb = int(root_block.get("volume_size", 8))
    root_type = root_block.get("volume_type", "gp3")
    ebs_monthly = root_gb * _EBS_MONTHLY_PER_GB.get(root_type, 0.08)
    monthly += ebs_monthly

    assumptions = ["on-demand pricing", "us-east-1", "730 hr/month"]
    if instance_type not in _EC2_HOURLY:
        assumptions.append(f"unknown instance type {instance_type!r} — using $0.10/hr estimate")

    details = (
        f"{instance_type} @ ${hourly:.4f}/hr = ${hourly * _HOURS_PER_MONTH:.2f}/mo "
        f"+ {root_gb}GB {root_type} EBS = ${ebs_monthly:.2f}/mo"
    )
    return monthly, details, assumptions


def _estimate_rds(config: dict) -> tuple[float, str, list[str]]:
    instance_class = config.get("instance_class", "db.t3.micro")
    hourly = _RDS_HOURLY.get(instance_class, 0.20)
    monthly = hourly * _HOURS_PER_MONTH

    # Storage
    storage_gb = int(config.get("allocated_storage", 20))
    storage_type = config.get("storage_type", "gp2")
    storage_monthly = storage_gb * _EBS_MONTHLY_PER_GB.get(storage_type, 0.10)
    monthly += storage_monthly

    # Multi-AZ doubles compute cost
    assumptions = ["on-demand pricing", "us-east-1", "730 hr/month"]
    if config.get("multi_az", False):
        monthly += hourly * _HOURS_PER_MONTH  # standby replica
        assumptions.append("Multi-AZ standby included (2x compute)")

    details = (
        f"{instance_class} @ ${hourly:.4f}/hr = ${hourly * _HOURS_PER_MONTH:.2f}/mo "
        f"+ {storage_gb}GB {storage_type} = ${storage_monthly:.2f}/mo"
    )
    return monthly, details, assumptions


def _estimate_ebs(config: dict) -> tuple[float, str, list[str]]:
    size_gb = int(config.get("size", 20))
    volume_type = config.get("type", "gp3")
    monthly = size_gb * _EBS_MONTHLY_PER_GB.get(volume_type, 0.08)

    details = f"{size_gb}GB {volume_type} @ ${_EBS_MONTHLY_PER_GB.get(volume_type, 0.08):.3f}/GB/mo = ${monthly:.2f}/mo"
    return monthly, details, ["us-east-1"]


def _estimate_eks(config: dict) -> tuple[float, str, list[str]]:
    monthly = _EKS_CLUSTER_HOURLY * _HOURS_PER_MONTH
    details = f"EKS cluster @ ${_EKS_CLUSTER_HOURLY}/hr = ${monthly:.2f}/mo (control plane only, excludes nodes)"
    return monthly, details, ["control plane only — add EC2 node costs separately"]


def _estimate_nat(config: dict) -> tuple[float, str, list[str]]:
    monthly = _NAT_GATEWAY_HOURLY * _HOURS_PER_MONTH
    details = f"NAT Gateway @ ${_NAT_GATEWAY_HOURLY}/hr = ${monthly:.2f}/mo (excludes data transfer)"
    return monthly, details, ["data processing charges not included"]


def _estimate_alb(config: dict) -> tuple[float, str, list[str]]:
    monthly = _ALB_HOURLY * _HOURS_PER_MONTH
    details = f"ALB @ ${_ALB_HOURLY}/hr = ${monthly:.2f}/mo (excludes LCU charges)"
    return monthly, details, ["LCU (request processing) charges not included"]


def _estimate_elasticache(config: dict) -> tuple[float, str, list[str]]:
    monthly = _ELASTICACHE_HOURLY * _HOURS_PER_MONTH
    details = f"ElastiCache @ ${_ELASTICACHE_HOURLY}/hr = ${monthly:.2f}/mo"
    return monthly, details, ["assumes cache.m6g.large — update pricing for other node types"]


def format_cost_summary(delta: CostDelta) -> str:
    """Return a human-readable cost summary for inclusion in PR comments."""
    sign = "+" if delta.net_monthly_delta >= 0 else ""
    lines = [
        "## Cost Estimate",
        "",
        "| | Monthly (USD) |",
        "|---|---|",
        f"| New resources | ${delta.new_monthly_cost:,.2f} |",
        f"| Removed resources | -${delta.removed_monthly_cost:,.2f} |",
        f"| **Net change** | **{sign}${delta.net_monthly_delta:,.2f}** |",
        "",
        "<details><summary>Per-resource breakdown</summary>",
        "",
        "| Resource | Action | Est. Monthly |",
        "|---|---|---|",
    ]
    for e in sorted(delta.estimates, key=lambda x: x.monthly_cost_usd, reverse=True):
        action_icon = {"create": "➕", "delete": "➖", "update": "✏️"}.get(e.action, "")
        lines.append(f"| `{e.resource_address}` | {action_icon} {e.action} | ${e.monthly_cost_usd:,.2f} |")

    lines += ["", "</details>", ""]

    if delta.warnings:
        lines.append("> **Note:** " + " | ".join(delta.warnings))

    lines.append(
        "> Estimates use on-demand us-east-1 pricing. "
        "Actual costs may differ based on region, reserved instances, and data transfer."
    )
    return "\n".join(lines)
