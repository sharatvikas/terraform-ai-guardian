"""Unit tests for the cost estimation rules engine."""

from __future__ import annotations

import pytest
from guardian.rules.cost import (
    CostDelta,
    ResourceCostEstimate,
    estimate_plan_cost,
    format_cost_summary,
)


def _resource(rtype: str, address: str, action: str = "create", **config) -> dict:
    return {"type": rtype, "address": address, "action": action, "config": config}


class TestEC2Estimation:
    def test_known_instance_type(self):
        resources = [_resource("aws_instance", "aws_instance.web", instance_type="t3.medium")]
        delta = estimate_plan_cost(resources)
        assert len(delta.estimates) == 1
        est = delta.estimates[0]
        # t3.medium = $0.0416/hr * 730 = $30.37/mo + 8GB gp3 EBS
        assert est.monthly_cost_usd > 30.0
        assert est.monthly_cost_usd < 35.0

    def test_unknown_instance_type_uses_default(self):
        resources = [_resource("aws_instance", "aws_instance.x", instance_type="z99.quantum")]
        delta = estimate_plan_cost(resources)
        assert delta.estimates[0].monthly_cost_usd > 0

    def test_ebs_root_volume_included(self):
        resources = [_resource(
            "aws_instance", "aws_instance.large",
            instance_type="t3.micro",
            root_block_device=[{"volume_size": 100, "volume_type": "gp3"}],
        )]
        delta = estimate_plan_cost(resources)
        # t3.micro ($7.59/mo) + 100GB gp3 ($8.00/mo) = ~$15.59
        assert delta.estimates[0].monthly_cost_usd > 14.0

    def test_delete_action_goes_to_removed_cost(self):
        resources = [_resource("aws_instance", "aws_instance.old", action="delete", instance_type="m5.xlarge")]
        delta = estimate_plan_cost(resources)
        assert delta.removed_monthly_cost > 0
        assert delta.new_monthly_cost == 0
        assert delta.net_monthly_delta < 0

    def test_noop_excluded(self):
        resources = [_resource("aws_instance", "aws_instance.noop", action="no-op", instance_type="t3.micro")]
        delta = estimate_plan_cost(resources)
        assert delta.estimates == []
        assert delta.net_monthly_delta == 0.0


class TestRDSEstimation:
    def test_single_az_rds(self):
        resources = [_resource(
            "aws_db_instance", "aws_db_instance.main",
            instance_class="db.t3.medium",
            allocated_storage=100,
            storage_type="gp2",
            multi_az=False,
        )]
        delta = estimate_plan_cost(resources)
        est = delta.estimates[0]
        # db.t3.medium = $0.068/hr * 730 = $49.64 + 100GB gp2 = $10 = $59.64
        assert 55.0 < est.monthly_cost_usd < 65.0

    def test_multi_az_doubles_compute(self):
        single = [_resource("aws_db_instance", "db.s", instance_class="db.m5.large", multi_az=False)]
        multi = [_resource("aws_db_instance", "db.m", instance_class="db.m5.large", multi_az=True)]

        single_delta = estimate_plan_cost(single)
        multi_delta = estimate_plan_cost(multi)

        # Multi-AZ should cost significantly more (standby replica doubles compute)
        assert multi_delta.net_monthly_delta > single_delta.net_monthly_delta


class TestEBSEstimation:
    def test_gp3_volume(self):
        resources = [_resource("aws_ebs_volume", "aws_ebs_volume.data", size=500, type="gp3")]
        delta = estimate_plan_cost(resources)
        # 500GB * $0.08/GB = $40/mo
        assert delta.estimates[0].monthly_cost_usd == pytest.approx(40.0, rel=0.01)

    def test_io1_volume_higher_cost(self):
        gp3 = estimate_plan_cost([_resource("aws_ebs_volume", "v.gp3", size=100, type="gp3")])
        io1 = estimate_plan_cost([_resource("aws_ebs_volume", "v.io1", size=100, type="io1")])
        assert io1.net_monthly_delta > gp3.net_monthly_delta


class TestMixedResources:
    def test_net_delta_is_new_minus_removed(self):
        resources = [
            _resource("aws_instance", "aws_instance.new", action="create", instance_type="t3.medium"),
            _resource("aws_instance", "aws_instance.old", action="delete", instance_type="t3.medium"),
        ]
        delta = estimate_plan_cost(resources)
        assert delta.net_monthly_delta == pytest.approx(
            delta.new_monthly_cost - delta.removed_monthly_cost, rel=0.001
        )

    def test_unknown_resource_type_skipped(self):
        resources = [
            _resource("aws_lambda_function", "lambda.x", action="create"),
            _resource("aws_instance", "ec2.y", action="create", instance_type="t3.micro"),
        ]
        delta = estimate_plan_cost(resources)
        # Lambda not in pricing table — only EC2 should be counted
        assert len(delta.estimates) == 1
        assert delta.estimates[0].resource_type == "aws_instance"

    def test_eks_and_nat_gateway(self):
        resources = [
            _resource("aws_eks_cluster", "eks.main", action="create"),
            _resource("aws_nat_gateway", "nat.az1", action="create"),
            _resource("aws_nat_gateway", "nat.az2", action="create"),
        ]
        delta = estimate_plan_cost(resources)
        # EKS = $73/mo, 2x NAT = 2 * $32.85 = $65.70 → total ~$138.70
        assert delta.net_monthly_delta > 100.0


class TestCostSummaryFormat:
    def test_format_renders_markdown_table(self):
        delta = CostDelta(
            new_monthly_cost=150.0,
            removed_monthly_cost=50.0,
            net_monthly_delta=100.0,
            estimates=[
                ResourceCostEstimate(
                    resource_type="aws_instance",
                    resource_address="aws_instance.web",
                    action="create",
                    monthly_cost_usd=150.0,
                    details="t3.large",
                ),
                ResourceCostEstimate(
                    resource_type="aws_instance",
                    resource_address="aws_instance.old",
                    action="delete",
                    monthly_cost_usd=50.0,
                    details="t3.small",
                ),
            ],
            warnings=[],
        )
        summary = format_cost_summary(delta)
        assert "## Cost Estimate" in summary
        assert "$150.00" in summary
        assert "$50.00" in summary
        assert "+$100.00" in summary
        assert "aws_instance.web" in summary

    def test_negative_delta_shows_savings(self):
        delta = CostDelta(
            new_monthly_cost=0.0,
            removed_monthly_cost=200.0,
            net_monthly_delta=-200.0,
            estimates=[
                ResourceCostEstimate("aws_instance", "old", "delete", 200.0, ""),
            ],
            warnings=[],
        )
        summary = format_cost_summary(delta)
        assert "-$200.00" in summary
