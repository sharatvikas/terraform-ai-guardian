"""Tests for the security rule engine and plan parser."""

import pytest
from pathlib import Path

from guardian.parser import parse_plan
from guardian.rules.security import RiskLevel, run_security_rules

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def plan_with_violations():
    return parse_plan(FIXTURES / "plan_with_violations.json")


@pytest.fixture
def findings(plan_with_violations):
    return run_security_rules(plan_with_violations)


class TestSecurityGroups:
    def test_detects_ssh_open_to_world(self, findings):
        sg = [f for f in findings if f.resource_address == "aws_security_group.web"]
        assert any("SSH" in f.title or "22" in f.title for f in sg), \
            "Expected SSH open-to-world finding"

    def test_finding_is_critical(self, findings):
        critical = [f for f in findings if f.risk_level == RiskLevel.CRITICAL]
        assert len(critical) > 0, "Expected at least one CRITICAL finding"


class TestIAM:
    def test_detects_wildcard_star_action(self, findings):
        iam = [f for f in findings if "admin" in f.resource_address]
        assert any(
            "wildcard" in f.title.lower() or "*" in f.title for f in iam
        ), "Expected wildcard IAM action finding"


class TestRDS:
    def test_detects_publicly_accessible(self, findings):
        rds = [f for f in findings if "aws_db_instance" in f.resource_address]
        assert any("publicly" in f.title.lower() for f in rds)

    def test_detects_unencrypted_rds(self, findings):
        rds = [f for f in findings if "aws_db_instance" in f.resource_address]
        assert any("encrypt" in f.title.lower() for f in rds)


class TestKMS:
    def test_detects_kms_key_destroy(self, findings):
        kms = [f for f in findings if "kms" in f.resource_address.lower()]
        assert len(kms) > 0, "Expected KMS destroy finding"
        assert any(f.risk_level == RiskLevel.CRITICAL for f in kms)


class TestEC2:
    def test_detects_imdsv1(self, findings):
        ec2 = [f for f in findings if "aws_instance" in f.resource_address]
        assert any("IMDSv2" in f.title or "imds" in f.title.lower() for f in ec2)

    def test_detects_unencrypted_ebs(self, findings):
        ec2 = [f for f in findings if "aws_instance" in f.resource_address]
        assert any("encrypt" in f.title.lower() for f in ec2)

    def test_clean_instance_produces_no_ec2_findings(self):
        plan = parse_plan(FIXTURES / "plan_clean.json")
        findings = run_security_rules(plan)
        assert [f for f in findings if f.category == "EC2"] == []


class TestParser:
    def test_parses_resource_count(self, plan_with_violations):
        assert len(plan_with_violations.resource_changes) == 6

    def test_parses_delete_action(self, plan_with_violations):
        deletes = [c for c in plan_with_violations.resource_changes if c.is_destroy]
        assert len(deletes) == 1
        assert "kms_key" in deletes[0].resource_type

    def test_creates_have_after_data(self, plan_with_violations):
        creates = [c for c in plan_with_violations.resource_changes if c.is_create]
        for c in creates:
            assert c.after is not None

    def test_parses_module_sources_and_provider_regions(self):
        plan = parse_plan(FIXTURES / "plan_clean.json")
        assert plan.module_sources == {"module.vpc": "terraform-aws-modules/vpc/aws"}
        assert plan.provider_regions == {"aws": "us-east-1"}

    def test_plan_without_configuration_block(self, plan_with_violations):
        assert plan_with_violations.module_sources == {}
        assert plan_with_violations.provider_regions == {}


class TestFindingsShape:
    def test_findings_are_sorted_most_severe_first(self, findings):
        order = list(RiskLevel)
        indices = [order.index(f.risk_level) for f in findings]
        assert indices == sorted(indices)

    def test_all_findings_have_recommendations(self, findings):
        for f in findings:
            assert f.recommendation
            assert f.resource_address
