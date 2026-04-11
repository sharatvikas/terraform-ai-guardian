"""Tests for security rule engine."""

import json
import pytest
from pathlib import Path

from guardian.parser import parse_plan, ChangeAction
from guardian.rules.security import run_security_checks, RiskLevel


FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict:
    with open(FIXTURES / name) as f:
        return json.load(f)


@pytest.fixture
def plan_with_violations():
    return parse_plan(FIXTURES / "plan_with_violations.json")


class TestSecurityGroups:
    def test_detects_ssh_open_to_world(self, plan_with_violations):
        findings = run_security_checks(plan_with_violations.changes)
        sg_findings = [f for f in findings if "aws_security_group.web" in f.resource_address]
        assert any("SSH" in f.message or "22" in f.message for f in sg_findings), \
            "Expected SSH open-to-world finding"

    def test_finding_is_critical(self, plan_with_violations):
        findings = run_security_checks(plan_with_violations.changes)
        critical = [f for f in findings if f.risk_level == RiskLevel.CRITICAL]
        assert len(critical) > 0, "Expected at least one CRITICAL finding"


class TestIAM:
    def test_detects_wildcard_star_action(self, plan_with_violations):
        findings = run_security_checks(plan_with_violations.changes)
        iam_findings = [f for f in findings if "admin" in f.resource_address]
        assert any("wildcard" in f.message.lower() or "*" in f.message for f in iam_findings), \
            "Expected wildcard IAM action finding"


class TestRDS:
    def test_detects_publicly_accessible(self, plan_with_violations):
        findings = run_security_checks(plan_with_violations.changes)
        rds_findings = [f for f in findings if "aws_db_instance" in f.resource_address]
        assert any("publicly" in f.message.lower() for f in rds_findings)

    def test_detects_unencrypted_rds(self, plan_with_violations):
        findings = run_security_checks(plan_with_violations.changes)
        rds_findings = [f for f in findings if "aws_db_instance" in f.resource_address]
        assert any("encrypt" in f.message.lower() for f in rds_findings)


class TestKMS:
    def test_detects_kms_key_destroy(self, plan_with_violations):
        findings = run_security_checks(plan_with_violations.changes)
        kms_findings = [f for f in findings if "kms" in f.resource_address.lower()]
        assert len(kms_findings) > 0, "Expected KMS destroy finding"
        assert any(f.risk_level == RiskLevel.CRITICAL for f in kms_findings)


class TestEC2:
    def test_detects_imdsv1(self, plan_with_violations):
        findings = run_security_checks(plan_with_violations.changes)
        ec2_findings = [f for f in findings if "aws_instance" in f.resource_address]
        assert any("IMDSv2" in f.message or "imds" in f.message.lower() for f in ec2_findings)

    def test_detects_unencrypted_ebs(self, plan_with_violations):
        findings = run_security_checks(plan_with_violations.changes)
        ec2_findings = [f for f in findings if "aws_instance" in f.resource_address]
        assert any("encrypt" in f.message.lower() for f in ec2_findings)


class TestParser:
    def test_parses_resource_count(self, plan_with_violations):
        assert len(plan_with_violations.changes) == 6

    def test_parses_delete_action(self, plan_with_violations):
        deletes = [c for c in plan_with_violations.changes if c.action == ChangeAction.DELETE]
        assert len(deletes) == 1
        assert "kms_key" in deletes[0].resource_type

    def test_creates_have_after_data(self, plan_with_violations):
        creates = [c for c in plan_with_violations.changes if c.action == ChangeAction.CREATE]
        for c in creates:
            assert c.after is not None


class TestStandardsEngine:
    def test_tag_violations(self, plan_with_violations):
        from guardian.rules.standards import StandardsLoader
        loader = StandardsLoader(FIXTURES.parent.parent / "standards.yaml")
        violations = loader.evaluate(plan_with_violations.changes)
        # aws_security_group.web has no tags at all
        sg_violations = [v for v in violations if "aws_security_group.web" in v.resource_address]
        assert len(sg_violations) > 0, "Expected tag violations for security group"

    def test_rds_deletion_protection(self, plan_with_violations):
        from guardian.rules.standards import StandardsLoader
        loader = StandardsLoader(FIXTURES.parent.parent / "standards.yaml")
        violations = loader.evaluate(plan_with_violations.changes)
        rds_violations = [v for v in violations if "aws_db_instance" in v.resource_address]
        rule_ids = {v.id for v in rds_violations}
        assert "RDS-001" in rule_ids or "RDS-003" in rule_ids
