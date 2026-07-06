"""Tests for the org standards engine (config loading + plan evaluation)."""

from pathlib import Path

import pytest

from guardian.parser import parse_plan
from guardian.rules.security import RiskLevel
from guardian.rules.standards import (
    StandardsConfig,
    StandardsError,
    StandardsEvaluator,
    StandardViolation,
    load_standards,
)

FIXTURES = Path(__file__).parent / "fixtures"

FULL_CONFIG = """
version: 1
required_tags: [Environment, Team, Owner]
tag_values:
  Environment: [production, staging, development, sandbox]
allowed_instance_types:
  aws_instance: ["t3.*", "m6i.*"]
  aws_db_instance: ["db.t3.*", "db.r6g.*"]
allowed_regions: [us-east-1, us-west-2]
encryption:
  s3: true
  rds: true
  ebs: true
naming_patterns:
  aws_s3_bucket: "^[a-z0-9][a-z0-9.-]{2,62}$"
module_allowlist:
  enforce: true
  allowed_sources:
    - "terraform-aws-modules/*"
    - "./modules/*"
severities:
  naming_patterns: MEDIUM
"""


@pytest.fixture
def config(tmp_path) -> StandardsConfig:
    f = tmp_path / ".tf-guardian.yml"
    f.write_text(FULL_CONFIG)
    return load_standards(f)


@pytest.fixture
def violating_plan():
    return parse_plan(FIXTURES / "plan_standards_violations.json")


@pytest.fixture
def clean_plan():
    return parse_plan(FIXTURES / "plan_clean.json")


@pytest.fixture
def violations(config, violating_plan) -> list[StandardViolation]:
    return StandardsEvaluator(config).evaluate(violating_plan)


def by_rule(violations, rule_id):
    return [v for v in violations if v.rule_id == rule_id]


# ─── Config loading ───────────────────────────────────────────────────────────

class TestLoadStandards:
    def test_loads_all_sections(self, config):
        assert config.required_tags == ["Environment", "Team", "Owner"]
        assert config.allowed_regions == ["us-east-1", "us-west-2"]
        assert config.encryption == {"s3": True, "rds": True, "ebs": True}
        assert "aws_s3_bucket" in config.naming_patterns
        assert config.module_allowlist_enforce is True
        assert not config.is_empty

    def test_severity_override_and_defaults(self, config):
        assert config.severity_for("naming_patterns") == RiskLevel.MEDIUM  # overridden
        assert config.severity_for("required_tags") == RiskLevel.HIGH      # default

    def test_explicit_missing_file_raises(self):
        with pytest.raises(StandardsError, match="not found"):
            load_standards("/nonexistent/.tf-guardian.yml")

    def test_no_config_found_returns_empty(self, tmp_path):
        config = load_standards(search_dir=tmp_path)
        assert config.is_empty
        assert StandardsEvaluator(config).evaluate(
            parse_plan(FIXTURES / "plan_standards_violations.json")
        ) == []

    def test_auto_discovers_tf_guardian_yml(self, tmp_path):
        (tmp_path / ".tf-guardian.yml").write_text("required_tags: [Environment]\n")
        config = load_standards(search_dir=tmp_path)
        assert config.required_tags == ["Environment"]
        assert config.source_file.endswith(".tf-guardian.yml")

    def test_invalid_yaml_raises(self, tmp_path):
        f = tmp_path / ".tf-guardian.yml"
        f.write_text("required_tags: [unclosed\n  nope: {{")
        with pytest.raises(StandardsError, match="parse"):
            load_standards(f)

    def test_invalid_regex_raises_at_load_time(self, tmp_path):
        f = tmp_path / ".tf-guardian.yml"
        f.write_text('naming_patterns:\n  aws_s3_bucket: "([unclosed"\n')
        with pytest.raises(StandardsError, match="invalid regex"):
            load_standards(f)

    def test_invalid_severity_raises(self, tmp_path):
        f = tmp_path / ".tf-guardian.yml"
        f.write_text("severities:\n  required_tags: BANANAS\n")
        with pytest.raises(StandardsError, match="unknown severity"):
            load_standards(f)

    def test_unknown_encryption_service_raises(self, tmp_path):
        f = tmp_path / ".tf-guardian.yml"
        f.write_text("encryption:\n  quantum_disk: true\n")
        with pytest.raises(StandardsError, match="unknown encryption service"):
            load_standards(f)

    def test_non_mapping_top_level_raises(self, tmp_path):
        f = tmp_path / ".tf-guardian.yml"
        f.write_text("- just\n- a\n- list\n")
        with pytest.raises(StandardsError, match="must be a mapping"):
            load_standards(f)

    def test_legacy_standards_yaml_still_loads(self):
        # The repo-root legacy file (condition-rule format) must keep working.
        config = load_standards(Path(__file__).parent.parent / "standards.yaml")
        assert len(config.custom_rules) > 0
        rule_ids = {r.id for r in config.custom_rules}
        assert "TAG-001" in rule_ids
        assert "RDS-001" in rule_ids

    def test_legacy_rule_with_bad_condition_type_raises(self, tmp_path):
        f = tmp_path / ".tf-guardian.yml"
        f.write_text(
            "standards:\n"
            "  - id: X-001\n"
            "    conditions:\n"
            "      - type: telepathy\n"
            "        field: tags\n"
        )
        with pytest.raises(StandardsError, match="unknown condition type"):
            load_standards(f)


# ─── Evaluation: violating plan ───────────────────────────────────────────────

class TestEvaluation:
    def test_clean_plan_has_no_violations(self, config, clean_plan):
        assert StandardsEvaluator(config).evaluate(clean_plan) == []

    def test_missing_required_tags(self, violations):
        missing = by_rule(violations, "STD-TAG-001")
        legacy = [v for v in missing if v.resource_address == "aws_instance.legacy"]
        missing_tags = {v.message.split("'")[1] for v in legacy}
        assert missing_tags == {"Team", "Owner"}
        assert all(v.severity == RiskLevel.HIGH for v in legacy)

    def test_disallowed_tag_value(self, violations):
        bad_values = by_rule(violations, "STD-TAG-002")
        assert any(
            v.resource_address == "aws_instance.legacy" and "'prod'" in v.message
            for v in bad_values
        )

    def test_disallowed_instance_types(self, violations):
        compute = by_rule(violations, "STD-COMPUTE-001")
        addresses = {v.resource_address for v in compute}
        assert "aws_instance.legacy" in addresses          # m4.10xlarge
        assert "aws_db_instance.reporting" in addresses    # db.m3.medium

    def test_disallowed_region_from_availability_zone(self, violations):
        regions = by_rule(violations, "STD-REGION-001")
        assert any(
            v.resource_address == "aws_instance.legacy" and "eu-central-1" in v.message
            for v in regions
        )

    def test_disallowed_provider_region(self, violations):
        provider_regions = by_rule(violations, "STD-REGION-002")
        assert len(provider_regions) == 1
        assert provider_regions[0].resource_address == "provider.aws.frankfurt"
        assert "eu-central-1" in provider_regions[0].message

    def test_unencrypted_rds(self, violations):
        rds = by_rule(violations, "STD-ENC-RDS")
        assert {v.resource_address for v in rds} == {"aws_db_instance.reporting"}

    def test_unencrypted_ebs_and_root_volume(self, violations):
        ebs = by_rule(violations, "STD-ENC-EBS")
        addresses = {v.resource_address for v in ebs}
        assert "aws_ebs_volume.scratch" in addresses
        assert "aws_instance.legacy" in addresses  # root_block_device.encrypted = false

    def test_s3_bucket_without_sse(self, violations):
        s3 = by_rule(violations, "STD-ENC-S3")
        assert {v.resource_address for v in s3} == {"aws_s3_bucket.Analytics_Data"}

    def test_s3_bucket_with_companion_sse_resource_passes(self, config, clean_plan):
        # plan_clean.json encrypts its bucket via a separate SSE configuration resource
        violations = StandardsEvaluator(config).evaluate(clean_plan)
        assert by_rule(violations, "STD-ENC-S3") == []

    def test_naming_pattern_violation(self, violations):
        naming = by_rule(violations, "STD-NAME-001")
        assert any(v.resource_address == "aws_s3_bucket.Analytics_Data" for v in naming)
        # severity override from the config applies
        assert all(v.severity == RiskLevel.MEDIUM for v in naming)

    def test_module_allowlist_violation(self, violations):
        mod = by_rule(violations, "STD-MOD-001")
        assert len(mod) == 1
        assert mod[0].resource_address == "module.snowflake_loader.aws_iam_role.loader"
        assert "random-person/snowflake-loader" in mod[0].message

    def test_allowlisted_module_passes(self, config, clean_plan):
        violations = StandardsEvaluator(config).evaluate(clean_plan)
        assert by_rule(violations, "STD-MOD-001") == []

    def test_destroyed_resources_are_skipped(self, violations):
        # aws_db_instance.deprecated is a pure delete — standards do not apply
        assert not any(v.resource_address == "aws_db_instance.deprecated" for v in violations)

    def test_every_violation_is_fully_structured(self, violations):
        assert violations, "fixture should produce violations"
        for v in violations:
            assert v.rule_id.startswith("STD-")
            assert isinstance(v.severity, RiskLevel)
            assert v.resource_address
            assert v.message
            assert v.fix_hint

    def test_to_finding_conversion(self, violations):
        finding = violations[0].to_finding()
        assert finding.category == "Standards"
        assert finding.risk_level == violations[0].severity
        assert violations[0].rule_id in finding.title
        assert finding.recommendation


# ─── Legacy condition rules against the security fixture ─────────────────────

class TestLegacyConditionRules:
    @pytest.fixture
    def legacy_violations(self):
        config = load_standards(Path(__file__).parent.parent / "standards.yaml")
        plan = parse_plan(FIXTURES / "plan_with_violations.json")
        return StandardsEvaluator(config).evaluate(plan)

    def test_tag_rules_fire(self, legacy_violations):
        sg = [v for v in legacy_violations if v.resource_address == "aws_security_group.web"]
        assert any(v.rule_id == "TAG-001" for v in sg)

    def test_rds_rules_fire(self, legacy_violations):
        rds_ids = {
            v.rule_id for v in legacy_violations
            if "aws_db_instance" in v.resource_address
        }
        assert "RDS-001" in rds_ids  # deletion_protection = false
        assert "RDS-003" in rds_ids  # publicly_accessible = true

    def test_ec2_imdsv2_rule_fires(self, legacy_violations):
        ec2_ids = {
            v.rule_id for v in legacy_violations
            if v.resource_address == "aws_instance.bastion"
        }
        assert "EC2-001" in ec2_ids
        assert "EC2-002" in ec2_ids

    def test_message_templating(self, legacy_violations):
        v = next(v for v in legacy_violations if v.rule_id == "TAG-001")
        assert "{resource_address}" not in v.message
        assert v.resource_address in v.message
