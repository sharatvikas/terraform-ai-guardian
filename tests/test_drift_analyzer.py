"""Tests for Terraform drift detection analyzer."""

from __future__ import annotations

import json
import pytest

from guardian.drift.analyzer import (
    DriftFinding,
    DriftReport,
    parse_plan_json,
    _classify_severity,
    _diff_attributes,
    _normalize_action,
)


# ─── Fixtures ─────────────────────────────────────────────────────────────────

def make_plan(resource_changes: list) -> dict:
    return {
        "format_version": "1.2",
        "terraform_version": "1.7.5",
        "resource_changes": resource_changes,
    }


def make_change(
    resource_type: str,
    name: str,
    actions: list,
    before: dict | None = None,
    after: dict | None = None,
) -> dict:
    return {
        "address": f"{resource_type}.{name}",
        "type": resource_type,
        "name": name,
        "change": {
            "actions": actions,
            "before": before or {},
            "after": after or {},
        },
    }


# ─── parse_plan_json ──────────────────────────────────────────────────────────

class TestParsePlanJson:
    def test_no_changes_returns_empty(self):
        plan = make_plan([make_change("aws_instance", "web", ["no-op"])])
        assert parse_plan_json(plan) == []

    def test_detects_update(self):
        plan = make_plan([
            make_change(
                "aws_instance", "web", ["update"],
                before={"instance_type": "t3.micro"},
                after={"instance_type": "t3.large"},
            )
        ])
        findings = parse_plan_json(plan)
        assert len(findings) == 1
        assert findings[0].change_action == "update"
        assert any(a.name == "instance_type" for a in findings[0].changed_attributes)

    def test_detects_create(self):
        plan = make_plan([
            make_change("aws_security_group", "new_sg", ["create"], after={"name": "new-sg"})
        ])
        findings = parse_plan_json(plan)
        assert len(findings) == 1
        assert findings[0].change_action == "create"

    def test_detects_delete(self):
        plan = make_plan([
            make_change("aws_s3_bucket", "logs", ["delete"], before={"bucket": "my-logs"})
        ])
        findings = parse_plan_json(plan)
        assert len(findings) == 1
        assert findings[0].change_action == "delete"

    def test_detects_replace(self):
        plan = make_plan([
            make_change("aws_db_instance", "main", ["create", "delete"],
                        before={"identifier": "prod-db"},
                        after={"identifier": "prod-db-new"})
        ])
        findings = parse_plan_json(plan)
        assert len(findings) == 1
        assert findings[0].change_action == "replace"

    def test_module_path_stored(self):
        plan = make_plan([
            make_change("aws_instance", "web", ["update"],
                        before={"type": "t3.micro"}, after={"type": "t3.large"})
        ])
        findings = parse_plan_json(plan, module_path="modules/compute")
        assert findings[0].module == "modules/compute"

    def test_multiple_resources(self):
        plan = make_plan([
            make_change("aws_instance", "a", ["update"],
                        before={"type": "t3.micro"}, after={"type": "t3.large"}),
            make_change("aws_s3_bucket", "b", ["delete"], before={"bucket": "x"}),
            make_change("aws_instance", "c", ["no-op"]),
        ])
        findings = parse_plan_json(plan)
        assert len(findings) == 2


# ─── Severity Classification ──────────────────────────────────────────────────

class TestClassifySeverity:
    def _attrs_from(self, **kwargs):
        from guardian.drift.analyzer import DriftAttribute
        return [
            DriftAttribute(name=k, before=None, after=v, action="update")
            for k, v in kwargs.items()
        ]

    def test_s3_public_access_is_critical(self):
        attrs = self._attrs_from(block_public_acls=False, restrict_public_buckets=False)
        sev = _classify_severity("aws_s3_bucket_public_access_block", attrs, "update")
        assert sev == "CRITICAL"

    def test_rds_deletion_protection_off_is_high(self):
        attrs = self._attrs_from(deletion_protection=False)
        sev = _classify_severity("aws_rds_instance", attrs, "update")
        assert sev == "HIGH"

    def test_iam_policy_change_is_critical(self):
        # IAM policy resource type alone triggers CRITICAL
        sev = _classify_severity("aws_iam_role_policy", [], "update")
        assert sev == "CRITICAL"

    def test_tag_only_change_is_low(self):
        attrs = self._attrs_from(tags={"env": "prod"})
        sev = _classify_severity("aws_instance", attrs, "update")
        assert sev == "LOW"

    def test_rds_delete_is_high(self):
        sev = _classify_severity("aws_db_instance", [], "delete")
        assert sev == "HIGH"

    def test_unknown_resource_defaults_to_medium(self):
        from guardian.drift.analyzer import DriftAttribute
        attrs = [DriftAttribute("some_setting", "old", "new", "update")]
        sev = _classify_severity("aws_unknown_resource", attrs, "update")
        assert sev in ("LOW", "MEDIUM")


# ─── DriftFinding Properties ──────────────────────────────────────────────────

class TestDriftFinding:
    def make_finding(self, action="update", severity="LOW") -> DriftFinding:
        return DriftFinding(
            module=".",
            resource_address="aws_instance.web",
            resource_type="aws_instance",
            resource_name="web",
            change_action=action,
            changed_attributes=[],
            severity=severity,
        )

    def test_is_destructive_for_delete(self):
        assert self.make_finding("delete").is_destructive is True

    def test_is_destructive_for_replace(self):
        assert self.make_finding("replace").is_destructive is True

    def test_not_destructive_for_update(self):
        assert self.make_finding("update").is_destructive is False

    def test_summary_line_format(self):
        f = self.make_finding("update", "HIGH")
        line = f.summary_line
        assert "HIGH" in line
        assert "UPDATE" in line
        assert "aws_instance.web" in line


# ─── DriftReport ─────────────────────────────────────────────────────────────

class TestDriftReport:
    def make_report(self, findings=None) -> DriftReport:
        return DriftReport(
            modules_scanned=["."],
            modules_with_drift=["."],
            findings=findings or [],
        )

    def test_critical_findings_filter(self):
        report = self.make_report([
            DriftFinding(".", "a", "aws_iam_policy", "p", "update", [], severity="CRITICAL"),
            DriftFinding(".", "b", "aws_instance", "i", "update", [], severity="LOW"),
        ])
        assert len(report.critical_findings) == 1
        assert report.critical_findings[0].resource_address == "a"

    def test_to_dict_summary_counts(self):
        findings = [
            DriftFinding(".", f"r{i}", "t", "n", "update", [], severity=s)
            for i, s in enumerate(["CRITICAL", "HIGH", "MEDIUM", "LOW", "LOW"])
        ]
        report = self.make_report(findings)
        d = report.to_dict()
        assert d["summary"]["critical_count"] == 1
        assert d["summary"]["high_count"] == 1
        assert d["summary"]["medium_count"] == 1
        assert d["summary"]["low_count"] == 2
        assert d["summary"]["total_drift_resources"] == 5

    def test_to_dict_findings_sorted_by_severity(self):
        findings = [
            DriftFinding(".", "low", "t", "n", "update", [], severity="LOW"),
            DriftFinding(".", "critical", "t", "n", "update", [], severity="CRITICAL"),
            DriftFinding(".", "high", "t", "n", "update", [], severity="HIGH"),
        ]
        report = self.make_report(findings)
        d = report.to_dict()
        severities = [f["severity"] for f in d["findings"]]
        assert severities == ["CRITICAL", "HIGH", "LOW"]

    def test_to_dict_has_all_keys(self):
        d = self.make_report().to_dict()
        assert "summary" in d
        assert "modules_scanned" in d
        assert "modules_with_drift" in d
        assert "findings" in d


# ─── _normalize_action ────────────────────────────────────────────────────────

class TestNormalizeAction:
    def test_replace_from_create_delete(self):
        assert _normalize_action(["create", "delete"]) == "replace"

    def test_update(self):
        assert _normalize_action(["update"]) == "update"

    def test_create(self):
        assert _normalize_action(["create"]) == "create"

    def test_delete(self):
        assert _normalize_action(["delete"]) == "delete"

    def test_replace_explicit(self):
        assert _normalize_action(["replace"]) == "replace"
