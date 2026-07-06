"""Drift analysis engine — parses terraform plan JSON and classifies drift findings.

Drift classification:
  CRITICAL — Security-sensitive changes (security groups, IAM, encryption removed)
  HIGH     — Availability/data risk (autoscaling disabled, deletion protection off)
  MEDIUM   — Configuration drift (tags removed, logging disabled, non-default params)
  LOW      — Cosmetic/metadata drift (name changes, description updates)

Each finding includes:
  - resource address and type
  - drift type (create/update/delete)
  - changed attributes with before/after values
  - AI-generated root cause and remediation
  - risk classification
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ─── Risk Classification ──────────────────────────────────────────────────────

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

# Resource types and attributes that constitute CRITICAL drift
_CRITICAL_PATTERNS = [
    # Security groups with ingress 0.0.0.0/0 added
    ("aws_security_group", "ingress", "cidr_blocks", "0.0.0.0/0"),
    ("aws_security_group_rule", "cidr_blocks", None, "0.0.0.0/0"),
    # IAM changes
    ("aws_iam_role_policy", None, None, None),
    ("aws_iam_policy", None, None, None),
    ("aws_iam_user_policy", None, None, None),
    # Encryption removal
    ("aws_s3_bucket_server_side_encryption_configuration", None, None, None),
    ("aws_ebs_volume", "encrypted", "after", "false"),
    ("aws_rds_cluster", "storage_encrypted", "after", "false"),
    # Public access enabled
    ("aws_s3_bucket_public_access_block", "block_public_acls", "after", "false"),
    ("aws_s3_bucket_public_access_block", "restrict_public_buckets", "after", "false"),
]

_HIGH_PATTERNS = [
    # Deletion protection removed
    ("aws_rds_instance", "deletion_protection", "after", "false"),
    ("aws_rds_cluster", "deletion_protection", "after", "false"),
    ("aws_db_instance", "deletion_protection", "after", "false"),
    # Backup disabled
    ("aws_db_instance", "backup_retention_period", "after", "0"),
    ("aws_rds_cluster", "backup_retention_period", "after", "0"),
    # Multi-AZ disabled in prod
    ("aws_db_instance", "multi_az", "after", "false"),
    # Logging disabled
    ("aws_s3_bucket_logging", None, None, None),
    ("aws_cloudtrail", "enable_logging", "after", "false"),
]

_MEDIUM_PATTERNS = [
    # Tag removal
    ("*", "tags", None, None),
    # Monitoring disabled
    ("aws_db_instance", "monitoring_interval", "after", "0"),
    # Auto minor version upgrade disabled
    ("aws_db_instance", "auto_minor_version_upgrade", "after", "false"),
]


@dataclass
class DriftAttribute:
    name: str
    before: Any
    after: Any
    action: str  # "update", "add", "delete"


@dataclass
class DriftFinding:
    module: str
    resource_address: str
    resource_type: str
    resource_name: str
    change_action: str        # "create", "update", "delete", "replace"
    changed_attributes: list[DriftAttribute]
    severity: str = "LOW"
    root_cause: str = ""      # AI-generated
    remediation: str = ""     # AI-generated
    tags: dict = field(default_factory=dict)

    @property
    def is_destructive(self) -> bool:
        return self.change_action in ("delete", "replace")

    @property
    def summary_line(self) -> str:
        attrs = ", ".join(a.name for a in self.changed_attributes[:3])
        suffix = f" (+{len(self.changed_attributes) - 3} more)" if len(self.changed_attributes) > 3 else ""
        return f"[{self.severity}] {self.change_action.upper()} {self.resource_address} — {attrs}{suffix}"


@dataclass
class DriftReport:
    modules_scanned: list[str]
    modules_with_drift: list[str]
    findings: list[DriftFinding]
    ai_summary: str = ""
    scan_timestamp: str = ""

    @property
    def critical_findings(self) -> list[DriftFinding]:
        return [f for f in self.findings if f.severity == "CRITICAL"]

    @property
    def high_findings(self) -> list[DriftFinding]:
        return [f for f in self.findings if f.severity == "HIGH"]

    def to_dict(self) -> dict:
        return {
            "summary": {
                "modules_scanned": len(self.modules_scanned),
                "modules_with_drift": len(self.modules_with_drift),
                "total_drift_resources": len(self.findings),
                "critical_count": len(self.critical_findings),
                "high_count": len(self.high_findings),
                "medium_count": len([f for f in self.findings if f.severity == "MEDIUM"]),
                "low_count": len([f for f in self.findings if f.severity == "LOW"]),
                "destructive_count": len([f for f in self.findings if f.is_destructive]),
            },
            "modules_scanned": self.modules_scanned,
            "modules_with_drift": self.modules_with_drift,
            "ai_summary": self.ai_summary,
            "scan_timestamp": self.scan_timestamp,
            "findings": [
                {
                    "module": f.module,
                    "resource": f.resource_address,
                    "resource_type": f.resource_type,
                    "action": f.change_action,
                    "severity": f.severity,
                    "root_cause": f.root_cause,
                    "remediation": f.remediation,
                    "changed_attributes": [
                        {"name": a.name, "before": a.before, "after": a.after, "action": a.action}
                        for a in f.changed_attributes
                    ],
                    "is_destructive": f.is_destructive,
                }
                for f in sorted(self.findings, key=lambda x: SEVERITY_RANK.get(x.severity, 0), reverse=True)
            ],
        }


# ─── Plan Parser ──────────────────────────────────────────────────────────────

def parse_plan_json(plan_json: dict, module_path: str = ".") -> list[DriftFinding]:
    """Parse a terraform plan JSON and extract drift findings."""
    findings = []
    resource_changes = plan_json.get("resource_changes", [])

    for change in resource_changes:
        actions = change.get("change", {}).get("actions", ["no-op"])
        if actions == ["no-op"]:
            continue

        resource_type = change.get("type", "")
        resource_name = change.get("name", "")
        address = change.get("address", f"{resource_type}.{resource_name}")

        before = change.get("change", {}).get("before") or {}
        after = change.get("change", {}).get("after") or {}

        action = _normalize_action(actions)
        changed_attrs = _diff_attributes(before, after, action)

        if not changed_attrs and action not in ("create", "delete"):
            continue

        severity = _classify_severity(resource_type, changed_attrs, action)

        finding = DriftFinding(
            module=module_path,
            resource_address=address,
            resource_type=resource_type,
            resource_name=resource_name,
            change_action=action,
            changed_attributes=changed_attrs,
            severity=severity,
        )
        findings.append(finding)

    return findings


def _normalize_action(actions: list[str]) -> str:
    if "replace" in actions or ({"create", "delete"} <= set(actions)):
        return "replace"
    if "create" in actions:
        return "create"
    if "delete" in actions:
        return "delete"
    return "update"


def _diff_attributes(before: dict, after: dict, action: str) -> list[DriftAttribute]:
    """Extract changed attributes between before/after state."""
    attrs = []
    all_keys = set(before.keys()) | set(after.keys())

    for key in all_keys:
        b = before.get(key)
        a = after.get(key)

        if b == a:
            continue
        if key in ("id", "arn", "tags_all"):
            continue

        if key not in before:
            change_action = "add"
        elif key not in after:
            change_action = "delete"
        else:
            change_action = "update"

        attrs.append(DriftAttribute(name=key, before=b, after=a, action=change_action))

    return attrs


def _classify_severity(resource_type: str, attrs: list[DriftAttribute], action: str) -> str:
    """Classify drift severity based on resource type and attribute changes."""
    attr_map = {a.name: a for a in attrs}

    # Check CRITICAL patterns
    for rtype, attr, field_name, value in _CRITICAL_PATTERNS:
        if rtype != "*" and rtype != resource_type:
            continue
        if attr and attr not in attr_map:
            continue
        if field_name == "after" and attr:
            a = attr_map.get(attr)
            if a and _matches_value(a.after, value):
                return "CRITICAL"
        elif rtype == resource_type and attr is None:
            return "CRITICAL"
        elif attr and field_name is None and attr in attr_map:
            a = attr_map[attr]
            if value and _matches_value(a.after, value):
                return "CRITICAL"

    # Check HIGH patterns
    for rtype, attr, field_name, value in _HIGH_PATTERNS:
        if rtype != "*" and rtype != resource_type:
            continue
        if attr and attr not in attr_map:
            continue
        if field_name == "after" and attr and attr in attr_map:
            a = attr_map[attr]
            if _matches_value(str(a.after), value):
                return "HIGH"

    # Destructive actions on data resources = HIGH by default
    if action in ("delete", "replace") and any(
        kw in resource_type
        for kw in ("rds", "db_instance", "dynamodb", "s3", "efs", "elasticache")
    ):
        return "HIGH"

    # Tag-only changes = LOW (checked before generic MEDIUM patterns —
    # a pure tag drift is cosmetic even though tag removal appears there)
    if attrs and all(a.name in ("tags", "description", "name") for a in attrs):
        return "LOW"

    # Check MEDIUM patterns
    for rtype, attr, field_name, value in _MEDIUM_PATTERNS:
        if rtype != "*" and rtype != resource_type:
            continue
        if attr and attr in attr_map:
            return "MEDIUM"

    return "MEDIUM" if attrs else "LOW"


def _matches_value(actual: Any, expected: str) -> bool:
    if actual is None:
        return False
    # Case-insensitive: plan JSON booleans render as Python True/False,
    # while pattern tables use lowercase "true"/"false".
    s = str(actual).lower()
    if expected.lower() in s:
        return True
    if isinstance(actual, list) and expected in actual:
        return True
    return False


# ─── Artifact Loader ──────────────────────────────────────────────────────────

def load_artifacts(artifacts_dir: str) -> dict[str, list[DriftFinding]]:
    """Load all drift JSON artifacts from the CI artifact directory."""
    findings_by_module: dict[str, list[DriftFinding]] = {}
    base = Path(artifacts_dir)

    for drift_json in base.rglob("drift.json"):
        module_path = str(drift_json.parent.relative_to(base))
        try:
            plan = json.loads(drift_json.read_text())
            findings = parse_plan_json(plan, module_path=module_path)
            if findings:
                findings_by_module[module_path] = findings
        except Exception as e:
            # Log but don't fail — partial results are better than none
            print(f"Warning: could not parse {drift_json}: {e}")

    return findings_by_module
