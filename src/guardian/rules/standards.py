"""Org standards engine — loads `.tf-guardian.yml` and evaluates Terraform plans against it.

Supports two config styles, which may coexist in one file:

1. First-class sections (recommended)::

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
      efs: true
      dynamodb: false
    naming_patterns:
      aws_s3_bucket: "^[a-z0-9][a-z0-9.-]{2,62}$"
      aws_iam_role: "^[a-z][a-z0-9-]+-role$"
    module_allowlist:
      enforce: true
      allowed_sources:
        - "terraform-aws-modules/*"
        - "git::https://github.com/my-org/*"

2. Legacy condition rules (backwards compatible with `.guardian/standards.yaml`)::

    standards:
      - id: RDS-001
        severity: HIGH
        resource_types: ["aws_db_instance"]
        message: "{resource_address} must have deletion_protection = true"
        conditions:
          - type: equals
            field: deletion_protection
            value: true
            remediation: "Add deletion_protection = true"
"""

from __future__ import annotations

import fnmatch
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from guardian.parser import ResourceChange, TerraformPlan
from guardian.rules.security import Finding, RiskLevel

logger = logging.getLogger("guardian.standards")

#: Default file names searched (in order) when no explicit path is given.
DEFAULT_CONFIG_FILES = (
    ".tf-guardian.yml",
    ".tf-guardian.yaml",
    ".guardian/standards.yaml",
    "standards.yaml",
)

#: resource_type -> attribute holding the compute size, for allowed_instance_types.
_INSTANCE_TYPE_ATTRS = {
    "aws_instance": "instance_type",
    "aws_launch_template": "instance_type",
    "aws_db_instance": "instance_class",
    "aws_rds_cluster_instance": "instance_class",
    "aws_elasticache_cluster": "node_type",
    "aws_opensearch_domain": "instance_type",
}

#: Encryption checks keyed by config toggle. Each entry: resource_type -> (attr_path, expected).
_ENCRYPTION_CHECKS: dict[str, list[tuple[str, str, str]]] = {
    # toggle: [(resource_type, dotted attribute path, fix hint)]
    "rds": [
        ("aws_db_instance", "storage_encrypted", "Set storage_encrypted = true"),
        ("aws_rds_cluster", "storage_encrypted", "Set storage_encrypted = true"),
    ],
    "ebs": [
        ("aws_ebs_volume", "encrypted", "Set encrypted = true"),
        ("aws_instance", "root_block_device.encrypted",
         "Add root_block_device { encrypted = true }"),
    ],
    "efs": [
        ("aws_efs_file_system", "encrypted", "Set encrypted = true"),
    ],
    "dynamodb": [
        ("aws_dynamodb_table", "server_side_encryption.enabled",
         "Add server_side_encryption { enabled = true }"),
    ],
}

_S3_SSE_RESOURCE = "aws_s3_bucket_server_side_encryption_configuration"


class StandardsError(Exception):
    """Raised when the standards config file is missing, unparsable, or invalid."""


@dataclass
class StandardViolation:
    """A structured org-standards violation."""

    rule_id: str
    severity: RiskLevel
    resource_address: str
    message: str
    fix_hint: str = ""

    def to_finding(self) -> Finding:
        """Convert to the shared Finding shape used by the report pipeline."""
        return Finding(
            risk_level=self.severity,
            category="Standards",
            resource_address=self.resource_address,
            title=f"[{self.rule_id}] {self.message}",
            description=self.message,
            recommendation=self.fix_hint or "See your organisation's Terraform standards.",
        )


def _parse_severity(raw: Any, context: str, default: RiskLevel = RiskLevel.MEDIUM) -> RiskLevel:
    if raw is None:
        return default
    name = str(raw).strip().upper()
    try:
        return RiskLevel[name]
    except KeyError:
        raise StandardsError(
            f"{context}: unknown severity {raw!r} "
            f"(expected one of {', '.join(level.name for level in RiskLevel)})"
        ) from None


def _compile_pattern(pattern: str, context: str) -> re.Pattern[str]:
    try:
        return re.compile(pattern)
    except re.error as e:
        raise StandardsError(f"{context}: invalid regex {pattern!r}: {e}") from None


# ─── Legacy condition rules ───────────────────────────────────────────────────

@dataclass
class ConditionRule:
    """A legacy condition-based rule from a `standards:` list."""

    id: str
    severity: RiskLevel
    resource_types: list[str]
    conditions: list[dict[str, Any]]
    message: str
    description: str = ""

    _VALID_TYPES = frozenset({
        "required", "equals", "not_equals", "matches", "not_matches",
        "in", "not_in", "min_length",
    })

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ConditionRule":
        if not isinstance(raw, dict) or "id" not in raw:
            raise StandardsError(f"standards rule missing required 'id' key: {raw!r}")
        rule_id = str(raw["id"])
        conditions = raw.get("conditions") or []
        if not isinstance(conditions, list):
            raise StandardsError(f"rule {rule_id}: 'conditions' must be a list")
        for cond in conditions:
            ctype = cond.get("type") if isinstance(cond, dict) else None
            if ctype not in cls._VALID_TYPES:
                raise StandardsError(
                    f"rule {rule_id}: unknown condition type {ctype!r} "
                    f"(expected one of {', '.join(sorted(cls._VALID_TYPES))})"
                )
            if ctype in ("matches", "not_matches"):
                _compile_pattern(str(cond.get("pattern", "")), f"rule {rule_id}")
        return cls(
            id=rule_id,
            severity=_parse_severity(raw.get("severity"), f"rule {rule_id}"),
            resource_types=list(raw.get("resource_types", ["*"])),
            conditions=conditions,
            message=str(raw.get("message") or raw.get("description") or rule_id),
            description=str(raw.get("description", "")),
        )

    def applies_to(self, resource_type: str) -> bool:
        return "*" in self.resource_types or resource_type in self.resource_types

    def evaluate(self, change: ResourceChange) -> StandardViolation | None:
        if not self.applies_to(change.resource_type):
            return None
        values = change.after or {}
        for condition in self.conditions:
            if not self._condition_holds(condition, values):
                return StandardViolation(
                    rule_id=self.id,
                    severity=self.severity,
                    resource_address=change.address,
                    message=self.message.format(
                        resource_address=change.address,
                        resource_type=change.resource_type,
                    ),
                    fix_hint=str(condition.get("remediation", "")).strip(),
                )
        return None

    def _condition_holds(self, condition: dict[str, Any], values: dict[str, Any]) -> bool:
        cond_type = condition.get("type")
        value = get_nested(values, condition.get("field", ""))

        if cond_type == "required":
            return value is not None and value != "" and value != []
        if cond_type == "equals":
            return value == condition.get("value")
        if cond_type == "not_equals":
            return value != condition.get("value")
        if cond_type == "matches":
            return value is None or bool(re.search(condition.get("pattern", ""), str(value)))
        if cond_type == "not_matches":
            return value is None or not re.search(condition.get("pattern", ""), str(value))
        if cond_type == "in":
            return value is None or value in condition.get("values", [])
        if cond_type == "not_in":
            return value not in condition.get("values", [])
        if cond_type == "min_length":
            return isinstance(value, (str, list)) and len(value) >= condition.get("value", 0)
        return True  # unreachable — validated at load time


def get_nested(obj: Any, path: str) -> Any:
    """Traverse a dot-notation path like 'tags.Environment' through nested dicts/lists.

    Lists take the first element (Terraform plan JSON renders single blocks as 1-lists).
    """
    if not path:
        return obj
    cur = obj
    for part in path.split("."):
        if isinstance(cur, list):
            cur = cur[0] if cur else None
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


# ─── First-class config ───────────────────────────────────────────────────────

@dataclass
class StandardsConfig:
    """Parsed, validated org standards."""

    required_tags: list[str] = field(default_factory=list)
    tag_values: dict[str, list[str]] = field(default_factory=dict)
    allowed_instance_types: dict[str, list[str]] = field(default_factory=dict)
    allowed_regions: list[str] = field(default_factory=list)
    encryption: dict[str, bool] = field(default_factory=dict)
    naming_patterns: dict[str, re.Pattern[str]] = field(default_factory=dict)
    module_allowlist: list[str] = field(default_factory=list)
    module_allowlist_enforce: bool = False
    custom_rules: list[ConditionRule] = field(default_factory=list)
    severities: dict[str, RiskLevel] = field(default_factory=dict)
    source_file: str = ""

    _DEFAULT_SEVERITIES = {
        "required_tags": RiskLevel.HIGH,
        "tag_values": RiskLevel.MEDIUM,
        "allowed_instance_types": RiskLevel.MEDIUM,
        "allowed_regions": RiskLevel.HIGH,
        "encryption": RiskLevel.HIGH,
        "naming_patterns": RiskLevel.LOW,
        "module_allowlist": RiskLevel.HIGH,
    }

    def severity_for(self, section: str) -> RiskLevel:
        return self.severities.get(section, self._DEFAULT_SEVERITIES.get(section, RiskLevel.MEDIUM))

    @property
    def is_empty(self) -> bool:
        return not any((
            self.required_tags, self.tag_values, self.allowed_instance_types,
            self.allowed_regions, self.encryption, self.naming_patterns,
            self.module_allowlist, self.custom_rules,
        ))


def load_standards(path: str | Path | None = None, search_dir: str | Path = ".") -> StandardsConfig:
    """Load and validate a standards config.

    If ``path`` is given it must exist. Otherwise the default file names are
    searched under ``search_dir``; an empty config is returned when none exist.
    """
    if path:
        config_path = Path(path)
        if not config_path.exists():
            raise StandardsError(f"Standards file not found: {config_path}")
    else:
        config_path = None
        for candidate in DEFAULT_CONFIG_FILES:
            p = Path(search_dir) / candidate
            if p.exists():
                config_path = p
                break
        if config_path is None:
            logger.info("No standards config found under %s — standards checks skipped", search_dir)
            return StandardsConfig()

    try:
        raw = yaml.safe_load(config_path.read_text())
    except yaml.YAMLError as e:
        raise StandardsError(f"Could not parse {config_path}: {e}") from e
    except OSError as e:
        raise StandardsError(f"Could not read {config_path}: {e}") from e

    if raw is None:
        return StandardsConfig(source_file=str(config_path))
    if not isinstance(raw, dict):
        raise StandardsError(f"{config_path}: top level must be a mapping, got {type(raw).__name__}")

    return _parse_config(raw, str(config_path))


def _parse_config(raw: dict[str, Any], source_file: str) -> StandardsConfig:
    ctx = source_file

    def _str_list(key: str) -> list[str]:
        value = raw.get(key) or []
        if not isinstance(value, list):
            raise StandardsError(f"{ctx}: '{key}' must be a list")
        return [str(v) for v in value]

    tag_values_raw = raw.get("tag_values") or {}
    if not isinstance(tag_values_raw, dict):
        raise StandardsError(f"{ctx}: 'tag_values' must be a mapping of tag -> allowed values")
    tag_values = {str(k): [str(x) for x in (v or [])] for k, v in tag_values_raw.items()}

    ait_raw = raw.get("allowed_instance_types") or {}
    if not isinstance(ait_raw, dict):
        raise StandardsError(f"{ctx}: 'allowed_instance_types' must map resource_type -> patterns")
    allowed_instance_types = {str(k): [str(x) for x in (v or [])] for k, v in ait_raw.items()}

    enc_raw = raw.get("encryption") or {}
    if not isinstance(enc_raw, dict):
        raise StandardsError(f"{ctx}: 'encryption' must be a mapping of service -> bool")
    known_services = set(_ENCRYPTION_CHECKS) | {"s3"}
    encryption: dict[str, bool] = {}
    for service, enabled in enc_raw.items():
        if service not in known_services:
            raise StandardsError(
                f"{ctx}: unknown encryption service {service!r} "
                f"(expected one of {', '.join(sorted(known_services))})"
            )
        encryption[str(service)] = bool(enabled)

    naming_raw = raw.get("naming_patterns") or {}
    if not isinstance(naming_raw, dict):
        raise StandardsError(f"{ctx}: 'naming_patterns' must map resource_type -> regex")
    naming_patterns = {
        str(rtype): _compile_pattern(str(pattern), f"{ctx}: naming_patterns.{rtype}")
        for rtype, pattern in naming_raw.items()
    }

    mod_raw = raw.get("module_allowlist") or {}
    if isinstance(mod_raw, list):  # shorthand: bare list of sources implies enforce
        mod_raw = {"enforce": True, "allowed_sources": mod_raw}
    if not isinstance(mod_raw, dict):
        raise StandardsError(f"{ctx}: 'module_allowlist' must be a mapping or a list of sources")
    module_allowlist = [str(s) for s in (mod_raw.get("allowed_sources") or [])]
    module_allowlist_enforce = bool(mod_raw.get("enforce", bool(module_allowlist)))

    severities_raw = raw.get("severities") or {}
    if not isinstance(severities_raw, dict):
        raise StandardsError(f"{ctx}: 'severities' must be a mapping of section -> level")
    severities = {
        str(section): _parse_severity(level, f"{ctx}: severities.{section}")
        for section, level in severities_raw.items()
    }

    custom_raw = raw.get("standards") or raw.get("custom_rules") or []
    if not isinstance(custom_raw, list):
        raise StandardsError(f"{ctx}: 'standards' must be a list of rules")
    custom_rules = [ConditionRule.from_dict(r) for r in custom_raw]

    config = StandardsConfig(
        required_tags=_str_list("required_tags"),
        tag_values=tag_values,
        allowed_instance_types=allowed_instance_types,
        allowed_regions=_str_list("allowed_regions"),
        encryption=encryption,
        naming_patterns=naming_patterns,
        module_allowlist=module_allowlist,
        module_allowlist_enforce=module_allowlist_enforce,
        custom_rules=custom_rules,
        severities=severities,
        source_file=source_file,
    )
    logger.info(
        "Loaded standards from %s: %d required tags, %d instance-type policies, "
        "%d regions, %d encryption toggles, %d naming patterns, %d module sources, %d custom rules",
        source_file, len(config.required_tags), len(config.allowed_instance_types),
        len(config.allowed_regions), len(config.encryption), len(config.naming_patterns),
        len(config.module_allowlist), len(config.custom_rules),
    )
    return config


# ─── Evaluator ────────────────────────────────────────────────────────────────

class StandardsEvaluator:
    """Evaluates a parsed Terraform plan against a StandardsConfig."""

    def __init__(self, config: StandardsConfig) -> None:
        self.config = config

    def evaluate(self, plan: TerraformPlan) -> list[StandardViolation]:
        if self.config.is_empty:
            return []

        violations: list[StandardViolation] = []
        sse_configured_buckets = _buckets_with_sse(plan)

        for change in plan.resource_changes:
            if not (change.is_create or change.is_update or change.is_replace):
                continue  # standards apply to resources being created/changed, not destroyed
            violations.extend(self._check_tags(change))
            violations.extend(self._check_instance_type(change))
            violations.extend(self._check_region(change))
            violations.extend(self._check_encryption(change, sse_configured_buckets))
            violations.extend(self._check_naming(change))
            violations.extend(self._check_module(change, plan))
            for rule in self.config.custom_rules:
                v = rule.evaluate(change)
                if v:
                    violations.append(v)

        violations.extend(self._check_provider_regions(plan))
        logger.info("Standards evaluation: %d violation(s)", len(violations))
        return violations

    # — tags —
    def _check_tags(self, change: ResourceChange) -> list[StandardViolation]:
        after = change.after or {}
        if "tags" not in after and "tags_all" not in after:
            return []  # resource type does not support tags
        tags = after.get("tags") or after.get("tags_all") or {}
        if not isinstance(tags, dict):
            tags = {}

        out = []
        for tag in self.config.required_tags:
            if not str(tags.get(tag) or "").strip():
                out.append(StandardViolation(
                    rule_id="STD-TAG-001",
                    severity=self.config.severity_for("required_tags"),
                    resource_address=change.address,
                    message=f"{change.address} is missing required tag '{tag}'",
                    fix_hint=f'Add tags = {{ {tag} = "<value>" }} to the resource block.',
                ))
        for tag, allowed in self.config.tag_values.items():
            value = tags.get(tag)
            if value is not None and allowed and str(value) not in allowed:
                out.append(StandardViolation(
                    rule_id="STD-TAG-002",
                    severity=self.config.severity_for("tag_values"),
                    resource_address=change.address,
                    message=f"{change.address} tag '{tag}' has disallowed value '{value}'",
                    fix_hint=f"Use one of: {', '.join(allowed)}",
                ))
        return out

    # — instance types —
    def _check_instance_type(self, change: ResourceChange) -> list[StandardViolation]:
        patterns = self.config.allowed_instance_types.get(change.resource_type)
        if not patterns:
            return []
        attr = _INSTANCE_TYPE_ATTRS.get(change.resource_type, "instance_type")
        actual = get_nested(change.after or {}, attr)
        if not actual:
            return []  # unknown until apply (after_unknown) — nothing to assert
        if any(fnmatch.fnmatch(str(actual), p) for p in patterns):
            return []
        return [StandardViolation(
            rule_id="STD-COMPUTE-001",
            severity=self.config.severity_for("allowed_instance_types"),
            resource_address=change.address,
            message=(
                f"{change.address} uses disallowed {attr} '{actual}' "
                f"for {change.resource_type}"
            ),
            fix_hint=f"Allowed families: {', '.join(patterns)}",
        )]

    # — regions —
    def _check_region(self, change: ResourceChange) -> list[StandardViolation]:
        if not self.config.allowed_regions:
            return []
        after = change.after or {}
        region = after.get("region")
        az = after.get("availability_zone")
        candidate: str | None = None
        if isinstance(region, str) and region:
            candidate = region
        elif isinstance(az, str) and az:
            candidate = az.rstrip("abcdef")  # us-east-1a -> us-east-1
        if candidate and candidate not in self.config.allowed_regions:
            return [StandardViolation(
                rule_id="STD-REGION-001",
                severity=self.config.severity_for("allowed_regions"),
                resource_address=change.address,
                message=f"{change.address} targets disallowed region '{candidate}'",
                fix_hint=f"Deploy only to: {', '.join(self.config.allowed_regions)}",
            )]
        return []

    def _check_provider_regions(self, plan: TerraformPlan) -> list[StandardViolation]:
        if not self.config.allowed_regions:
            return []
        out = []
        for provider, region in plan.provider_regions.items():
            if region not in self.config.allowed_regions:
                out.append(StandardViolation(
                    rule_id="STD-REGION-002",
                    severity=self.config.severity_for("allowed_regions"),
                    resource_address=f"provider.{provider}",
                    message=f"Provider '{provider}' is configured for disallowed region '{region}'",
                    fix_hint=f"Deploy only to: {', '.join(self.config.allowed_regions)}",
                ))
        return out

    # — encryption —
    def _check_encryption(
        self, change: ResourceChange, sse_configured_buckets: set[str]
    ) -> list[StandardViolation]:
        out = []
        after = change.after or {}
        unknown = change.after_unknown or {}

        if self.config.encryption.get("s3") and change.resource_type == "aws_s3_bucket":
            inline_sse = get_nested(after, "server_side_encryption_configuration.rule")
            if not inline_sse and change.resource_name not in sse_configured_buckets:
                out.append(StandardViolation(
                    rule_id="STD-ENC-S3",
                    severity=self.config.severity_for("encryption"),
                    resource_address=change.address,
                    message=f"{change.address} has no server-side encryption configuration",
                    fix_hint=(
                        "Add an aws_s3_bucket_server_side_encryption_configuration resource "
                        "for this bucket (aws:kms or AES256)."
                    ),
                ))

        for service, checks in _ENCRYPTION_CHECKS.items():
            if not self.config.encryption.get(service):
                continue
            for rtype, attr_path, fix in checks:
                if change.resource_type != rtype:
                    continue
                if get_nested(unknown, attr_path):
                    continue  # value computed at apply time — cannot assert
                value = get_nested(after, attr_path)
                if value is not True:
                    out.append(StandardViolation(
                        rule_id=f"STD-ENC-{service.upper()}",
                        severity=self.config.severity_for("encryption"),
                        resource_address=change.address,
                        message=f"{change.address} does not have encryption at rest enabled "
                                f"({attr_path} != true)",
                        fix_hint=fix,
                    ))
        return out

    # — naming —
    def _check_naming(self, change: ResourceChange) -> list[StandardViolation]:
        pattern = self.config.naming_patterns.get(change.resource_type)
        if pattern is None:
            return []
        after = change.after or {}
        # Prefer the provider-visible name; fall back to the Terraform resource name.
        candidate = after.get("bucket") or after.get("name") or after.get("identifier") \
            or change.resource_name
        if not isinstance(candidate, str) or not candidate:
            return []
        if pattern.search(candidate):
            return []
        return [StandardViolation(
            rule_id="STD-NAME-001",
            severity=self.config.severity_for("naming_patterns"),
            resource_address=change.address,
            message=(
                f"{change.address} name '{candidate}' does not match the required "
                f"pattern for {change.resource_type}"
            ),
            fix_hint=f"Rename to match: {pattern.pattern}",
        )]

    # — modules —
    def _check_module(self, change: ResourceChange, plan: TerraformPlan) -> list[StandardViolation]:
        if not (self.config.module_allowlist_enforce and self.config.module_allowlist):
            return []
        if not change.module_address:
            return []
        # Root-level module call governs the allowlist decision.
        # "module.vpc[0].module.subnets" -> "module.vpc" (config keys carry no index)
        root_call = re.sub(r"\[[^\]]*\]", "", ".".join(change.module_address.split(".")[:2]))
        source = plan.module_sources.get(root_call, "")
        if not source:
            return []  # source not resolvable from plan configuration — do not guess
        if any(fnmatch.fnmatch(source, p) for p in self.config.module_allowlist):
            return []
        return [StandardViolation(
            rule_id="STD-MOD-001",
            severity=self.config.severity_for("module_allowlist"),
            resource_address=change.address,
            message=(
                f"{change.address} comes from non-allowlisted module source '{source}' "
                f"({root_call})"
            ),
            fix_hint=f"Use an approved module source: {', '.join(self.config.module_allowlist)}",
        )]


def _buckets_with_sse(plan: TerraformPlan) -> set[str]:
    """Resource names of aws_s3_bucket_server_side_encryption_configuration in this plan."""
    return {
        rc.resource_name
        for rc in plan.resource_changes
        if rc.resource_type == _S3_SSE_RESOURCE and not rc.is_destroy
    }


# ─── Backwards compatibility ─────────────────────────────────────────────────

class StandardsLoader:
    """Compatibility shim for the previous API: StandardsLoader(path).evaluate(plan)."""

    def __init__(self, standards_file: str | Path | None = None) -> None:
        self.config = load_standards(standards_file) if standards_file else StandardsConfig()

    def evaluate(self, plan: TerraformPlan) -> list[StandardViolation]:
        return StandardsEvaluator(self.config).evaluate(plan)
