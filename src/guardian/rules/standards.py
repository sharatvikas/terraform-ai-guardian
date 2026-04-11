"""Custom standards loader — parses a YAML standards file and evaluates plan resources."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from guardian.parser import ResourceChange
from guardian.rules.security import Finding, RiskLevel


class StandardViolation(Finding):
    """A violation found by a custom org standard."""
    pass


class StandardRule:
    """Represents a single rule from the standards YAML."""

    def __init__(self, rule_def: dict[str, Any]) -> None:
        self.id: str = rule_def["id"]
        self.description: str = rule_def.get("description", "")
        self.severity: str = rule_def.get("severity", "MEDIUM").upper()
        self.resource_types: list[str] = rule_def.get("resource_types", ["*"])
        self.conditions: list[dict[str, Any]] = rule_def.get("conditions", [])
        self.message: str = rule_def.get("message", self.description)

    def applies_to(self, resource_type: str) -> bool:
        return "*" in self.resource_types or resource_type in self.resource_types

    def evaluate(self, change: ResourceChange) -> StandardViolation | None:
        """Evaluate all conditions against the resource change. Returns violation if any fail."""
        if not self.applies_to(change.resource_type):
            return None

        values = change.after or {}
        for condition in self.conditions:
            if not self._evaluate_condition(condition, values):
                return StandardViolation(
                    rule_id=self.id,
                    resource_address=change.resource_address,
                    risk_level=RiskLevel[self.severity],
                    message=self.message.format(
                        resource_address=change.resource_address,
                        resource_type=change.resource_type,
                    ),
                    remediation=condition.get("remediation", ""),
                )
        return None

    def _evaluate_condition(self, condition: dict[str, Any], values: dict[str, Any]) -> bool:
        """Evaluate a single condition. Returns True if condition is satisfied (no violation)."""
        cond_type = condition.get("type")
        field = condition.get("field", "")
        field_value = self._get_nested(values, field)

        if cond_type == "required":
            # Field must exist and be non-empty/non-null
            return field_value is not None and field_value != "" and field_value != []

        if cond_type == "equals":
            expected = condition.get("value")
            return field_value == expected

        if cond_type == "not_equals":
            expected = condition.get("value")
            return field_value != expected

        if cond_type == "matches":
            pattern = condition.get("pattern", "")
            if field_value is None:
                return True  # field absent is not a violation for pattern match
            return bool(re.search(pattern, str(field_value)))

        if cond_type == "not_matches":
            pattern = condition.get("pattern", "")
            if field_value is None:
                return True
            return not bool(re.search(pattern, str(field_value)))

        if cond_type == "in":
            allowed = condition.get("values", [])
            return field_value in allowed

        if cond_type == "not_in":
            blocked = condition.get("values", [])
            return field_value not in blocked

        if cond_type == "min_length":
            minimum = condition.get("value", 0)
            return isinstance(field_value, (str, list)) and len(field_value) >= minimum

        # Unknown condition type — treat as satisfied to avoid false positives
        return True

    @staticmethod
    def _get_nested(obj: dict[str, Any], path: str) -> Any:
        """Traverse dot-notation path like 'tags.Environment'."""
        if not path:
            return obj
        parts = path.split(".")
        cur = obj
        for part in parts:
            if not isinstance(cur, dict):
                return None
            cur = cur.get(part)
        return cur


class StandardsLoader:
    """
    Loads custom org standards from a YAML file.

    Standards file format:
    ```yaml
    version: "1"
    standards:
      - id: ORG-001
        description: All resources must have an Environment tag
        severity: HIGH
        resource_types: ["*"]
        conditions:
          - type: required
            field: tags.Environment
            remediation: Add tags = { Environment = \"production\" } to your resource
        message: "{resource_address} missing required tag: Environment"
    ```
    """

    def __init__(self, standards_file: str | Path | None = None) -> None:
        self.rules: list[StandardRule] = []
        if standards_file:
            self.load(standards_file)

    def load(self, standards_file: str | Path) -> None:
        path = Path(standards_file)
        if not path.exists():
            raise FileNotFoundError(f"Standards file not found: {path}")

        with open(path) as f:
            data = yaml.safe_load(f)

        raw_rules = data.get("standards", [])
        self.rules = [StandardRule(r) for r in raw_rules]

    def evaluate(self, changes: list[ResourceChange]) -> list[StandardViolation]:
        """Evaluate all changes against all loaded rules. Returns list of violations."""
        violations: list[StandardViolation] = []
        for change in changes:
            if change.action not in ("create", "update"):
                continue
            for rule in self.rules:
                violation = rule.evaluate(change)
                if violation:
                    violations.append(violation)
        return violations
