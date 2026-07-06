"""OPA (Open Policy Agent) policy enforcement for Terraform plans.

Runs terraform plan JSON through OPA policies to enforce organization-wide
infrastructure guardrails before apply. Supports both a local `opa` binary
and the OPA REST API (for teams running OPA as a service).

Policy bundles are loaded from:
  - The `policies/` directory relative to the working directory
  - The OPA_BUNDLE_PATH environment variable
  - The OPA server at OPA_URL (if configured)

Usage:
    evaluator = OPAEvaluator()
    results = evaluator.evaluate(plan_json_path="plan.json")
    if results.has_violations():
        sys.exit(1)
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx


OPA_URL = os.environ.get("OPA_URL", "")
OPA_BUNDLE_PATH = os.environ.get("OPA_BUNDLE_PATH", "policies")
OPA_QUERY = os.environ.get("OPA_QUERY", "data.terraform.deny")


@dataclass
class PolicyViolation:
    """A single OPA policy violation."""

    policy: str
    rule: str
    message: str
    resource: str = ""
    severity: str = "HIGH"  # CRITICAL | HIGH | MEDIUM | LOW

    def __str__(self) -> str:
        prefix = f"[{self.severity}]"
        resource_part = f" ({self.resource})" if self.resource else ""
        return f"{prefix} {self.rule}{resource_part}: {self.message}"


@dataclass
class OPAResult:
    """Aggregated result of running OPA against a Terraform plan."""

    violations: list[PolicyViolation] = field(default_factory=list)
    warnings: list[PolicyViolation] = field(default_factory=list)
    policies_evaluated: int = 0
    plan_path: str = ""
    query: str = ""
    error: str = ""

    def has_violations(self) -> bool:
        return len(self.violations) > 0

    def summary(self) -> str:
        if self.error:
            return f"OPA evaluation error: {self.error}"
        lines = [
            f"OPA Policy Evaluation: {self.policies_evaluated} policies evaluated",
            f"Violations: {len(self.violations)}  Warnings: {len(self.warnings)}",
        ]
        if self.violations:
            lines.append("\n## Violations (BLOCK APPLY)")
            for v in self.violations:
                lines.append(f"  - {v}")
        if self.warnings:
            lines.append("\n## Warnings (REVIEW RECOMMENDED)")
            for w in self.warnings:
                lines.append(f"  - {w}")
        if not self.violations and not self.warnings:
            lines.append("All policies passed.")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_path": self.plan_path,
            "query": self.query,
            "policies_evaluated": self.policies_evaluated,
            "violations": [
                {
                    "policy": v.policy,
                    "rule": v.rule,
                    "message": v.message,
                    "resource": v.resource,
                    "severity": v.severity,
                }
                for v in self.violations
            ],
            "warnings": [
                {
                    "policy": w.policy,
                    "rule": w.rule,
                    "message": w.message,
                    "resource": w.resource,
                    "severity": w.severity,
                }
                for w in self.warnings
            ],
            "passed": not self.has_violations(),
            "error": self.error,
        }


class OPAEvaluator:
    """Evaluates Terraform plan JSON against OPA policies."""

    def __init__(
        self,
        bundle_path: str = OPA_BUNDLE_PATH,
        query: str = OPA_QUERY,
        opa_url: str = OPA_URL,
    ):
        self.bundle_path = bundle_path
        self.query = query
        self.opa_url = opa_url

    def evaluate(self, plan_json_path: str) -> OPAResult:
        """Evaluate a terraform plan JSON file against all configured policies."""
        result = OPAResult(plan_path=plan_json_path, query=self.query)

        # Load plan JSON
        try:
            plan_data = json.loads(Path(plan_json_path).read_text())
        except (OSError, json.JSONDecodeError) as exc:
            result.error = f"Failed to load plan JSON: {exc}"
            return result

        # Prefer OPA server if configured
        if self.opa_url:
            return self._evaluate_via_api(plan_data, result)

        # Fall back to local opa binary
        if shutil.which("opa"):
            return self._evaluate_via_binary(plan_json_path, result)

        # Fall back to built-in Python policy rules
        return self._evaluate_builtin(plan_data, result)

    # ── OPA REST API ──────────────────────────────────────────────────────────

    def _evaluate_via_api(self, plan_data: dict, result: OPAResult) -> OPAResult:
        """POST plan data to OPA server and parse deny/warn results."""
        endpoint = f"{self.opa_url}/v1/data/terraform/deny"
        try:
            resp = httpx.post(endpoint, json={"input": plan_data}, timeout=30)
            resp.raise_for_status()
            data = resp.json().get("result", [])
            result.policies_evaluated = 1
            for msg in data:
                result.violations.append(
                    PolicyViolation(
                        policy="opa-server",
                        rule="terraform.deny",
                        message=msg if isinstance(msg, str) else str(msg),
                        severity="HIGH",
                    )
                )

            # Check warnings
            warn_endpoint = f"{self.opa_url}/v1/data/terraform/warn"
            warn_resp = httpx.post(warn_endpoint, json={"input": plan_data}, timeout=30)
            if warn_resp.status_code == 200:
                for msg in warn_resp.json().get("result", []):
                    result.warnings.append(
                        PolicyViolation(
                            policy="opa-server",
                            rule="terraform.warn",
                            message=msg if isinstance(msg, str) else str(msg),
                            severity="MEDIUM",
                        )
                    )
        except Exception as exc:
            result.error = f"OPA API error: {exc}"
        return result

    # ── OPA Binary ────────────────────────────────────────────────────────────

    def _evaluate_via_binary(self, plan_path: str, result: OPAResult) -> OPAResult:
        """Run `opa eval` with the bundle path and parse deny results."""
        bundle = Path(self.bundle_path)
        if not bundle.exists():
            # No bundle directory — write built-in policies to a temp bundle
            bundle = self._write_builtin_bundle()

        try:
            cmd = [
                "opa", "eval",
                "--data", str(bundle),
                "--input", plan_path,
                "--format", "json",
                self.query,
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if proc.returncode not in (0, 2):
                result.error = f"opa eval failed: {proc.stderr}"
                return result

            output = json.loads(proc.stdout)
            result.policies_evaluated = 1
            for binding in output.get("result", []):
                for expr in binding.get("expressions", []):
                    for msg in expr.get("value", []):
                        result.violations.append(
                            PolicyViolation(
                                policy=str(bundle),
                                rule=self.query,
                                message=msg if isinstance(msg, str) else str(msg),
                                severity="HIGH",
                            )
                        )
        except subprocess.TimeoutExpired:
            result.error = "opa eval timed out after 60s"
        except Exception as exc:
            result.error = f"opa binary error: {exc}"

        return result

    # ── Built-in Python Policies ──────────────────────────────────────────────

    def _evaluate_builtin(self, plan_data: dict, result: OPAResult) -> OPAResult:
        """Run built-in Python policy rules when no OPA binary/server is available."""
        checks = [
            _check_public_s3_buckets,
            _check_unencrypted_rds,
            _check_iam_wildcard_policies,
            _check_security_group_open_world,
            _check_missing_tags,
            _check_deletion_protection,
        ]
        result.policies_evaluated = len(checks)

        resource_changes = plan_data.get("resource_changes", [])

        for check in checks:
            violations, warnings = check(resource_changes)
            result.violations.extend(violations)
            result.warnings.extend(warnings)

        return result

    def _write_builtin_bundle(self) -> Path:
        """Write built-in Rego policies to a temp directory for opa eval."""
        tmp = Path(tempfile.mkdtemp(prefix="guardian-opa-"))
        policy_path = tmp / "terraform.rego"
        policy_path.write_text(_BUILTIN_REGO)
        return tmp


# ── Built-in Policy Rules (Python fallback) ───────────────────────────────────

def _resource_changes_of_type(changes: list[dict], rtype: str) -> list[dict]:
    return [c for c in changes if c.get("type", "").startswith(rtype) and
            c.get("change", {}).get("actions", []) not in [["no-op"], ["delete"]]]


def _check_public_s3_buckets(
    changes: list[dict],
) -> tuple[list[PolicyViolation], list[PolicyViolation]]:
    violations, warnings = [], []
    for rc in _resource_changes_of_type(changes, "aws_s3_bucket"):
        after = rc.get("change", {}).get("after", {}) or {}
        acl = after.get("acl", "private")
        if acl in ("public-read", "public-read-write", "authenticated-read"):
            violations.append(PolicyViolation(
                policy="builtin",
                rule="no_public_s3_buckets",
                message=f"S3 bucket ACL is '{acl}' — public access is not allowed",
                resource=rc.get("address", ""),
                severity="CRITICAL",
            ))
    return violations, warnings


def _check_unencrypted_rds(
    changes: list[dict],
) -> tuple[list[PolicyViolation], list[PolicyViolation]]:
    violations, warnings = [], []
    for rc in _resource_changes_of_type(changes, "aws_db_instance"):
        after = rc.get("change", {}).get("after", {}) or {}
        if not after.get("storage_encrypted", False):
            violations.append(PolicyViolation(
                policy="builtin",
                rule="rds_encryption_required",
                message="RDS instance storage_encrypted must be true",
                resource=rc.get("address", ""),
                severity="CRITICAL",
            ))
    return violations, warnings


def _check_iam_wildcard_policies(
    changes: list[dict],
) -> tuple[list[PolicyViolation], list[PolicyViolation]]:
    violations, warnings = [], []
    for rc in _resource_changes_of_type(changes, "aws_iam_"):
        after = rc.get("change", {}).get("after", {}) or {}
        policy_doc = after.get("policy") or after.get("assume_role_policy", "")
        if not policy_doc:
            continue
        if isinstance(policy_doc, str):
            try:
                policy_doc = json.loads(policy_doc)
            except json.JSONDecodeError:
                continue
        for stmt in policy_doc.get("Statement", []):
            action = stmt.get("Action", [])
            if isinstance(action, str):
                action = [action]
            if "*" in action and stmt.get("Effect") == "Allow":
                resource = stmt.get("Resource", "")
                violations.append(PolicyViolation(
                    policy="builtin",
                    rule="no_iam_wildcard_actions",
                    message=f"IAM policy allows Action: '*' on Resource: {resource}",
                    resource=rc.get("address", ""),
                    severity="CRITICAL",
                ))
    return violations, warnings


def _check_security_group_open_world(
    changes: list[dict],
) -> tuple[list[PolicyViolation], list[PolicyViolation]]:
    violations, warnings = [], []
    dangerous_ports = {22: "SSH", 3389: "RDP", 5432: "PostgreSQL", 3306: "MySQL"}
    for rc in _resource_changes_of_type(changes, "aws_security_group"):
        after = rc.get("change", {}).get("after", {}) or {}
        for rule in after.get("ingress", []):
            cidrs = rule.get("cidr_blocks", []) + rule.get("ipv6_cidr_blocks", [])
            open_world = any(c in ("0.0.0.0/0", "::/0") for c in cidrs)
            if not open_world:
                continue
            from_port = rule.get("from_port", 0)
            to_port = rule.get("to_port", 0)
            for port, name in dangerous_ports.items():
                if from_port <= port <= to_port:
                    violations.append(PolicyViolation(
                        policy="builtin",
                        rule="no_open_world_sensitive_ports",
                        message=f"{name} (port {port}) open to 0.0.0.0/0",
                        resource=rc.get("address", ""),
                        severity="HIGH",
                    ))
    return violations, warnings


def _check_missing_tags(
    changes: list[dict],
) -> tuple[list[PolicyViolation], list[PolicyViolation]]:
    violations, warnings = [], []
    required_tags = {"owner", "environment", "team"}
    for rc in changes:
        if rc.get("change", {}).get("actions", []) in [["no-op"], ["delete"]]:
            continue
        after = rc.get("change", {}).get("after", {}) or {}
        tags = after.get("tags") or {}
        if not isinstance(tags, dict):
            continue
        tag_keys = {k.lower() for k in tags}
        missing = required_tags - tag_keys
        if missing:
            warnings.append(PolicyViolation(
                policy="builtin",
                rule="required_tags",
                message=f"Missing required tags: {', '.join(sorted(missing))}",
                resource=rc.get("address", ""),
                severity="MEDIUM",
            ))
    return violations, warnings


def _check_deletion_protection(
    changes: list[dict],
) -> tuple[list[PolicyViolation], list[PolicyViolation]]:
    violations, warnings = [], []
    protected_types = ("aws_db_instance", "aws_rds_cluster", "aws_dynamodb_table")
    for rc in changes:
        if not any(rc.get("type", "").startswith(t) for t in protected_types):
            continue
        if rc.get("change", {}).get("actions", []) in [["no-op"]]:
            continue
        after = rc.get("change", {}).get("after", {}) or {}
        if after.get("deletion_protection") is False:
            warnings.append(PolicyViolation(
                policy="builtin",
                rule="deletion_protection_recommended",
                message="deletion_protection is false on a stateful resource",
                resource=rc.get("address", ""),
                severity="HIGH",
            ))
    return violations, warnings


# ── Built-in Rego (written to disk for opa binary mode) ──────────────────────

_BUILTIN_REGO = """\
package terraform

import future.keywords.if
import future.keywords.in

# Deny public S3 buckets
deny contains msg if {
    rc := input.resource_changes[_]
    rc.type == "aws_s3_bucket"
    acl := rc.change.after.acl
    acl in {"public-read", "public-read-write", "authenticated-read"}
    msg := sprintf("S3 bucket %v has public ACL '%v'", [rc.address, acl])
}

# Deny unencrypted RDS
deny contains msg if {
    rc := input.resource_changes[_]
    rc.type == "aws_db_instance"
    not rc.change.after.storage_encrypted
    msg := sprintf("RDS instance %v must have storage_encrypted = true", [rc.address])
}

# Deny SSH/RDP open to world
deny contains msg if {
    rc := input.resource_changes[_]
    rc.type == "aws_security_group"
    rule := rc.change.after.ingress[_]
    cidr := rule.cidr_blocks[_]
    cidr == "0.0.0.0/0"
    rule.from_port <= 22
    rule.to_port >= 22
    msg := sprintf("Security group %v allows SSH from 0.0.0.0/0", [rc.address])
}

# Warn on missing required tags
warn contains msg if {
    rc := input.resource_changes[_]
    not rc.change.after.tags.owner
    msg := sprintf("Resource %v is missing required tag 'owner'", [rc.address])
}
"""
