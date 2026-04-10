"""Security rule engine — detects high-risk patterns in Terraform plans."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from guardian.parser import ResourceChange, TerraformPlan


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"

    def __gt__(self, other: "RiskLevel") -> bool:
        order = [RiskLevel.NONE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        return order.index(self) > order.index(other)


@dataclass
class Finding:
    risk_level: RiskLevel
    category: str
    resource_address: str
    title: str
    description: str
    recommendation: str


def run_security_rules(plan: TerraformPlan) -> list[Finding]:
    """Run all security rules against a Terraform plan and return findings."""
    findings: list[Finding] = []

    for change in plan.resource_changes:
        # Skip no-ops and reads
        if not (change.is_create or change.is_update or change.is_replace or change.is_destroy):
            continue

        findings.extend(_check_iam(change))
        findings.extend(_check_security_groups(change))
        findings.extend(_check_s3(change))
        findings.extend(_check_rds(change))
        findings.extend(_check_kms(change))
        findings.extend(_check_secrets_in_attributes(change))
        findings.extend(_check_dangerous_destroys(change))

    return sorted(findings, key=lambda f: list(RiskLevel).index(f.risk_level))


def _check_iam(change: ResourceChange) -> list[Finding]:
    findings = []
    after = change.after or {}

    if change.resource_type not in ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"):
        return []

    policy_doc = after.get("policy", "") or ""
    if isinstance(policy_doc, dict):
        policy_doc = str(policy_doc)

    # Star action with star resource is admin
    if '"Action": "*"' in policy_doc or '"Action":["*"]' in policy_doc:
        if '"Resource": "*"' in policy_doc or '"Resource":["*"]' in policy_doc:
            findings.append(Finding(
                risk_level=RiskLevel.CRITICAL,
                category="IAM",
                resource_address=change.address,
                title="IAM policy grants full admin access (Action:* + Resource:*)",
                description=(
                    f"{change.address} grants wildcard actions on all resources. "
                    "This is equivalent to AWS AdministratorAccess and violates least-privilege."
                ),
                recommendation=(
                    "Replace wildcard with specific actions (e.g. s3:GetObject, s3:PutObject) "
                    "and scope Resource to specific ARNs."
                ),
            ))
        else:
            findings.append(Finding(
                risk_level=RiskLevel.HIGH,
                category="IAM",
                resource_address=change.address,
                title="IAM policy uses wildcard action (*)",
                description=f"{change.address} uses Action:* which grants broad permissions.",
                recommendation="Enumerate specific required actions instead of using *.",
            ))

    # PassRole is often used for privilege escalation
    if "iam:PassRole" in policy_doc and '"Resource": "*"' in policy_doc:
        findings.append(Finding(
            risk_level=RiskLevel.HIGH,
            category="IAM",
            resource_address=change.address,
            title="iam:PassRole allowed on all resources — privilege escalation risk",
            description=(
                "Allowing iam:PassRole on Resource:* enables privilege escalation — "
                "the holder can pass any role to any service."
            ),
            recommendation="Scope iam:PassRole to specific role ARNs.",
        ))

    return findings


def _check_security_groups(change: ResourceChange) -> list[Finding]:
    findings = []

    if change.resource_type not in ("aws_security_group", "aws_security_group_rule"):
        return []

    after = change.after or {}
    ingress_rules = after.get("ingress", []) or []

    # For aws_security_group_rule
    if change.resource_type == "aws_security_group_rule":
        rule_type = after.get("type", "")
        if rule_type == "ingress":
            ingress_rules = [after]

    for rule in ingress_rules:
        if not isinstance(rule, dict):
            continue
        cidrs = rule.get("cidr_blocks", []) or []
        ipv6_cidrs = rule.get("ipv6_cidr_blocks", []) or []
        from_port = rule.get("from_port", 0)
        to_port = rule.get("to_port", 65535)
        protocol = rule.get("protocol", "-1")

        is_open_to_world = "0.0.0.0/0" in cidrs or "::/0" in ipv6_cidrs

        if is_open_to_world:
            sensitive_ports = {
                22: "SSH",
                3306: "MySQL",
                5432: "PostgreSQL",
                6379: "Redis",
                27017: "MongoDB",
                9200: "Elasticsearch",
                2379: "etcd",
            }

            if protocol == "-1":  # All traffic
                findings.append(Finding(
                    risk_level=RiskLevel.CRITICAL,
                    category="Network",
                    resource_address=change.address,
                    title="Security group allows ALL traffic from 0.0.0.0/0",
                    description=f"{change.address} opens all ports/protocols to the internet.",
                    recommendation="Restrict to specific ports and source CIDR blocks.",
                ))
            else:
                for port in range(from_port, min(to_port + 1, 65536)):
                    if port in sensitive_ports:
                        findings.append(Finding(
                            risk_level=RiskLevel.CRITICAL,
                            category="Network",
                            resource_address=change.address,
                            title=f"Security group exposes {sensitive_ports[port]} (:{port}) to 0.0.0.0/0",
                            description=(
                                f"{change.address} allows public internet access to port {port} "
                                f"({sensitive_ports[port]}). This should never be public."
                            ),
                            recommendation=f"Restrict port {port} to your VPC CIDR or specific trusted IPs.",
                        ))
                        break

                if not any(p in range(from_port, to_port + 1) for p in sensitive_ports):
                    findings.append(Finding(
                        risk_level=RiskLevel.MEDIUM,
                        category="Network",
                        resource_address=change.address,
                        title=f"Security group allows ports {from_port}-{to_port} from 0.0.0.0/0",
                        description=f"{change.address} opens ports to the public internet.",
                        recommendation="Confirm this is intentional. Restrict source CIDR if possible.",
                    ))

    return findings


def _check_s3(change: ResourceChange) -> list[Finding]:
    findings = []

    if change.resource_type == "aws_s3_bucket_public_access_block":
        after = change.after or {}
        blocking_fields = [
            "block_public_acls",
            "block_public_policy",
            "ignore_public_acls",
            "restrict_public_buckets",
        ]
        disabled = [f for f in blocking_fields if after.get(f) is False]
        if disabled:
            findings.append(Finding(
                risk_level=RiskLevel.HIGH,
                category="S3",
                resource_address=change.address,
                title="S3 public access block is being disabled",
                description=f"{change.address} disables: {', '.join(disabled)}. Bucket may become public.",
                recommendation=(
                    "Keep all public access block settings as true unless the bucket "
                    "explicitly serves public static content."
                ),
            ))

    if change.resource_type == "aws_s3_bucket" and change.is_create:
        after = change.after or {}
        # Old-style ACL on bucket directly
        if after.get("acl") in ("public-read", "public-read-write"):
            findings.append(Finding(
                risk_level=RiskLevel.CRITICAL,
                category="S3",
                resource_address=change.address,
                title=f"S3 bucket created with ACL={after['acl']}",
                description=f"{change.address} is being created publicly accessible.",
                recommendation="Remove the ACL or use 'private'. Add aws_s3_bucket_public_access_block.",
            ))

    return findings


def _check_rds(change: ResourceChange) -> list[Finding]:
    findings = []

    if change.resource_type not in ("aws_db_instance", "aws_rds_cluster"):
        return []

    after = change.after or {}

    if after.get("publicly_accessible") is True:
        findings.append(Finding(
            risk_level=RiskLevel.CRITICAL,
            category="RDS",
            resource_address=change.address,
            title="RDS instance is publicly accessible",
            description=f"{change.address} has publicly_accessible=true. Database is reachable from internet.",
            recommendation="Set publicly_accessible=false. Use a bastion or VPN for access.",
        ))

    if after.get("storage_encrypted") is False or (
        change.is_create and not after.get("storage_encrypted", True)
    ):
        findings.append(Finding(
            risk_level=RiskLevel.HIGH,
            category="RDS",
            resource_address=change.address,
            title="RDS instance storage is not encrypted",
            description=f"{change.address} has storage_encrypted=false.",
            recommendation="Enable storage_encrypted=true. Requires replacement for existing instances.",
        ))

    return findings


def _check_kms(change: ResourceChange) -> list[Finding]:
    findings = []

    if change.resource_type == "aws_kms_key" and change.is_destroy:
        findings.append(Finding(
            risk_level=RiskLevel.CRITICAL,
            category="KMS",
            resource_address=change.address,
            title="KMS key is being destroyed",
            description=(
                f"{change.address} is scheduled for deletion. Any data encrypted with "
                "this key will be permanently unrecoverable."
            ),
            recommendation=(
                "Verify no data depends on this key. Consider disabling instead of deleting. "
                "KMS keys have a mandatory 7-30 day deletion window."
            ),
        ))

    return findings


def _check_secrets_in_attributes(change: ResourceChange) -> list[Finding]:
    """Detect obvious secrets embedded in resource attributes."""
    findings = []
    after = change.after or {}

    secret_patterns = re.compile(
        r"(password|secret|token|api_key|private_key|access_key)",
        re.IGNORECASE,
    )
    plaintext_pattern = re.compile(r"^[A-Za-z0-9+/]{20,}$")

    for key, value in _flatten(after).items():
        if not isinstance(value, str) or not value:
            continue
        if secret_patterns.search(key) and plaintext_pattern.match(value):
            findings.append(Finding(
                risk_level=RiskLevel.HIGH,
                category="Secrets",
                resource_address=change.address,
                title=f"Possible plaintext secret in attribute '{key}'",
                description=(
                    f"{change.address}.{key} contains a value that looks like a "
                    "hardcoded secret. Secrets in Terraform state are stored in plaintext."
                ),
                recommendation=(
                    "Use AWS Secrets Manager or SSM Parameter Store with data sources. "
                    "Never hardcode secrets in Terraform."
                ),
            ))

    return findings


def _check_dangerous_destroys(change: ResourceChange) -> list[Finding]:
    """Flag destruction of stateful, hard-to-recover resources."""
    findings = []

    critical_types = {
        "aws_db_instance": "RDS database",
        "aws_rds_cluster": "Aurora cluster",
        "aws_dynamodb_table": "DynamoDB table",
        "aws_s3_bucket": "S3 bucket",
        "aws_elasticsearch_domain": "Elasticsearch domain",
        "aws_opensearch_domain": "OpenSearch domain",
        "aws_elasticache_replication_group": "ElastiCache cluster",
        "aws_kms_key": "KMS key",
        "aws_iam_role": "IAM role",
    }

    if change.is_destroy and change.resource_type in critical_types:
        resource_label = critical_types[change.resource_type]
        findings.append(Finding(
            risk_level=RiskLevel.HIGH,
            category="Blast Radius",
            resource_address=change.address,
            title=f"{resource_label} is scheduled for DESTROY",
            description=(
                f"{change.address} ({resource_label}) will be permanently deleted. "
                "This action cannot be undone."
            ),
            recommendation=(
                "Confirm this is intentional. Ensure backups exist. "
                "Consider adding lifecycle { prevent_destroy = true } for production resources."
            ),
        ))

    return findings


def _flatten(d: dict, prefix: str = "") -> dict[str, Any]:
    """Flatten nested dict for secret scanning."""
    result = {}
    for k, v in d.items():
        key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            result.update(_flatten(v, key))
        else:
            result[key] = v
    return result
