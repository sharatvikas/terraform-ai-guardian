package terraform

import future.keywords.if
import future.keywords.in

# ── S3 Security ───────────────────────────────────────────────────────────────

# Deny public S3 bucket ACLs
deny contains msg if {
    rc := input.resource_changes[_]
    rc.type == "aws_s3_bucket"
    not rc.change.actions[_] == "delete"
    acl := rc.change.after.acl
    acl in {"public-read", "public-read-write", "authenticated-read"}
    msg := sprintf("[CRITICAL] %v: S3 bucket ACL '%v' allows public access", [rc.address, acl])
}

# Deny S3 without versioning (warn)
warn contains msg if {
    rc := input.resource_changes[_]
    rc.type == "aws_s3_bucket_versioning"
    not rc.change.actions[_] == "delete"
    rc.change.after.versioning_configuration[_].status != "Enabled"
    msg := sprintf("[MEDIUM] %v: S3 versioning should be enabled", [rc.address])
}

# ── RDS Security ──────────────────────────────────────────────────────────────

# Deny unencrypted RDS storage
deny contains msg if {
    rc := input.resource_changes[_]
    rc.type == "aws_db_instance"
    not rc.change.actions[_] == "delete"
    not rc.change.after.storage_encrypted
    msg := sprintf("[CRITICAL] %v: RDS instance must have storage_encrypted = true", [rc.address])
}

# Deny publicly accessible RDS
deny contains msg if {
    rc := input.resource_changes[_]
    rc.type == "aws_db_instance"
    not rc.change.actions[_] == "delete"
    rc.change.after.publicly_accessible
    msg := sprintf("[HIGH] %v: RDS instance must not be publicly_accessible", [rc.address])
}

# Warn on missing deletion protection
warn contains msg if {
    rc := input.resource_changes[_]
    rc.type in {"aws_db_instance", "aws_rds_cluster"}
    not rc.change.actions[_] == "delete"
    rc.change.after.deletion_protection == false
    msg := sprintf("[HIGH] %v: deletion_protection should be true on stateful resources", [rc.address])
}

# ── IAM Security ──────────────────────────────────────────────────────────────

# Deny IAM policies with wildcard actions
deny contains msg if {
    rc := input.resource_changes[_]
    rc.type in {"aws_iam_policy", "aws_iam_role_policy"}
    not rc.change.actions[_] == "delete"
    doc := json.unmarshal(rc.change.after.policy)
    stmt := doc.Statement[_]
    stmt.Effect == "Allow"
    stmt.Action == "*"
    msg := sprintf("[CRITICAL] %v: IAM policy allows Action: '*' (wildcard)", [rc.address])
}

# ── Networking ────────────────────────────────────────────────────────────────

# Deny SSH open to world
deny contains msg if {
    rc := input.resource_changes[_]
    rc.type == "aws_security_group"
    not rc.change.actions[_] == "delete"
    ingress := rc.change.after.ingress[_]
    "0.0.0.0/0" in ingress.cidr_blocks
    ingress.from_port <= 22
    ingress.to_port >= 22
    msg := sprintf("[HIGH] %v: SSH (port 22) open to 0.0.0.0/0", [rc.address])
}

# Deny RDP open to world
deny contains msg if {
    rc := input.resource_changes[_]
    rc.type == "aws_security_group"
    not rc.change.actions[_] == "delete"
    ingress := rc.change.after.ingress[_]
    "0.0.0.0/0" in ingress.cidr_blocks
    ingress.from_port <= 3389
    ingress.to_port >= 3389
    msg := sprintf("[HIGH] %v: RDP (port 3389) open to 0.0.0.0/0", [rc.address])
}

# ── Tagging ───────────────────────────────────────────────────────────────────

# Warn on missing 'owner' tag
warn contains msg if {
    rc := input.resource_changes[_]
    not rc.change.actions[_] == "delete"
    not rc.change.actions[_] == "no-op"
    not rc.change.after.tags.owner
    msg := sprintf("[MEDIUM] %v: missing required tag 'owner'", [rc.address])
}

# Warn on missing 'environment' tag
warn contains msg if {
    rc := input.resource_changes[_]
    not rc.change.actions[_] == "delete"
    not rc.change.actions[_] == "no-op"
    not rc.change.after.tags.environment
    msg := sprintf("[MEDIUM] %v: missing required tag 'environment'", [rc.address])
}
