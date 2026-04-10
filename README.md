# terraform-ai-guardian

> **AI-powered Terraform plan reviewer.** Runs as a GitHub Actions step in your IaC pipeline — analyzes every `terraform plan` output with Claude, flags security risks, cost implications, blast radius concerns, and drift from your org's standards before any engineer approves the PR.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-ready-2088FF.svg)](https://github.com/features/actions)
[![Terraform](https://img.shields.io/badge/terraform-1.7+-623CE4.svg)](https://terraform.io)
[![Claude API](https://img.shields.io/badge/Claude-API-orange.svg)](https://anthropic.com)

---

## The Problem

Terraform plans are hard to review. A 400-line plan output touches 23 resources across 4 modules — most reviewers skim it and click approve. This is how security groups get opened to the world, expensive resources get provisioned in the wrong region, and critical RDS instances get destroyed.

`terraform-ai-guardian` reads every plan like a paranoid senior SRE would.

---

## What It Reviews

### Security Analysis
- IAM policy changes: privilege escalation, `*` actions, `*` resources
- Security group changes: ingress from 0.0.0.0/0, unusual port openings
- S3 bucket ACL / public access block removals
- KMS key deletions or key policy weakening
- Secrets in resource attributes (plaintext passwords, tokens)

### Blast Radius Assessment
- Resources marked for **destroy** — how critical are they?
- Dependencies: what downstream resources depend on what's being changed?
- Data resources (RDS, S3, DynamoDB) getting modified or destroyed
- Rate of change: >50 resources changing in one plan is flagged

### Cost Implications
- New resource types added — estimated monthly cost
- Instance type changes (smaller → larger → cost increase warning)
- Multi-AZ enablement cost delta
- Reserved capacity vs. on-demand implications

### Standards Drift
- Missing required tags (team, environment, cost-center)
- Resources in wrong region for account type
- Non-approved instance types or storage configurations
- Module version pinning violations

---

## Sample PR Comment

```
## Terraform AI Guardian Review

**Plan Summary:** 12 resources to add, 3 to change, 1 to destroy
**Risk Level:** 🔴 HIGH — requires SRE review

---

### 🔴 Critical Issues (must fix before merge)

**[SECURITY] Security group opens port 5432 to 0.0.0.0/0**
Resource: `aws_security_group.payments_db_sg`
The planned change adds an ingress rule allowing all IP addresses (0.0.0.0/0)
to connect to port 5432 (PostgreSQL). This exposes the database to the public
internet. Likely a mistake — intended to allow VPC CIDR only.

**Fix:** Change `cidr_blocks = ["0.0.0.0/0"]` to `cidr_blocks = [var.vpc_cidr]`

---

### 🟡 Warnings (review carefully)

**[BLAST RADIUS] RDS instance scheduled for destroy**
Resource: `aws_db_instance.payments_primary`
This plan will DESTROY the primary payments database. If this is intentional
(e.g., replacement with a different engine), ensure a snapshot exists first.
Last backup: not visible in plan — check manually.

**[COST] New c5.4xlarge instance — est. $280/month**
Resource: `aws_instance.analytics_worker`
The c5.4xlarge is 4x the cost of the current c5.xlarge. Confirm this is
intentional and the workload justifies it.

---

### ✅ Approved Items (no concerns)

- S3 bucket lifecycle policy update (standard, no security impact)
- IAM role tag updates (non-security, low blast radius)
- Route53 CNAME record addition (low risk)

---

*Analyzed by terraform-ai-guardian using Claude API. Review time: 8s*
*[View full analysis](logs/plan-review-2026-04-08.json)*
```

---

## Integration

### GitHub Actions

```yaml
# .github/workflows/terraform.yaml
name: Terraform

on:
  pull_request:
    paths: ['infrastructure/**']

jobs:
  plan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Terraform Plan
        id: plan
        run: |
          terraform init
          terraform plan -out=tfplan
          terraform show -json tfplan > plan.json

      - name: AI Guardian Review
        uses: sharatvikas/terraform-ai-guardian@v1
        with:
          plan-file: plan.json
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          github-token: ${{ secrets.GITHUB_TOKEN }}
          # Optional: block merge if HIGH risk detected
          fail-on-risk: HIGH
          # Optional: custom org standards
          standards-file: .guardian/standards.yaml
```

### Custom Org Standards

```yaml
# .guardian/standards.yaml
required_tags:
  - team
  - environment
  - cost-center
  - managed-by

blocked_resources:
  - aws_instance:  # Must use EKS instead
      message: "Use EKS pods instead of bare EC2 instances"
      exceptions: [bastion, jenkins]

instance_allowlist:
  ec2: [t3.medium, t3.large, c5.xlarge, c5.2xlarge, m5.xlarge, m5.2xlarge]
  rds: [db.t3.medium, db.r5.large, db.r5.xlarge]

security_rules:
  - no_public_rds: true
  - no_public_s3: true
  - require_encryption_at_rest: true
  - max_iam_policy_statements: 10
```

---

## Architecture

```
PR opened with Terraform changes
           │
           ▼
┌──────────────────────┐
│  terraform plan -out │
│  terraform show -json│
└──────────┬───────────┘
           │ plan.json
           ▼
┌──────────────────────────────────────────┐
│         terraform-ai-guardian            │
│                                          │
│  1. Parse plan JSON                      │
│  2. Extract: creates, updates, destroys  │
│  3. Apply rule-based checks (fast)       │
│  4. Send to Claude API for deep analysis │
│  5. Merge findings + format              │
└──────────────────┬───────────────────────┘
                   │
           ┌───────▼────────┐
           │  PR Comment    │ ← Risk level + findings
           │  Check Status  │ ← Pass/fail based on risk
           └────────────────┘
```

---

## Project Structure

```
terraform-ai-guardian/
├── action.yaml                 # GitHub Action definition
├── src/
│   └── guardian/
│       ├── main.py             # Action entrypoint
│       ├── parser.py           # Terraform plan JSON parser
│       ├── rules/
│       │   ├── security.py     # Security rule engine
│       │   ├── blast_radius.py # Blast radius calculator
│       │   └── standards.py    # Org standards checker
│       ├── ai/
│       │   └── analyzer.py     # Claude API deep analysis
│       └── reporter/
│           ├── github.py       # PR comment formatter
│           └── slack.py        # Slack notification
├── tests/
│   ├── fixtures/               # Sample plan JSON files for testing
│   └── test_rules.py
├── docs/
│   ├── STANDARDS_SCHEMA.md     # Standards file reference
│   └── RISK_LEVELS.md
└── examples/
    ├── basic-workflow.yaml
    └── advanced-workflow.yaml
```

---

## Roadmap

- [x] GitHub Actions integration
- [x] Security rule engine (IAM, SG, S3)
- [x] Blast radius assessment
- [x] PR comment with risk level
- [ ] Cost estimation via Infracost integration
- [ ] Org standards custom rules
- [ ] Slack notification support
- [ ] GitLab CI support
- [ ] OPA/Rego policy integration
- [ ] Historical risk trend dashboard

---

## License

MIT — see [LICENSE](LICENSE).
