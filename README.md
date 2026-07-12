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

## Try it locally

A one-command, fully offline demo runs the **real** reviewer (`guardian.main`) against the repo's fixture plans and `.tf-guardian.yml`, in Slack dry-run mode — no cloud, no API key, no network:

```bash
./demo/run_demo.sh
```

It reviews a violating plan (HIGH risk, 13 standards violations → exit 1) and a clean plan (NONE risk → exit 0), printing the rendered PR-comment markdown, the structured standards violations, the risk-gate decision, and the Slack Block Kit dry-run payload for each. See [`demo/OUTPUT.md`](demo/OUTPUT.md) for a captured real run and [`demo/README.md`](demo/README.md) for details.

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
          # Optional: explicit standards config (auto-discovered otherwise)
          standards-file: .tf-guardian.yml
          # Optional: Slack notifications (see below)
          slack-bot-token: ${{ secrets.SLACK_BOT_TOKEN }}
          slack-channel: C0INFRA
```

### Org Standards (`.tf-guardian.yml`)

Drop a `.tf-guardian.yml` at the repo root (or point `standards-file` anywhere).
Guardian auto-discovers `.tf-guardian.yml`, `.tf-guardian.yaml`,
`.guardian/standards.yaml`, then `standards.yaml`. Every section is optional.

```yaml
version: 1

# Tags every taggable resource must carry (checked on create/update)
required_tags: [Environment, Team, Owner]

# Allowed values for specific tags
tag_values:
  Environment: [production, staging, development, sandbox]

# Instance-size allowlists per resource type — glob patterns
allowed_instance_types:
  aws_instance: ["t3.*", "m6i.*"]
  aws_db_instance: ["db.t3.*", "db.r6g.*"]

# Regions infrastructure may target. Checked against provider config,
# resource `region` attributes, and availability zones.
allowed_regions: [us-east-1, us-west-2]

# Encryption-at-rest requirements per service
encryption:
  s3: true      # SSE config inline or via companion resource
  rds: true     # storage_encrypted on instances + clusters
  ebs: true     # volumes + instance root block devices
  efs: true
  dynamodb: false

# Naming conventions — Python regexes per resource type
naming_patterns:
  aws_s3_bucket: "^[a-z0-9][a-z0-9.-]{2,62}$"

# Only these module sources may be used (glob patterns)
module_allowlist:
  enforce: true
  allowed_sources:
    - "terraform-aws-modules/*"
    - "./modules/*"

# Per-section severity overrides (CRITICAL / HIGH / MEDIUM / LOW)
severities:
  naming_patterns: LOW
```

Each violation is structured — rule id (`STD-TAG-001`, `STD-ENC-RDS`,
`STD-MOD-001`, …), severity, resource address, message, and a fix hint — and
feeds into the overall risk gate, the PR comment, and the Slack summary. An
invalid config (bad regex, unknown severity, malformed YAML) **fails the run
loudly** instead of silently skipping checks.

Legacy condition-based rules are still supported under a `standards:` key
(`type: required|equals|not_equals|matches|not_matches|in|not_in|min_length`) —
see `standards.yaml` in this repo for a complete example.

### Slack Notifications

Two delivery modes, plus a dry-run:

| Mode | Configuration | Behaviour |
|------|--------------|-----------|
| Webhook | `slack-webhook-url` | One message per review |
| Bot token | `slack-bot-token` + `slack-channel` | **Thread-per-PR**: the first review of a PR posts a parent message; later runs for the same PR reply in its thread |
| Dry run | `slack-dry-run: true` | Logs the exact Block Kit payload, sends nothing |

The message is a Block Kit summary: risk level, finding counts, standards
violation count, monthly cost delta (when Infracost or the built-in estimator
ran), top findings, and the AI analysis. The bot token needs `chat:write`
(plus `channels:history` for thread lookup; without it Guardian degrades
gracefully to non-threaded posts). Slack failures never fail the CI gate —
they log a workflow warning.

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
├── .tf-guardian.yml            # Example org standards config
├── src/
│   └── guardian/
│       ├── main.py             # Action entrypoint
│       ├── parser.py           # Terraform plan JSON parser (+ module sources, provider regions)
│       ├── rules/
│       │   ├── security.py     # Security rule engine
│       │   ├── standards.py    # Org standards engine (.tf-guardian.yml)
│       │   ├── cost.py         # Built-in cost estimator
│       │   └── infracost.py    # Infracost CLI integration
│       ├── policy/
│       │   └── opa.py          # OPA/Rego policy enforcement
│       ├── drift/              # Nightly drift detection engine + CLI
│       ├── ai/
│       │   └── analyzer.py     # Claude API deep analysis
│       └── reporter/
│           ├── github.py       # PR comment formatter
│           └── slack.py        # Block Kit reporter (webhook / bot token / thread-per-PR)
└── tests/
    ├── fixtures/               # Sample plan JSONs (violations, clean, standards)
    ├── test_security_rules.py
    ├── test_standards.py
    ├── test_slack_reporter.py
    ├── test_cost_estimator.py
    └── test_drift_analyzer.py
```

---

## Roadmap

- [x] GitHub Actions integration
- [x] Security rule engine (IAM, SG, S3, RDS, KMS, EC2)
- [x] Blast radius assessment
- [x] PR comment with risk level
- [x] Cost estimation via Infracost integration (built-in estimator fallback)
- [x] Org standards engine (`.tf-guardian.yml`: tags, instance types, regions, encryption, naming, module allowlists)
- [x] Slack notification support (Block Kit, webhook + bot token, thread-per-PR, dry-run)
- [x] OPA/Rego policy integration
- [x] Drift detection (nightly multi-account scan + AI root-cause analysis)
- [ ] GitLab CI support
- [ ] Historical risk trend dashboard

---

## License

MIT — see [LICENSE](LICENSE).
