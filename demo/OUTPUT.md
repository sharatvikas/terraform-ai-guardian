# Demo Output — captured, real, offline

This file is the **verbatim captured output** of `demo/run_demo.sh` running the
real `guardian` CLI against the repo's existing fixture plans and
`.tf-guardian.yml`. No cloud, no real Slack, no API key.

## Command

```bash
./demo/run_demo.sh
```

Under the hood, for each plan the script runs the real entrypoint
(`guardian` = `guardian.main:main`) like this:

```bash
env \
  PLAN_FILE=tests/fixtures/<plan>.json \
  STANDARDS_FILE=.tf-guardian.yml \
  FAIL_ON_RISK=HIGH \
  SLACK_DRY_RUN=true \
  'INPUT_OPA-ENABLED=false' \
  GITHUB_STEP_SUMMARY=<tempfile>   `# captures the PR-comment markdown` \
  GITHUB_OUTPUT=<tempfile>         `# captures the risk-gate outputs` \
  guardian
```

- `SLACK_DRY_RUN=true` — the Slack Block Kit payload is **logged, never sent**.
- No `ANTHROPIC_API_KEY` — the **LLM "AI Deep Analysis" path is skipped**; the
  rule-based path (security rules + org-standards drift + cost) runs offline.
- `INPUT_OPA-ENABLED=false` — the optional OPA/rego engine needs the external
  `opa` binary and is not part of the rule-based path.

## Result summary (the headline)

| case      | plan                                         | risk | standards-violations | **exit code** |
|-----------|----------------------------------------------|------|----------------------|---------------|
| violating | `tests/fixtures/plan_standards_violations.json` | **HIGH** | **13** | **1** (gate blocks) |
| clean     | `tests/fixtures/plan_clean.json`             | **NONE** | **0**  | **0** (gate passes) |

The violating plan trips `Risk HIGH >= threshold HIGH` and the process **exits 1**
— which fails the GitHub Action / merge gate. The clean plan produces no findings
and **exits 0**. Same binary, same config, opposite outcome.

---

# CASE 1 — Violating plan (`plan_standards_violations.json`)

6 resource changes (4 add, 1 change, 1 destroy). Trips 3 security findings +
13 org-standards violations = 16 findings total → **HIGH** → **exit 1**.

## 1a. Rendered PR-comment markdown

```markdown
<!-- terraform-ai-guardian -->
## 🟠 Terraform AI Guardian — Risk: **HIGH**

**Plan file:** `tests/fixtures/plan_standards_violations.json`  |  **Issues:** 0 critical, 12 high, 3 medium

---

### 🟠 High — Review Carefully

**EC2 root EBS volume is not encrypted**
- **Resource:** `aws_instance.legacy`
- aws_instance.legacy has root_block_device.encrypted = false.
- **Fix:** Set root_block_device { encrypted = true } (requires replacement).

**RDS instance storage is not encrypted**
- **Resource:** `aws_db_instance.reporting`
- aws_db_instance.reporting has storage_encrypted=false.
- **Fix:** Enable storage_encrypted=true. Requires replacement for existing instances.

**RDS database is scheduled for DESTROY**
- **Resource:** `aws_db_instance.deprecated`
- aws_db_instance.deprecated (RDS database) will be permanently deleted. This action cannot be undone.
- **Fix:** Confirm this is intentional. Ensure backups exist. Consider adding lifecycle { prevent_destroy = true } for production resources.

**[STD-TAG-001] aws_instance.legacy is missing required tag 'Team'**
- **Resource:** `aws_instance.legacy`
- aws_instance.legacy is missing required tag 'Team'
- **Fix:** Add tags = { Team = "<value>" } to the resource block.

**[STD-TAG-001] aws_instance.legacy is missing required tag 'Owner'**
- **Resource:** `aws_instance.legacy`
- aws_instance.legacy is missing required tag 'Owner'
- **Fix:** Add tags = { Owner = "<value>" } to the resource block.

**[STD-REGION-001] aws_instance.legacy targets disallowed region 'eu-central-1'**
- **Resource:** `aws_instance.legacy`
- aws_instance.legacy targets disallowed region 'eu-central-1'
- **Fix:** Deploy only to: us-east-1, us-west-2

**[STD-ENC-EBS] aws_instance.legacy does not have encryption at rest enabled (root_block_device.encrypted != true)**
- **Resource:** `aws_instance.legacy`
- aws_instance.legacy does not have encryption at rest enabled (root_block_device.encrypted != true)
- **Fix:** Add root_block_device { encrypted = true }

**[STD-ENC-S3] aws_s3_bucket.Analytics_Data has no server-side encryption configuration**
- **Resource:** `aws_s3_bucket.Analytics_Data`
- aws_s3_bucket.Analytics_Data has no server-side encryption configuration
- **Fix:** Add an aws_s3_bucket_server_side_encryption_configuration resource for this bucket (aws:kms or AES256).

**[STD-ENC-RDS] aws_db_instance.reporting does not have encryption at rest enabled (storage_encrypted != true)**
- **Resource:** `aws_db_instance.reporting`
- aws_db_instance.reporting does not have encryption at rest enabled (storage_encrypted != true)
- **Fix:** Set storage_encrypted = true

**[STD-ENC-EBS] aws_ebs_volume.scratch does not have encryption at rest enabled (encrypted != true)**
- **Resource:** `aws_ebs_volume.scratch`
- aws_ebs_volume.scratch does not have encryption at rest enabled (encrypted != true)
- **Fix:** Set encrypted = true

**[STD-MOD-001] module.snowflake_loader.aws_iam_role.loader comes from non-allowlisted module source 'git::https://github.com/random-person/snowflake-loader' (module.snowflake_loader)**
- **Resource:** `module.snowflake_loader.aws_iam_role.loader`
- module.snowflake_loader.aws_iam_role.loader comes from non-allowlisted module source 'git::https://github.com/random-person/snowflake-loader' (module.snowflake_loader)
- **Fix:** Use an approved module source: terraform-aws-modules/*, git::https://github.com/sharatvikas/*, ./modules/*

**[STD-REGION-002] Provider 'aws.frankfurt' is configured for disallowed region 'eu-central-1'**
- **Resource:** `provider.aws.frankfurt`
- Provider 'aws.frankfurt' is configured for disallowed region 'eu-central-1'
- **Fix:** Deploy only to: us-east-1, us-west-2


### 🟡 Medium — Informational

**[STD-TAG-002] aws_instance.legacy tag 'Environment' has disallowed value 'prod'**
- **Resource:** `aws_instance.legacy`
- aws_instance.legacy tag 'Environment' has disallowed value 'prod'
- **Fix:** Use one of: production, staging, development, sandbox

**[STD-COMPUTE-001] aws_instance.legacy uses disallowed instance_type 'm4.10xlarge' for aws_instance**
- **Resource:** `aws_instance.legacy`
- aws_instance.legacy uses disallowed instance_type 'm4.10xlarge' for aws_instance
- **Fix:** Allowed families: t3.*, t4g.*, m6i.*, m7g.*, c6i.*, r6g.*

**[STD-COMPUTE-001] aws_db_instance.reporting uses disallowed instance_class 'db.m3.medium' for aws_db_instance**
- **Resource:** `aws_db_instance.reporting`
- aws_db_instance.reporting uses disallowed instance_class 'db.m3.medium' for aws_db_instance
- **Fix:** Allowed families: db.t3.*, db.t4g.*, db.r6g.*, db.m6g.*


### 💰 Cost Estimate

| | Before | After | Delta |
|---|---|---|---|
| Monthly | $14.41 | $245.00 | **+$230.59/mo** |
| Hourly  | $0.0197 | $0.3356 | — |

*Source: builtin*

<details><summary>Top resources by cost</summary>

| Resource | Monthly |
|---|---|
| `aws_db_instance.reporting` | $148.00 |
| `aws_instance.legacy` | $81.00 |
| `aws_ebs_volume.scratch` | $16.00 |
| `aws_db_instance.deprecated` | $14.41 |
</details>

---
*Analysis by [terraform-ai-guardian](https://github.com/sharatvikas/terraform-ai-guardian) using Claude API*
```

## 1b. Structured standards violations (rule id / severity / resource / fix hint)

The engine emitted **13** structured `StandardViolation`s. Distilled from the
PR comment above:

| rule id        | severity | resource                                       | fix hint |
|----------------|----------|------------------------------------------------|----------|
| STD-TAG-001    | HIGH     | `aws_instance.legacy`                          | Add tags = { Team = "<value>" } |
| STD-TAG-001    | HIGH     | `aws_instance.legacy`                          | Add tags = { Owner = "<value>" } |
| STD-TAG-002    | MEDIUM   | `aws_instance.legacy`                          | Use one of: production, staging, development, sandbox |
| STD-COMPUTE-001| MEDIUM   | `aws_instance.legacy`                          | Allowed families: t3.*, t4g.*, m6i.*, m7g.*, c6i.*, r6g.* |
| STD-COMPUTE-001| MEDIUM   | `aws_db_instance.reporting`                    | Allowed families: db.t3.*, db.t4g.*, db.r6g.*, db.m6g.* |
| STD-REGION-001 | HIGH     | `aws_instance.legacy`                          | Deploy only to: us-east-1, us-west-2 |
| STD-REGION-002 | HIGH     | `provider.aws.frankfurt`                       | Deploy only to: us-east-1, us-west-2 |
| STD-ENC-EBS    | HIGH     | `aws_instance.legacy`                          | Add root_block_device { encrypted = true } |
| STD-ENC-EBS    | HIGH     | `aws_ebs_volume.scratch`                       | Set encrypted = true |
| STD-ENC-S3     | HIGH     | `aws_s3_bucket.Analytics_Data`                 | Add an aws_s3_bucket_server_side_encryption_configuration resource |
| STD-ENC-RDS    | HIGH     | `aws_db_instance.reporting`                    | Set storage_encrypted = true |
| STD-NAME-001   | LOW      | `aws_s3_bucket.Analytics_Data`                 | Rename to match: `^[a-z0-9][a-z0-9.-]{2,62}$` |
| STD-MOD-001    | HIGH     | `module.snowflake_loader.aws_iam_role.loader`  | Use an approved module source |

(3 additional security findings — unencrypted EBS/RDS, RDS DESTROY blast radius —
also feed the gate; total findings = 16.)

## 1c. Risk gate decision + Action outputs + exit code

Console tail:

```
Overall risk: HIGH
Posting review to Slack...
::notice::Slack dry-run enabled — payload logged, nothing sent
::error::Risk HIGH >= threshold HIGH
```

`GITHUB_OUTPUT`:

```
standards-violations=13
monthly-cost-delta=230.59
cost-source=builtin
risk-level=HIGH
critical-count=0
warning-count=15
```

**Exit code: `1`** → merge gate blocks the PR.

## 1d. Slack Block Kit dry-run payload

```json
{
  "text": "Terraform plan review: HIGH risk — 16 finding(s) — 13 standards violation(s)",
  "blocks": [
    {
      "type": "header",
      "text": { "type": "plain_text", "text": "Terraform AI Guardian — HIGH", "emoji": true }
    },
    {
      "type": "section",
      "fields": [
        { "type": "mrkdwn", "text": "*Risk Level*\n:large_orange_circle: HIGH" },
        { "type": "mrkdwn", "text": "*Plan File*\n`tests/fixtures/plan_standards_violations.json`" },
        { "type": "mrkdwn", "text": "*Critical / High*\n0 / 12" },
        { "type": "mrkdwn", "text": "*Standards Violations*\n13" },
        { "type": "mrkdwn", "text": "*Monthly Cost Δ*\n$+230.59 (builtin)" }
      ]
    },
    { "type": "divider" },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*Top Findings*\n:large_orange_circle: *EC2 root EBS volume is not encrypted*\n        `aws_instance.legacy`\n:large_orange_circle: *RDS instance storage is not encrypted*\n        `aws_db_instance.reporting`\n:large_orange_circle: *RDS database is scheduled for DESTROY*\n        `aws_db_instance.deprecated`\n:large_orange_circle: *[STD-TAG-001] aws_instance.legacy is missing required tag 'Team'*\n        `aws_instance.legacy`\n:large_orange_circle: *[STD-TAG-001] aws_instance.legacy is missing required tag 'Owner'*\n        `aws_instance.legacy`\n_…and 11 more finding(s) — see the PR comment._"
      }
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*Org Standards Violations*\n:large_orange_circle: *STD-TAG-001* `aws_instance.legacy`\n        aws_instance.legacy is missing required tag 'Team'\n:large_orange_circle: *STD-TAG-001* `aws_instance.legacy`\n        aws_instance.legacy is missing required tag 'Owner'\n:large_yellow_circle: *STD-TAG-002* `aws_instance.legacy`\n        aws_instance.legacy tag 'Environment' has disallowed value 'prod'\n:large_yellow_circle: *STD-COMPUTE-001* `aws_instance.legacy`\n        aws_instance.legacy uses disallowed instance_type 'm4.10xlarge' for aws_instance\n:large_orange_circle: *STD-REGION-001* `aws_instance.legacy`\n        aws_instance.legacy targets disallowed region 'eu-central-1'\n:large_orange_circle: *STD-ENC-EBS* `aws_instance.legacy`\n        aws_instance.legacy does not have encryption at rest enabled (root_block_device.encrypted != true)\n:large_orange_circle: *STD-ENC-S3* `aws_s3_bucket.Analytics_Data`\n        aws_s3_bucket.Analytics_Data has no server-side encryption configuration\n:white_circle: *STD-NAME-001* `aws_s3_bucket.Analytics_Data`\n        aws_s3_bucket.Analytics_Data name 'Analytics_Data_Bucket' does not match the required pattern for aws_s3_bucket\n_…and 5 more violation(s)._"
      }
    },
    {
      "type": "context",
      "elements": [ { "type": "mrkdwn", "text": "terraform-ai-guardian • plan review" } ]
    }
  ],
  "unfurl_links": false
}
```

---

# CASE 2 — Clean plan (`plan_clean.json`)

5 resource changes (5 add). 0 security findings, 0 standards violations → **NONE** → **exit 0**.

## 2a. Rendered PR-comment markdown

```markdown
<!-- terraform-ai-guardian -->
## ✅ Terraform AI Guardian — Risk: **NONE**

**Plan file:** `tests/fixtures/plan_clean.json`  |  **Issues:** 0 critical, 0 high, 0 medium

---

### ✅ No automated rule violations found


### 💰 Cost Estimate

| | Before | After | Delta |
|---|---|---|---|
| Monthly | $0.00 | $358.74 | **+$358.74/mo** |
| Hourly  | $0.0000 | $0.4914 | — |

*Source: builtin*

<details><summary>Top resources by cost</summary>

| Resource | Monthly |
|---|---|
| `aws_db_instance.primary` | $294.00 |
| `aws_instance.api` | $64.74 |
</details>

---
*Analysis by [terraform-ai-guardian](https://github.com/sharatvikas/terraform-ai-guardian) using Claude API*
```

## 2b. Structured standards violations

None. `standards-violations=0`.

## 2c. Risk gate decision + Action outputs + exit code

Console tail:

```
Overall risk: NONE
Posting review to Slack...
::notice::Slack dry-run enabled — payload logged, nothing sent
```

`GITHUB_OUTPUT`:

```
standards-violations=0
monthly-cost-delta=358.74
cost-source=builtin
risk-level=NONE
critical-count=0
warning-count=0
```

**Exit code: `0`** → merge gate passes. (No `::error::` line — the gate was never tripped.)

## 2d. Slack Block Kit dry-run payload

```json
{
  "text": "Terraform plan review: NONE risk",
  "blocks": [
    {
      "type": "header",
      "text": { "type": "plain_text", "text": "Terraform AI Guardian — NONE", "emoji": true }
    },
    {
      "type": "section",
      "fields": [
        { "type": "mrkdwn", "text": "*Risk Level*\n:large_green_circle: NONE" },
        { "type": "mrkdwn", "text": "*Plan File*\n`tests/fixtures/plan_clean.json`" },
        { "type": "mrkdwn", "text": "*Critical / High*\n0 / 0" },
        { "type": "mrkdwn", "text": "*Standards Violations*\n0" },
        { "type": "mrkdwn", "text": "*Monthly Cost Δ*\n$+358.74 (builtin)" }
      ]
    },
    { "type": "divider" },
    {
      "type": "context",
      "elements": [ { "type": "mrkdwn", "text": "terraform-ai-guardian • plan review" } ]
    }
  ],
  "unfurl_links": false
}
```

---

## What this proves

1. **Same binary, opposite verdicts.** The identical `guardian` entrypoint and
   `.tf-guardian.yml` produce **exit 1 / HIGH** for the violating plan and
   **exit 0 / NONE** for the clean plan — i.e. the risk gate genuinely blocks bad
   plans and lets good ones through.
2. **Structured, actionable standards drift.** 13 violations carry a stable rule
   id, severity, resource address, and fix hint — spanning tags, tag values,
   instance types, regions (incl. a provider-level region), encryption
   (S3/EBS/RDS), naming, and module allowlist.
3. **Blast-radius / security awareness.** The RDS `DESTROY` and unencrypted
   EBS/RDS findings come from the security engine, independent of standards.
4. **Slack Block Kit renders correctly in dry-run** — a full, sendable payload is
   produced and logged, with **nothing actually sent** (`SLACK_DRY_RUN=true`).

## Honest gaps / caveats

- **LLM path skipped (offline):** with no `ANTHROPIC_API_KEY`, the "🤖 AI Deep
  Analysis" section is omitted. Everything shown is the deterministic rule-based
  path. Export `ANTHROPIC_API_KEY` to additionally exercise it (requires network).
- **Cost is a built-in heuristic, not `infracost`:** `infracost` is not installed
  here, so the offline built-in estimator runs (`Source: builtin`). It prices a
  curated set of resource types (EC2, RDS, EBS, EKS, NAT, ALB, ElastiCache) with
  hardcoded on-demand us-east-1 rates — good enough for a directional monthly
  delta, but not authoritative. Resource types outside those tables aren't
  priced, and if a plan contains no priceable resources cost is reported as
  `skipped` (genuinely unknown) rather than a fake `$0`. Install `infracost` and
  set `INFRACOST_API_KEY` for accurate, real-pricing numbers.
- **OPA disabled:** the optional OPA/rego engine (`policies/terraform.rego`) needs
  the external `opa` binary, which isn't part of the offline rule-based path.
- **PR comment / Slack are not delivered:** no `GITHUB_TOKEN` and dry-run Slack, by
  design — this is a localhost proof, not a live post.
