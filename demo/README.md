# terraform-ai-guardian — runnable local demo

A one-command, fully-offline proof that the guardian plan reviewer works on
localhost. It runs the **real** CLI (`guardian.main`) against the repo's existing
fixture plans and `.tf-guardian.yml`, in Slack dry-run mode, using the rule-based
path (security rules + org-standards drift + cost). No cloud, no real Slack, no
API key, no network ports bound.

## Run it

```bash
./demo/run_demo.sh
```

That's it. On first run it creates an isolated venv at `.venv-demo/`,
`pip install -e .`, then evaluates two fixture plans and prints every artifact.
Uses `python3.12` by default; override with `PYTHON_BIN=python3.14 ./demo/run_demo.sh`.

## What it does

For each of two fixture plans it invokes the real entrypoint and captures:

- the rendered **PR-comment markdown** (via `GITHUB_STEP_SUMMARY`),
- the structured **org-standards violations** (rule id / severity / resource / fix hint),
- the **risk gate decision + exit code** (via `GITHUB_OUTPUT` and the process exit status),
- the **Slack Block Kit dry-run payload** (logged, never sent).

| plan | fixture | expected outcome |
|------|---------|------------------|
| violating | `tests/fixtures/plan_standards_violations.json` | HIGH risk, 13 standards violations, **exit 1** |
| clean     | `tests/fixtures/plan_clean.json`                | NONE risk, 0 violations, **exit 0** |

The script exits `0` only if the violating plan gated (exit 1) and the clean plan
passed (exit 0).

## How the CLI is driven

The reviewer is entirely environment-driven (it's a GitHub Action). The demo sets:

| env var | value | why |
|---------|-------|-----|
| `PLAN_FILE` | fixture path | the terraform plan JSON to review |
| `STANDARDS_FILE` | `.tf-guardian.yml` | enables the org-standards engine |
| `FAIL_ON_RISK` | `HIGH` | risk gate threshold |
| `SLACK_DRY_RUN` | `true` | build + log the Block Kit payload, send nothing |
| `INPUT_OPA-ENABLED` | `false` | skip optional OPA engine (needs external `opa` binary) |
| `GITHUB_STEP_SUMMARY` | tempfile | side-channel that receives the PR-comment markdown |
| `GITHUB_OUTPUT` | tempfile | side-channel that receives the risk-gate outputs |

Notably **absent**: `ANTHROPIC_API_KEY` (LLM review skipped — offline) and
`GITHUB_TOKEN` (no live PR comment posted).

## Artifacts

Each run writes per-case files under `demo/out/` (git-ignored, regenerated each run):

```
demo/out/<case>.console.log     full stdout+stderr
demo/out/<case>.pr-comment.md   rendered PR comment
demo/out/<case>.outputs.txt     GitHub Action outputs (risk-level, counts, ...)
demo/out/<case>.slack.json      extracted Slack Block Kit dry-run payload
demo/out/<case>.exit-code.txt   process exit code
```

## Captured evidence

See [`OUTPUT.md`](./OUTPUT.md) for the exact command and the real, captured output
of both cases side by side (PR comment, violations table, exit codes, Slack JSON),
plus honest caveats (LLM path skipped offline; cost estimator degraded to skipped).
