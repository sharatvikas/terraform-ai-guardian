#!/usr/bin/env bash
#
# run_demo.sh — one-command, fully-offline demo of terraform-ai-guardian.
#
# Runs the REAL guardian CLI (guardian.main) against the repo's existing
# fixture plan JSONs and .tf-guardian.yml, in Slack dry-run mode, using the
# rule-based path (security rules + org-standards drift + cost). No cloud, no
# real Slack, no API key required.
#
#   * Violating plan  -> HIGH risk, structured standards violations, exit 1
#   * Clean plan      -> NONE risk, no violations,                   exit 0
#
# The LLM "AI deep analysis" path is intentionally skipped: it needs
# ANTHROPIC_API_KEY and network access. Set ANTHROPIC_API_KEY before running to
# additionally exercise it. OPA is disabled here because the `opa` binary is an
# external dependency that is not required for the rule-based path.
#
# Binds no network ports.
#
set -euo pipefail

# ── Locate repo root (parent of this demo/ dir) ──────────────────────────────
DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${DEMO_DIR}/.." && pwd)"
OUT_DIR="${DEMO_DIR}/out"
VENV_DIR="${REPO_ROOT}/.venv-demo"

VIOLATING_PLAN="tests/fixtures/plan_standards_violations.json"
CLEAN_PLAN="tests/fixtures/plan_clean.json"
STANDARDS="${REPO_ROOT}/.tf-guardian.yml"

PYTHON_BIN="${PYTHON_BIN:-python3.12}"

cd "${REPO_ROOT}"
mkdir -p "${OUT_DIR}"

# ── Ensure an isolated venv with the package installed ───────────────────────
if [[ ! -x "${VENV_DIR}/bin/guardian" ]]; then
  echo ">> Creating venv at ${VENV_DIR} and installing terraform-ai-guardian ..."
  "${PYTHON_BIN}" -m venv "${VENV_DIR}"
  # shellcheck disable=SC1091
  source "${VENV_DIR}/bin/activate"
  pip install -q --upgrade pip >/dev/null
  pip install -q -e "${REPO_ROOT}" >/dev/null
else
  # shellcheck disable=SC1091
  source "${VENV_DIR}/bin/activate"
fi

echo ">> guardian entrypoint: $(command -v guardian)"
echo ">> python: $(python --version 2>&1)"
echo

# ── Runner: execute guardian for one plan, capture every artifact ────────────
# Args: <label> <plan-file> <expected-exit-note>
run_case () {
  local label="$1" plan="$2"
  local console="${OUT_DIR}/${label}.console.log"
  local pr_comment="${OUT_DIR}/${label}.pr-comment.md"
  local outputs="${OUT_DIR}/${label}.outputs.txt"
  local slack="${OUT_DIR}/${label}.slack.json"

  # GitHub Action side-channels: the PR-comment markdown is written to
  # GITHUB_STEP_SUMMARY, and the Action outputs (risk-level, standards-violations,
  # counts) are written to GITHUB_OUTPUT. We point them at temp files to capture.
  local step_summary output_file
  step_summary="$(mktemp)"
  output_file="$(mktemp)"

  echo "════════════════════════════════════════════════════════════════════════"
  echo " CASE: ${label}   plan=${plan}"
  echo "════════════════════════════════════════════════════════════════════════"

  set +e
  env \
    PLAN_FILE="${plan}" \
    STANDARDS_FILE="${STANDARDS}" \
    FAIL_ON_RISK="HIGH" \
    SLACK_DRY_RUN="true" \
    'INPUT_OPA-ENABLED=false' \
    GITHUB_STEP_SUMMARY="${step_summary}" \
    GITHUB_OUTPUT="${output_file}" \
    GUARDIAN_LOG_LEVEL="INFO" \
    guardian >"${console}" 2>&1
  local code=$?
  set -e

  cp "${step_summary}" "${pr_comment}"
  cp "${output_file}" "${outputs}"
  echo "${code}" > "${OUT_DIR}/${label}.exit-code.txt"

  # Extract the Slack Block Kit dry-run payload (valid JSON) from the console log.
  python - "${console}" "${slack}" <<'PY'
import json, sys
log, out = sys.argv[1], sys.argv[2]
text = open(log).read()
marker = "payload that would be sent:"
i = text.find(marker)
if i == -1:
    open(out, "w").write("{}\n")
    sys.exit(0)
brace = text.find("{", i)
obj, _ = json.JSONDecoder().raw_decode(text[brace:])
open(out, "w").write(json.dumps(obj, indent=2))
PY

  echo
  echo ">> Console output:"
  cat "${console}"
  echo
  echo ">> Rendered PR-comment markdown  (${pr_comment}):"
  echo "------------------------------------------------------------------------"
  cat "${pr_comment}"
  echo "------------------------------------------------------------------------"
  echo
  echo ">> GitHub Action outputs (risk gate decision) (${outputs}):"
  cat "${outputs}"
  echo
  echo ">> Slack Block Kit dry-run payload (${slack}):"
  cat "${slack}"
  echo
  echo ">> EXIT CODE for ${label}: ${code}"
  echo
  rm -f "${step_summary}" "${output_file}"
}

run_case "violating" "${VIOLATING_PLAN}"
run_case "clean"     "${CLEAN_PLAN}"

# ── Summary table ────────────────────────────────────────────────────────────
vio_code="$(cat "${OUT_DIR}/violating.exit-code.txt")"
clean_code="$(cat "${OUT_DIR}/clean.exit-code.txt")"
vio_risk="$(grep '^risk-level=' "${OUT_DIR}/violating.outputs.txt" | cut -d= -f2)"
clean_risk="$(grep '^risk-level=' "${OUT_DIR}/clean.outputs.txt" | cut -d= -f2)"
vio_std="$(grep '^standards-violations=' "${OUT_DIR}/violating.outputs.txt" | cut -d= -f2)"
clean_std="$(grep '^standards-violations=' "${OUT_DIR}/clean.outputs.txt" | cut -d= -f2)"

echo "════════════════════════════════════════════════════════════════════════"
echo " SUMMARY"
echo "════════════════════════════════════════════════════════════════════════"
printf "%-12s | %-9s | %-20s | %-4s\n" "case" "risk" "standards-violations" "exit"
printf "%-12s-+-%-9s-+-%-20s-+-%-4s\n" "------------" "---------" "--------------------" "----"
printf "%-12s | %-9s | %-20s | %-4s\n" "violating" "${vio_risk}"   "${vio_std}"   "${vio_code}"
printf "%-12s | %-9s | %-20s | %-4s\n" "clean"     "${clean_risk}" "${clean_std}" "${clean_code}"
echo
echo "Artifacts written to: ${OUT_DIR}/"
echo "  <case>.console.log  <case>.pr-comment.md  <case>.outputs.txt  <case>.slack.json  <case>.exit-code.txt"
echo

if [[ "${vio_code}" == "1" && "${clean_code}" == "0" ]]; then
  echo "RESULT: PASS — violating plan gated (exit 1), clean plan passed (exit 0)."
  exit 0
else
  echo "RESULT: UNEXPECTED — violating exit=${vio_code} (want 1), clean exit=${clean_code} (want 0)."
  exit 1
fi
