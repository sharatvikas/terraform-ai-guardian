"""Slack reporter for terraform-ai-guardian.

Posts a Block Kit review summary to Slack via either:

* an incoming **webhook** (``SLACK_WEBHOOK_URL``) — simplest, no threading; or
* a **bot token** (``SLACK_BOT_TOKEN`` + ``SLACK_CHANNEL``) — enables the
  thread-per-PR convention: the first review of a PR becomes a parent message
  tagged with message metadata, and subsequent runs for the same PR reply in
  its thread instead of flooding the channel.

``SLACK_DRY_RUN=true`` logs the exact payload without sending anything —
useful in CI while wiring up credentials.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

import httpx

from guardian.rules.security import Finding, RiskLevel

if TYPE_CHECKING:  # pragma: no cover
    from guardian.rules.standards import StandardViolation

logger = logging.getLogger("guardian.slack")

_SLACK_API = "https://slack.com/api"
_METADATA_EVENT_TYPE = "terraform_guardian_review"
_MAX_BLOCK_TEXT = 2900  # Slack hard limit is 3000 chars per section text
_MAX_FINDINGS_SHOWN = 5
_MAX_VIOLATIONS_SHOWN = 8

_RISK_EMOJI = {
    RiskLevel.CRITICAL: ":red_circle:",
    RiskLevel.HIGH: ":large_orange_circle:",
    RiskLevel.MEDIUM: ":large_yellow_circle:",
    RiskLevel.LOW: ":white_circle:",
    RiskLevel.NONE: ":large_green_circle:",
}


class SlackError(Exception):
    """Raised when Slack rejects a message after retries."""


@dataclass
class SlackConfig:
    webhook_url: str = ""
    bot_token: str = ""
    channel: str = ""
    dry_run: bool = False
    thread_per_pr: bool = True

    @classmethod
    def from_env(cls) -> "SlackConfig":
        return cls(
            webhook_url=os.environ.get("SLACK_WEBHOOK_URL", ""),
            bot_token=os.environ.get("SLACK_BOT_TOKEN", ""),
            channel=os.environ.get("SLACK_CHANNEL", ""),
            dry_run=os.environ.get("SLACK_DRY_RUN", "").lower() in ("1", "true", "yes"),
            thread_per_pr=os.environ.get("SLACK_THREAD_PER_PR", "true").lower() != "false",
        )

    @property
    def enabled(self) -> bool:
        return bool(self.webhook_url or (self.bot_token and self.channel))


@dataclass
class ReviewSummary:
    """Everything the Slack message needs, decoupled from the pipeline objects."""

    overall_risk: RiskLevel
    findings: list[Finding] = field(default_factory=list)
    violations: list["StandardViolation"] = field(default_factory=list)
    plan_file: str = ""
    pr_url: str = ""
    pr_key: str = ""          # stable identity for threading, e.g. "org/repo#42"
    ai_summary: str = ""
    cost_delta_monthly: float | None = None
    cost_source: str = ""


def _truncate(text: str, limit: int = _MAX_BLOCK_TEXT) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def build_review_blocks(summary: ReviewSummary) -> list[dict[str, Any]]:
    """Build the Block Kit blocks for a review summary. Pure function — unit-testable."""
    emoji = _RISK_EMOJI.get(summary.overall_risk, ":question:")
    counts = {level: 0 for level in RiskLevel}
    for f in summary.findings:
        counts[f.risk_level] += 1

    fields = [
        {"type": "mrkdwn", "text": f"*Risk Level*\n{emoji} {summary.overall_risk.name}"},
        {"type": "mrkdwn", "text": f"*Plan File*\n`{summary.plan_file or 'n/a'}`"},
        {"type": "mrkdwn",
         "text": f"*Critical / High*\n{counts[RiskLevel.CRITICAL]} / {counts[RiskLevel.HIGH]}"},
        {"type": "mrkdwn",
         "text": f"*Standards Violations*\n{len(summary.violations)}"},
    ]
    if summary.cost_delta_monthly is not None:
        source = f" ({summary.cost_source})" if summary.cost_source else ""
        fields.append({
            "type": "mrkdwn",
            "text": f"*Monthly Cost Δ*\n${summary.cost_delta_monthly:+,.2f}{source}",
        })
    if summary.pr_url:
        fields.append({"type": "mrkdwn", "text": f"*Pull Request*\n<{summary.pr_url}|View PR>"})

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"Terraform AI Guardian — {summary.overall_risk.name}",
                "emoji": True,
            },
        },
        {"type": "section", "fields": fields[:10]},  # Slack allows max 10 fields
        {"type": "divider"},
    ]

    top = sorted(summary.findings, key=lambda f: list(RiskLevel).index(f.risk_level))
    top = [f for f in top if f.risk_level != RiskLevel.NONE][:_MAX_FINDINGS_SHOWN]
    if top:
        lines = [
            f"{_RISK_EMOJI.get(f.risk_level, '')} *{f.title}*\n"
            f"        `{f.resource_address}`"
            for f in top
        ]
        more = len(summary.findings) - len(top)
        if more > 0:
            lines.append(f"_…and {more} more finding(s) — see the PR comment._")
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": _truncate("*Top Findings*\n" + "\n".join(lines))},
        })

    if summary.violations:
        vlines = []
        for v in summary.violations[:_MAX_VIOLATIONS_SHOWN]:
            vlines.append(
                f"{_RISK_EMOJI.get(v.severity, '')} *{v.rule_id}* `{v.resource_address}`\n"
                f"        {v.message}"
            )
        more = len(summary.violations) - _MAX_VIOLATIONS_SHOWN
        if more > 0:
            vlines.append(f"_…and {more} more violation(s)._")
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": _truncate("*Org Standards Violations*\n" + "\n".join(vlines)),
            },
        })

    if summary.ai_summary:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": _truncate(f"*AI Analysis*\n{summary.ai_summary}")},
        })

    blocks.append({
        "type": "context",
        "elements": [{"type": "mrkdwn", "text": "terraform-ai-guardian • plan review"}],
    })
    return blocks


def build_fallback_text(summary: ReviewSummary) -> str:
    """Plain-text fallback shown in notifications."""
    parts = [f"Terraform plan review: {summary.overall_risk.name} risk"]
    if summary.findings:
        parts.append(f"{len(summary.findings)} finding(s)")
    if summary.violations:
        parts.append(f"{len(summary.violations)} standards violation(s)")
    if summary.pr_url:
        parts.append(summary.pr_url)
    return " — ".join(parts)


class SlackReporter:
    """Posts review summaries to Slack with retry, threading, and dry-run support."""

    def __init__(self, config: SlackConfig, client: httpx.Client | None = None) -> None:
        self.config = config
        self._client = client
        self._owns_client = client is None

    @property
    def enabled(self) -> bool:
        return self.config.enabled or self.config.dry_run

    def post_review(self, summary: ReviewSummary) -> bool:
        """Post a review summary. Returns True when delivered (or dry-run). Never raises
        on delivery failure — reporting must not break the CI gate."""
        if not self.enabled:
            logger.debug("Slack reporting not configured — skipping")
            return False

        blocks = build_review_blocks(summary)
        payload: dict[str, Any] = {
            "text": build_fallback_text(summary),
            "blocks": blocks,
            "unfurl_links": False,
        }

        if self.config.dry_run:
            logger.info(
                "SLACK DRY RUN — payload that would be sent:\n%s",
                json.dumps(payload, indent=2, default=str),
            )
            print("::notice::Slack dry-run enabled — payload logged, nothing sent")
            return True

        try:
            if self.config.bot_token and self.config.channel:
                return self._post_via_bot(payload, summary)
            return self._post_via_webhook(payload)
        except (SlackError, httpx.HTTPError) as e:
            logger.error("Slack delivery failed: %s", e)
            print(f"::warning::Slack notification failed: {e}")
            return False
        finally:
            if self._owns_client and self._client is not None:
                self._client.close()
                self._client = None

    # ── transports ──────────────────────────────────────────────────────────

    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=15.0)
        return self._client

    def _post_via_webhook(self, payload: dict[str, Any]) -> bool:
        resp = self._request("POST", self.config.webhook_url, json=payload)
        if resp.status_code != 200:
            raise SlackError(f"webhook returned {resp.status_code}: {resp.text[:200]}")
        logger.info("Posted review to Slack webhook")
        return True

    def _post_via_bot(self, payload: dict[str, Any], summary: ReviewSummary) -> bool:
        body: dict[str, Any] = {"channel": self.config.channel, **payload}

        thread_ts = None
        if self.config.thread_per_pr and summary.pr_key:
            thread_ts = self._find_pr_thread(summary.pr_key)
            if thread_ts:
                body["thread_ts"] = thread_ts
                logger.info("Replying in existing PR thread %s", thread_ts)
            else:
                # This message becomes the thread parent; tag it for future lookups.
                body["metadata"] = {
                    "event_type": _METADATA_EVENT_TYPE,
                    "event_payload": {"pr": summary.pr_key},
                }

        resp = self._request(
            "POST",
            f"{_SLACK_API}/chat.postMessage",
            json=body,
            headers={"Authorization": f"Bearer {self.config.bot_token}"},
        )
        data = resp.json()
        if not data.get("ok"):
            raise SlackError(f"chat.postMessage failed: {data.get('error', 'unknown_error')}")
        logger.info(
            "Posted review to %s (%s)",
            self.config.channel,
            "thread reply" if thread_ts else "new thread parent",
        )
        return True

    def _find_pr_thread(self, pr_key: str) -> str | None:
        """Find the parent message for this PR by scanning recent channel history
        for our metadata tag. Returns its ts, or None if not found / not permitted."""
        try:
            resp = self._request(
                "GET",
                f"{_SLACK_API}/conversations.history",
                params={
                    "channel": self.config.channel,
                    "limit": 100,
                    "include_all_metadata": "true",
                },
                headers={"Authorization": f"Bearer {self.config.bot_token}"},
            )
            data = resp.json()
            if not data.get("ok"):
                logger.warning(
                    "conversations.history failed (%s) — posting without thread",
                    data.get("error", "unknown_error"),
                )
                return None
            for message in data.get("messages", []):
                meta = message.get("metadata") or {}
                if (
                    meta.get("event_type") == _METADATA_EVENT_TYPE
                    and (meta.get("event_payload") or {}).get("pr") == pr_key
                ):
                    return message.get("ts")
        except httpx.HTTPError as e:
            logger.warning("Thread lookup failed (%s) — posting without thread", e)
        return None

    def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """HTTP request with bounded retries on 429 and 5xx."""
        last_exc: Exception | None = None
        for attempt in range(3):
            try:
                resp = self.client.request(method, url, **kwargs)
            except httpx.HTTPError as e:
                last_exc = e
                logger.warning("Slack request error (attempt %d/3): %s", attempt + 1, e)
                time.sleep(min(2**attempt, 4))
                continue
            if resp.status_code == 429:
                delay = float(resp.headers.get("Retry-After", 2 ** attempt))
                logger.warning("Slack rate limited — retrying in %.0fs", delay)
                time.sleep(min(delay, 30))
                continue
            if resp.status_code >= 500:
                logger.warning("Slack server error %d (attempt %d/3)", resp.status_code, attempt + 1)
                time.sleep(min(2**attempt, 4))
                continue
            return resp
        if last_exc:
            raise SlackError(f"request to {url} failed after retries: {last_exc}")
        raise SlackError(f"request to {url} failed after retries (rate limited or 5xx)")


# ─── Backwards-compatible entry point ────────────────────────────────────────

def post_analysis_to_slack(
    overall_risk: RiskLevel,
    findings: list[Finding],
    ai_summary: str,
    plan_file: str,
    pr_url: str | None = None,
    webhook_url: str | None = None,
    violations: list["StandardViolation"] | None = None,
    cost_delta_monthly: float | None = None,
    cost_source: str = "",
    pr_key: str = "",
) -> bool:
    """Post analysis results to Slack using environment configuration.

    Kept for compatibility with the existing pipeline; new code should use
    SlackReporter directly.
    """
    config = SlackConfig.from_env()
    if webhook_url:
        config.webhook_url = webhook_url
    reporter = SlackReporter(config)
    return reporter.post_review(ReviewSummary(
        overall_risk=overall_risk,
        findings=findings,
        violations=violations or [],
        plan_file=plan_file,
        pr_url=pr_url or "",
        pr_key=pr_key,
        ai_summary=ai_summary,
        cost_delta_monthly=cost_delta_monthly,
        cost_source=cost_source,
    ))
