"""Tests for the Slack reporter — Block Kit payload shape, transports, threading, dry-run."""

import json

import httpx

from guardian.reporter.slack import (
    ReviewSummary,
    SlackConfig,
    SlackReporter,
    build_fallback_text,
    build_review_blocks,
)
from guardian.rules.security import Finding, RiskLevel
from guardian.rules.standards import StandardViolation


def make_finding(risk=RiskLevel.CRITICAL, title="SSH open to world", address="aws_security_group.web"):
    return Finding(
        risk_level=risk,
        category="Network",
        resource_address=address,
        title=title,
        description="desc",
        recommendation="fix it",
    )


def make_violation(rule_id="STD-TAG-001", severity=RiskLevel.HIGH):
    return StandardViolation(
        rule_id=rule_id,
        severity=severity,
        resource_address="aws_instance.web",
        message="aws_instance.web is missing required tag 'Team'",
        fix_hint="Add the tag",
    )


def make_summary(**overrides) -> ReviewSummary:
    defaults = dict(
        overall_risk=RiskLevel.HIGH,
        findings=[make_finding()],
        violations=[make_violation()],
        plan_file="tfplan.json",
        pr_url="https://github.com/org/repo/pull/42",
        pr_key="org/repo#42",
        ai_summary="Looks risky.",
        cost_delta_monthly=123.45,
        cost_source="infracost",
    )
    defaults.update(overrides)
    return ReviewSummary(**defaults)


# ─── Block building ───────────────────────────────────────────────────────────

class TestBuildReviewBlocks:
    def test_structure(self):
        blocks = build_review_blocks(make_summary())
        types = [b["type"] for b in blocks]
        assert types[0] == "header"
        assert "section" in types
        assert types[-1] == "context"
        assert "HIGH" in blocks[0]["text"]["text"]

    def test_summary_fields(self):
        fields = build_review_blocks(make_summary())[1]["fields"]
        text = json.dumps(fields)
        assert "tfplan.json" in text
        assert "Standards Violations" in text
        assert "+123.45" in text
        assert "infracost" in text
        assert "pull/42" in text
        assert len(fields) <= 10  # Slack hard limit

    def test_top_findings_listed_most_severe_first(self):
        summary = make_summary(findings=[
            make_finding(RiskLevel.MEDIUM, title="medium issue"),
            make_finding(RiskLevel.CRITICAL, title="critical issue"),
        ])
        blocks = build_review_blocks(summary)
        findings_block = next(
            b for b in blocks
            if b["type"] == "section" and "Top Findings" in b.get("text", {}).get("text", "")
        )
        text = findings_block["text"]["text"]
        assert text.index("critical issue") < text.index("medium issue")

    def test_findings_capped_at_five_with_overflow_note(self):
        summary = make_summary(
            findings=[make_finding(title=f"finding {i}") for i in range(9)],
        )
        blocks = build_review_blocks(summary)
        text = next(
            b["text"]["text"] for b in blocks
            if b["type"] == "section" and "Top Findings" in b.get("text", {}).get("text", "")
        )
        assert text.count("finding ") == 5
        assert "4 more finding(s)" in text

    def test_violations_section(self):
        blocks = build_review_blocks(make_summary())
        text = next(
            b["text"]["text"] for b in blocks
            if b["type"] == "section" and "Standards Violations" in b.get("text", {}).get("text", "")
        )
        assert "STD-TAG-001" in text
        assert "aws_instance.web" in text

    def test_no_optional_sections_when_empty(self):
        summary = make_summary(
            findings=[], violations=[], ai_summary="", cost_delta_monthly=None,
            overall_risk=RiskLevel.NONE,
        )
        blocks = build_review_blocks(summary)
        text = json.dumps(blocks)
        assert "Top Findings" not in text
        assert "Org Standards Violations" not in text
        assert "AI Analysis" not in text

    def test_ai_summary_truncated_to_slack_limit(self):
        summary = make_summary(ai_summary="x" * 5000)
        blocks = build_review_blocks(summary)
        for block in blocks:
            if block["type"] == "section" and "text" in block:
                assert len(block["text"]["text"]) <= 3000

    def test_fallback_text(self):
        text = build_fallback_text(make_summary())
        assert "HIGH" in text
        assert "1 finding(s)" in text
        assert "1 standards violation(s)" in text


# ─── Reporter transports ─────────────────────────────────────────────────────

def reporter_with_transport(config: SlackConfig, handler) -> SlackReporter:
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return SlackReporter(config, client=client)


class TestWebhookTransport:
    def test_posts_payload_to_webhook(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["url"] = str(request.url)
            seen["payload"] = json.loads(request.content)
            return httpx.Response(200, text="ok")

        config = SlackConfig(webhook_url="https://hooks.slack.com/services/T/B/x")
        reporter = reporter_with_transport(config, handler)
        assert reporter.post_review(make_summary()) is True
        assert seen["url"] == config.webhook_url
        assert seen["payload"]["blocks"][0]["type"] == "header"
        assert seen["payload"]["text"]  # notification fallback present

    def test_webhook_failure_returns_false_not_raise(self):
        def handler(request):
            return httpx.Response(400, text="invalid_payload")

        config = SlackConfig(webhook_url="https://hooks.slack.com/services/T/B/x")
        reporter = reporter_with_transport(config, handler)
        assert reporter.post_review(make_summary()) is False

    def test_retries_on_429_then_succeeds(self):
        calls = {"n": 0}

        def handler(request):
            calls["n"] += 1
            if calls["n"] == 1:
                return httpx.Response(429, headers={"Retry-After": "0"})
            return httpx.Response(200, text="ok")

        config = SlackConfig(webhook_url="https://hooks.slack.com/services/T/B/x")
        reporter = reporter_with_transport(config, handler)
        assert reporter.post_review(make_summary()) is True
        assert calls["n"] == 2


class TestBotTokenTransport:
    def make_config(self):
        return SlackConfig(bot_token="xoxb-test", channel="C0INFRA")

    def test_first_post_creates_thread_parent_with_metadata(self):
        requests = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            if "conversations.history" in str(request.url):
                return httpx.Response(200, json={"ok": True, "messages": []})
            return httpx.Response(200, json={"ok": True, "ts": "111.222"})

        reporter = reporter_with_transport(self.make_config(), handler)
        assert reporter.post_review(make_summary()) is True

        post = json.loads(requests[-1].content)
        assert post["channel"] == "C0INFRA"
        assert "thread_ts" not in post
        assert post["metadata"]["event_type"] == "terraform_guardian_review"
        assert post["metadata"]["event_payload"]["pr"] == "org/repo#42"
        assert requests[-1].headers["Authorization"] == "Bearer xoxb-test"

    def test_subsequent_post_replies_in_existing_thread(self):
        requests = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            if "conversations.history" in str(request.url):
                return httpx.Response(200, json={"ok": True, "messages": [
                    {"ts": "999.000", "metadata": {
                        "event_type": "terraform_guardian_review",
                        "event_payload": {"pr": "org/repo#42"},
                    }},
                    {"ts": "111.000", "metadata": {
                        "event_type": "terraform_guardian_review",
                        "event_payload": {"pr": "org/repo#7"},
                    }},
                ]})
            return httpx.Response(200, json={"ok": True, "ts": "999.001"})

        reporter = reporter_with_transport(self.make_config(), handler)
        assert reporter.post_review(make_summary()) is True

        post = json.loads(requests[-1].content)
        assert post["thread_ts"] == "999.000"
        assert "metadata" not in post

    def test_thread_lookup_failure_degrades_gracefully(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if "conversations.history" in str(request.url):
                return httpx.Response(200, json={"ok": False, "error": "missing_scope"})
            return httpx.Response(200, json={"ok": True, "ts": "1.2"})

        reporter = reporter_with_transport(self.make_config(), handler)
        assert reporter.post_review(make_summary()) is True

    def test_api_error_returns_false(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if "conversations.history" in str(request.url):
                return httpx.Response(200, json={"ok": True, "messages": []})
            return httpx.Response(200, json={"ok": False, "error": "channel_not_found"})

        reporter = reporter_with_transport(self.make_config(), handler)
        assert reporter.post_review(make_summary()) is False

    def test_no_thread_lookup_without_pr_key(self):
        requests = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return httpx.Response(200, json={"ok": True, "ts": "1.2"})

        reporter = reporter_with_transport(self.make_config(), handler)
        assert reporter.post_review(make_summary(pr_key="")) is True
        assert all("conversations.history" not in str(r.url) for r in requests)


class TestDryRunAndConfig:
    def test_dry_run_sends_nothing(self):
        def handler(request):
            raise AssertionError("dry-run must not hit the network")

        config = SlackConfig(webhook_url="https://hooks.slack.com/x", dry_run=True)
        reporter = reporter_with_transport(config, handler)
        assert reporter.post_review(make_summary()) is True

    def test_dry_run_logs_payload(self, caplog):
        config = SlackConfig(dry_run=True)
        with caplog.at_level("INFO", logger="guardian.slack"):
            SlackReporter(config).post_review(make_summary())
        assert "SLACK DRY RUN" in caplog.text
        assert "Terraform AI Guardian" in caplog.text

    def test_unconfigured_reporter_is_noop(self):
        reporter = SlackReporter(SlackConfig())
        assert reporter.enabled is False
        assert reporter.post_review(make_summary()) is False

    def test_config_from_env(self, monkeypatch):
        monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-1")
        monkeypatch.setenv("SLACK_CHANNEL", "C1")
        monkeypatch.setenv("SLACK_DRY_RUN", "true")
        monkeypatch.setenv("SLACK_THREAD_PER_PR", "false")
        monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
        config = SlackConfig.from_env()
        assert config.bot_token == "xoxb-1"
        assert config.channel == "C1"
        assert config.dry_run is True
        assert config.thread_per_pr is False
        assert config.enabled is True
