"""Tests for reading Claude's answer out of a response."""

from types import SimpleNamespace

import pytest

from guardian.ai.response import ClaudeNoAnswerError, answer_text


def block(kind: str, text: str = "") -> SimpleNamespace:
    if kind == "text":
        return SimpleNamespace(type="text", text=text)
    return SimpleNamespace(type=kind, thinking="", signature="sig")


def response(*blocks, stop_reason="end_turn", stop_details=None) -> SimpleNamespace:
    return SimpleNamespace(content=list(blocks), stop_reason=stop_reason, stop_details=stop_details)


def test_skips_leading_thinking_blocks():
    assert answer_text(response(block("thinking"), block("text", "LOW risk"))) == "LOW risk"


def test_joins_multiple_text_blocks():
    assert answer_text(response(block("text", "a "), block("thinking"), block("text", "b"))) == "a b"


def test_refusal_raises_with_category():
    r = response(stop_reason="refusal", stop_details=SimpleNamespace(category="cyber"))
    with pytest.raises(ClaudeNoAnswerError, match="cyber"):
        answer_text(r)


def test_thinking_only_cut_off_by_max_tokens_says_so():
    with pytest.raises(ClaudeNoAnswerError, match="max_tokens"):
        answer_text(response(block("thinking"), stop_reason="max_tokens"))
