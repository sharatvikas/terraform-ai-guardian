"""Reading Claude's answer out of a Messages API response."""

from __future__ import annotations

from typing import Any


class ClaudeNoAnswerError(RuntimeError):
    """Raised when a response holds no usable text: a refusal, or output cut off by max_tokens."""


def answer_text(response: Any) -> str:
    """Return the text of the response's `text` blocks, joined.

    Current models think by default, so a response can begin with `thinking` blocks:
    the answer is read by block type, never as `content[0]`.
    """
    if response.stop_reason == "refusal":
        details = getattr(response, "stop_details", None)
        category = getattr(details, "category", None) if details else None
        raise ClaudeNoAnswerError(f"Claude declined the request (category: {category or 'unspecified'})")

    text = "".join(block.text for block in response.content if block.type == "text").strip()
    if not text:
        if response.stop_reason == "max_tokens":
            raise ClaudeNoAnswerError("Claude ran out of max_tokens before writing an answer; raise max-tokens")
        raise ClaudeNoAnswerError(f"Claude returned no text (stop_reason: {response.stop_reason})")
    return text
