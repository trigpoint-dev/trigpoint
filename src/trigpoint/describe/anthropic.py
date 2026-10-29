"""Claude adapter (optional): uses the official Anthropic SDK."""

from __future__ import annotations

from typing import Any

try:
    import anthropic
except ImportError as exc:  # pragma: no cover
    raise ImportError("This adapter needs: pip install 'trigpoint[anthropic]'") from exc

from trigpoint.errors import LLMError
from trigpoint.extract.base import clip
from trigpoint.security import Redactor


class AnthropicLLM:
    """Calls Claude through ``client.messages.create``.

    Credentials come from the usual SDK sources (``ANTHROPIC_API_KEY`` etc.) unless you pass a
    configured ``client``. ``effort`` (default ``"low"``: a one-sentence description needs no
    deep reasoning) is sent as ``output_config.effort``; pass ``None`` to omit it for models
    that do not support the parameter. Sampling parameters are deliberately not set: current
    Claude models reject non-default values.
    """

    def __init__(
        self,
        *,
        model: str = "claude-opus-5-5",
        client: anthropic.Anthropic | None = None,
        effort: str | None = "low",
        redactor: Redactor | None = None,
    ) -> None:
        self._model = model
        self._client = client or anthropic.Anthropic()
        self._effort = effort
        self._redactor = redactor or Redactor()

    def complete(self, *, system: str, user: str, max_tokens: int) -> str:
        kwargs: dict[str, Any] = {
            "model": self._model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        if self._effort is not None:
            kwargs["output_config"] = {"effort": self._effort}
        try:
            response = self._client.messages.create(**kwargs)
        except anthropic.APIStatusError as exc:
            raise LLMError(
                f"Claude request failed ({exc.status_code}): "
                f"{clip(self._redactor.redact(exc.message), 200)}"
            ) from exc
        except anthropic.APIConnectionError as exc:  # includes timeouts
            raise LLMError(f"network error calling Claude: {type(exc).__name__}") from exc
        if response.stop_reason == "refusal":
            return ""  # declined: no description
        # Skip thinking blocks; only text blocks carry the answer.
        return "".join(b.text for b in response.content if b.type == "text")
