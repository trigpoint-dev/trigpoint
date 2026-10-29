"""The provider-neutral LLM port. Any model works: implement ``complete`` or wrap a function.

Adapters shipped with trigpoint:

* ``CallableLLM``         wrap any function (Bedrock, Vertex, a local pipeline, a test double);
* ``OpenAICompatibleLLM`` the /chat/completions protocol spoken by OpenAI, Azure OpenAI,
                          Gemini's compatibility endpoint, Mistral, Groq, Together, OpenRouter,
                          vLLM, Ollama, LM Studio and many more (``trigpoint[openai-compat]``);
* ``AnthropicLLM``        Claude via the official SDK (``trigpoint[anthropic]``).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from trigpoint.errors import LLMError

__all__ = ["CallableLLM", "LLMClient", "LLMError"]


class LLMClient(Protocol):
    """Minimal text-in, text-out chat completion.

    Implementations should raise ``LLMError`` for provider failures (the describe pass skips
    that item and continues) and return an empty string when the model declines to answer.
    """

    def complete(self, *, system: str, user: str, max_tokens: int) -> str: ...


class CallableLLM:
    """Adapt ``fn(system, user, max_tokens) -> str`` to the ``LLMClient`` protocol."""

    def __init__(self, fn: Callable[[str, str, int], str]) -> None:
        self._fn = fn

    def complete(self, *, system: str, user: str, max_tokens: int) -> str:
        return self._fn(system, user, max_tokens)
