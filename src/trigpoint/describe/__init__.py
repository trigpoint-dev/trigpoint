"""Optional LLM pass that fills in missing repo and module descriptions.

Works with any LLM: implement ``LLMClient`` or wrap a function with ``CallableLLM``. The
ready-made adapters live in submodules so their optional dependencies are only imported on use:

    from trigpoint.describe.openai_compat import OpenAICompatibleLLM   # trigpoint[openai-compat]
    from trigpoint.describe.anthropic import AnthropicLLM              # trigpoint[anthropic]
"""

from trigpoint.describe.describe import (
    DescribeConfig,
    DescribeStats,
    clean_description,
    describe_repo_map,
)
from trigpoint.describe.llm import CallableLLM, LLMClient, LLMError

__all__ = [
    "CallableLLM",
    "DescribeConfig",
    "DescribeStats",
    "LLMClient",
    "LLMError",
    "clean_description",
    "describe_repo_map",
]
