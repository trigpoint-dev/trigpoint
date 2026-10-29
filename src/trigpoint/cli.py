"""Command line: ``trigpoint map PATH``."""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from trigpoint import __version__
from trigpoint.api import Limits, build_repo_map, render_markdown
from trigpoint.describe import LLMClient, describe_repo_map
from trigpoint.errors import TrigpointError


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trigpoint", description="Safe, budgeted repo grounding for LLMs and agents."
    )
    parser.add_argument("--version", action="version", version=f"trigpoint {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    m = sub.add_parser("map", help="Build and print a repo map for a local directory.")
    m.add_argument("path", help="Directory to map.")
    m.add_argument("--budget", type=int, default=4000, help="Token budget (default 4000).")
    m.add_argument("--format", choices=("markdown", "json"), default="markdown")
    m.add_argument("--name", help="Override the repository name.")
    m.add_argument(
        "--max-file-bytes", type=int, default=Limits().max_file_bytes, help="Per-file read cap."
    )
    d = m.add_argument_group(
        "optional LLM descriptions",
        "Fill in a repo/module description only where the repo has none. Works with any LLM.",
    )
    d.add_argument("--describe", action="store_true", help="Enable the LLM describe pass.")
    d.add_argument(
        "--llm",
        choices=("openai", "anthropic"),
        default="openai",
        help="'openai' = any OpenAI-compatible endpoint (hosted or local); 'anthropic' = Claude.",
    )
    d.add_argument("--model", help="Model name (required for --llm openai).")
    d.add_argument(
        "--base-url",
        default="https://api.openai.com/v1",
        help="OpenAI-compatible API root, e.g. http://localhost:11434/v1 for Ollama.",
    )
    d.add_argument(
        "--api-key-env",
        default="TRIGPOINT_LLM_API_KEY",
        help="Environment variable holding the API key (not needed for local servers).",
    )
    d.add_argument("--cache-dir", help="Cache generated descriptions here between runs.")
    return parser


def _make_llm(args: argparse.Namespace) -> LLMClient:
    """Build the chosen provider adapter. Imported lazily so extras stay optional."""
    if args.llm == "anthropic":
        from trigpoint.describe.anthropic import AnthropicLLM

        return AnthropicLLM(model=args.model) if args.model else AnthropicLLM()
    from trigpoint.describe.openai_compat import OpenAICompatibleLLM

    if not args.model:
        raise TrigpointError("--model is required with --llm openai")
    return OpenAICompatibleLLM(
        model=args.model,
        base_url=args.base_url,
        api_key=os.environ.get(args.api_key_env) or os.environ.get("OPENAI_API_KEY"),
    )


def _describe(args: argparse.Namespace, repo_map):  # type: ignore[no-untyped-def]
    from trigpoint.cache import ArtifactCache, LocalFsStore

    cache = None
    key = None
    if args.cache_dir:
        cache = ArtifactCache(LocalFsStore(args.cache_dir))
        digest = hashlib.sha256(str(Path(args.path).resolve()).encode()).hexdigest()[:12]
        key = f"local-{digest}"
    updated, stats = describe_repo_map(repo_map, _make_llm(args), repo_key=key, cache=cache)
    print(
        f"trigpoint: describe: {stats.accepted} added, {stats.cache_hits} cached, "
        f"{stats.llm_calls} LLM calls, {stats.rejected} rejected, {stats.failed} failed"
        + (" (stopped early after repeated failures)" if stats.aborted else ""),
        file=sys.stderr,
    )
    return updated


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    try:
        repo_map = build_repo_map(
            args.path, name=args.name, limits=Limits(max_file_bytes=args.max_file_bytes)
        )
        if args.describe:
            repo_map = _describe(args, repo_map)
    except ImportError as exc:
        print(f"trigpoint: error: {exc}", file=sys.stderr)
        return 2
    except (TrigpointError, OSError, ValueError) as exc:
        print(f"trigpoint: error: {exc}", file=sys.stderr)
        return 2
    try:
        if args.format == "json":
            print(repo_map.to_json(indent=2))
            return 0
        rendered = render_markdown(repo_map, budget_tokens=args.budget)
        sys.stdout.write(rendered.markdown)
        sys.stdout.flush()
    except BrokenPipeError:  # e.g. `trigpoint map . | head`
        return 0
    for warning in rendered.warnings:
        print(f"trigpoint: warning: {warning}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
