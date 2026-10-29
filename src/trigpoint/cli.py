"""Command line: ``trigpoint map PATH``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from trigpoint import __version__
from trigpoint.api import Limits, build_repo_map, render_markdown
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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    try:
        repo_map = build_repo_map(
            args.path, name=args.name, limits=Limits(max_file_bytes=args.max_file_bytes)
        )
    except (TrigpointError, OSError) as exc:
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
