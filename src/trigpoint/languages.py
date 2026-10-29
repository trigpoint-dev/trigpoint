"""Language detection and file-kind heuristics (generated / test)."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

EXT_LANG: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".cs": "csharp",
    ".rb": "ruby",
    ".php": "php",
    ".swift": "swift",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".scala": "scala",
    ".sh": "shell",
    ".bash": "shell",
    ".ps1": "powershell",
    ".sql": "sql",
    ".html": "html",
    ".css": "css",
    ".scss": "css",
    ".vue": "vue",
    ".svelte": "svelte",
    ".dart": "dart",
    ".lua": "lua",
    ".ex": "elixir",
    ".exs": "elixir",
    ".r": "r",
    ".tf": "terraform",
    ".proto": "protobuf",
    ".md": "markdown",
    ".rst": "rst",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".txt": "text",
}

NAME_LANG: dict[str, str] = {
    "Dockerfile": "dockerfile",
    "Makefile": "make",
    "Jenkinsfile": "groovy",
    "CMakeLists.txt": "cmake",
}

# Languages that describe the product's code, as opposed to docs/config/markup.
CODE_LANGS = frozenset(
    {
        "python",
        "javascript",
        "typescript",
        "go",
        "rust",
        "java",
        "kotlin",
        "csharp",
        "ruby",
        "php",
        "swift",
        "c",
        "cpp",
        "scala",
        "shell",
        "powershell",
        "sql",
        "vue",
        "svelte",
        "dart",
        "lua",
        "elixir",
        "r",
        "terraform",
    }
)

_SHEBANG = re.compile(r"^#!.*\b(python|node|bash|sh|ruby|perl|php)\b")
_SHEBANG_LANG = {
    "python": "python",
    "node": "javascript",
    "bash": "shell",
    "sh": "shell",
    "ruby": "ruby",
    "perl": "perl",
    "php": "php",
}


def detect_language(path: str, first_line: str = "") -> str:
    name = PurePosixPath(path).name
    if name in NAME_LANG:
        return NAME_LANG[name]
    if name.startswith("Dockerfile"):
        return "dockerfile"
    ext = PurePosixPath(path).suffix.lower()
    if ext in EXT_LANG:
        return EXT_LANG[ext]
    m = _SHEBANG.match(first_line)
    if m:
        return _SHEBANG_LANG[m.group(1)]
    return "other"


GENERATED_DIRS = frozenset({"node_modules", "vendor", "dist", "build", "__pycache__", ".next"})
_GENERATED_NAME = re.compile(
    r"(?:\.min\.(?:js|css)$|_pb2(?:_grpc)?\.pyi?$|\.pb\.go$|\.generated\.|\.snap$|"
    r"(?:^|/)(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|uv\.lock|"
    r"Cargo\.lock|Gemfile\.lock|composer\.lock|go\.sum)$)"
)
_GENERATED_HEADER = re.compile(
    r"DO NOT EDIT|@generated|Code generated|auto-?generated|automatically generated",
    re.IGNORECASE,
)


def is_generated_path(path: str) -> bool:
    parts = path.split("/")
    return any(p in GENERATED_DIRS for p in parts[:-1]) or bool(_GENERATED_NAME.search(path))


def is_generated_text(head: str) -> bool:
    return bool(_GENERATED_HEADER.search(head))


_TEST_DIRS = frozenset({"test", "tests", "__tests__", "spec", "specs", "e2e", "testing"})
_TEST_NAME = re.compile(
    r"(?:^test_.*\.py$|_test\.(?:py|go)$|^conftest\.py$|\.(?:test|spec)\.[jt]sx?$|"
    r"Tests?\.(?:java|kt|cs)$|_spec\.rb$)"
)


def is_test_path(path: str) -> bool:
    parts = path.split("/")
    return any(p.lower() in _TEST_DIRS for p in parts[:-1]) or bool(_TEST_NAME.search(parts[-1]))
