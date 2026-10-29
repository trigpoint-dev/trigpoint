"""Symbol extraction with two engines.

* ``ast`` engine (Python): precise. Top-level functions/classes plus one level of class
  methods. It never descends into nested functions or classes.
* regex engine (JS/TS/Go/Rust/Java/Kotlin/C#/Ruby, and Python files that fail to parse):
  column-0 declarations only, which approximates "top level" without a real parser. A
  tree-sitter engine is a planned drop-in for this slot.

Caps: 200 symbols per file, 200-char signatures, 120-char docs.
"""

from __future__ import annotations

import ast
import re

from trigpoint.domain import FileRecord, Symbol
from trigpoint.extract.base import (
    MAX_SIGNATURE_CHARS,
    MAX_SYMBOLS_PER_FILE,
    clip,
    first_line,
)

_FuncNode = ast.FunctionDef | ast.AsyncFunctionDef


def _dunder_all(tree: ast.Module) -> set[str] | None:
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets
        ):
            try:
                value = ast.literal_eval(node.value)
            except (ValueError, SyntaxError):
                return None
            if isinstance(value, (list, tuple)):
                return {v for v in value if isinstance(v, str)}
    return None


def _func_signature(node: _FuncNode) -> str:
    prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
    sig = f"{prefix} {node.name}({ast.unparse(node.args)})"
    if node.returns is not None:
        sig += f" -> {ast.unparse(node.returns)}"
    return clip(sig, MAX_SIGNATURE_CHARS)


def _class_signature(node: ast.ClassDef) -> str:
    bases = [ast.unparse(b) for b in node.bases]
    return clip(f"class {node.name}({', '.join(bases)})" if bases else f"class {node.name}", 200)


def _python_symbols(rec: FileRecord, text: str) -> list[Symbol]:
    tree = ast.parse(text)
    declared = _dunder_all(tree)
    out: list[Symbol] = []

    def exported(name: str) -> bool:
        if declared is not None:
            return name in declared
        return not name.startswith("_")

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.append(
                Symbol(
                    name=node.name,
                    kind="function",
                    path=rec.path,
                    line=node.lineno,
                    end_line=node.end_lineno or node.lineno,
                    signature=_func_signature(node),
                    doc=first_line(ast.get_docstring(node)),
                    exported=exported(node.name),
                )
            )
        elif isinstance(node, ast.ClassDef):
            out.append(
                Symbol(
                    name=node.name,
                    kind="class",
                    path=rec.path,
                    line=node.lineno,
                    end_line=node.end_lineno or node.lineno,
                    signature=_class_signature(node),
                    doc=first_line(ast.get_docstring(node)),
                    exported=exported(node.name),
                )
            )
            for sub in node.body:
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    out.append(
                        Symbol(
                            name=sub.name,
                            kind="method",
                            path=rec.path,
                            line=sub.lineno,
                            end_line=sub.end_lineno or sub.lineno,
                            signature=_func_signature(sub),
                            doc=first_line(ast.get_docstring(sub)),
                            parent=node.name,
                            exported=not sub.name.startswith("_"),
                        )
                    )
        if len(out) >= MAX_SYMBOLS_PER_FILE:
            break
    return out[:MAX_SYMBOLS_PER_FILE]


# (kind, compiled pattern with named group "name"; optional group "export")
_JS = [
    (
        "function",
        re.compile(
            r"^(?P<export>export\s+)?(?:default\s+)?(?:async\s+)?function\*?\s+(?P<name>\w+)\s*\("
        ),
    ),
    (
        "class",
        re.compile(r"^(?P<export>export\s+)?(?:default\s+)?(?:abstract\s+)?class\s+(?P<name>\w+)"),
    ),
    ("interface", re.compile(r"^(?P<export>export\s+)?interface\s+(?P<name>\w+)")),
    ("type", re.compile(r"^(?P<export>export\s+)?type\s+(?P<name>\w+)\s*(?:<[^>]*>)?\s*=")),
    (
        "function",
        re.compile(
            r"^(?P<export>export\s+)?(?:const|let|var)\s+(?P<name>\w+)\s*(?::[^=]+)?=\s*"
            r"(?:async\s*)?(?:\([^)]*\)|\w+)\s*(?::[^=]+)?=>"
        ),
    ),
]
_GO = [
    ("function", re.compile(r"^func\s+(?:\([^)]*\)\s*)?(?P<name>\w+)\s*[\[(]")),
    ("struct", re.compile(r"^type\s+(?P<name>\w+)\s+struct\b")),
    ("interface", re.compile(r"^type\s+(?P<name>\w+)\s+interface\b")),
]
_RUST = [
    ("function", re.compile(r"^(?P<export>pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(?P<name>\w+)")),
    ("struct", re.compile(r"^(?P<export>pub(?:\([^)]*\))?\s+)?struct\s+(?P<name>\w+)")),
    ("enum", re.compile(r"^(?P<export>pub(?:\([^)]*\))?\s+)?enum\s+(?P<name>\w+)")),
    ("trait", re.compile(r"^(?P<export>pub(?:\([^)]*\))?\s+)?trait\s+(?P<name>\w+)")),
]
_JVM = [
    (
        "class",
        re.compile(
            r"^(?P<export>public\s+)?(?:(?:abstract|final|sealed|data|open|static)\s+)*"
            r"(?:class|record|object)\s+(?P<name>\w+)"
        ),
    ),
    ("interface", re.compile(r"^(?P<export>public\s+)?interface\s+(?P<name>\w+)")),
    ("enum", re.compile(r"^(?P<export>public\s+)?enum\s+(?:class\s+)?(?P<name>\w+)")),
]
_RUBY = [
    ("function", re.compile(r"^def\s+(?:self\.)?(?P<name>\w+[?!]?)")),
    ("class", re.compile(r"^class\s+(?P<name>\w+)")),
    ("class", re.compile(r"^module\s+(?P<name>\w+)")),
]
_PY_FALLBACK = [
    ("function", re.compile(r"^(?:async\s+)?def\s+(?P<name>\w+)\s*\(")),
    ("class", re.compile(r"^class\s+(?P<name>\w+)")),
]

_REGEX_ENGINES: dict[str, list[tuple[str, re.Pattern[str]]]] = {
    "javascript": _JS,
    "typescript": _JS,
    "go": _GO,
    "rust": _RUST,
    "java": _JVM,
    "kotlin": _JVM,
    "csharp": _JVM,
    "ruby": _RUBY,
    "python": _PY_FALLBACK,
}


def _regex_symbols(rec: FileRecord, text: str) -> list[Symbol]:
    patterns = _REGEX_ENGINES.get(rec.language)
    if not patterns:
        return []
    out: list[Symbol] = []
    for lineno, line in enumerate(text.split("\n"), start=1):
        if not line or line[0] in " \t":
            continue  # column 0 only: top-level declarations
        for kind, pattern in patterns:
            m = pattern.match(line)
            if not m:
                continue
            name = m.group("name")
            groups = m.groupdict()
            if rec.language == "go":
                is_exported = name[:1].isupper()
            elif rec.language == "ruby" or rec.language == "python":
                is_exported = not name.startswith("_")
            elif "export" in groups:
                is_exported = groups["export"] is not None
            else:
                is_exported = True
            out.append(
                Symbol(
                    name=name,
                    kind=kind,
                    path=rec.path,
                    line=lineno,
                    end_line=lineno,
                    signature=clip(line.rstrip("{ \t"), MAX_SIGNATURE_CHARS),
                    exported=is_exported,
                )
            )
            break
        if len(out) >= MAX_SYMBOLS_PER_FILE:
            break
    return out


def extract_symbols(rec: FileRecord, text: str) -> list[Symbol]:
    if rec.language == "python":
        try:
            return _python_symbols(rec, text)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            return _regex_symbols(rec, text)
    return _regex_symbols(rec, text)
