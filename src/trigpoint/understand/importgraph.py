"""Internal import graph and PageRank importance.

Only edges between files inside the repo are kept. Python imports come from the AST;
JS/TS relative imports from a regex. Scores are deterministic (sorted iteration).
"""

from __future__ import annotations

import ast
import re
from pathlib import PurePosixPath

from trigpoint.domain import FileRecord

_JS_IMPORT = re.compile(
    r"""(?:import\s[^'"]*?from\s*|import\s*|require\(\s*|export\s[^'"]*?from\s*)['"](\.{1,2}/[^'"]+)['"]"""
)
_JS_EXTS = ("", ".ts", ".tsx", ".js", ".jsx", ".mjs", "/index.ts", "/index.tsx", "/index.js")
DAMPING = 0.85


def python_imports(text: str) -> list[tuple[int, str]]:
    """Return (relative_level, dotted_module) pairs; names imported are appended as submodules."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    out: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out.extend((0, a.name) for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            out.append((node.level, base))
            for a in node.names:
                if a.name != "*":
                    out.append((node.level, f"{base}.{a.name}" if base else a.name))
    return out


def js_imports(text: str) -> list[str]:
    return [m.group(1) for m in _JS_IMPORT.finditer(text)]


def _python_module_index(paths: list[str]) -> dict[str, str]:
    index: dict[str, str] = {}
    for p in sorted(paths):
        if not p.endswith((".py", ".pyi")):
            continue
        parts = list(PurePosixPath(p).with_suffix("").parts)
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]
        if not parts:
            continue
        # Register the full dotted path and every suffix after a leading src-style dir,
        # so `import pkg.mod` resolves whether the repo root or `src/` is the import root.
        for start in range(min(len(parts), 3)):
            index.setdefault(".".join(parts[start:]), p)
    return index


def _resolve_python(src: str, level: int, module: str, index: dict[str, str]) -> str | None:
    if level:
        pkg = list(PurePosixPath(src).parent.parts)
        if level > 1:
            pkg = pkg[: len(pkg) - (level - 1)]
        dotted = ".".join([*pkg, *([module] if module else [])])
        return index.get(dotted)
    return index.get(module)


def _resolve_js(src: str, spec: str, path_set: set[str]) -> str | None:
    base = PurePosixPath(src).parent
    parts: list[str] = list(base.parts)
    for seg in spec.split("/"):
        if seg == "..":
            if parts:
                parts.pop()
        elif seg not in ("", "."):
            parts.append(seg)
    stem = "/".join(parts)
    for ext in _JS_EXTS:
        if stem + ext in path_set:
            return stem + ext
    return None


def build_edges(
    files: tuple[FileRecord, ...],
    py_raw: dict[str, list[tuple[int, str]]],
    js_raw: dict[str, list[str]],
) -> dict[str, set[str]]:
    paths = [f.path for f in files]
    path_set = set(paths)
    index = _python_module_index(paths)
    edges: dict[str, set[str]] = {}
    for src, imports in py_raw.items():
        for level, module in imports:
            dst = _resolve_python(src, level, module, index)
            if dst and dst != src:
                edges.setdefault(src, set()).add(dst)
    for src, specs in js_raw.items():
        for spec in specs:
            dst = _resolve_js(src, spec, path_set)
            if dst and dst != src:
                edges.setdefault(src, set()).add(dst)
    return edges


def pagerank(
    nodes: list[str],
    edges: dict[str, set[str]],
    *,
    iterations: int = 50,
    tolerance: float = 1e-9,
) -> dict[str, float]:
    """Power-iteration PageRank over ``nodes``; scores sum to 1. Importers point at importees."""
    n = len(nodes)
    if n == 0:
        return {}
    order = sorted(nodes)
    out_links = {u: sorted(v for v in edges.get(u, ()) if v in set(order)) for u in order}
    rank = dict.fromkeys(order, 1.0 / n)
    for _ in range(iterations):
        dangling = sum(rank[u] for u in order if not out_links[u])
        base = (1.0 - DAMPING) / n + DAMPING * dangling / n
        nxt = dict.fromkeys(order, base)
        for u in order:
            targets = out_links[u]
            if targets:
                share = DAMPING * rank[u] / len(targets)
                for v in targets:
                    nxt[v] += share
        delta = sum(abs(nxt[u] - rank[u]) for u in order)
        rank = nxt
        if delta < tolerance:
            break
    return rank
