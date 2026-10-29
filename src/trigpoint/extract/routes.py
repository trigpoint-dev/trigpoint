"""FastAPI route extraction (AST only; nothing is imported or executed).

Per file we find routers (`X = APIRouter(prefix=...)` / `FastAPI(...)`), decorated handlers
and `include_router` calls. A repo-level pass then applies `include_router` prefixes by
following `module.router` references. Routers reached through aliases are left with their
file-local path (a documented limitation).
"""

from __future__ import annotations

import ast
import re
from pathlib import PurePosixPath

from trigpoint.domain import FileRecord, Route, RouterInclude

_GATE = re.compile(r"fastapi|APIRouter")
_METHODS = frozenset({"get", "post", "put", "delete", "patch", "options", "head", "trace"})
_MAX_PREFIX_DEPTH = 4


def _join(*parts: str) -> str:
    joined = "/".join(p.strip("/") for p in parts if p and p.strip("/"))
    return "/" + joined if joined else "/"


def _const_str(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _kw(call: ast.Call, name: str) -> ast.expr | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _call_name(call: ast.Call) -> str:
    f = call.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return ""


def extract_routes(rec: FileRecord, text: str) -> tuple[list[Route], list[RouterInclude]]:
    if not _GATE.search(text):
        return [], []
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return [], []

    prefixes: dict[str, str] = {}
    for node in ast.walk(tree):
        target: ast.expr | None = None
        value: ast.expr | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
        elif isinstance(node, ast.AnnAssign):
            target, value = node.target, node.value
        if (
            isinstance(target, ast.Name)
            and isinstance(value, ast.Call)
            and _call_name(value) in ("APIRouter", "FastAPI")
        ):
            prefixes[target.id] = _const_str(_kw(value, "prefix")) or ""

    routes: list[Route] = []
    includes: list[RouterInclude] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                if not (
                    isinstance(dec, ast.Call)
                    and isinstance(dec.func, ast.Attribute)
                    and isinstance(dec.func.value, ast.Name)
                ):
                    continue
                attr = dec.func.attr
                router = dec.func.value.id
                if attr not in _METHODS and attr not in ("api_route", "websocket"):
                    continue
                if router not in prefixes:
                    continue  # not a router we can attribute to FastAPI in this file
                raw = _const_str(dec.args[0]) if dec.args else _const_str(_kw(dec, "path"))
                local = _join(prefixes[router], raw if raw is not None else "<dynamic>")
                if attr == "api_route":
                    methods_node = _kw(dec, "methods")
                    methods = (
                        [
                            e.value.upper()
                            for e in methods_node.elts
                            if isinstance(e, ast.Constant) and isinstance(e.value, str)
                        ]
                        if isinstance(methods_node, (ast.List, ast.Tuple, ast.Set))
                        else ["GET"]
                    )
                elif attr == "websocket":
                    methods = ["WEBSOCKET"]
                else:
                    methods = [attr.upper()]
                for method in methods:
                    routes.append(
                        Route(
                            method=method,
                            path=local,
                            handler=node.name,
                            file=rec.path,
                            line=node.lineno,
                            router=router,
                            local_path=local,
                        )
                    )
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "include_router"
            and node.args
        ):
            child = node.args[0]
            hint = ""
            if isinstance(child, ast.Attribute):
                child_var = child.attr
                if isinstance(child.value, ast.Name):
                    hint = child.value.id
                elif isinstance(child.value, ast.Attribute):
                    hint = child.value.attr
            elif isinstance(child, ast.Name):
                child_var = child.id
            else:
                continue
            includes.append(
                RouterInclude(
                    file=rec.path,
                    parent_var=ast.unparse(node.func.value),
                    child_var=child_var,
                    child_hint=hint,
                    prefix=_const_str(_kw(node, "prefix")) or "",
                )
            )
    return routes, includes


def _stem(path: str) -> str:
    p = PurePosixPath(path)
    return p.parent.name if p.stem == "__init__" else p.stem


def resolve_router_prefixes(routes: list[Route], includes: list[RouterInclude]) -> list[Route]:
    """Apply include_router prefixes to routes, following parent routers a few levels."""
    ordered = sorted(includes, key=lambda i: (i.file, i.parent_var, i.child_var, i.prefix))

    def chain(var: str, file: str, depth: int) -> str:
        if depth >= _MAX_PREFIX_DEPTH:
            return ""
        for inc in ordered:
            if inc.child_var == var and inc.child_hint and inc.child_hint == _stem(file):
                return _join(chain(inc.parent_var, inc.file, depth + 1), inc.prefix)
            if inc.child_var == var and not inc.child_hint and inc.file == file:
                return _join(chain(inc.parent_var, inc.file, depth + 1), inc.prefix)
        return ""

    resolved: list[Route] = []
    for r in routes:
        prefix = chain(r.router, r.file, 0)
        path = _join(prefix, r.local_path) if prefix.strip("/") else r.local_path
        resolved.append(Route(r.method, path, r.handler, r.file, r.line, r.router, r.local_path))
    return resolved
