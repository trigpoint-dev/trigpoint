"""Assemble a RepoMap: walk -> extract -> understand -> redact."""

from __future__ import annotations

from pathlib import Path, PurePosixPath

from trigpoint.domain import (
    SCHEMA_VERSION,
    DocInfo,
    FileRecord,
    ModelDef,
    RepoMap,
    Route,
    RouterInclude,
    Symbol,
)
from trigpoint.errors import SecurityError
from trigpoint.extract.docs import find_root_readme, is_readme, summarize_markdown
from trigpoint.extract.manifests import (
    MANIFEST_NAMES,
    ManifestInfo,
    build_stack,
    parse_manifest,
)
from trigpoint.extract.models import extract_models
from trigpoint.extract.routes import extract_routes, resolve_router_prefixes
from trigpoint.extract.symbols import extract_symbols
from trigpoint.security import Limits, PathPolicy, Redactor, read_text_safely, redact_dataclass
from trigpoint.understand.classify import classify
from trigpoint.understand.importgraph import (
    build_edges,
    js_imports,
    pagerank,
    python_imports,
)
from trigpoint.understand.modules import build_modules, module_of
from trigpoint.understand.tree import TreeConfig, build_tree
from trigpoint.walk import _git, walk

_SYMBOL_LANGS = frozenset(
    {"python", "javascript", "typescript", "go", "rust", "java", "kotlin", "csharp", "ruby"}
)
_DOC_LANGS = frozenset({"markdown", "rst", "text", "other"})
MAX_IMPORTANCE_ENTRIES = 2000

# Identifier-like fields are never redacted, so redaction cannot corrupt paths or names.
_REDACT_SKIP = frozenset(
    {
        "path",
        "file",
        "blob_sha",
        "commit_sha",
        "name",
        "kind",
        "method",
        "handler",
        "router",
        "local_path",
        "table",
        "parent",
        "type",
        "language",
        "languages",
        "importance",
        "tree",
        "dependencies",
        "manifests",
        "frameworks",
        "datastores",
        "infra",
        "package_managers",
        "models",
    }
)


def _head_sha(root: Path, limits: Limits) -> str:
    out = _git(root, ["rev-parse", "HEAD"], limits.git_timeout_s)
    return out.decode("ascii", "replace").strip() if out else ""


def build_repo_map(
    root: str | Path,
    *,
    name: str | None = None,
    commit_sha: str | None = None,
    policy: PathPolicy | None = None,
    limits: Limits | None = None,
    redactor: Redactor | None = None,
    tree: TreeConfig | None = None,
) -> RepoMap:
    """Build a RepoMap for a directory. Nothing in the repo is executed or imported."""
    root_path = Path(root).resolve(strict=True)
    limits = limits or Limits()
    policy = policy or PathPolicy.from_repo(root_path)
    redactor = redactor or Redactor()

    result = walk(root_path, policy=policy, limits=limits)
    files = result.files

    symbols: list[Symbol] = []
    routes: list[Route] = []
    includes: list[RouterInclude] = []
    models: list[ModelDef] = []
    manifests: list[ManifestInfo] = []
    readme_docs: dict[str, DocInfo] = {}
    py_raw: dict[str, list[tuple[int, str]]] = {}
    js_raw: dict[str, list[str]] = {}

    for rec in files:
        if rec.is_binary or rec.is_generated or rec.size > limits.max_file_bytes:
            continue
        base = PurePosixPath(rec.path).name
        is_manifest = base in MANIFEST_NAMES
        is_doc = rec.language in _DOC_LANGS and is_readme(rec.path)
        is_code = rec.language in _SYMBOL_LANGS and not rec.is_test
        if not (is_manifest or is_doc or is_code):
            continue
        try:
            text = read_text_safely(root_path, rec.path, policy=policy, limits=limits)
        except (SecurityError, OSError):
            continue

        if is_manifest:
            info = parse_manifest(rec.path, text)
            if info is not None:
                manifests.append(info)
        if is_doc:
            readme_docs[rec.path] = summarize_markdown(text)
        if not is_code:
            continue
        symbols.extend(extract_symbols(rec, text))
        if rec.language == "python":
            file_routes, file_includes = extract_routes(rec, text)
            routes.extend(file_routes)
            includes.extend(file_includes)
            models.extend(extract_models(rec, text))
            py_raw[rec.path] = python_imports(text)
        elif rec.language in ("javascript", "typescript"):
            js_raw[rec.path] = js_imports(text)

    routes = sorted(
        resolve_router_prefixes(routes, includes), key=lambda r: (r.path, r.method, r.file, r.line)
    )
    routes_t = tuple(routes)
    stack = build_stack(files, manifests)

    graph_nodes = [
        f.path
        for f in files
        if f.language in _SYMBOL_LANGS and not (f.is_test or f.is_generated or f.is_binary)
    ]
    edges = build_edges(files, py_raw, js_raw)
    scores = pagerank(graph_nodes, edges)
    importance = tuple(sorted(scores.items(), key=lambda kv: (-kv[1], kv[0])))[
        :MAX_IMPORTANCE_ENTRIES
    ]

    root_readme = find_root_readme(files)
    doc = readme_docs.get(root_readme, DocInfo()) if root_readme else DocInfo()
    if root_readme:
        doc = DocInfo(root_readme, doc.title, doc.summary)

    # A README describes a module only when it sits directly in that module's folder.
    descriptions: dict[str, str] = {}
    for path, readme in sorted(readme_docs.items()):
        parent = str(PurePosixPath(path).parent)
        if parent != "." and readme.summary and module_of(path) == parent:
            descriptions.setdefault(parent, readme.summary)

    modules = build_modules(
        files, tuple(symbols), routes_t, tuple(models), dict(scores), descriptions
    )
    classification = classify(files, stack, routes_t, manifests)
    paths_for_tree = [f.path for f in files if not f.is_generated]

    repo_map = RepoMap(
        schema_version=SCHEMA_VERSION,
        name=name or root_path.name,
        commit_sha=commit_sha if commit_sha is not None else _head_sha(root_path, limits),
        classification=classification,
        stack=stack,
        doc=doc,
        files=files,
        symbols=tuple(symbols),
        routes=routes_t,
        models=tuple(models),
        modules=modules,
        importance=importance,
        tree=build_tree(paths_for_tree, tree),
    )
    return redact_dataclass(repo_map, redactor, skip=_REDACT_SKIP)


def count_files(files: tuple[FileRecord, ...]) -> tuple[int, int, int]:
    """Return (total, test, generated) file counts."""
    return (
        len(files),
        sum(1 for f in files if f.is_test),
        sum(1 for f in files if f.is_generated),
    )
