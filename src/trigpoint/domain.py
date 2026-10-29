"""Core data model. Plain frozen dataclasses so everything is hashable and JSON-friendly."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass
from typing import Any, TypeVar

from trigpoint.errors import SchemaError

_T = TypeVar("_T")

SCHEMA_VERSION = 2


@dataclass(frozen=True, slots=True)
class FileRecord:
    path: str
    language: str
    size: int
    loc: int
    blob_sha: str
    is_binary: bool
    is_generated: bool
    is_test: bool


@dataclass(frozen=True, slots=True)
class Symbol:
    name: str
    kind: str  # function | method | class | interface | type | struct | enum | trait
    path: str
    line: int
    end_line: int
    signature: str = ""
    doc: str = ""
    parent: str = ""
    exported: bool = True

    @property
    def qualname(self) -> str:
        return f"{self.parent}.{self.name}" if self.parent else self.name


@dataclass(frozen=True, slots=True)
class Route:
    method: str
    path: str  # fully resolved where include_router prefixes could be followed
    handler: str
    file: str
    line: int
    router: str = ""
    local_path: str = ""  # router prefix + decorator path, before include_router prefixes


@dataclass(frozen=True, slots=True)
class RouterInclude:
    file: str
    parent_var: str
    child_var: str
    child_hint: str  # module the router was reached through (`users` in users.router)
    prefix: str


@dataclass(frozen=True, slots=True)
class FieldDef:
    name: str
    type: str


@dataclass(frozen=True, slots=True)
class ModelDef:
    name: str
    kind: str  # sqlalchemy | pydantic
    file: str
    line: int
    table: str = ""
    fields: tuple[FieldDef, ...] = ()


@dataclass(frozen=True, slots=True)
class StackInfo:
    languages: tuple[tuple[str, int], ...] = ()  # (language, loc), descending
    frameworks: tuple[str, ...] = ()
    datastores: tuple[str, ...] = ()
    infra: tuple[str, ...] = ()
    package_managers: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    manifests: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DocInfo:
    path: str = ""
    title: str = ""
    summary: str = ""
    generated: bool = False  # True when an LLM wrote the summary (the README gave nothing)


@dataclass(frozen=True, slots=True)
class Classification:
    type: str  # monorepo | webapp | service/api | library | unknown
    confidence: float
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SymbolRef:
    name: str
    kind: str
    path: str
    line: int


@dataclass(frozen=True, slots=True)
class Module:
    name: str
    path: str
    loc: int
    languages: tuple[tuple[str, int], ...]
    description: str
    top_symbols: tuple[SymbolRef, ...]
    route_indices: tuple[int, ...]
    models: tuple[str, ...]
    description_generated: bool = False  # True when an LLM wrote the description


@dataclass(frozen=True, slots=True)
class RepoMap:
    schema_version: int
    name: str
    commit_sha: str
    classification: Classification
    stack: StackInfo
    doc: DocInfo
    files: tuple[FileRecord, ...]
    symbols: tuple[Symbol, ...]
    routes: tuple[Route, ...]
    models: tuple[ModelDef, ...]
    modules: tuple[Module, ...]
    importance: tuple[tuple[str, float], ...]
    tree: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int | None = None) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


def _many(items: Iterable[Any], build: Callable[[Any], _T]) -> tuple[_T, ...]:
    return tuple(build(i) for i in items)


def _pairs(items: Iterable[Any]) -> tuple[tuple[Any, Any], ...]:
    return tuple((a, b) for a, b in items)


def repo_map_from_dict(data: dict[str, Any]) -> RepoMap:
    """Rebuild a RepoMap from ``RepoMap.to_dict()`` output (e.g. after a JSON round trip).

    Raises SchemaError for an unsupported ``schema_version`` or a malformed document, so a
    cache can treat either as a miss and recompute.
    """
    try:
        if data["schema_version"] != SCHEMA_VERSION:
            raise SchemaError(
                f"unsupported schema_version {data['schema_version']!r} (want {SCHEMA_VERSION})"
            )
        cls = data["classification"]
        stack = data["stack"]
        return RepoMap(
            schema_version=data["schema_version"],
            name=data["name"],
            commit_sha=data["commit_sha"],
            classification=Classification(
                cls["type"], float(cls["confidence"]), tuple(cls["evidence"])
            ),
            stack=StackInfo(
                languages=_pairs(stack["languages"]),
                frameworks=tuple(stack["frameworks"]),
                datastores=tuple(stack["datastores"]),
                infra=tuple(stack["infra"]),
                package_managers=tuple(stack["package_managers"]),
                dependencies=tuple(stack["dependencies"]),
                manifests=tuple(stack["manifests"]),
            ),
            doc=DocInfo(**data["doc"]),
            files=_many(data["files"], lambda d: FileRecord(**d)),
            symbols=_many(data["symbols"], lambda d: Symbol(**d)),
            routes=_many(data["routes"], lambda d: Route(**d)),
            models=_many(
                data["models"],
                lambda d: ModelDef(**{**d, "fields": _many(d["fields"], lambda f: FieldDef(**f))}),
            ),
            modules=_many(
                data["modules"],
                lambda d: Module(
                    **{
                        **d,
                        "languages": _pairs(d["languages"]),
                        "top_symbols": _many(d["top_symbols"], lambda s: SymbolRef(**s)),
                        "route_indices": tuple(d["route_indices"]),
                        "models": tuple(d["models"]),
                    }
                ),
            ),
            importance=_pairs(data["importance"]),
            tree=data["tree"],
        )
    except SchemaError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise SchemaError(f"malformed RepoMap document: {exc}") from exc
