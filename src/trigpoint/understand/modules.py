"""Group files into modules and summarise each one."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping

from trigpoint.domain import FileRecord, ModelDef, Module, Route, Symbol, SymbolRef
from trigpoint.languages import CODE_LANGS
from trigpoint.understand.classify import CONVENTIONAL_ROOTS

ROOT_MODULE = "(root)"
_KIND_ORDER = {
    "class": 0,
    "struct": 0,
    "interface": 1,
    "trait": 1,
    "enum": 1,
    "type": 2,
    "function": 3,
}
MAX_TOP_SYMBOLS = 10


def module_of(path: str) -> str:
    """First dir under a conventional root, else the top-level dir, else the root module."""
    parts = path.split("/")
    if len(parts) == 1:
        return ROOT_MODULE
    if parts[0] in CONVENTIONAL_ROOTS and len(parts) > 2:
        return f"{parts[0]}/{parts[1]}"
    return parts[0]


def build_modules(
    files: tuple[FileRecord, ...],
    symbols: tuple[Symbol, ...],
    routes: tuple[Route, ...],
    models: tuple[ModelDef, ...],
    importance: Mapping[str, float],
    descriptions: Mapping[str, str],
) -> tuple[Module, ...]:
    loc: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for f in files:
        if f.is_binary or f.is_generated:
            continue
        mod = module_of(f.path)
        loc[mod]  # ensure the module exists even if it only holds docs/config
        if f.language in CODE_LANGS:
            loc[mod][f.language] += f.loc

    test_paths = {f.path for f in files if f.is_test}
    sym_by_mod: dict[str, list[Symbol]] = defaultdict(list)
    for s in symbols:
        if s.exported and s.kind != "method" and s.path not in test_paths:
            sym_by_mod[module_of(s.path)].append(s)
    route_idx: dict[str, list[int]] = defaultdict(list)
    for i, r in enumerate(routes):
        route_idx[module_of(r.file)].append(i)
    model_names: dict[str, list[str]] = defaultdict(list)
    for m in models:
        model_names[module_of(m.file)].append(m.name)

    out: list[Module] = []
    for name in sorted(loc):
        langs = tuple(sorted(loc[name].items(), key=lambda kv: (-kv[1], kv[0])))
        ranked = sorted(
            sym_by_mod.get(name, []),
            key=lambda s: (
                -importance.get(s.path, 0.0),
                _KIND_ORDER.get(s.kind, 9),
                s.path,
                s.line,
            ),
        )[:MAX_TOP_SYMBOLS]
        out.append(
            Module(
                name=name,
                path=name if name != ROOT_MODULE else "",
                loc=sum(v for _, v in langs),
                languages=langs,
                description=descriptions.get(name, ""),
                top_symbols=tuple(SymbolRef(s.name, s.kind, s.path, s.line) for s in ranked),
                route_indices=tuple(route_idx.get(name, ())),
                models=tuple(sorted(model_names.get(name, ()))),
            )
        )
    out.sort(key=lambda m: (-m.loc, m.name))
    return tuple(out)
