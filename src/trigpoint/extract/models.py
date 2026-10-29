"""SQLAlchemy and Pydantic model extraction (AST only).

Limitation: a class is recognised as a Pydantic/SQLAlchemy model from its bases within the
same file (plus well-known base names such as ``Base``/``DeclarativeBase``/``Model``).
Subclasses of models defined in *other* files are not followed in this version.
"""

from __future__ import annotations

import ast
import re

from trigpoint.domain import FieldDef, FileRecord, ModelDef
from trigpoint.extract.base import clip

_GATE = re.compile(r"sqlalchemy|pydantic|BaseModel|BaseSettings|DeclarativeBase|\bBase\b")
_PYDANTIC_BASES = frozenset({"BaseModel", "BaseSettings", "RootModel"})
_SA_BASES = frozenset({"DeclarativeBase", "DeclarativeBaseNoMeta", "Base", "Model"})
_SA_FIELD_CALLS = frozenset({"Column", "mapped_column"})
_MAX_FIELDS = 30


def _base_names(cls: ast.ClassDef) -> list[str]:
    names: list[str] = []
    for b in cls.bases:
        if isinstance(b, ast.Name):
            names.append(b.id)
        elif isinstance(b, ast.Attribute):
            names.append(b.attr)
        elif isinstance(b, ast.Subscript) and isinstance(b.value, (ast.Name, ast.Attribute)):
            names.append(b.value.id if isinstance(b.value, ast.Name) else b.value.attr)
    return names


def _call_func_name(call: ast.Call) -> str:
    f = call.func
    return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""


def _sa_fields(cls: ast.ClassDef) -> tuple[str, list[FieldDef]]:
    table = ""
    fields: list[FieldDef] = []
    for stmt in cls.body:
        target: ast.expr | None = None
        value: ast.expr | None = None
        annotation: ast.expr | None = None
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            target, value = stmt.targets[0], stmt.value
        elif isinstance(stmt, ast.AnnAssign):
            target, value, annotation = stmt.target, stmt.value, stmt.annotation
        if not isinstance(target, ast.Name):
            continue
        if target.id == "__tablename__" and isinstance(value, ast.Constant):
            table = str(value.value)
            continue
        if not isinstance(value, ast.Call):
            continue
        fname = _call_func_name(value)
        if fname in _SA_FIELD_CALLS:
            if annotation is not None:
                ftype = ast.unparse(annotation)
            else:
                first = next((a for a in value.args if not isinstance(a, ast.Constant)), None)
                ftype = ast.unparse(first) if first is not None else "Any"
            fields.append(FieldDef(target.id, clip(ftype, 60)))
        elif fname == "relationship":
            arg = value.args[0] if value.args else None
            tgt = ast.unparse(arg).strip("'\"") if arg is not None else "?"
            fields.append(FieldDef(target.id, clip(f"relationship({tgt})", 60)))
        if len(fields) >= _MAX_FIELDS:
            break
    return table, fields


def _pydantic_fields(cls: ast.ClassDef) -> list[FieldDef]:
    fields: list[FieldDef] = []
    for stmt in cls.body:
        if (
            isinstance(stmt, ast.AnnAssign)
            and isinstance(stmt.target, ast.Name)
            and not stmt.target.id.startswith("_")
            and stmt.target.id != "model_config"
        ):
            ftype = ast.unparse(stmt.annotation)
            if ftype.startswith("ClassVar"):
                continue
            fields.append(FieldDef(stmt.target.id, clip(ftype, 60)))
            if len(fields) >= _MAX_FIELDS:
                break
    return fields


def _is_abstract(cls: ast.ClassDef) -> bool:
    return any(
        isinstance(s, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "__abstract__" for t in s.targets)
        for s in cls.body
    )


def _has_sa_columns(cls: ast.ClassDef) -> bool:
    for stmt in cls.body:
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            value = stmt.value
            if isinstance(value, ast.Call) and _call_func_name(value) in (
                _SA_FIELD_CALLS | {"relationship"}
            ):
                return True
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            if any(isinstance(t, ast.Name) and t.id == "__tablename__" for t in targets):
                return True
    return False


def extract_models(rec: FileRecord, text: str) -> list[ModelDef]:
    if not _GATE.search(text):
        return []
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    classes = [n for n in tree.body if isinstance(n, ast.ClassDef)]

    pydantic: set[str] = set()
    sqla: set[str] = set()
    changed = True
    while changed:  # resolve in-file inheritance to a fixpoint
        changed = False
        for cls in classes:
            bases = _base_names(cls)
            if cls.name not in pydantic and any(
                b in _PYDANTIC_BASES or b in pydantic for b in bases
            ):
                pydantic.add(cls.name)
                changed = True
            if (
                cls.name not in sqla
                and not _is_abstract(cls)
                and _has_sa_columns(cls)
                and any(b in _SA_BASES or b.endswith("Base") or b in sqla for b in bases)
            ):
                sqla.add(cls.name)
                changed = True

    out: list[ModelDef] = []
    for cls in classes:
        if cls.name in sqla:
            table, fields = _sa_fields(cls)
            out.append(ModelDef(cls.name, "sqlalchemy", rec.path, cls.lineno, table, tuple(fields)))
        elif cls.name in pydantic:
            out.append(
                ModelDef(
                    cls.name, "pydantic", rec.path, cls.lineno, "", tuple(_pydantic_fields(cls))
                )
            )
    return out
