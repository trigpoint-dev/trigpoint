"""Collapsed directory tree (ASCII, deterministic)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TreeConfig:
    max_depth: int = 4
    max_children: int = 15
    max_lines: int = 500


class _Node:
    __slots__ = ("children", "is_file")

    def __init__(self) -> None:
        self.children: dict[str, _Node] = {}
        self.is_file = False

    def count_files(self) -> int:
        if self.is_file:
            return 1
        return sum(c.count_files() for c in self.children.values())


def build_tree(paths: list[str], config: TreeConfig | None = None) -> str:
    cfg = config or TreeConfig()
    root = _Node()
    for p in paths:
        node = root
        for part in p.split("/"):
            node = node.children.setdefault(part, _Node())
        node.is_file = True

    lines: list[str] = []

    def emit(node: _Node, prefix: str, depth: int) -> None:
        names = sorted(node.children, key=lambda n: (node.children[n].is_file, n))  # dirs first
        shown, hidden = names[: cfg.max_children], names[cfg.max_children :]
        for i, name in enumerate(shown):
            if len(lines) >= cfg.max_lines:
                return
            child = node.children[name]
            last = i == len(shown) - 1 and not hidden
            branch = "`-- " if last else "|-- "
            if child.is_file:
                lines.append(f"{prefix}{branch}{name}")
                continue
            if depth + 1 >= cfg.max_depth:
                lines.append(f"{prefix}{branch}{name}/ ({child.count_files()} files)")
                continue
            lines.append(f"{prefix}{branch}{name}/")
            emit(child, prefix + ("    " if last else "|   "), depth + 1)
        if hidden and len(lines) < cfg.max_lines:
            files = sum(node.children[n].count_files() for n in hidden)
            lines.append(f"{prefix}`-- ... (+{len(hidden)} more, {files} files)")

    emit(root, "", 0)
    if len(lines) >= cfg.max_lines:
        lines.append("... (tree truncated)")
    return "\n".join(lines)
