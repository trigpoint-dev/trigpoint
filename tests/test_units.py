from __future__ import annotations

from trigpoint.domain import FileRecord
from trigpoint.extract.docs import summarize_markdown
from trigpoint.extract.symbols import extract_symbols
from trigpoint.understand.importgraph import pagerank
from trigpoint.understand.modules import ROOT_MODULE, module_of
from trigpoint.understand.tree import TreeConfig, build_tree


def rec(path: str, language: str) -> FileRecord:
    return FileRecord(path, language, 0, 0, "", False, False, False)


def test_pagerank_is_normalised_and_deterministic() -> None:
    nodes = ["a", "b", "c", "d"]
    edges = {"a": {"c"}, "b": {"c"}, "c": {"d"}}
    r1, r2 = pagerank(nodes, edges), pagerank(list(reversed(nodes)), edges)
    assert r1 == r2
    assert abs(sum(r1.values()) - 1.0) < 1e-6
    assert r1["d"] > r1["c"] > r1["a"]


def test_pagerank_handles_cycles_and_empty() -> None:
    assert pagerank([], {}) == {}
    r = pagerank(["a", "b"], {"a": {"b"}, "b": {"a"}})
    assert abs(r["a"] - r["b"]) < 1e-9


def test_module_grouping() -> None:
    assert module_of("README.md") == ROOT_MODULE
    assert module_of("src/api/users.py") == "src/api"
    assert module_of("packages/web/src/x.ts") == "packages/web"
    assert module_of("src/main.py") == "src"
    assert module_of("scripts/run.sh") == "scripts"


def test_markdown_summary_skips_badges_and_code() -> None:
    doc = summarize_markdown(
        "# Title\n\n[![b](x)](y)\n\n```\ncode\n```\n\nThis library does a useful thing well.\n"
    )
    assert doc.title == "Title"
    assert doc.summary == "This library does a useful thing well."


def test_markdown_with_nothing_usable() -> None:
    assert summarize_markdown("# T\n\n- a\n- b\n").summary == ""
    assert summarize_markdown("").summary == ""


def test_tree_limits() -> None:
    paths = [f"d{i}/f.txt" for i in range(30)] + ["a/b/c/d/e/f.txt"]
    tree = build_tree(paths, TreeConfig(max_depth=3, max_children=5, max_lines=100))
    assert "more" in tree
    capped = build_tree(
        [f"f{i}.txt" for i in range(100)], TreeConfig(max_lines=10, max_children=99)
    )
    assert capped.endswith("... (tree truncated)")


def test_python_syntax_error_falls_back_to_regex() -> None:
    # ast.parse fails on the whole file, so the lenient regex engine still finds both defs.
    syms = extract_symbols(rec("x.py", "python"), "def good(a):\n    pass\ndef broken(:\n")
    assert [s.name for s in syms] == ["good", "broken"]


def test_symbol_caps() -> None:
    text = "\n".join(f"def f{i}(): pass" for i in range(500))
    assert len(extract_symbols(rec("x.py", "python"), text)) == 200
    long_args = ", ".join(f"arg{i}: int" for i in range(100))
    sig = extract_symbols(rec("y.py", "python"), f"def f({long_args}): pass")[0].signature
    assert len(sig) <= 200 and sig.endswith("...")


def test_go_and_rust_engines() -> None:
    go = extract_symbols(
        rec("m.go", "go"),
        "package m\nfunc Serve() {}\nfunc (s *S) helper() {}\ntype Server struct {}\n",
    )
    assert {(s.name, s.exported) for s in go} == {
        ("Serve", True),
        ("helper", False),
        ("Server", True),
    }
    rs = extract_symbols(rec("m.rs", "rust"), "pub fn run() {}\nfn hidden() {}\npub struct App;\n")
    assert {(s.name, s.exported) for s in rs} == {("run", True), ("hidden", False), ("App", True)}
