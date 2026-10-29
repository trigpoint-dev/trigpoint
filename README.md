# trigpoint

Safe, budgeted repo grounding for LLMs and agents.

> **Status: pre-alpha.** The security core and the local pipeline exist; GitHub App auth,
> hardened sync and caching are next. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for
> the design and roadmap.

trigpoint turns a Git repository into a structured, token-budgeted `RepoMap` that an LLM
or agent can be grounded on. It is built for backends and agents, so the hard parts are
handled for you:

- **GitHub App auth** where the token never lands in a clone URL, `.git/config` or `argv`.
- **Hardened shared clones** with cheap no-op refreshes.
- **Layered secrets protection** on everything that is read, persisted or sent to a model.
- **Prompt-injection-aware output**: repo text is fenced as untrusted content.
- **Deterministic, cache-friendly rendering** within a token budget.

## What exists today

```
trigpoint map .                      # Markdown RepoMap for a local directory, 4000-token budget
trigpoint map . --budget 1500        # tighter budget: sections degrade, the overview survives
trigpoint map . --format json        # the full structured RepoMap
```

```python
from trigpoint.api import build_repo_map, render_markdown

repo_map = build_repo_map("path/to/repo")
print(render_markdown(repo_map, budget_tokens=4000).markdown)
```

- **Parsing** (static, nothing is executed): file inventory with blob SHAs; symbols (Python
  `ast` plus a regex engine for JS/TS/Go/Rust/JVM/Ruby); FastAPI routes with
  `include_router` prefixes; SQLAlchemy and Pydantic models; stack detection from manifests;
  README prose.
- **Understanding**: repo type, modules, an import graph with PageRank importance, a
  collapsed directory tree.
- **Rendering**: seven sections packed greedily into a token budget, deterministic output.
- **`trigpoint.security`**: secret-path policy, secret scanner and redactor, `SecretStr`,
  untrusted-content fencing with injection heuristics, and path containment helpers.

Known limits in this version: models that inherit from models defined in other files are
not followed, and routers reached through import aliases keep their file-local path.

## Development

```
python -m venv .venv
.venv\Scripts\activate          # Windows;  source .venv/bin/activate elsewhere
pip install -e ".[dev]"
ruff check . && ruff format --check . && mypy && pytest
```

## License

MIT. See [LICENSE](LICENSE). Security reports: see [SECURITY.md](SECURITY.md).
