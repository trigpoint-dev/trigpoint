# trigpoint

Safe, budgeted repo grounding for LLMs and agents.

> **Status: pre-alpha.** The security core, the local pipeline, the cache layers, the
> hardened git sync, GitHub App auth with discovery, and the optional LLM describe pass
> exist; an MCP server is next. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the
> design and roadmap.

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
- **Caching** (`trigpoint.cache`): three chained layers behind a `CacheStore` port. The
  repo-map is keyed by `(repo_key, git SHA, extractor + schema version)`, the LLM describe
  step by `(repo_key, sha256(rendered section))`, and `connection.md` by project. The local
  store writes atomically (temp file + rename, no hard links or lock files), shards its
  directories and isolates tenants, so it is safe on EFS or Amazon S3 Files mounts. Stale or
  corrupt entries are treated as misses and healed.
- **Hardened sync** (`trigpoint.sync`): shared shallow clones, one per repo and branch, with a
  per-project link to each. A refresh is `ls-remote` first; if the branch tip equals the local
  HEAD nothing is fetched. The access token travels only in git's environment, scoped to the
  git host, and is never in argv, the clone URL or `.git/config`. Branch names are validated
  twice (strict rules, then `git check-ref-format`). Secret paths are excluded before
  checkout, so they are never written to disk. A reader/writer lock keeps a refresh from
  changing files under a running parse. Needs git 2.31 or newer.
- **GitHub App auth** (`trigpoint.auth`, `pip install "trigpoint[github]"`): works with **any**
  GitHub App, since you supply its app id and private key and nothing is tied to an org.
  Signs the RS256 app JWT, exchanges it for installation tokens (least privilege by default:
  `contents:read`, `metadata:read`; optionally narrowed to specific repos), caches them in
  memory and refreshes before expiry with one request per burst. Includes pickers for
  installations, repositories and branches, and configurable endpoints for GitHub Enterprise
  Server. The HTTP client never follows redirects or cross-origin pagination links, handles
  rate limits and retries, and redacts errors.

  ```python
  from trigpoint.auth import GitHubApp
  from trigpoint.sync import Syncer

  app = GitHubApp.from_env()  # TRIGPOINT_GITHUB_APP_ID + _PRIVATE_KEY (or _PRIVATE_KEY_PATH)
  inst = app.discovery.find_installation("some-org")  # or list_installations()
  repos = app.discovery.list_repositories(inst.id)  # repo picker
  branches = app.discovery.list_branches(inst.id, "some-org", repos[0].name)  # branch picker

  syncer = Syncer(
      "/data/shared",
      clone_root="/data/projects",
      base_url=app.endpoints.git_base_url,
      token_provider=app.token_provider(inst.id),
  )
  result = syncer.ensure("some-org", repos[0].name, "main", project_id="proj-1")
  ```
- **Optional LLM descriptions** (`trigpoint.describe`): works with **any LLM**. It fills in a
  repo description only when the README gave nothing usable, and a one-liner for modules that
  have no README of their own; nothing else is ever generated. The model's only input is the
  already-rendered, already-redacted Markdown, fenced as untrusted. Its output is treated as
  untrusted too: cleaned (reasoning blocks, preambles and markdown are stripped, so weaker and
  local models work), rejected if it contains links, markup, secrets or instruction-like text,
  and marked `(generated)` in the render. Results are cached, so a repeat run costs no calls,
  and repeated provider failures stop the pass. It never runs unless you ask for it.

  ```python
  from trigpoint.describe import CallableLLM, describe_repo_map
  from trigpoint.describe.openai_compat import OpenAICompatibleLLM  # trigpoint[openai-compat]

  llm = OpenAICompatibleLLM(model="llama3", base_url="http://localhost:11434/v1")  # Ollama
  # llm = OpenAICompatibleLLM(model="gpt-...", api_key=...)          # OpenAI, Azure, Gemini, Groq, ...
  # from trigpoint.describe.anthropic import AnthropicLLM             # trigpoint[anthropic]
  # llm = AnthropicLLM()
  # llm = CallableLLM(lambda system, user, max_tokens: my_model(system, user))   # anything else

  described, stats = describe_repo_map(repo_map, llm)
  ```

  CLI: `trigpoint map . --describe --llm openai --model llama3 --base-url http://localhost:11434/v1`
  (or `--llm anthropic`), optionally with `--cache-dir`.
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
