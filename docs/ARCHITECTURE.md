# Architecture: `trigpoint`

Status: design, nothing implemented. Name decided: **trigpoint** (a trig point is the
surveying pillar every map is measured from; fits "grounding"). Package/import/CLI: `trigpoint`.

## 1. Vision

A **grounding layer** between GitHub and LLM/agent systems. Agents should not each
reinvent: authenticate to GitHub, clone safely, understand a repo, fit it in a prompt,
stay fresh, and not leak secrets. This library does that once, well.

Three planes:

| Plane | Question it answers | Surface |
|---|---|---|
| **Read** (grounding) | "What is in this repo?" | RepoMap, search, file slices, task-aware context |
| **Event** (freshness) | "What changed?" | webhook verification, push -> refresh, diff context |
| **Action** (write-back) | "Let the agent act." | least-privilege GitHub App ops (PR, comment, check) |

v0.1 ships Read + GitHub App auth/sync. Event and Action are designed for now so the
core types don't need breaking changes later.

Non-goals: not a vector DB, never executes repo code (static analysis only), not an LSP
replacement, not a hosted service (a thin server wrapper may come later).

## 2. Principles

1. **Hexagonal.** Pure domain core; every I/O concern (auth, git, storage, LLM, clock)
   is a Protocol with swappable adapters. Core never imports adapters.
2. **Content-addressed + immutable.** Facts are keyed by git blob SHA; assembled maps by
   commit SHA. Immutable objects make concurrent writers safe on EFS/S3 (create-if-absent).
3. **Deterministic output.** Same commit + config => byte-identical output (sorted, no
   timestamps). This makes LLM prompt caching hit and golden tests possible.
4. **Provenance everywhere.** Every fact carries `path:line` and is pinned to a SHA, so
   agents can cite and verify. "Grounding" = answers are checkable.
5. **Untrusted input.** Repo content is hostile: to git, to the parser, to secrets
   hygiene, and to the downstream LLM (prompt injection).
6. **Small stable public API**, everything else private. Published JSON Schema for RepoMap.

## 3. System view

```
                 +-------------------- agents / apps / MCP (later) ---------------------+
                 |  get_repo_map  context_for(task)  search  get_file  diff  open_pr    |
                 +----------------------------------+-----------------------------------+
                                                    |  public facade (repolens.api)
 +--------------------------------------------------v-----------------------------------+
 |  Application: Pipeline / Orchestrator (sync core, async wrappers)                      |
 |   resolve ref -> ensure clone -> index (incremental) -> rank -> render -> cache        |
 +--+----------+-----------+-----------+------------+------------+-----------+----------+
    |          |           |           |            |            |           |
  auth        sync       index      extract       rank/ctx     render     describe
 (ports)    (ports)     (facts)    (plugins)    (PageRank,   (budget,     (LLM port,
                                                 task-aware)  formats)    optional)
    |          |           |                                      |
 GitHub App   git CLI   FactStore  <----- CacheStore (L0 mem, L1 disk, L2 EFS/S3) -----+
 PAT/anon     hardened  (immutable)                                                     |
                                                                                        |
 security (cross-cutting): path policy, secret scanner, redactor, injection fencing, limits
```

## 4. Domain model

- `RepoRef(host, owner, repo, branch)` -> `repo_key` = readable sanitized prefix + short
  hash of the exact tuple (no `a_b/c` vs `a/b_c` collisions; branch `/` safe).
- `Snapshot(repo_ref, commit_sha)` : the unit everything is pinned to.
- `FileRecord(path, language, size, loc, blob_sha, is_binary, is_generated, is_test)`.
- `Fact` (typed, namespaced `kind`): `symbol | route | model | dependency | doc | import | ...`
  each with `Span(path, start_line, end_line)`, `extractor`, `extractor_version`, stable id
  like `sym:src/app/api.py#UserRouter.create`.
- `RepoMap`: files + facts + modules + classification + import graph + tree. Versioned
  (`schema_version`), JSON-serializable, with a published JSON Schema.
- `Rendered(markdown, sections, token_estimate, dropped[])`: `dropped` powers
  `explain()` ("why isn't X in my context?").

## 5. Auth (GitHub App first-class)

- App JWT (RS256, iat-60s, exp<=10m) -> installation token (`contents:read`, narrowed to
  the requested repositories). Single-flight refresh per installation; refresh 5 min early.
- Token is a `SecretStr`-style object: redacted `repr`/`str`/pickle/logging; only
  `.reveal()` inside the git-env builder.
- **Passing to git:** `GIT_CONFIG_COUNT/KEY_n/VALUE_n` env (keeps token out of argv and
  `ps`); `-c` fallback for git < 2.31. Header
  `Authorization: basic base64(x-access-token:TOKEN)` set as
  `http.https://github.com/.extraheader` (host-scoped: LFS/submodule redirects to another
  host never receive it). Clone URL stays clean; nothing in `.git/config`.
  Also `GIT_TERMINAL_PROMPT=0`, null system/global config, `GIT_LFS_SKIP_SMUDGE=1`,
  no submodule recursion, `core.hooksPath` disabled, `protocol.allow` restricted.
- **GitHub Enterprise Server:** configurable `api_base` / `git_host`; the header scope
  derives from it (this is what makes enterprise IT adoption possible).
- Discovery: `list_installations`, `list_repos`, `list_branches` (Link pagination,
  ETag/conditional requests, primary + secondary rate-limit backoff).
- **Separate read vs write identities:** recommend two Apps (read-only grounding, scoped
  write for the Action plane) so a grounding deployment can never push.
- Other providers (`TokenAuth`, `NoAuth`/local path) implement the same `AuthProvider`.
  GitLab/Bitbucket are future adapters, not v0.1.

## 6. Sync (shared clones)

- Layout: `shared/{repo_key}/clone`, `.lock`, `state.json`; per-project symlink
  `clone_root/{project_id}/{reponame}` (Windows junction fallback). Projects on the same
  repo share one clone.
- Flow under lock: `ls-remote refs/heads/<b>`; SHA == local HEAD -> no-op;
  else `fetch --depth 1 --no-tags` of the explicit refspec, `reset --hard FETCH_HEAD`,
  `clean -fdx`.
- **Reader/writer lock:** parse holds shared, refresh holds exclusive (so `reset --hard`
  never mutates files under a parser). flock-style, works on EFS (NFSv4); stale-lock timeout.
- **Hardened args:** strict regex for owner/repo, `git check-ref-format`, reject leading
  `-`, fully-qualified refs, `--end-of-options` and `--`, no shell, timeouts, output caps.
- **Post-refresh sanitize + cap** (layer 3 of secrets): delete secret-adjacent files from
  the working tree; cap file size/count/total size/git runtime.
- **Webhook-driven refresh (Event plane):** `verify_signature()` (HMAC-SHA256,
  constant-time) + `push -> RefreshRequest`. `ls-remote` stays as the polling fallback.

### Ephemeral disk (the 2.4 problem)
Make the clone disposable and the *index* durable:
1. `ls-remote` -> SHA.
2. If the assembled map for `(repo, sha, extractor_ver)` exists in L2 -> return it, **no clone**.
3. Else clone lazily, extract only blobs missing from the fact store (see 7), store, return.

Result: pod restart => cache hit, zero clone. Disk choice affects speed only.
Target storage is **Amazon S3 Files** (NFS 4.1/4.2 file system over an S3 bucket); see 7b
for what it does and does not give us. (Mountpoint for S3 is a different product and
*is* unsuitable for git trees; S3 Files is not that.)
SQLite on a network FS is unsafe, so durable artifacts are write-once files (JSON/zstd),
SQLite is only a *local* ephemeral query index rebuilt from them.

## 7. Index: incremental, content-addressed

Upgrade over a single whole-repo cache keyed by commit:

- **L-blob facts**: key `(blob_sha, extractor_id, extractor_version)` -> facts for that file.
  A new commit re-extracts only changed blobs. Identical files across branches/forks dedupe.
- **L-map**: key `(repo_key, commit_sha, pipeline_version)` -> assembled RepoMap
  (= merge of blob facts + classify + graph). This is the layer in the original spec.
- **L-describe**: key `(repo_key, sha256(rendered_section))` -> LLM text.
- **L-render**: per-project `connection.md` (output only, never input).
- **Tenant scoping:** blob caches are namespaced per installation/tenant by default.
  Cross-tenant sharing is opt-in only (avoids hash-probing side channels).
- Writes publish atomically via tmp file + rename (never hard links: S3 Files has none).
  Keys are content-addressed, so two workers racing write identical bytes and a
  rename-overwrite is benign.
- Local query index: SQLite + FTS5 (stdlib) built from facts for symbol/lexical search.

## 7b. Storage profile: Amazon S3 Files

Verified against AWS docs ([limits](https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-files-quotas.html),
[sync](https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-files-synchronization.html)):

| S3 Files fact | Consequence for trigpoint |
|---|---|
| NFS 4.1/4.2, **advisory** locks (512/file, 8192/mount) | Cross-pod RW lock works (server-side). One persistent lock file per repo, never create/delete per acquisition; no per-blob locks. |
| Symlinks supported, **hard links not** | Per-project symlinks OK. Never use `link()`; tmp+rename only. Git's link-then-rename fallback must be verified. |
| FS rename is instant, but S3 side = copy+delete per object; **versioning required**; export after 60 s write inactivity | Git (thousands of small files, lock files, renames) amplifies S3 requests/versions. Immutable content-addressed artifacts are the ideal workload. |
| Bucket is source of truth; conflicting FS file -> `.s3files-lost+found-<id>` | **No mutable shared files** (no shared `state.json`/pointer files). Single writer per path or immutable only. |
| First access to a directory imports metadata for *all* entries | Shard keys (`ab/cd/<sha>`), never huge flat directories. |
| Path component <=255 B, full key <=1024 B, no `//`, `.`/`..` | `repo_key` and cache keys are length-bounded and validated. |
| Data unread 30 d is expired to S3 (metadata stays) | Cold reads are slower, not lost. Fine for caches. |
| Versioned bucket keeps old versions; deletes only add delete markers | **Secrets written to the mount persist in S3 history.** |

Resulting storage profile (two roots, independently configurable):

- `artifact_root` -> S3 Files mount (**recommended default for the durable layers**):
  blob facts, repo-map, describe cache, rendered output. Write-once, sharded, tenant-prefixed.
  Bonus: the bucket is the source of truth, so other services can read the same artifacts
  with plain S3 `GetObject`, and the library needs no S3 SDK for this (it is just a path).
- `clone_root` -> default **node-local disk**; S3 Files/EFS supported but experimental until
  benchmarked (clone+fetch latency, request/version cost, rename behavior, git's
  `link()` fallback, concurrent fetch under advisory lock).
- If a clone does live on S3 Files: **sanitize before materialize.** Deleting a secret file
  after checkout is too late (it is already exported and versioned). So the syncer fetches
  then checks out with a denylist applied (sparse-checkout negative patterns) so
  secret-adjacent paths never touch the mount. Also: SSE-KMS bucket, lifecycle rule for
  noncurrent versions, per-tenant S3 Files access point (root dir + POSIX uid/gid) for isolation.
- Readers on other pods can see stale directory/attribute state (close-to-open semantics):
  treat a miss as "recompute or retry once", never trust negative `exists()` caching.

Benchmark task (before committing clone-on-S3-Files): measure shallow clone, no-op sync,
and fetch+reset on emptyDir vs EFS vs S3 Files with a large and a small repo; record
latency, S3 PUT count, and versions created.

## 8. Parse & extract

- **Walk** via `git ls-files -s` (blob SHA free, honors .gitignore); `os.walk` + `pathspec`
  fallback for non-git dirs. Never follow symlinks leaving the root. Binary = NUL in first
  8 KB; generated = markers/lockfiles/minified/vendor/`*_pb2.py`; test = path conventions.
- **Extractor plugin protocol** (entry-point group `repolens.extractors`):
  `matches(FileRecord) -> bool`, `extract(FileContext) -> Iterable[Fact]`, `id`, `version`.
  Runs in a bounded worker pool with per-file timeout, size cap, recursion limit
  (a pathological file cannot hang or OOM the pipeline).
- First-party extractors: **symbols** (stdlib `ast` for Python; tree-sitter extra for
  TS/JS/Go/Java/Rust; regex fallback; no nested functions; 200/file, sig 200, doc 120),
  **routes** (FastAPI via AST incl. `APIRouter`/`include_router` prefixes; pluggable for
  Flask/Django/Express), **models** (SQLAlchemy 1.x/2.0 + Pydantic), **manifests**
  (stack detection), **docs** (README/prose).
- Community "framework packs" are the expected growth path; a "write an extractor"
  guide + conformance test kit ship in-repo.

## 9. Understand: classify, modules, graph

- Repo type (monorepo/webapp/service-api/library/unknown) as `{type, confidence, evidence[]}`.
- Modules: first dir under `src|app|packages|services|internal|pkg|lib`, else top-level;
  each with LOC, language mix, README blurb, top-10 exported symbols, routes, models.
- Import graph (Python `ast`, JS/TS via tree-sitter or regex) resolved to internal files;
  hand-rolled PageRank. Upgrade path: symbol-level references (Aider-style).
- **Task-aware ranking:** personalized PageRank biased by `focus_files`, query terms
  (FTS5 hits), and recently-changed files -> `context_for(task, focus, budget)`.
  Static `RepoMap` is the always-on orientation layer; `context_for` is the per-task layer.

## 10. Render

- Seven sections (provisional): Overview, Stack, Modules, Routes, Data models,
  Key symbols, Directory tree (depth 4 / 15 children / 500 lines, configurable).
- Greedy packing against a budget: mandatory sections first, then priority order;
  degrade by truncating the lowest-ranked items, never silently drop a section.
- Pluggable `TokenCounter` (default chars/4; optional tiktoken / provider counters).
- Formats: Markdown (default), JSON, XML-tagged (friendly to Claude-style prompts).
- Stable ordering and stable prefix so provider **prompt caching** hits across calls.
- Every line anchored to `path:line` (+ optional GitHub permalink at the pinned SHA).

## 11. Security model (threats specific to LLM + GitHub + agents)

| Threat | Mitigation |
|---|---|
| Token leakage (argv, URL, .git/config, logs, tracebacks) | env-based git config, host-scoped header, `SecretStr`, global redaction filter, tests asserting absence |
| Malicious repo vs git (hooks, filters, fsmonitor, submodules, LFS, ext:: protocols) | null configs, hooks/fsmonitor disabled, protocol allowlist, no recursion, `SKIP_SMUDGE` |
| Argument/ref injection via user-supplied branch | validation + `--end-of-options` + fully-qualified refs |
| Path traversal / symlink escape | resolve + containment check on every read |
| Parser DoS (huge/deep files, zip bombs) | size/time/recursion caps, isolated worker pool |
| Secrets in repo content | layer a: never read secret-adjacent paths (denylist + .gitignore); layer b: scan+redact all persisted and LLM-bound text (key blocks, AWS, GH/Slack/Stripe/Google tokens, JWT, conn strings, `secret=` assignments, entropy w/ hex excluded); layer c: sanitize+cap clone on refresh |
| **Indirect prompt injection** (README/comments saying "ignore instructions") | render repo text inside explicit untrusted-content fences with provenance, strip/neutralize control sequences, heuristic injection flagging surfaced in `Rendered.warnings`; describe-LLM treats input as data; docs tell integrators never to grant write-tools based on grounded text alone |
| Cross-tenant cache leakage | tenant-namespaced caches, opt-in sharing |
| Over-privileged agent | read/write App separation, per-request narrowed installation tokens, audit events |

## 12. Agent integration surface

1. **Static injection:** `connection.md` in the system prompt (works today, any LLM).
2. **Tool-calling:** the same capabilities as typed functions; MCP server (extra, later):
   `get_repo_map`, `context_for`, `search_symbols`, `get_file(path, range)`,
   `list_routes`, `diff_context(base, head)`, `resolve(ref)`.
3. **Event-driven agents:** webhook -> refresh -> agent run -> Action plane (PR/comment/
   check). Reference examples for Claude Agent SDK and generic function-calling loops.
Everything returns plain dataclasses / JSON so a server wrapper is ~100 lines.

## 13. Quality: evaluation & observability

- **Eval harness (credibility asset):** localization benchmark - given an issue/task,
  is the human fix's file set within the top-K / budget of `context_for`? Metrics:
  file-recall@budget, tokens used, latency. Drives ranking changes with evidence;
  run on a small fixed repo set in CI (non-gating) and publish results.
- Tests: per-extractor fixtures, secrets corpus incl. false positives (git SHAs),
  property tests on ref/arg sanitization, multi-process lock test, local bare-repo
  integration, mocked GitHub (`respx`), golden render files, "token never appears in
  argv/.git/config/logs/exceptions" test.
- Structured logging, optional OpenTelemetry spans/metrics, `explain()` for budget drops,
  no telemetry phoning home.

## 14. Packaging & repo layout

```
src/trigpoint/
  api.py                    # the only stable public surface
  domain/    types.py facts.py repomap.py errors.py
  ports/     auth.py git.py store.py llm.py tokens.py
  adapters/  github_app/ token_auth.py git_cli/ store_local/ (also serves S3 Files/EFS mounts, they are just paths) store_s3/ (SDK, optional)
  sync/      repo_key.py refs.py locks.py syncer.py sanitize.py webhooks.py
  index/     walk.py facts_store.py sqlite_index.py
  extract/   base.py symbols/ routes.py models.py manifests.py docs.py
  understand/ classify.py modules.py importgraph.py rank.py
  render/    sections.py budget.py tree.py formats.py
  describe/  describe.py
  security/  paths.py scanner.py entropy.py redact.py fence.py limits.py
  cli.py
tests/  fixtures/  golden/        eval/        docs/  examples/
```

Extras: `[github]` (httpx, PyJWT[crypto]), `[treesitter]`, `[s3]`, `[mcp]`, `[otel]`.
Core deps: stdlib + `tomli` (py3.10) + `filelock` + `pathspec`. `>=3.10`, tested on
Linux/macOS/Windows. MIT. semver for the package; independent `schema_version` and
`extractor_version`.

## 15. Roadmap

| Ver | Scope |
|---|---|
| 0.1 | scaffold, security core, local pipeline, CLI, GitHub App auth + discovery + hardened sync, L-map cache, Markdown render |
| 0.2 | incremental blob-fact store, SQLite/FTS5 search, `context_for`, JSON schema, webhooks verify |
| 0.3 | tree-sitter multi-language pack, describe pass, S3 store, eval harness published |
| 0.4 | MCP server, Action-plane helpers (PR/comment/check), OTel |
| 1.0 | API freeze, framework packs from community, GHES hardening, benchmarks vs alternatives |

## 16. Decisions

Locked: MIT; GitHub App sync in v0.1; MCP later; audience = general IT/software
(not OT/industrial); library-first with optional thin server later; Python >=3.10.
Name: **trigpoint** (`RepoMap` stays the core class). Storage target: Amazon S3 Files (7b).
GitHub org: **trigpoint-dev** (repo `trigpoint-dev/trigpoint`; org name was free when checked,
the plain `trigpoint` account is taken; PyPI and npm `trigpoint` are free).
Open: trademark/domain check for `trigpoint`; clone generation slots (default: single clone + RW lock);
exact seven render sections; budget default (4K tokens).
