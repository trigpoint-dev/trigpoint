# trigpoint

Safe, budgeted repo grounding for LLMs and agents.

> **Status: pre-alpha.** Only the security core exists so far. See
> [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design and roadmap.

trigpoint turns a Git repository into a structured, token-budgeted `RepoMap` that an LLM
or agent can be grounded on. It is built for backends and agents, so the hard parts are
handled for you:

- **GitHub App auth** where the token never lands in a clone URL, `.git/config` or `argv`.
- **Hardened shared clones** with cheap no-op refreshes.
- **Layered secrets protection** on everything that is read, persisted or sent to a model.
- **Prompt-injection-aware output**: repo text is fenced as untrusted content.
- **Deterministic, cache-friendly rendering** within a token budget.

## What exists today

`trigpoint.security`: secret-path policy, secret scanner and redactor, `SecretStr`,
untrusted-content fencing with injection heuristics, and path containment helpers.

## Development

```
python -m venv .venv
.venv\Scripts\activate          # Windows;  source .venv/bin/activate elsewhere
pip install -e ".[dev]"
ruff check . && ruff format --check . && mypy && pytest
```

## License

MIT. See [LICENSE](LICENSE). Security reports: see [SECURITY.md](SECURITY.md).
