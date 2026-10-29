from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from conftest import LEAKED_TOKEN
from trigpoint.api import build_repo_map
from trigpoint.cache import ArtifactCache, LocalFsStore, repo_key
from trigpoint.cache.base import NS_CONNECTION, NS_REPO_MAP
from trigpoint.cache.keys import (
    connection_key,
    describe_key,
    repo_map_key,
)
from trigpoint.domain import SCHEMA_VERSION, RepoMap, repo_map_from_dict
from trigpoint.errors import InvalidKeyError, LimitExceededError, SchemaError

SHA = "a" * 40
SHA2 = "b" * 40


@pytest.fixture
def built(sample_repo: Path) -> RepoMap:
    return build_repo_map(sample_repo, commit_sha=SHA)


# -- keys ------------------------------------------------------------------------------------
def test_repo_key_avoids_underscore_collisions() -> None:
    assert repo_key("a_b", "c", "main") != repo_key("a", "b_c", "main")


def test_repo_key_is_case_insensitive_for_owner_and_repo_but_not_branch() -> None:
    assert repo_key("Org", "Repo", "main") == repo_key("org", "repo", "main")
    assert repo_key("org", "repo", "Main") != repo_key("org", "repo", "main")


def test_repo_key_distinguishes_slashed_branches_and_hosts() -> None:
    assert repo_key("o", "r", "feat/x") != repo_key("o", "r", "feat-x")
    assert repo_key("o", "r", "main") != repo_key("o", "r", "main", host="ghe.corp.example")


def test_repo_key_is_filesystem_safe_and_bounded() -> None:
    key = repo_key("o" * 100, "r" * 100, "feature/" + "x" * 200)
    assert len(key) <= 100
    assert all(c.isalnum() or c in "._-" for c in key)


@pytest.mark.parametrize(
    ("owner", "repo", "branch"),
    [
        ("..", "r", "main"),
        ("o", "r", "--upload-pack=evil"),
        ("o", "r", "-x"),
        ("o", "r", "a..b"),
        ("o", "r", ""),
        ("o", "r", "a\nb"),
        ("o/x", "r", "main"),
        ("o", "r.lock", "main"),
        ("-o", "r", "main"),
    ],
)
def test_repo_key_rejects_hostile_input(owner: str, repo: str, branch: str) -> None:
    with pytest.raises(InvalidKeyError):
        repo_key(owner, repo, branch)


def test_cache_keys_validate_and_vary() -> None:
    rk = repo_key("o", "r", "main")
    assert repo_map_key(rk, SHA) != repo_map_key(rk, SHA2)
    assert describe_key(rk, "section A") != describe_key(rk, "section B")
    assert describe_key(rk, "same") == describe_key(rk, "same")
    with pytest.raises(InvalidKeyError):
        repo_map_key(rk, "not-a-sha")
    with pytest.raises(InvalidKeyError):
        connection_key("../escape")


# -- local store -------------------------------------------------------------------------------
def test_store_round_trip_and_miss(tmp_path: Path) -> None:
    store = LocalFsStore(tmp_path)
    assert store.get(NS_REPO_MAP, "k1.json") is None
    store.put(NS_REPO_MAP, "k1.json", b"hello")
    assert store.get(NS_REPO_MAP, "k1.json") == b"hello"
    store.put(NS_REPO_MAP, "k1.json", b"hello")  # idempotent
    assert store.get(NS_REPO_MAP, "k1.json") == b"hello"


def test_store_layout_is_sharded_and_leaves_no_temp_files(tmp_path: Path) -> None:
    store = LocalFsStore(tmp_path, tenant="acme")
    store.put(NS_CONNECTION, "p1.md", b"x")
    files = [p for p in (tmp_path / "acme").rglob("*") if p.is_file()]
    assert len(files) == 1 and files[0].name == "p1.md"
    # tenant/namespace/ab/cd/key
    assert len(files[0].relative_to(tmp_path / "acme").parts) == 4
    assert not list(tmp_path.rglob("*.part")) and not list(tmp_path.rglob("*.lock"))


def test_store_tenants_are_isolated(tmp_path: Path) -> None:
    LocalFsStore(tmp_path, tenant="a").put(NS_CONNECTION, "p.md", b"secret-of-a")
    assert LocalFsStore(tmp_path, tenant="b").get(NS_CONNECTION, "p.md") is None


@pytest.mark.parametrize("key", ["../x", "a/b", "a\\b", "", ".", "..", "x" * 201, "a b"])
def test_store_rejects_unsafe_keys(tmp_path: Path, key: str) -> None:
    store = LocalFsStore(tmp_path)
    with pytest.raises(InvalidKeyError):
        store.put(NS_CONNECTION, key, b"x")
    with pytest.raises(InvalidKeyError):
        store.get(NS_CONNECTION, key)


def test_store_rejects_bad_tenant_and_namespace(tmp_path: Path) -> None:
    with pytest.raises(InvalidKeyError):
        LocalFsStore(tmp_path, tenant="../evil")
    with pytest.raises(InvalidKeyError):
        LocalFsStore(tmp_path).get("not-a-namespace", "k")


def test_store_enforces_size_cap(tmp_path: Path) -> None:
    store = LocalFsStore(tmp_path, max_bytes=10)
    with pytest.raises(LimitExceededError):
        store.put(NS_CONNECTION, "p.md", b"x" * 11)


def test_concurrent_writers_never_expose_partial_data(tmp_path: Path) -> None:
    store = LocalFsStore(tmp_path)
    payload = b"0123456789" * 50_000
    stop = threading.Event()
    seen: list[bytes] = []

    def writer() -> None:
        for _ in range(15):
            store.put(NS_CONNECTION, "p.md", payload)

    def reader() -> None:
        while not stop.is_set():
            got = store.get(NS_CONNECTION, "p.md")
            if got is not None:
                seen.append(got)

    r = threading.Thread(target=reader)
    writers = [threading.Thread(target=writer) for _ in range(4)]
    r.start()
    for t in writers:
        t.start()
    for t in writers:
        t.join()
    stop.set()
    r.join()
    assert seen and all(s == payload for s in seen)
    assert store.get(NS_CONNECTION, "p.md") == payload
    assert not list(tmp_path.rglob(".tmp-*"))


# -- serialisation -------------------------------------------------------------------------------
def test_repo_map_survives_a_json_round_trip(built: RepoMap) -> None:
    again = repo_map_from_dict(json.loads(built.to_json()))
    assert again == built
    assert again.to_json() == built.to_json()


def test_from_dict_rejects_bad_documents(built: RepoMap) -> None:
    doc = json.loads(built.to_json())
    with pytest.raises(SchemaError):
        repo_map_from_dict({**doc, "schema_version": SCHEMA_VERSION + 1})
    broken = dict(doc)
    del broken["stack"]
    with pytest.raises(SchemaError):
        repo_map_from_dict(broken)
    with pytest.raises(SchemaError):
        repo_map_from_dict({**doc, "files": [{"path": "x"}]})


# -- artifact layers ---------------------------------------------------------------------------
def test_repo_map_layer_hits_without_rebuilding(tmp_path: Path, built: RepoMap) -> None:
    cache = ArtifactCache(LocalFsStore(tmp_path))
    rk = repo_key("o", "shop", "main")
    calls = 0

    def build() -> RepoMap:
        nonlocal calls
        calls += 1
        return built

    first, hit1 = cache.get_or_build_repo_map(rk, SHA, build)
    second, hit2 = cache.get_or_build_repo_map(rk, SHA, build)
    assert (hit1, hit2, calls) == (False, True, 1)
    assert second == first == built
    # A new commit is a new key, so it rebuilds; the old entry is untouched.
    _, hit3 = cache.get_or_build_repo_map(rk, SHA2, build)
    assert (hit3, calls) == (False, 2)
    assert cache.get_repo_map(rk, SHA) == built


def test_corrupt_or_stale_entries_are_misses(tmp_path: Path, built: RepoMap) -> None:
    store = LocalFsStore(tmp_path)
    cache = ArtifactCache(store)
    rk = repo_key("o", "shop", "main")
    store.put(NS_REPO_MAP, repo_map_key(rk, SHA), b"{not json")
    assert cache.get_repo_map(rk, SHA) is None
    stale = {**json.loads(built.to_json()), "schema_version": 999}
    store.put(NS_REPO_MAP, repo_map_key(rk, SHA), json.dumps(stale).encode())
    assert cache.get_repo_map(rk, SHA) is None
    rebuilt, hit = cache.get_or_build_repo_map(rk, SHA, lambda: built)
    assert (rebuilt, hit) == (built, False)
    assert cache.get_repo_map(rk, SHA) == built  # healed


def test_uncommitted_dirs_are_not_cached(tmp_path: Path, built: RepoMap) -> None:
    cache_dir = tmp_path / "cache"
    cache = ArtifactCache(LocalFsStore(cache_dir))
    _, hit = cache.get_or_build_repo_map("k", "", lambda: built)
    assert hit is False
    assert not cache_dir.exists() or not [p for p in cache_dir.rglob("*") if p.is_file()]


def test_describe_layer_is_shared_by_section_content(tmp_path: Path) -> None:
    cache = ArtifactCache(LocalFsStore(tmp_path))
    rk = repo_key("o", "r", "main")
    assert cache.get_description(rk, "## Modules\n...") is None
    cache.put_description(rk, "## Modules\n...", "A billing service.")
    assert cache.get_description(rk, "## Modules\n...") == "A billing service."
    assert cache.get_description(rk, "## Modules\nchanged") is None


def test_free_text_is_redacted_before_it_is_stored(tmp_path: Path) -> None:
    store = LocalFsStore(tmp_path)
    cache = ArtifactCache(store)
    rk = repo_key("o", "r", "main")
    cache.put_description(rk, "section", f"Uses key {LEAKED_TOKEN} internally.")
    cache.put_connection("proj-1", f"# Map\nkey={LEAKED_TOKEN}\n")
    on_disk = b"".join(p.read_bytes() for p in tmp_path.rglob("*") if p.is_file())
    assert LEAKED_TOKEN.encode() not in on_disk
    assert LEAKED_TOKEN not in (cache.get_connection("proj-1") or "")
    assert LEAKED_TOKEN not in (cache.get_description(rk, "section") or "")


def test_connection_layer_is_per_project(tmp_path: Path) -> None:
    cache = ArtifactCache(LocalFsStore(tmp_path))
    cache.put_connection("p1", "one")
    cache.put_connection("p2", "two")
    assert (cache.get_connection("p1"), cache.get_connection("p2")) == ("one", "two")
    assert cache.get_connection("p3") is None
