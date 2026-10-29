"""Repo-type classification: monorepo | webapp | service/api | library | unknown."""

from __future__ import annotations

from pathlib import PurePosixPath

from trigpoint.domain import Classification, FileRecord, Route, StackInfo
from trigpoint.extract.manifests import ManifestInfo, is_backend, is_frontend

CONVENTIONAL_ROOTS = ("src", "app", "packages", "services", "internal", "pkg", "lib", "apps")
_WORKSPACE_ROOTS = frozenset({"apps", "packages", "services"})


def classify(
    files: tuple[FileRecord, ...],
    stack: StackInfo,
    routes: tuple[Route, ...],
    manifests: list[ManifestInfo],
) -> Classification:
    evidence: list[str] = []

    workspace = [m.path for m in manifests if m.workspace]
    nested_dirs = {
        str(PurePosixPath(m.path).parent)
        for m in manifests
        if m.ecosystem != "compose"
        and PurePosixPath(m.path).parent.parts[:1]
        and PurePosixPath(m.path).parent.parts[0] in _WORKSPACE_ROOTS
    }
    if workspace:
        evidence.append(f"workspace config: {workspace[0]}")
    if len(nested_dirs) >= 2:
        evidence.append(f"{len(nested_dirs)} manifests under apps/packages/services")
    if workspace or len(nested_dirs) >= 2:
        return Classification("monorepo", 0.9 if workspace else 0.75, tuple(evidence))

    has_html = any(f.path.endswith(("index.html",)) for f in files)
    if is_frontend(stack.frameworks):
        evidence.append(
            "frontend framework: " + ", ".join(f for f in stack.frameworks if is_frontend((f,)))
        )
        if has_html:
            evidence.append("index.html present")
        return Classification("webapp", 0.85 if has_html else 0.7, tuple(evidence))

    if routes:
        evidence.append(f"{len(routes)} HTTP routes")
    if is_backend(stack.frameworks):
        evidence.append(
            "backend framework: " + ", ".join(f for f in stack.frameworks if is_backend((f,)))
        )
    if routes or is_backend(stack.frameworks):
        if "Docker" in stack.infra:
            evidence.append("Dockerfile present")
        return Classification("service/api", 0.9 if routes else 0.7, tuple(evidence))

    libs = [m.path for m in manifests if m.library_hint]
    if libs:
        evidence.append(f"publishable package manifest: {libs[0]}")
        return Classification("library", 0.65, tuple(evidence))

    return Classification("unknown", 0.3, ("no strong signals",))
