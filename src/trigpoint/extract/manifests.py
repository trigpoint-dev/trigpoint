"""Stack detection from package manifests, compose files and file layout."""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from trigpoint.domain import FileRecord, StackInfo
from trigpoint.languages import CODE_LANGS

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised on 3.10 only
    import tomli as tomllib

MANIFEST_NAMES = frozenset(
    {
        "pyproject.toml",
        "requirements.txt",
        "package.json",
        "go.mod",
        "Cargo.toml",
        "Gemfile",
        "pom.xml",
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
        "pnpm-workspace.yaml",
        "go.work",
        "lerna.json",
    }
)

_FRAMEWORKS = {
    "fastapi": "FastAPI",
    "flask": "Flask",
    "django": "Django",
    "starlette": "Starlette",
    "sqlalchemy": "SQLAlchemy",
    "sqlmodel": "SQLModel",
    "pydantic": "Pydantic",
    "alembic": "Alembic",
    "celery": "Celery",
    "pytest": "pytest",
    "react": "React",
    "next": "Next.js",
    "vue": "Vue",
    "svelte": "Svelte",
    "@angular/core": "Angular",
    "express": "Express",
    "@nestjs/core": "NestJS",
    "vite": "Vite",
    "jest": "Jest",
    "github.com/gin-gonic/gin": "Gin",
    "github.com/labstack/echo": "Echo",
    "github.com/gofiber/fiber": "Fiber",
    "spring-boot": "Spring Boot",
    "rails": "Rails",
    "actix-web": "Actix",
    "axum": "Axum",
    "rocket": "Rocket",
    "tokio": "Tokio",
}
_FRONTEND = frozenset({"React", "Next.js", "Vue", "Svelte", "Angular", "Vite"})
_BACKEND = frozenset(
    {
        "FastAPI",
        "Flask",
        "Django",
        "Starlette",
        "Express",
        "NestJS",
        "Gin",
        "Echo",
        "Fiber",
        "Spring Boot",
        "Rails",
        "Actix",
        "Axum",
        "Rocket",
    }
)
_DATASTORES = {
    "psycopg2": "PostgreSQL",
    "psycopg": "PostgreSQL",
    "asyncpg": "PostgreSQL",
    "pg": "PostgreSQL",
    "postgres": "PostgreSQL",
    "pymysql": "MySQL",
    "mysqlclient": "MySQL",
    "mysql2": "MySQL",
    "mysql": "MySQL",
    "mariadb": "MySQL",
    "redis": "Redis",
    "ioredis": "Redis",
    "pymongo": "MongoDB",
    "mongoose": "MongoDB",
    "mongodb": "MongoDB",
    "mongo": "MongoDB",
    "elasticsearch": "Elasticsearch",
    "kafka-python": "Kafka",
    "confluent-kafka": "Kafka",
    "kafkajs": "Kafka",
    "kafka": "Kafka",
    "pika": "RabbitMQ",
    "amqplib": "RabbitMQ",
    "rabbitmq": "RabbitMQ",
}

_DEP_NAME = re.compile(r"^[A-Za-z0-9_.@/\-]+")


@dataclass
class ManifestInfo:
    path: str
    ecosystem: str
    dependencies: set[str] = field(default_factory=set)
    images: set[str] = field(default_factory=set)
    workspace: bool = False
    library_hint: bool = False
    app_hint: bool = False


def _dep_name(spec: str) -> str:
    m = _DEP_NAME.match(spec.strip())
    return m.group(0).lower().replace("_", "-") if m else ""


def _py_spec_name(spec: str) -> str:
    name = re.split(r"[\s\[<>=!~;@(]", spec.strip(), maxsplit=1)[0]
    return name.lower().replace("_", "-")


def _toml(text: str) -> dict[str, Any]:
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return {}


def parse_manifest(path: str, text: str) -> ManifestInfo | None:
    name = PurePosixPath(path).name
    if name == "pyproject.toml":
        data = _toml(text)
        info = ManifestInfo(path, "python")
        project = data.get("project", {})
        for spec in project.get("dependencies", []):
            info.dependencies.add(_py_spec_name(str(spec)))
        for group in project.get("optional-dependencies", {}).values():
            info.dependencies.update(_py_spec_name(str(s)) for s in group)
        poetry = data.get("tool", {}).get("poetry", {})
        info.dependencies.update(k.lower() for k in poetry.get("dependencies", {}))
        info.dependencies.discard("python")
        info.dependencies.discard("")
        info.workspace = bool(data.get("tool", {}).get("uv", {}).get("workspace"))
        info.library_hint = bool(project or poetry)
        return info
    if name == "requirements.txt":
        info = ManifestInfo(path, "python")
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if line and not line.startswith("-"):
                info.dependencies.add(_py_spec_name(line))
        info.dependencies.discard("")
        return info
    if name == "package.json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
        if not isinstance(data, dict):
            return None
        info = ManifestInfo(path, "node")
        for key in ("dependencies", "devDependencies", "peerDependencies"):
            section = data.get(key)
            if isinstance(section, dict):
                info.dependencies.update(str(k).lower() for k in section)
        info.workspace = bool(data.get("workspaces"))
        info.library_hint = bool(data.get("main") or data.get("exports") or data.get("module"))
        info.app_hint = bool(data.get("private")) or "start" in (data.get("scripts") or {})
        return info
    if name == "go.mod":
        info = ManifestInfo(path, "go")
        for line in text.splitlines():
            m = re.match(r"^\s*(?:require\s+)?([a-z0-9.\-]+\.[a-z]+/[^\s]+)\s+v", line)
            if m:
                info.dependencies.add(m.group(1).lower())
        return info
    if name == "go.work":
        return ManifestInfo(path, "go", workspace=True)
    if name == "Cargo.toml":
        data = _toml(text)
        info = ManifestInfo(path, "rust")
        info.dependencies.update(k.lower() for k in data.get("dependencies", {}))
        info.workspace = "workspace" in data
        info.library_hint = "lib" in data
        info.app_hint = "bin" in data
        return info
    if name == "Gemfile":
        info = ManifestInfo(path, "ruby")
        info.dependencies.update(
            m.group(1).lower() for m in re.finditer(r"^\s*gem\s+['\"]([^'\"]+)['\"]", text, re.M)
        )
        return info
    if name == "pom.xml":
        info = ManifestInfo(path, "java")
        info.dependencies.update(
            m.group(1).lower() for m in re.finditer(r"<artifactId>([^<]+)</artifactId>", text)
        )
        return info
    if name in ("pnpm-workspace.yaml", "lerna.json"):
        return ManifestInfo(path, "node", workspace=True)
    if name.startswith(("docker-compose", "compose.")):
        info = ManifestInfo(path, "compose")
        info.images.update(
            m.group(1).lower() for m in re.finditer(r"^\s*image:\s*['\"]?([^\s'\"]+)", text, re.M)
        )
        return info
    return None


def _infra_from_files(files: tuple[FileRecord, ...]) -> set[str]:
    infra: set[str] = set()
    for f in files:
        p = f.path
        name = PurePosixPath(p).name
        if name.startswith("Dockerfile"):
            infra.add("Docker")
        elif name.startswith(("docker-compose", "compose.")) and name.endswith((".yml", ".yaml")):
            infra.add("Docker Compose")
        elif p.startswith(".github/workflows/"):
            infra.add("GitHub Actions")
        elif name == ".gitlab-ci.yml":
            infra.add("GitLab CI")
        elif name == "Jenkinsfile":
            infra.add("Jenkins")
        elif p.endswith(".tf"):
            infra.add("Terraform")
        elif name == "Chart.yaml":
            infra.add("Helm")
        elif p.split("/")[0] in ("k8s", "kubernetes") or "/k8s/" in p:
            infra.add("Kubernetes")
        elif name in ("serverless.yml", "serverless.yaml"):
            infra.add("Serverless")
    return infra


_PKG_MANAGERS = {
    "pyproject.toml": "pip/pyproject",
    "requirements.txt": "pip",
    "package.json": "npm",
    "go.mod": "go modules",
    "Cargo.toml": "cargo",
    "Gemfile": "bundler",
    "pom.xml": "maven",
}


def build_stack(files: tuple[FileRecord, ...], manifests: list[ManifestInfo]) -> StackInfo:
    loc: dict[str, int] = {}
    for f in files:
        if f.language in CODE_LANGS and not f.is_generated and not f.is_binary:
            loc[f.language] = loc.get(f.language, 0) + f.loc
    languages = tuple(sorted(loc.items(), key=lambda kv: (-kv[1], kv[0])))

    frameworks: set[str] = set()
    datastores: set[str] = set()
    deps: set[str] = set()
    managers: set[str] = set()
    for m in manifests:
        base = PurePosixPath(m.path).name
        if base in _PKG_MANAGERS:
            managers.add(_PKG_MANAGERS[base])
        deps.update(m.dependencies)
        for dep in m.dependencies:
            for key, label in _FRAMEWORKS.items():
                if dep == key or (key.startswith("github.com/") and dep.startswith(key)):
                    frameworks.add(label)
            if dep.startswith("spring-boot"):
                frameworks.add("Spring Boot")
            # `psycopg2-binary`, `mysql-connector-python`, `redis-om`: name or hyphenated variant.
            for key, label in _DATASTORES.items():
                if dep == key or dep.startswith(key + "-"):
                    datastores.add(label)
        for image in m.images:
            short = image.split("/")[-1].split(":")[0]
            for key, label in _DATASTORES.items():
                if short == key or short.startswith(key):
                    datastores.add(label)

    return StackInfo(
        languages=languages,
        frameworks=tuple(sorted(frameworks)),
        datastores=tuple(sorted(datastores)),
        infra=tuple(sorted(_infra_from_files(files))),
        package_managers=tuple(sorted(managers)),
        dependencies=tuple(sorted(deps))[:60],
        manifests=tuple(sorted(m.path for m in manifests)),
    )


def is_frontend(frameworks: tuple[str, ...]) -> bool:
    return any(f in _FRONTEND for f in frameworks)


def is_backend(frameworks: tuple[str, ...]) -> bool:
    return any(f in _BACKEND for f in frameworks)
