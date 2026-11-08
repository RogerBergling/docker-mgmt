"""Discovery and validation of Compose projects.

Discovery is intentionally conservative: it starts from configured roots,
never follows directory symlinks by default, skips Docker daemon storage and
other protected paths, and validates candidate YAML with Docker Compose before
offering it for mutation. Running projects are merged in even when their
Compose files live outside the configured roots, so the dashboard can account
for every Compose project on the daemon.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional, Sequence

from .config import Config
from .docker import (
    ComposeConfigError,
    DockerClient,
    DockerError,
    normalize_project_name,
)
from .models import ComposeProject

BASE_NAMES: tuple[str, ...] = (
    "compose.yaml",
    "compose.yml",
    "docker-compose.yaml",
    "docker-compose.yml",
)
OVERRIDE_NAMES: tuple[str, ...] = (
    "compose.override.yaml",
    "compose.override.yml",
    "docker-compose.override.yaml",
    "docker-compose.override.yml",
)
BASE_OVERRIDE_MAP: dict[str, tuple[str, ...]] = {
    "compose.yaml": ("compose.override.yaml", "compose.override.yml"),
    "compose.yml": ("compose.override.yaml", "compose.override.yml"),
    "docker-compose.yaml": (
        "docker-compose.override.yaml",
        "docker-compose.override.yml",
    ),
    "docker-compose.yml": (
        "docker-compose.override.yaml",
        "docker-compose.override.yml",
    ),
}
YAML_SUFFIXES = frozenset({".yml", ".yaml"})
MAX_YAML_BYTES = 5 * 1024 * 1024
PROTECTED_PATHS: tuple[str, ...] = (
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/var/run",
    "/var/lib/docker",
    "/var/lib/containers",
    "/snap",
    "/boot",
    "/lost+found",
)
SERVICES_RE = re.compile(r"(?m)^[ \t]*services[ \t]*:")


class ScanError(DockerError):
    """Discovery could not be completed."""


@dataclass
class ScanResult:
    projects: list[ComposeProject] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    candidate_count: int = 0
    duration_seconds: float = 0.0


def _is_protected_path(path: Path) -> bool:
    text = os.path.abspath(str(path))
    return any(
        text == protected or text.startswith(protected + os.sep)
        for protected in PROTECTED_PATHS
    )


def _is_within_roots(path: Path, roots: Sequence[Path]) -> bool:
    resolved = path.resolve(strict=False)
    for root in roots:
        try:
            if resolved == root or resolved.is_relative_to(root):
                return True
        except ValueError:
            continue
    return False


def _candidate_name_matches(name: str, all_yaml: bool) -> bool:
    lowered = name.lower()
    if lowered in BASE_NAMES or lowered in OVERRIDE_NAMES:
        return True
    if all_yaml:
        return Path(lowered).suffix in YAML_SUFFIXES
    return "compose" in lowered and Path(lowered).suffix in YAML_SUFFIXES


def _looks_like_compose(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            data = handle.read(256 * 1024)
    except OSError:
        return False
    try:
        text = data.decode("utf-8", "replace")
    except Exception:
        return False
    return SERVICES_RE.search(text) is not None


def scan_candidates(
    config: Config,
    *,
    roots: Optional[Sequence[Path]] = None,
    all_yaml: Optional[bool] = None,
) -> tuple[list[Path], list[str]]:
    """Find plausible Compose files without invoking Docker."""

    warnings: list[str] = []
    include_all_yaml = config.include_all_yaml if all_yaml is None else all_yaml
    selected_roots: list[Path] = []
    for raw_root in roots or config.scan_roots:
        root = Path(raw_root).expanduser()
        if not root.is_absolute():
            root = Path.cwd() / root
        try:
            resolved = root.resolve(strict=True)
        except (OSError, RuntimeError):
            warnings.append(f"scan root does not exist: {root}")
            continue
        if not resolved.is_dir():
            warnings.append(f"scan root is not a directory: {root}")
            continue
        if _is_protected_path(resolved):
            warnings.append(f"refusing to scan protected path: {resolved}")
            continue
        if resolved not in selected_roots:
            selected_roots.append(resolved)

    entries: dict[Path, str] = {}
    for root in selected_roots:
        def onerror(error: OSError, root: Path = root) -> None:
            warnings.append(f"cannot scan {error.filename or root}: {error.strerror}")

        for dirpath, dirnames, filenames in os.walk(
            root,
            topdown=True,
            followlinks=config.follow_symlinks,
            onerror=onerror,
        ):
            current = Path(dirpath)
            try:
                depth = len(current.relative_to(root).parts)
            except ValueError:
                depth = config.max_depth
            if depth >= config.max_depth:
                dirnames[:] = []

            filtered: list[str] = []
            for dirname in sorted(dirnames):
                child = current / dirname
                if dirname in config.exclude_dirs:
                    continue
                if not config.include_hidden and dirname.startswith("."):
                    continue
                if _is_protected_path(child):
                    continue
                if child.is_symlink():
                    if not config.follow_symlinks:
                        continue
                    try:
                        if _is_protected_path(child.resolve(strict=False)):
                            continue
                    except (OSError, RuntimeError):
                        continue
                filtered.append(dirname)
            dirnames[:] = filtered

            for filename in sorted(filenames):
                if Path(filename).suffix.lower() not in YAML_SUFFIXES:
                    continue
                if not _candidate_name_matches(filename, include_all_yaml):
                    continue
                path = current / filename
                try:
                    resolved = path.resolve(strict=True)
                except (OSError, RuntimeError):
                    warnings.append(f"cannot resolve candidate: {path}")
                    continue
                if _is_protected_path(resolved):
                    warnings.append(f"ignoring protected path: {path} -> {resolved}")
                    continue
                if not _is_within_roots(resolved, selected_roots):
                    warnings.append(
                        f"ignoring symlink that escapes scan roots: {path} -> {resolved}"
                    )
                    continue
                try:
                    if resolved.stat().st_size > MAX_YAML_BYTES:
                        warnings.append(
                            f"ignoring oversized Compose file "
                            f"(> {MAX_YAML_BYTES // (1024 * 1024)} MiB): {resolved}"
                        )
                        continue
                except OSError:
                    warnings.append(f"cannot stat candidate: {resolved}")
                    continue
                lowered = filename.lower()
                if lowered not in BASE_NAMES and lowered not in OVERRIDE_NAMES:
                    if not _looks_like_compose(resolved):
                        continue
                entries.setdefault(resolved, lowered)

    # Handle standard Compose file precedence and overrides per directory.
    per_directory: dict[Path, dict[str, Path]] = {}
    for resolved, lowered in entries.items():
        per_directory.setdefault(resolved.parent, {})[lowered] = resolved

    selected: dict[Path, str] = {}
    for directory, names in per_directory.items():
        bases = [name for name in BASE_NAMES if name in names]
        if len(bases) > 1:
            chosen = bases[0]
            warnings.append(
                f"{directory}: multiple base Compose files found; using "
                f"{chosen} and ignoring {', '.join(bases[1:])}"
            )
            for name in bases[1:]:
                names.pop(name, None)
        if bases:
            for override in OVERRIDE_NAMES:
                names.pop(override, None)
        else:
            for override in OVERRIDE_NAMES:
                if override in names:
                    warnings.append(
                        f"{directory}: ignoring {override} because no base "
                        f"compose.yaml/docker-compose.yml exists"
                    )
                    names.pop(override, None)
        for name, resolved in names.items():
            selected[resolved] = name

    return sorted(selected), warnings


def _project_stub(
    files: Sequence[Path],
    *,
    project_name: Optional[str] = None,
    source: str = "scan",
    error: Optional[str] = None,
) -> ComposeProject:
    primary = Path(files[0])
    name = normalize_project_name(project_name or primary.parent.name)
    return ComposeProject(
        files=tuple(Path(path) for path in files),
        project_name=name,
        valid=False,
        error=error,
        source=source,
    )


def _normalise_files(files: Sequence[Path]) -> tuple[Path, ...]:
    normalised: list[Path] = []
    for raw in files:
        path = Path(raw).expanduser()
        if not path.is_absolute():
            path = Path.cwd() / path
        path = path.resolve(strict=False)
        if path not in normalised:
            normalised.append(path)
    return tuple(normalised)


def _with_standard_overrides(files: Sequence[Path]) -> tuple[Path, ...]:
    """Explicitly merge standard override files so they are validated/trusted.

    Using `-f BASE` makes the file list explicit; Compose does not discover a
    sibling compose.override.yaml in that mode. Adding matching overrides both
    preserves normal Compose semantics and lets the root trust check inspect
    them before `up -d`.
    """

    result = list(_normalise_files(files))
    for path in list(result):
        for override_name in BASE_OVERRIDE_MAP.get(path.name.lower(), ()):
            override = (path.parent / override_name).resolve(strict=False)
            if override.exists() and override not in result:
                result.append(override)
    return tuple(result)


def build_project(
    files: Sequence[Path],
    docker: DockerClient,
    *,
    project_name: Optional[str] = None,
    source: str = "scan",
) -> ComposeProject:
    resolved_files = _with_standard_overrides(files)
    for path in resolved_files:
        try:
            if path.stat().st_size > MAX_YAML_BYTES:
                return _project_stub(
                    resolved_files,
                    project_name=project_name,
                    source=source,
                    error=f"Compose file is too large to validate safely: {path}",
                )
        except OSError:
            pass
    try:
        metadata = docker.compose_config(
            resolved_files, project_name=project_name
        )
    except ComposeConfigError as exc:
        return _project_stub(
            resolved_files,
            project_name=project_name,
            source=source,
            error=exc.message,
        )
    reference_warnings, unverified_references = reference_findings(
        resolved_files
    )
    return ComposeProject(
        files=resolved_files,
        project_name=metadata.project_name or normalize_project_name(
            resolved_files[0].parent.name
        ),
        services=list(metadata.analysis.services),
        valid=True,
        error=None,
        warnings=list(metadata.analysis.warnings) + reference_warnings,
        critical_warnings=list(metadata.analysis.critical_warnings),
        env_files=_project_env_files(
            resolved_files[0].parent, metadata.analysis.env_files
        ),
        build_contexts=metadata.analysis.build_contexts,
        extra_files=metadata.analysis.extra_files,
        source=source,
        unverified_references=unverified_references,
    )


def _project_env_files(project_dir: Path, discovered: Sequence[Path]) -> tuple[Path, ...]:
    """Include the automatically loaded project-level .env file in trust checks."""

    env_files = list(discovered)
    dotenv = project_dir / ".env"
    try:
        if dotenv.exists() and dotenv not in env_files:
            env_files.append(dotenv)
    except OSError:
        pass
    return tuple(env_files)


def reference_findings(
    files: Sequence[Path],
) -> tuple[list[str], bool]:
    """Detect include/extends because their referenced files need manual trust."""

    warnings: list[str] = []
    pattern = re.compile(r"(?m)^[ \t]*(include|extends)[ \t]*:")
    unverified = False
    for path in files:
        try:
            size = path.stat().st_size
            if size > MAX_YAML_BYTES:
                warnings.append(
                    f"{path}: too large to inspect for include/extends; "
                    "referenced files could not be trust-checked"
                )
                unverified = True
                continue
            with path.open("rb") as handle:
                text = handle.read(MAX_YAML_BYTES).decode("utf-8", "replace")
        except OSError:
            continue
        match = pattern.search(text)
        if match:
            unverified = True
            warnings.append(
                f"{path}: uses `{match.group(1)}`; referenced files are not "
                "individually trust-checked. Keep the entire project tree "
                "controlled by root/current user, or set "
                "security.allow_unverified_references=true after review."
            )
    return warnings, unverified


def _config_files_from_label(raw: object, working_dir: Optional[str]) -> list[Path]:
    paths: list[Path] = []
    if not isinstance(raw, str):
        return paths
    for piece in raw.split(","):
        piece = piece.strip()
        if not piece:
            continue
        path = Path(piece)
        if not path.is_absolute() and working_dir:
            path = Path(working_dir) / path
        if path not in paths:
            paths.append(path)
    return paths


def _running_groups(
    docker: DockerClient, warnings: list[str]
) -> dict[str, dict[str, object]]:
    """Collect project name -> config files from containers and compose ls."""

    groups: dict[str, dict[str, object]] = {}
    try:
        containers = docker.list_containers(all_containers=True)
    except DockerError as exc:
        warnings.append(f"cannot read running containers: {exc}")
        containers = []

    for container in containers:
        if not container.project:
            continue
        group = groups.setdefault(
            container.project, {"files": [], "working_dir": container.working_dir}
        )
        files = group["files"]
        assert isinstance(files, list)
        for path in container.config_files:
            if path not in files:
                files.append(path)

    try:
        listed = docker.compose_ls()
    except DockerError:
        listed = []
    for item in listed:
        name = item.get("Name")
        if not isinstance(name, str) or not name:
            continue
        group = groups.setdefault(name, {"files": [], "working_dir": None})
        files = group["files"]
        assert isinstance(files, list)
        raw = item.get("ConfigFiles", "")
        working_dir = group.get("working_dir")
        for path in _config_files_from_label(
            raw, str(working_dir) if working_dir else None
        ):
            if path not in files:
                files.append(path)

    return groups


def _merge_running_projects(
    projects: list[ComposeProject],
    docker: DockerClient,
    warnings: list[str],
) -> list[ComposeProject]:
    groups = _running_groups(docker, warnings)
    by_name: dict[str, list[ComposeProject]] = {}
    by_file_set: dict[frozenset[Path], ComposeProject] = {}
    for project in projects:
        by_name.setdefault(project.project_name, []).append(project)
        file_key = frozenset(path.resolve(strict=False) for path in project.files)
        if file_key:
            by_file_set.setdefault(file_key, project)

    for name, group in groups.items():
        raw_files = group.get("files")
        working_dir = group.get("working_dir")
        files = [Path(path) for path in raw_files] if isinstance(raw_files, list) else []
        file_key = frozenset(path.resolve(strict=False) for path in files)
        candidates = by_name.get(name, [])

        # A project started with an explicit `-p` name has the same Compose
        # files as the scanned project but a different project name. Adopt the
        # running name and pass `-p` to every Compose command; otherwise a later
        # `up -d` would create a duplicate project.
        existing_for_files = by_file_set.get(file_key) if file_key else None
        if existing_for_files is not None:
            if existing_for_files.project_name != name:
                old_name = existing_for_files.project_name
                existing_for_files.project_name = normalize_project_name(name)
                by_name.get(old_name, []).remove(existing_for_files)
                by_name.setdefault(existing_for_files.project_name, []).append(
                    existing_for_files
                )
                warnings.append(
                    f"{existing_for_files.primary_file}: using running project name "
                    f"{existing_for_files.project_name!r} instead of derived "
                    f"{old_name!r}; add a top-level `name: "
                    f"{existing_for_files.project_name}` to make this explicit"
                )
            if existing_for_files.source == "scan":
                existing_for_files.source = "scan+running"
            continue

        if candidates:
            existing = candidates[0]
            existing_set = {path.resolve(strict=False) for path in existing.files}
            running_set = {path.resolve(strict=False) for path in files}
            same_or_subset = (
                not files
                or existing_set == running_set
                or existing_set.issubset(running_set)
                or running_set.issubset(existing_set)
            )
            if same_or_subset:
                if existing.source == "scan":
                    existing.source = "scan+running"
                continue
            existing.blockers.append(
                f"project name {name!r} is also used by running containers with "
                f"different config files: {', '.join(str(path) for path in files) or 'unknown'}"
            )
            continue

        if files:
            project = build_project(files, docker, project_name=name, source="running")
            if project.project_name != name:
                project.project_name = normalize_project_name(name)
            projects.append(project)
            by_name.setdefault(name, []).append(project)
            by_file_set.setdefault(file_key, project)
        else:
            projects.append(
                _project_stub(
                    [Path(f"<unknown:{name}>")],
                    project_name=name,
                    source="running",
                    error="running project has no compose config file label",
                )
            )

    # Duplicate names among scanned/custom files make project-scoped mutations
    # ambiguous: Compose would operate on the same project for both files.
    grouped: dict[str, list[ComposeProject]] = {}
    for project in projects:
        grouped.setdefault(project.project_name, []).append(project)
    for name, group in grouped.items():
        if len(group) > 1:
            paths = ", ".join(str(project.primary_file) for project in group)
            for project in group:
                project.blockers.append(
                    f"project name {name!r} is shared by multiple Compose files: {paths}; "
                    "give each project a unique top-level `name:` or move the files "
                    "into separate directories"
                )

    return projects


def scan_projects(
    config: Config,
    docker: DockerClient,
    *,
    roots: Optional[Sequence[Path]] = None,
    all_yaml: Optional[bool] = None,
    include_running: bool = True,
) -> ScanResult:
    started = time.monotonic()
    candidates, warnings = scan_candidates(config, roots=roots, all_yaml=all_yaml)
    projects: list[ComposeProject] = []
    for candidate in candidates:
        projects.append(build_project([candidate], docker, source="scan"))
    if include_running:
        projects = _merge_running_projects(projects, docker, warnings)
    projects.sort(key=lambda project: (project.project_name, str(project.primary_file)))
    return ScanResult(
        projects=projects,
        warnings=warnings,
        candidate_count=len(candidates),
        duration_seconds=time.monotonic() - started,
    )


def project_matches(project: ComposeProject, query: str) -> bool:
    lowered = query.strip().lower()
    if not lowered:
        return False
    if project.project_name.lower() == lowered:
        return True
    for path in project.files:
        if str(path).lower() == lowered or str(path.resolve(strict=False)).lower() == lowered:
            return True
    return False


def select_projects(
    projects: Sequence[ComposeProject], queries: Sequence[str]
) -> tuple[list[ComposeProject], list[str]]:
    """Resolve exact names/paths, then allow a unique substring match."""

    selected: list[ComposeProject] = []
    errors: list[str] = []
    for query in queries:
        matches = [project for project in projects if project_matches(project, query)]
        if not matches:
            matches = [
                project
                for project in projects
                if query.lower() in project.project_name.lower()
                or any(
                    query.lower() in str(path).lower() for path in project.files
                )
            ]
        unique: list[ComposeProject] = []
        for project in matches:
            if project not in unique:
                unique.append(project)
        if not unique:
            errors.append(f"no project matches {query!r}")
        elif len(unique) > 1:
            names = ", ".join(
                f"{project.project_name} ({project.primary_file})"
                for project in unique
            )
            errors.append(f"{query!r} is ambiguous; matches: {names}")
        else:
            if unique[0] not in selected:
                selected.append(unique[0])
    return selected, errors


def project_to_dict(project: ComposeProject) -> dict[str, object]:
    return {
        "project": project.project_name,
        "files": [str(path) for path in project.files],
        "source": project.source,
        "unverified_references": project.unverified_references,
        "valid": project.valid,
        "error": project.error,
        "blockers": list(project.blockers),
        "warnings": list(project.warnings),
        "critical_warnings": list(project.critical_warnings),
        "env_files": [str(path) for path in project.env_files],
        "build_contexts": [str(path) for path in project.build_contexts],
        "extra_files": [str(path) for path in project.extra_files],
        "services": [
            {
                "name": service.name,
                "image": service.image,
                "build": service.has_build,
                "build_context": service.build_context,
                "env_files": [str(path) for path in service.env_files],
                "warnings": list(service.warnings),
                "critical_warnings": list(service.critical_warnings),
            }
            for service in project.services
        ],
    }


def container_to_dict(container: object) -> dict[str, object]:
    return {
        "id": getattr(container, "id", ""),
        "name": getattr(container, "name", ""),
        "image": getattr(container, "image", ""),
        "image_id": getattr(container, "image_id", ""),
        "state": getattr(container, "state", ""),
        "status": getattr(container, "status", ""),
        "health": getattr(container, "health", ""),
        "restart_count": getattr(container, "restart_count", 0),
        "exit_code": getattr(container, "exit_code", None),
        "project": getattr(container, "project", None),
        "service": getattr(container, "service", None),
        "config_files": [
            str(path) for path in getattr(container, "config_files", ())
        ],
        "ports": list(getattr(container, "ports", ())),
        "created": getattr(container, "created", ""),
    }


def summarize_scan(result: ScanResult) -> str:
    valid = sum(1 for project in result.projects if project.valid)
    invalid = len(result.projects) - valid
    return (
        f"{len(result.projects)} project(s): {valid} valid, {invalid} invalid "
        f"({result.candidate_count} candidate file(s), "
        f"{result.duration_seconds:.1f}s)"
    )


def aggregate_warnings(projects: Iterable[ComposeProject]) -> list[str]:
    warnings: list[str] = []
    for project in projects:
        for warning in [*project.warnings, *project.critical_warnings, *project.blockers]:
            if warning not in warnings:
                warnings.append(warning)
    return warnings
