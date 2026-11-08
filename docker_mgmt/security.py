"""Compose security analysis and filesystem trust checks.

Two separate concerns are handled here:

1. Static review of the resolved Compose model (privileged containers, host
   namespaces, Docker socket mounts, mutable image tags, wildcard ports, ...).
2. Trust of the files that a Docker-privileged run will consume before
   `compose up`. If another local user can change a Compose file, .env file, or
   build context, that user can leverage Docker access. Such projects are
   blocked from mutating actions unless the operator explicitly opts out.
"""

from __future__ import annotations

import os
import stat as stat_module
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional, Sequence

from .models import ServiceInfo


@dataclass
class ComposeAnalysis:
    services: list[ServiceInfo] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    critical_warnings: list[str] = field(default_factory=list)
    env_files: tuple[Path, ...] = ()
    build_contexts: tuple[Path, ...] = ()
    extra_files: tuple[Path, ...] = ()


def _append_unique(target: list[str], value: str) -> None:
    if value not in target:
        target.append(value)


def _as_list(value: object) -> list[object]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _resolve_local_path(value: str, base: Path) -> Optional[Path]:
    if not value:
        return None
    if "://" in value or value.startswith("git@") or value.startswith("github.com/"):
        return None
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = base / path
    return path.resolve(strict=False)


def image_is_mutable(image: Optional[str]) -> bool:
    """Return True for floating tags that commonly change under the operator."""

    if not image:
        return False
    if "@sha256:" in image:
        return False
    reference = image.split("@", 1)[0]
    last = reference.rsplit("/", 1)[-1]
    if ":" in last:
        tag = last.rsplit(":", 1)[1]
    else:
        tag = "latest"
    return tag in {
        "latest",
        "stable",
        "main",
        "master",
        "edge",
        "nightly",
        "dev",
        "rolling",
    }


def _volume_source(volume: object) -> Optional[str]:
    if isinstance(volume, dict):
        source = volume.get("source")
        if isinstance(source, str) and source:
            return source
        return None
    if isinstance(volume, str):
        # Short syntax: [source:]target[:mode]
        parts = volume.split(":")
        if len(parts) >= 2 and parts[0] and not parts[0].startswith("/"):
            return parts[0]
        if len(parts) >= 2 and parts[0].startswith("/"):
            return parts[0]
    return None


def _is_sensitive_mount(source: str) -> Optional[str]:
    normalized = os.path.normpath(source)
    if normalized in {
        "/",
        "/etc",
        "/root",
        "/var/lib/docker",
        "/var/run",
        "/run",
        "/boot",
        "/dev",
        "/proc",
        "/sys",
        "/var/run/docker.sock",
        "/run/docker.sock",
    }:
        return "sensitive host path"
    for prefix, reason in (
        ("/var/run/", "sensitive host path"),
        ("/run/", "sensitive host path"),
        ("/var/lib/docker/", "Docker daemon state"),
        ("/etc/", "system configuration"),
        ("/root/", "root home directory"),
        ("/boot/", "boot files"),
        ("/dev/", "host devices"),
        ("/proc/", "host process information"),
        ("/sys/", "host kernel interfaces"),
    ):
        if normalized.startswith(prefix):
            return reason
    if normalized.endswith("/docker.sock"):
        return "Docker socket"
    return None


def _env_file_paths(service: dict[str, object], project_dir: Path) -> list[Path]:
    paths: list[Path] = []
    for entry in _as_list(service.get("env_file")):
        raw: Optional[str] = None
        if isinstance(entry, str):
            raw = entry
        elif isinstance(entry, dict):
            value = entry.get("path")
            if isinstance(value, str):
                raw = value
        if raw:
            resolved = _resolve_local_path(raw, project_dir)
            if resolved is not None and resolved not in paths:
                paths.append(resolved)
    return paths


def _build_context(service: dict[str, object], project_dir: Path) -> Optional[Path]:
    build = service.get("build")
    raw: Optional[str] = None
    if isinstance(build, str):
        raw = build
    elif isinstance(build, dict):
        value = build.get("context")
        if isinstance(value, str):
            raw = value
    if not raw:
        return None
    return _resolve_local_path(raw, project_dir)


def _build_dockerfile(
    service: dict[str, object], context: Optional[Path]
) -> Optional[Path]:
    if context is None:
        return None
    build = service.get("build")
    if not isinstance(build, dict):
        raw = "Dockerfile"
    else:
        if build.get("dockerfile_inline"):
            return None
        value = build.get("dockerfile")
        raw = value if isinstance(value, str) and value else "Dockerfile"
    dockerfile = Path(raw).expanduser()
    if not dockerfile.is_absolute():
        dockerfile = context / dockerfile
    return dockerfile.resolve(strict=False)


def analyze_compose(data: dict[str, object], project_dir: Path) -> ComposeAnalysis:
    """Extract service metadata and security findings from `compose config` JSON."""

    result = ComposeAnalysis()
    services_obj = data.get("services")
    if not isinstance(services_obj, dict):
        return result

    env_files: list[Path] = []
    build_contexts: list[Path] = []
    extra_files: list[Path] = []

    for raw_name, raw_service in services_obj.items():
        name = str(raw_name)
        service = raw_service if isinstance(raw_service, dict) else {}
        info = ServiceInfo(name=name)

        image = service.get("image")
        if isinstance(image, str) and image:
            info.image = image
            if image_is_mutable(image):
                message = (
                    f"{name}: image {image!r} uses a floating tag; pin a version "
                    "or digest for reproducible, reviewable updates"
                )
                _append_unique(result.warnings, message)

        build = service.get("build")
        if build is not None:
            info.has_build = True
            context = _build_context(service, project_dir)
            if context is not None:
                info.build_context = str(context)
                if context not in build_contexts:
                    build_contexts.append(context)
                dockerfile = _build_dockerfile(service, context)
                if dockerfile is not None and dockerfile not in extra_files:
                    extra_files.append(dockerfile)
                message = (
                    f"{name}: build context contents are not recursively "
                    "trust-checked; keep the whole context controlled by "
                    "root/current user"
                )
                info.warnings.append(message)
                _append_unique(result.warnings, message)
            else:
                message = (
                    f"{name}: build context is remote or unresolved and cannot be "
                    "root-trust-checked"
                )
                info.warnings.append(message)
                _append_unique(result.warnings, message)

        service_env_files = _env_file_paths(service, project_dir)
        info.env_files = tuple(service_env_files)
        for path in service_env_files:
            if path not in env_files:
                env_files.append(path)

        if service.get("privileged") is True:
            message = f"{name}: privileged container (full host capabilities)"
            info.critical_warnings.append(message)
            _append_unique(result.critical_warnings, message)

        for key in ("network_mode", "pid", "ipc", "userns_mode"):
            value = service.get(key)
            if isinstance(value, str) and value == "host":
                message = f"{name}: host {key} namespace"
                info.critical_warnings.append(message)
                _append_unique(result.critical_warnings, message)

        cap_add = [str(item) for item in _as_list(service.get("cap_add"))]
        for capability in cap_add:
            upper = capability.upper()
            if upper in {"ALL", "SYS_ADMIN", "SYS_PTRACE"}:
                message = f"{name}: dangerous capability added: {capability}"
                info.critical_warnings.append(message)
                _append_unique(result.critical_warnings, message)
            elif upper.startswith("SYS_") or upper in {"NET_ADMIN", "NET_RAW"}:
                message = f"{name}: elevated capability added: {capability}"
                info.warnings.append(message)
                _append_unique(result.warnings, message)

        security_opt = [str(item) for item in _as_list(service.get("security_opt"))]
        for option in security_opt:
            lowered = option.lower()
            if "unconfined" in lowered:
                message = f"{name}: security sandbox disabled: {option}"
                info.critical_warnings.append(message)
                _append_unique(result.critical_warnings, message)

        for volume in _as_list(service.get("volumes")):
            source = _volume_source(volume)
            if source is None:
                continue
            if source.endswith("docker.sock"):
                message = f"{name}: mounts the Docker socket ({source})"
                info.critical_warnings.append(message)
                _append_unique(result.critical_warnings, message)
                continue
            reason = _is_sensitive_mount(source)
            if reason:
                message = f"{name}: mounts {reason} {source!r}"
                info.critical_warnings.append(message)
                _append_unique(result.critical_warnings, message)

        for port in _as_list(service.get("ports")):
            if not isinstance(port, dict):
                continue
            published = port.get("published")
            if published in (None, ""):
                continue
            host_ip = port.get("host_ip")
            if host_ip in (None, "", "0.0.0.0", "::"):
                message = (
                    f"{name}: publishes port {published} on all host interfaces; "
                    "bind to 127.0.0.1 or a firewall-protected address if it "
                    "should not be public"
                )
                info.warnings.append(message)
                _append_unique(result.warnings, message)

        if _as_list(service.get("devices")):
            message = f"{name}: maps host devices into the container"
            info.warnings.append(message)
            _append_unique(result.warnings, message)

        result.services.append(info)

    for section in ("secrets", "configs"):
        entries = data.get(section)
        if not isinstance(entries, dict):
            continue
        for entry in entries.values():
            if not isinstance(entry, dict):
                continue
            raw = entry.get("file")
            if not isinstance(raw, str):
                continue
            resolved = _resolve_local_path(raw, project_dir)
            if resolved is not None and resolved not in extra_files:
                extra_files.append(resolved)

    result.env_files = tuple(env_files)
    result.build_contexts = tuple(build_contexts)
    result.extra_files = tuple(extra_files)
    return result


def _path_chain(path: Path) -> list[Path]:
    """Return a path plus its parent chain, resolving symlinks where possible."""

    candidates: list[Path] = []
    absolute = path.expanduser()
    if not absolute.is_absolute():
        absolute = Path.cwd() / absolute
    for candidate in (absolute, absolute.resolve(strict=False)):
        if candidate not in candidates:
            candidates.append(candidate)
    resolved_chain: list[Path] = []
    try:
        resolved = absolute.resolve(strict=True)
    except (OSError, RuntimeError):
        resolved = absolute.resolve(strict=False)
    for candidate in [resolved, *resolved.parents]:
        if candidate not in resolved_chain:
            resolved_chain.append(candidate)
    for candidate in [absolute, *absolute.parents]:
        if candidate not in resolved_chain:
            resolved_chain.append(candidate)
    return resolved_chain


def check_path_trust(path: Path, *, euid: Optional[int] = None) -> list[str]:
    """Return trust problems for a file/directory a Docker-privileged run consumes.

    Docker access is root-equivalent even when the operator is only in the
    docker group. Therefore a file is trusted only if it is owned by root or the
    current user and no component is group/world-writable. Sticky root-owned
    directories such as /tmp are tolerated because non-owners cannot remove a
    root-owned entry there.
    """

    euid = os.geteuid() if euid is None else euid
    allowed_owners = {0, euid}
    issues: list[str] = []
    seen: set[tuple[str, str]] = set()
    target = path.expanduser()
    if not target.is_absolute():
        target = Path.cwd() / target
    try:
        target_resolved = target.resolve(strict=False)
    except (OSError, RuntimeError):
        target_resolved = target
    target_candidates = {target, target_resolved}
    for item in _path_chain(path):
        try:
            stat = item.stat()
        except OSError:
            if item in target_candidates:
                issues.append(f"{item} does not exist or is not readable")
            continue
        if stat.st_uid not in allowed_owners:
            key = (str(item), "owner")
            if key not in seen:
                seen.add(key)
                issues.append(
                    f"{item} is owned by uid {stat.st_uid}; root or current-user "
                    "ownership is required"
                )
        if stat.st_mode & 0o022:
            is_dir = stat_module.S_ISDIR(stat.st_mode)
            sticky = bool(stat.st_mode & 0o1000)
            # A sticky parent such as /tmp is acceptable for a file because
            # non-owners cannot remove a root/current-user-owned entry there.
            # A sticky directory used *as the target* (for example a shared
            # build context) is writable by others and is not trusted.
            if is_dir and sticky and item not in target_candidates:
                continue
            key = (str(item), "mode")
            if key not in seen:
                seen.add(key)
                if is_dir and sticky:
                    issues.append(
                        f"{item} is a sticky group/world-writable target directory "
                        f"(mode {stat.st_mode & 0o777:04o})"
                    )
                else:
                    issues.append(
                        f"{item} is group/world-writable (mode {stat.st_mode & 0o777:04o})"
                    )
    return issues


def check_project_trust(
    files: Sequence[Path],
    env_files: Sequence[Path] = (),
    build_contexts: Sequence[Path] = (),
    extra_files: Sequence[Path] = (),
    *,
    euid: Optional[int] = None,
) -> list[str]:
    """Check every local file/directory that can influence `compose up`."""

    issues: list[str] = []
    seen: set[str] = set()
    for path in [*files, *env_files, *build_contexts, *extra_files]:
        for issue in check_path_trust(Path(path), euid=euid):
            if issue not in seen:
                seen.add(issue)
                issues.append(issue)
    return issues


def installation_warnings(*, euid: Optional[int] = None) -> list[str]:
    """Warn when a root run uses code from a non-root-controlled checkout.

    The check cannot protect an already-compromised process, but it avoids the
    common mistake of running `sudo ./docker-mgmt` from a user-writable home
    directory in production.
    """

    euid = os.geteuid() if euid is None else euid
    if euid != 0:
        return []
    package_dir = Path(__file__).resolve().parent
    paths = [package_dir, *sorted(package_dir.glob("*.py"))]
    wrapper = package_dir.parent / "docker-mgmt"
    if wrapper.exists():
        paths.append(wrapper)
    issues: list[str] = []
    seen: set[str] = set()
    for path in paths:
        for issue in check_path_trust(path, euid=0):
            if issue not in seen:
                seen.add(issue)
                issues.append(issue)
    if not issues:
        return []
    return [
        "docker-mgmt is running as root from a path that is not fully "
        "root-controlled; a local user could modify code executed as root. "
        "Install or copy it to a root-owned directory (for example "
        "/opt/docker-mgmt) and run it from there."
    ] + issues[:5]


def collect_all_warnings(projects: Iterable[object]) -> list[str]:
    """Compatibility helper used by tests and reports."""

    warnings: list[str] = []
    for project in projects:
        for warning in getattr(project, "warnings", []):
            _append_unique(warnings, str(warning))
        for warning in getattr(project, "critical_warnings", []):
            _append_unique(warnings, str(warning))
    return warnings
