"""Configuration loading and validation.

The configuration intentionally uses INI rather than TOML so the tool can run
on older distribution Python versions (3.9+) with the standard library only.
The default config is root-controlled; this is a security boundary because the
tool runs docker commands with root-equivalent privileges.
"""

from __future__ import annotations

import configparser
import os
import stat as stat_module
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Sequence

from .runner import DockerMgmtError


class ConfigError(DockerMgmtError):
    """Invalid or unsafe configuration."""


DEFAULT_SCAN_ROOTS: tuple[str, ...] = (
    "/opt",
    "/srv",
    "/var/www",
    "/home",
    "/root",
)

DEFAULT_EXCLUDES: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".cache",
        ".npm",
        ".cargo",
        ".rustup",
        ".gradle",
        ".m2",
        ".venv",
        "venv",
        "__pycache__",
        "node_modules",
        "lost+found",
        "snap",
    }
)

_KNOWN_KEYS: dict[str, set[str]] = {
    "scan": {
        "roots",
        "include_all_yaml",
        "max_depth",
        "include_hidden",
        "follow_symlinks",
        "exclude_dirs",
    },
    "compose": {
        "command_timeout_seconds",
        "pull_timeout_seconds",
        "up_timeout_seconds",
        "wait_after_update",
        "wait_timeout_seconds",
    },
    "audit": {"path", "max_bytes"},
    "ui": {"color", "page_size"},
    "security": {"allow_unsafe_ownership", "allow_unverified_references"},
}


@dataclass
class Config:
    config_path: Optional[Path]
    scan_roots: tuple[Path, ...]
    include_all_yaml: bool = False
    max_depth: int = 8
    include_hidden: bool = False
    follow_symlinks: bool = False
    exclude_dirs: frozenset[str] = DEFAULT_EXCLUDES
    command_timeout: int = 120
    pull_timeout: int = 900
    up_timeout: int = 300
    wait_after_update: bool = False
    wait_timeout: int = 120
    audit_path: Path = Path("/var/log/docker-mgmt/audit.log")
    audit_max_bytes: int = 10 * 1024 * 1024
    color: bool = True
    page_size: int = 20
    allow_unsafe_ownership: bool = False
    allow_unverified_references: bool = False
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def config_display(self) -> str:
        return str(self.config_path) if self.config_path else "built-in defaults"

    @property
    def lock_path(self) -> Path:
        return default_lock_path()

    def as_dict(self) -> dict[str, object]:
        return {
            "config_path": self.config_display,
            "scan_roots": [str(path) for path in self.scan_roots],
            "include_all_yaml": self.include_all_yaml,
            "max_depth": self.max_depth,
            "include_hidden": self.include_hidden,
            "follow_symlinks": self.follow_symlinks,
            "exclude_dirs": sorted(self.exclude_dirs),
            "command_timeout_seconds": self.command_timeout,
            "pull_timeout_seconds": self.pull_timeout,
            "up_timeout_seconds": self.up_timeout,
            "wait_after_update": self.wait_after_update,
            "wait_timeout_seconds": self.wait_timeout,
            "audit_path": str(self.audit_path),
            "audit_max_bytes": self.audit_max_bytes,
            "color": self.color,
            "page_size": self.page_size,
            "allow_unsafe_ownership": self.allow_unsafe_ownership,
            "allow_unverified_references": self.allow_unverified_references,
            "warnings": list(self.warnings),
        }


def default_config_path() -> Path:
    if os.geteuid() == 0:
        return Path("/etc/docker-mgmt/config.ini")
    return Path.home() / ".config" / "docker-mgmt" / "config.ini"


def default_audit_path() -> Path:
    if os.geteuid() == 0:
        return Path("/var/log/docker-mgmt/audit.log")
    state_home = os.environ.get("XDG_STATE_HOME")
    if state_home:
        return Path(state_home) / "docker-mgmt" / "audit.log"
    return Path.home() / ".local" / "state" / "docker-mgmt" / "audit.log"


def default_lock_path() -> Path:
    override = os.environ.get("DOCKER_MGMT_LOCK")
    if override:
        return Path(override).expanduser()
    if os.geteuid() == 0:
        return Path("/run/docker-mgmt/docker-mgmt.lock")
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if runtime:
        return Path(runtime) / "docker-mgmt.lock"
    return Path(tempfile.gettempdir()) / f"docker-mgmt-{os.geteuid()}" / "docker-mgmt.lock"


def _resolve_config_candidate(explicit: Optional[str]) -> tuple[Optional[Path], bool]:
    """Return (path, required). A default path may be absent."""

    env_path = os.environ.get("DOCKER_MGMT_CONFIG")
    chosen = explicit or env_path
    if chosen:
        path = Path(chosen).expanduser()
        if not path.is_absolute():
            path = Path.cwd() / path
        return path, True

    candidates = [default_config_path()]
    for candidate in candidates:
        if candidate.exists():
            return candidate, False
    return None, False


def _check_config_permissions(path: Path) -> None:
    euid = os.geteuid()
    if euid == 0 and path.is_symlink():
        raise ConfigError(
            f"refusing to load symlinked config {path} as root; use a root-owned "
            "regular file so a writable parent cannot redirect configuration"
        )
    try:
        resolved = path.resolve()
    except (OSError, RuntimeError) as exc:
        raise ConfigError(f"cannot resolve config path {path}: {exc}") from exc
    try:
        stat = resolved.stat()
    except OSError as exc:
        raise ConfigError(f"cannot stat config file {resolved}: {exc}") from exc
    if not stat_module.S_ISREG(stat.st_mode):
        raise ConfigError(f"config path is not a regular file: {resolved}")

    # A config file is a control input for a Docker-privileged process. Whether
    # we run as root or as a user with Docker access, another local user who can
    # modify it can redirect the tool to attacker-controlled Compose files.
    allowed_owners = {0, euid}
    for parent in resolved.parents:
        try:
            parent_stat = parent.stat()
        except OSError as exc:
            raise ConfigError(
                f"cannot stat config directory {parent}: {exc}"
            ) from exc
        mode = parent_stat.st_mode
        sticky_world_writable = bool((mode & 0o1000) and (mode & 0o022))
        if (
            parent_stat.st_uid not in allowed_owners
            or (mode & 0o022 and not sticky_world_writable)
        ):
            raise ConfigError(
                f"refusing to load {resolved}: config directory {parent} is not "
                "controlled by root or the current user, or is group/world-writable"
            )
    if stat.st_uid not in allowed_owners:
        raise ConfigError(
            f"refusing to load {resolved}: it is owned by uid {stat.st_uid}, "
            "not root or the current user. Another user could change what this "
            "Docker-privileged tool executes."
        )
    if stat.st_mode & 0o022:
        raise ConfigError(
            f"refusing to load {resolved}: it is group- or world-writable "
            f"(mode {stat.st_mode & 0o777:04o}). Run `chmod 0644` on it."
        )


def _find_section(parser: configparser.ConfigParser, name: str) -> Optional[str]:
    for section in parser.sections():
        if section.lower() == name:
            return section
    return None


def _get(
    parser: configparser.ConfigParser, section: str, key: str, default: str
) -> str:
    actual = _find_section(parser, section)
    if actual is not None and parser.has_option(actual, key):
        return parser.get(actual, key)
    return default


def _parse_bool(
    value: str, *, name: str, default: bool, warnings: list[str]
) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "yes", "true", "on"}:
        return True
    if normalized in {"0", "no", "false", "off"}:
        return False
    warnings.append(f"invalid boolean for {name}: {value!r}; using {default}")
    return default


def _parse_int(
    value: str,
    *,
    name: str,
    default: int,
    minimum: int,
    maximum: int,
    warnings: list[str],
) -> int:
    try:
        parsed = int(value.strip())
    except (TypeError, ValueError):
        warnings.append(f"invalid integer for {name}: {value!r}; using {default}")
        return default
    if parsed < minimum or parsed > maximum:
        warnings.append(
            f"{name}={parsed} is outside {minimum}..{maximum}; using {default}"
        )
        return default
    return parsed


def _parse_list(value: str) -> list[str]:
    items: list[str] = []
    for raw in value.replace("\n", ",").split(","):
        item = raw.strip().strip("'\"")
        if item:
            items.append(item)
    return items


def _resolve_path(value: str, base: Path) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = base / path
    return path.resolve(strict=False)


def _unknown_keys(parser: configparser.ConfigParser, warnings: list[str]) -> None:
    for section in parser.sections():
        lowered = section.lower()
        if lowered not in _KNOWN_KEYS:
            warnings.append(f"unknown config section [{section}] ignored")
            continue
        for key in parser.options(section):
            if key.lower() not in _KNOWN_KEYS[lowered]:
                warnings.append(f"unknown config key {section}.{key} ignored")


def load_config(
    explicit_path: Optional[str] = None,
    *,
    roots_override: Optional[Sequence[str]] = None,
    all_yaml_override: Optional[bool] = None,
    no_color: bool = False,
) -> Config:
    """Load configuration, apply CLI overrides, and enforce file permissions."""

    warnings: list[str] = []
    path, required = _resolve_config_candidate(explicit_path)
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str.lower  # type: ignore[assignment]

    if path is not None and path.exists():
        _check_config_permissions(path)
        try:
            with path.open("r", encoding="utf-8") as handle:
                parser.read_file(handle)
        except OSError as exc:
            raise ConfigError(f"cannot read config file {path}: {exc}") from exc
        except configparser.Error as exc:
            raise ConfigError(f"invalid config file {path}: {exc}") from exc
        _unknown_keys(parser, warnings)
    elif path is not None and required:
        raise ConfigError(f"config file not found: {path}")
    elif path is not None and not path.exists():
        warnings.append(f"config file {path} does not exist; using built-in defaults")
        path = None

    base = path.parent if path else Path.cwd()

    roots_raw = _get(parser, "scan", "roots", ",".join(DEFAULT_SCAN_ROOTS))
    if roots_override is not None:
        roots_raw = ",".join(roots_override)
    roots: list[Path] = []
    for item in _parse_list(roots_raw):
        resolved = _resolve_path(item, base)
        if resolved not in roots:
            roots.append(resolved)
    if not roots:
        roots = [_resolve_path(item, base) for item in DEFAULT_SCAN_ROOTS]
        warnings.append("scan.roots is empty; using built-in defaults")

    include_all_yaml = _parse_bool(
        _get(parser, "scan", "include_all_yaml", "false"),
        name="scan.include_all_yaml",
        default=False,
        warnings=warnings,
    )
    if all_yaml_override:
        include_all_yaml = True

    max_depth = _parse_int(
        _get(parser, "scan", "max_depth", "8"),
        name="scan.max_depth",
        default=8,
        minimum=1,
        maximum=32,
        warnings=warnings,
    )
    include_hidden = _parse_bool(
        _get(parser, "scan", "include_hidden", "false"),
        name="scan.include_hidden",
        default=False,
        warnings=warnings,
    )
    follow_symlinks = _parse_bool(
        _get(parser, "scan", "follow_symlinks", "false"),
        name="scan.follow_symlinks",
        default=False,
        warnings=warnings,
    )

    extra_excludes = set()
    for item in _parse_list(_get(parser, "scan", "exclude_dirs", "")):
        name = Path(item).name
        if name and name not in {".", ".."}:
            extra_excludes.add(name)
    excludes = frozenset(DEFAULT_EXCLUDES | extra_excludes)

    command_timeout = _parse_int(
        _get(parser, "compose", "command_timeout_seconds", "120"),
        name="compose.command_timeout_seconds",
        default=120,
        minimum=5,
        maximum=7200,
        warnings=warnings,
    )
    pull_timeout = _parse_int(
        _get(parser, "compose", "pull_timeout_seconds", "900"),
        name="compose.pull_timeout_seconds",
        default=900,
        minimum=5,
        maximum=7200,
        warnings=warnings,
    )
    up_timeout = _parse_int(
        _get(parser, "compose", "up_timeout_seconds", "300"),
        name="compose.up_timeout_seconds",
        default=300,
        minimum=5,
        maximum=7200,
        warnings=warnings,
    )
    wait_after_update = _parse_bool(
        _get(parser, "compose", "wait_after_update", "false"),
        name="compose.wait_after_update",
        default=False,
        warnings=warnings,
    )
    wait_timeout = _parse_int(
        _get(parser, "compose", "wait_timeout_seconds", "120"),
        name="compose.wait_timeout_seconds",
        default=120,
        minimum=5,
        maximum=3600,
        warnings=warnings,
    )

    audit_raw = _get(parser, "audit", "path", "").strip()
    audit_path = (
        _resolve_path(audit_raw, base) if audit_raw else default_audit_path()
    )
    audit_max_bytes = _parse_int(
        _get(parser, "audit", "max_bytes", str(10 * 1024 * 1024)),
        name="audit.max_bytes",
        default=10 * 1024 * 1024,
        minimum=4096,
        maximum=1024 * 1024 * 1024,
        warnings=warnings,
    )

    color_raw = _get(parser, "ui", "color", "auto").strip().lower()
    if color_raw not in {"auto", "always", "never"}:
        warnings.append(f"invalid ui.color {color_raw!r}; using auto")
        color_raw = "auto"
    color = color_raw != "never"
    if color_raw == "auto":
        color = os.isatty(1)
    if no_color or os.environ.get("NO_COLOR") is not None:
        color = False

    page_size = _parse_int(
        _get(parser, "ui", "page_size", "20"),
        name="ui.page_size",
        default=20,
        minimum=5,
        maximum=100,
        warnings=warnings,
    )

    allow_unsafe_ownership = _parse_bool(
        _get(parser, "security", "allow_unsafe_ownership", "false"),
        name="security.allow_unsafe_ownership",
        default=False,
        warnings=warnings,
    )
    allow_unverified_references = _parse_bool(
        _get(parser, "security", "allow_unverified_references", "false"),
        name="security.allow_unverified_references",
        default=False,
        warnings=warnings,
    )
    if allow_unsafe_ownership:
        warnings.append(
            "security.allow_unsafe_ownership is enabled; Compose files, .env "
            "files or build contexts not controlled by root/current user will be accepted"
        )
    if allow_unverified_references:
        warnings.append(
            "security.allow_unverified_references is enabled; include/extends "
            "files are not individually trust-checked"
        )

    return Config(
        config_path=path,
        scan_roots=tuple(roots),
        include_all_yaml=include_all_yaml,
        max_depth=max_depth,
        include_hidden=include_hidden,
        follow_symlinks=follow_symlinks,
        exclude_dirs=excludes,
        command_timeout=command_timeout,
        pull_timeout=pull_timeout,
        up_timeout=up_timeout,
        wait_after_update=wait_after_update,
        wait_timeout=wait_timeout,
        audit_path=audit_path,
        audit_max_bytes=audit_max_bytes,
        color=color,
        page_size=page_size,
        allow_unsafe_ownership=allow_unsafe_ownership,
        allow_unverified_references=allow_unverified_references,
        warnings=tuple(warnings),
    )
