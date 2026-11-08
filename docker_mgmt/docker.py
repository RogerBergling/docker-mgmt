"""Thin, explicit wrapper around the Docker and Docker Compose CLIs.

This module deliberately does not use the Docker SDK and never mounts or
connects to the Docker socket itself. It shells out to the operator's `docker`
binary with argument vectors (never shell=True). The same privilege model as
running `docker` manually therefore applies.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

from .config import Config
from .models import Container
from .runner import (
    CommandResult,
    CommandRunner,
    DockerMgmtError,
    format_command,
    sanitize_text,
    summarize_output,
)
from .security import ComposeAnalysis, analyze_compose, check_path_trust


class DockerError(DockerMgmtError):
    """Docker or Docker Compose command failure."""


class DockerUnavailable(DockerError):
    """The Docker CLI or daemon is missing/unreachable."""


class ComposeConfigError(DockerError):
    """A Compose file could not be parsed or validated."""

    def __init__(self, files: Sequence[Path], message: str) -> None:
        self.files = tuple(files)
        self.message = message
        super().__init__(message)


@dataclass
class ComposeMetadata:
    project_name: str
    analysis: ComposeAnalysis


def normalize_project_name(value: str) -> str:
    """Approximate Compose's project-name normalisation."""

    lowered = value.lower()
    cleaned = re.sub(r"[^a-z0-9_-]", "", lowered)
    cleaned = cleaned.lstrip("_-")
    return cleaned or "default"


def parse_json_records(text: str) -> list[object]:
    """Parse a JSON array, a single object, or JSON Lines output."""

    text = (text or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        records: list[object] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return records
    if isinstance(data, list):
        return data
    return [data]


def _is_unknown_flag(result: CommandResult) -> bool:
    text = (result.stderr + "\n" + result.stdout).lower()
    return "unknown flag" in text or "unknown shorthand flag" in text


class DockerClient:
    def __init__(self, runner: CommandRunner, config: Config) -> None:
        self.runner = runner
        self.config = config
        found = shutil.which("docker")
        self.docker = str(Path(found).resolve()) if found else "docker"
        self._compose_version: Optional[tuple[int, int, int]] = None
        self._compose_version_string: Optional[str] = None
        self._server_version: Optional[str] = None

    # ------------------------------------------------------------------
    # Environment and command construction
    # ------------------------------------------------------------------
    def _env(self) -> dict[str, Optional[str]]:
        # Explicit -f/-p semantics must not be changed by a caller's shell.
        return {
            "COMPOSE_PROJECT_NAME": None,
            "COMPOSE_FILE": None,
            "COMPOSE_PROFILES": None,
            "COMPOSE_ENV_FILES": None,
            "COMPOSE_ANSI": "never",
        }

    @staticmethod
    def _normalise_files(files: Sequence[Path]) -> list[Path]:
        normalised: list[Path] = []
        for raw in files:
            path = Path(raw).expanduser()
            if not path.is_absolute():
                path = Path.cwd() / path
            try:
                path = path.resolve(strict=False)
            except (OSError, RuntimeError) as exc:
                raise DockerError(
                    f"cannot resolve Compose file path {path}: {exc}"
                ) from exc
            if path not in normalised:
                normalised.append(path)
        return normalised

    def compose_argv(
        self,
        files: Sequence[Path],
        *args: str,
        project_dir: Optional[Path] = None,
        project_name: Optional[str] = None,
    ) -> list[str]:
        files = self._normalise_files(files)
        if not files:
            raise DockerError("no Compose files supplied")
        directory = Path(project_dir).resolve(strict=False) if project_dir else files[0].parent
        argv = [
            self.docker,
            "compose",
            "--ansi",
            "never",
            "--project-directory",
            str(directory),
        ]
        if project_name:
            argv.extend(["-p", project_name])
        for path in files:
            argv.extend(["-f", str(path)])
        argv.extend(str(arg) for arg in args)
        return argv

    def _run(
        self,
        argv: Sequence[str],
        *,
        timeout: Optional[float] = None,
        capture: bool = True,
        cwd: Optional[Path] = None,
    ) -> CommandResult:
        return self.runner.run(
            argv,
            timeout=timeout or self.config.command_timeout,
            cwd=cwd,
            env=self._env(),
            capture=capture,
        )

    def _run_compose(
        self,
        files: Sequence[Path],
        args: Sequence[str],
        *,
        timeout: Optional[float] = None,
        project_name: Optional[str] = None,
    ) -> CommandResult:
        normalised = self._normalise_files(files)
        if not normalised:
            raise DockerError("no Compose files supplied")
        return self._run(
            self.compose_argv(normalised, *args, project_name=project_name),
            timeout=timeout or self.config.command_timeout,
            cwd=normalised[0].parent,
        )

    # ------------------------------------------------------------------
    # Availability and versions
    # ------------------------------------------------------------------
    def _validate_docker_binary(self) -> None:
        path = Path(self.docker)
        if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
            raise DockerUnavailable(
                "docker CLI not found or not executable; install Docker Engine and retry"
            )
        if os.geteuid() == 0:
            issues = check_path_trust(path, euid=0)
            if issues:
                raise DockerUnavailable(
                    "refusing to execute a docker binary from an unsafe path: "
                    + "; ".join(issues)
                )

    def ensure_available(self) -> str:
        self._validate_docker_binary()
        self._validate_environment()
        result = self._run(
            [self.docker, "version", "--format", "{{.Server.Version}}"],
            timeout=20,
        )
        if not result.ok:
            raise DockerUnavailable(
                "cannot talk to the Docker daemon: " + summarize_output(result)
            )
        self._server_version = result.stdout.strip()
        version = self.compose_version()
        if version is None:
            raise DockerUnavailable(
                "Docker Compose v2 is required (`docker compose version` failed)"
            )
        return self._server_version

    def server_version(self) -> Optional[str]:
        return self._server_version

    @staticmethod
    def _strict_environment_path_issues(path: Path) -> list[str]:
        """Trust check for directories used as executable/config search paths.

        Unlike a parent directory of a root-owned file, a search directory must
        not be sticky-world-writable: an attacker could create a new credential
        helper or CLI plugin in /tmp even if existing files are protected.
        """

        issues = check_path_trust(path, euid=0)
        try:
            mode = path.stat().st_mode
        except OSError:
            return issues
        if mode & 0o022:
            message = (
                f"{path} is group/world-writable (mode {mode & 0o777:04o})"
            )
            if message not in issues:
                issues.append(message)
        return issues

    def _root_environment_issues(self) -> list[str]:
        if os.geteuid() != 0:
            return []
        issues: list[str] = []
        for entry in os.environ.get("PATH", "").split(os.pathsep):
            if not entry:
                issues.append(
                    "PATH contains an empty entry (current directory), which is "
                    "not safe for a Docker-privileged process"
                )
                continue
            path = Path(entry)
            if path.is_dir():
                for issue in self._strict_environment_path_issues(path):
                    if issue not in issues:
                        issues.append(f"PATH {issue}")
        docker_config = os.environ.get("DOCKER_CONFIG")
        config_path = (
            Path(docker_config).expanduser()
            if docker_config
            else Path.home() / ".docker"
        )
        if config_path.exists():
            for issue in self._strict_environment_path_issues(config_path):
                if issue not in issues:
                    issues.append(f"Docker config {issue}")
        return issues

    def _validate_environment(self) -> None:
        issues = self._root_environment_issues()
        if issues:
            raise DockerUnavailable(
                "refusing to run with a root environment that is not "
                "root-controlled: " + "; ".join(issues[:5])
            )

    def environment_warnings(self) -> list[str]:
        """Warn about Docker environment variables that change the target/trust."""

        warnings: list[str] = []
        docker_host = os.environ.get("DOCKER_HOST")
        if docker_host:
            warnings.append(
                f"DOCKER_HOST is set; actions may target a remote daemon: {docker_host}"
            )
        docker_context = os.environ.get("DOCKER_CONTEXT")
        if docker_context and docker_context != "default":
            warnings.append(
                f"DOCKER_CONTEXT={docker_context!r} is set; verify it does not "
                "target an unexpected remote daemon"
            )
        docker_config = os.environ.get("DOCKER_CONFIG")
        if docker_config:
            config_path = Path(docker_config).expanduser()
            label = "DOCKER_CONFIG"
        elif os.geteuid() == 0:
            config_path = Path.home() / ".docker"
            label = "HOME/.docker"
        else:
            config_path = None
            label = ""
        if config_path is not None and config_path.exists():
            issues = (
                self._strict_environment_path_issues(config_path)
                if os.geteuid() == 0
                else check_path_trust(config_path, euid=os.geteuid())
            )
            if issues:
                warnings.append(
                    f"{label} points to a path not controlled by root/current "
                    "user; Docker CLI plugins or auth configuration could be altered: "
                    + "; ".join(issues[:3])
                )
        if os.geteuid() == 0:
            if any(not entry for entry in os.environ.get("PATH", "").split(os.pathsep)):
                warnings.append(
                    "root PATH contains an empty entry (current directory); "
                    "Docker credential helpers or CLI plugins could be intercepted"
                )
            for entry in os.environ.get("PATH", "").split(os.pathsep):
                if not entry:
                    continue
                path = Path(entry)
                if not path.is_dir():
                    continue
                issues = self._strict_environment_path_issues(path)
                if issues:
                    warnings.append(
                        "root PATH contains a directory not controlled by root; "
                        "Docker credential helpers or CLI plugins could be "
                        f"intercepted: {path}"
                    )
                    break
        return warnings

    def compose_version(self) -> Optional[tuple[int, int, int]]:
        if self._compose_version is not None:
            return self._compose_version
        result = self._run(
            [self.docker, "compose", "version", "--short"], timeout=20
        )
        if not result.ok:
            result = self._run(
                [self.docker, "compose", "version"], timeout=20
            )
        if not result.ok:
            return None
        text = result.stdout.strip() or result.stderr.strip()
        self._compose_version_string = text.splitlines()[0] if text else ""
        match = re.search(r"v?(\d+)\.(\d+)\.(\d+)", text)
        if not match:
            self._compose_version = (0, 0, 0)
        else:
            self._compose_version = (
                int(match.group(1)),
                int(match.group(2)),
                int(match.group(3)),
            )
        return self._compose_version

    def compose_version_string(self) -> str:
        if self._compose_version_string is None:
            self.compose_version()
        return self._compose_version_string or "unknown"

    # ------------------------------------------------------------------
    # Compose parsing and validation
    # ------------------------------------------------------------------
    def compose_config(
        self, files: Sequence[Path], *, project_name: Optional[str] = None
    ) -> ComposeMetadata:
        requested_name = project_name
        result = self._run_compose(
            files,
            ["config", "--format", "json"],
            timeout=self.config.command_timeout,
            project_name=project_name,
        )
        if not result.ok:
            if _is_unknown_flag(result):
                raise ComposeConfigError(
                    files,
                    "this Docker Compose version does not support "
                    "`config --format json`; upgrade to Compose v2.6 or newer",
                )
            raise ComposeConfigError(files, summarize_output(result))
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise ComposeConfigError(
                files, f"Compose returned invalid JSON: {exc}"
            ) from exc
        if not isinstance(data, dict):
            raise ComposeConfigError(files, "Compose returned an unexpected model")
        services = data.get("services")
        if not isinstance(services, dict):
            raise ComposeConfigError(files, "Compose model has no services mapping")

        name = data.get("name")
        if requested_name:
            project_name = normalize_project_name(requested_name)
        elif isinstance(name, str) and name.strip():
            project_name = normalize_project_name(name.strip())
        else:
            project_name = normalize_project_name(Path(files[0]).parent.name)
        analysis = analyze_compose(data, Path(files[0]).parent)
        return ComposeMetadata(project_name=project_name, analysis=analysis)

    def compose_validate(
        self, files: Sequence[Path], *, project_name: Optional[str] = None
    ) -> tuple[bool, Optional[str]]:
        result = self._run_compose(
            files,
            ["config", "--quiet"],
            timeout=self.config.command_timeout,
            project_name=project_name,
        )
        if result.ok:
            return True, None
        return False, summarize_output(result)

    # ------------------------------------------------------------------
    # Containers
    # ------------------------------------------------------------------
    def list_containers(self, all_containers: bool = True) -> list[Container]:
        args = [self.docker, "ps"]
        if all_containers:
            args.append("-a")
        args.extend(["-q", "--no-trunc"])
        result = self._run(args, timeout=self.config.command_timeout)
        if not result.ok:
            raise DockerError("cannot list containers: " + summarize_output(result))
        ids = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        containers: list[Container] = []
        for start in range(0, len(ids), 64):
            chunk = ids[start : start + 64]
            inspected = self._run(
                [self.docker, "inspect", "--type", "container", "--", *chunk],
                timeout=self.config.command_timeout,
            )
            if inspected.ok:
                containers.extend(self._parse_inspect(inspected.stdout))
                continue
            # A container may disappear between ps and inspect. Retry singly.
            for container_id in chunk:
                single = self._run(
                    [self.docker, "inspect", "--type", "container", "--", container_id],
                    timeout=self.config.command_timeout,
                )
                if single.ok:
                    containers.extend(self._parse_inspect(single.stdout))
        containers.sort(key=lambda item: (item.project or "~", item.name))
        return containers

    def _parse_inspect(self, text: str) -> list[Container]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return []
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            return []
        result: list[Container] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            container = self._container_from_inspect(item)
            if container is not None:
                result.append(container)
        return result

    def _container_from_inspect(self, item: dict[str, object]) -> Optional[Container]:
        state = item.get("State") if isinstance(item.get("State"), dict) else {}
        health_obj = (
            state.get("Health") if isinstance(state.get("Health"), dict) else {}
        )
        config = item.get("Config") if isinstance(item.get("Config"), dict) else {}
        labels = config.get("Labels")
        labels = labels if isinstance(labels, dict) else {}
        host_config = (
            item.get("HostConfig") if isinstance(item.get("HostConfig"), dict) else {}
        )

        state_text = str(state.get("Status", "") or "unknown")
        health = str(health_obj.get("Status", "") or "")
        try:
            exit_code = int(state.get("ExitCode", 0))
        except (TypeError, ValueError):
            exit_code = None
        status = state_text
        if health:
            status += f" ({health})"
        elif state_text == "exited" and exit_code is not None:
            status += f" ({exit_code})"

        name = str(item.get("Name", "") or "").lstrip("/")
        image_name = str(config.get("Image", "") or item.get("Image", "") or "")
        image_id = str(item.get("Image", "") or "")
        project = labels.get("com.docker.compose.project")
        service = labels.get("com.docker.compose.service")
        working_dir = labels.get("com.docker.compose.project.working_dir")
        config_hash = labels.get("com.docker.compose.config-hash")

        files: list[Path] = []
        raw_files = labels.get("com.docker.compose.project.config_files", "")
        if isinstance(raw_files, str) and raw_files.strip():
            for raw in raw_files.split(","):
                raw = raw.strip()
                if not raw:
                    continue
                path = Path(raw)
                if not path.is_absolute() and isinstance(working_dir, str) and working_dir:
                    path = Path(working_dir) / path
                if path not in files:
                    files.append(path)

        ports: list[str] = []
        bindings = host_config.get("PortBindings")
        if isinstance(bindings, dict):
            for container_port in sorted(bindings):
                values = bindings[container_port]
                if not isinstance(values, list):
                    continue
                for binding in values:
                    if not isinstance(binding, dict):
                        continue
                    host_ip = str(binding.get("HostIp", "") or "")
                    host_port = str(binding.get("HostPort", "") or "")
                    if host_port:
                        prefix = f"{host_ip}:" if host_ip else ""
                        ports.append(f"{prefix}{host_port}->{container_port}")
        ports = sorted(dict.fromkeys(ports))

        try:
            restart_count = int(item.get("RestartCount", 0) or 0)
        except (TypeError, ValueError):
            restart_count = 0

        return Container(
            id=str(item.get("Id", "") or ""),
            name=name,
            image=image_name,
            image_id=image_id,
            state=state_text,
            status=status,
            health=health,
            restart_count=restart_count,
            exit_code=exit_code,
            project=str(project) if project else None,
            service=str(service) if service else None,
            config_files=tuple(files),
            working_dir=str(working_dir) if working_dir else None,
            ports=tuple(ports),
            created=str(item.get("Created", "") or ""),
            config_hash=str(config_hash) if config_hash else None,
        )

    def image_id(self, image: str) -> Optional[str]:
        result = self._run(
            [self.docker, "image", "inspect", "--format", "{{.Id}}", "--", image],
            timeout=30,
        )
        if not result.ok:
            return None
        value = result.stdout.strip()
        return value or None

    def compose_ls(self) -> list[dict[str, object]]:
        result = self._run(
            [self.docker, "compose", "ls", "--all", "--format", "json"],
            timeout=30,
        )
        if not result.ok:
            return []
        return [item for item in parse_json_records(result.stdout) if isinstance(item, dict)]

    # ------------------------------------------------------------------
    # Mutating Compose operations
    # ------------------------------------------------------------------
    def pull(
        self, files: Sequence[Path], *, project_name: Optional[str] = None
    ) -> CommandResult:
        result = self._run_compose(
            files,
            ["pull", "--quiet", "--ignore-buildable"],
            timeout=self.config.pull_timeout,
            project_name=project_name,
        )
        if not result.ok and _is_unknown_flag(result):
            result = self._run_compose(
                files,
                ["pull", "--quiet"],
                timeout=self.config.pull_timeout,
                project_name=project_name,
            )
        return result

    def up(
        self,
        files: Sequence[Path],
        *,
        wait: bool = False,
        wait_timeout: Optional[int] = None,
        project_name: Optional[str] = None,
        pull_policy: Optional[str] = None,
    ) -> CommandResult:
        args = ["up", "-d"]
        if pull_policy:
            args.extend(["--pull", pull_policy])
        if wait:
            args.extend(
                ["--wait", "--wait-timeout", str(wait_timeout or self.config.wait_timeout)]
            )
        result = self._run_compose(
            files, args, timeout=self.config.up_timeout, project_name=project_name
        )
        if not result.ok and wait and _is_unknown_flag(result):
            retry_args = ["up", "-d"]
            if pull_policy:
                retry_args.extend(["--pull", pull_policy])
            result = self._run_compose(
                files,
                retry_args,
                timeout=self.config.up_timeout,
                project_name=project_name,
            )
        return result

    def stop(
        self, files: Sequence[Path], *, project_name: Optional[str] = None
    ) -> CommandResult:
        return self._run_compose(
            files, ["stop"], timeout=self.config.up_timeout, project_name=project_name
        )

    def restart(
        self, files: Sequence[Path], *, project_name: Optional[str] = None
    ) -> CommandResult:
        return self._run_compose(
            files,
            ["restart"],
            timeout=self.config.up_timeout,
            project_name=project_name,
        )

    def down(
        self, files: Sequence[Path], *, project_name: Optional[str] = None
    ) -> CommandResult:
        return self._run_compose(
            files, ["down"], timeout=self.config.up_timeout, project_name=project_name
        )

    def container_action(self, action: str, container: str) -> CommandResult:
        if action not in {"start", "stop", "restart"}:
            raise DockerError(f"unsupported container action: {action}")
        return self._run(
            [self.docker, action, "--", container], timeout=self.config.up_timeout
        )

    # ------------------------------------------------------------------
    # Logs, stats, disk
    # ------------------------------------------------------------------
    def stream_project_logs(
        self,
        files: Sequence[Path],
        *,
        tail: int = 200,
        follow: bool = False,
        project_name: Optional[str] = None,
    ) -> int:
        args = ["logs", "--tail", str(tail), "--no-color"]
        if follow:
            args.append("--follow")
        normalised = self._normalise_files(files)
        if not normalised:
            raise DockerError("no Compose files supplied")
        return self.runner.stream(
            self.compose_argv(normalised, *args, project_name=project_name),
            cwd=normalised[0].parent,
            env=self._env(),
        )

    def stream_container_logs(
        self, container: str, *, tail: int = 200, follow: bool = False
    ) -> int:
        args = [self.docker, "logs", "--tail", str(tail)]
        if follow:
            args.append("--follow")
        args.extend(["--", container])
        return self.runner.stream(args, env=self._env())

    def system_df(self) -> CommandResult:
        return self._run([self.docker, "system", "df"], timeout=60)

    def volume_list(self) -> CommandResult:
        return self._run(
            [self.docker, "volume", "ls", "--format", "{{.Name}}\t{{.Driver}}"],
            timeout=30,
        )

    def stats(self, container: Optional[str] = None) -> list[dict[str, object]]:
        args = [self.docker, "stats", "--no-stream", "--format", "{{json .}}"]
        if container:
            args.extend(["--", container])
        result = self._run(args, timeout=60)
        if not result.ok:
            raise DockerError("docker stats failed: " + summarize_output(result))
        return [
            item for item in parse_json_records(result.stdout) if isinstance(item, dict)
        ]

    def prune_images(self) -> CommandResult:
        return self._run([self.docker, "image", "prune", "-f"], timeout=300)

    def prune_build_cache(self) -> CommandResult:
        return self._run([self.docker, "builder", "prune", "-f"], timeout=300)

    def prune_containers(self) -> CommandResult:
        return self._run([self.docker, "container", "prune", "-f"], timeout=300)

    def prune_networks(self) -> CommandResult:
        return self._run([self.docker, "network", "prune", "-f"], timeout=300)

    def version_info(self) -> str:
        result = self._run(
            [
                self.docker,
                "version",
                "--format",
                "client={{.Client.Version}} server={{.Server.Version}}",
            ],
            timeout=20,
        )
        if result.ok and result.stdout.strip():
            return result.stdout.strip()
        fallback = self._run([self.docker, "--version"], timeout=10)
        return fallback.stdout.strip() or fallback.stderr.strip() or "unknown"

    def display_command(self, argv: Sequence[str]) -> str:
        return format_command(argv)

    def redact(self, text: str) -> str:
        from .runner import redact_text

        return redact_text(sanitize_text(text))
