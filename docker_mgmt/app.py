"""Interactive menu application."""

from __future__ import annotations

import os
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional, Sequence

from . import __version__
from .audit import (
    AuditError,
    AuditLogger,
    LockBusy,
    OperationLock,
    read_audit_records,
)
from .config import Config
from .discovery import (
    scan_projects,
    summarize_scan,
)
from .docker import (
    ComposeConfigError,
    DockerClient,
    DockerError,
    DockerUnavailable,
)
from .models import ComposeProject, Container, ProjectUpdateReport
from .runner import DockerMgmtError, summarize_output
from .security import check_project_trust
from .ui import QuitApp, UI
from .updates import apply_project, check_project


class App:
    def __init__(self, config: Config, docker: DockerClient, audit: AuditLogger) -> None:
        self.config = config
        self.docker = docker
        self.audit = audit
        self.ui: UI[str] = UI(config.color, config.page_size)
        self.projects: list[ComposeProject] = []
        self.scan_warnings: list[str] = []
        self.scan_candidate_count = 0
        self.audit_ready = False
        self.audit_error: Optional[str] = None

    # ------------------------------------------------------------------
    # Startup and shared safety helpers
    # ------------------------------------------------------------------
    def run(self) -> int:
        self._banner()
        try:
            self.docker.ensure_available()
        except DockerUnavailable as exc:
            self.ui.error(str(exc))
            self.ui.info("Run `./docker-mgmt doctor` for diagnostics.")
            return 2

        self.ui.key_values(
            [
                ("Docker", self.docker.version_info()),
                ("Compose", self.docker.compose_version_string()),
                ("Audit", self.config.audit_path),
            ]
        )
        self._ensure_audit(quiet=False)

        if os.environ.get("DOCKER_HOST"):
            self.ui.warn(
                "DOCKER_HOST is set; actions may target a remote Docker daemon: "
                + os.environ["DOCKER_HOST"]
            )
        if self.config.allow_unsafe_ownership:
            self.ui.warn(
                "security.allow_unsafe_ownership is enabled: non-root-writable "
                "Compose files can be used for root Docker operations."
            )

        try:
            self._rescan(initial=True)
        except DockerMgmtError as exc:
            self.ui.error(f"Initial scan failed: {exc}")
            self.ui.info("You can still use containers, disk, audit, and settings.")
        except OSError as exc:
            self.ui.error(f"Initial scan failed: {exc}")

        options = [
            ("Dashboard: projects, containers, health", "dashboard"),
            ("Compose projects: inspect, pull, update, stop, logs", "projects"),
            ("Containers: logs, restart, stop, stats", "containers"),
            ("Check for updates (pull, compare, optional apply)", "check"),
            ("Disk usage and safe cleanup", "disk"),
            ("Validate Compose files and security review", "validate"),
            ("Audit log", "audit"),
            ("Rescan configured roots", "rescan"),
            ("Scan a directory temporarily", "scan_dir"),
            ("Settings and security notes", "settings"),
            ("Exit", "exit"),
        ]
        while True:
            try:
                choice = self.ui.choose(
                    f"Main menu - docker-mgmt {__version__}",
                    options,
                    allow_back=False,
                )
                if choice in {None, "exit"}:
                    return 0
                if choice == "dashboard":
                    self._dashboard()
                elif choice == "projects":
                    self._projects_menu()
                elif choice == "containers":
                    self._containers_menu()
                elif choice == "check":
                    self._check_updates_menu()
                elif choice == "disk":
                    self._disk_menu()
                elif choice == "validate":
                    self._validate_menu()
                elif choice == "audit":
                    self._audit_menu()
                elif choice == "rescan":
                    self._rescan()
                    self.ui.pause()
                elif choice == "scan_dir":
                    self._scan_directory_menu()
                elif choice == "settings":
                    self._settings_menu()
            except QuitApp:
                return 0
            except KeyboardInterrupt:
                self.ui.info("")
                self.ui.info("Interrupted.")
                return 130
            except (DockerMgmtError, AuditError, LockBusy, OSError) as exc:
                self.ui.error(str(exc))
                self.ui.pause()

    def _banner(self) -> None:
        self.ui.header(f"docker-mgmt {__version__}")
        self.ui.info(
            "Explicit, audited Docker Compose management. No Watchtower and no "
            "automatic updates."
        )
        self.ui.info(
            "Docker access is root-equivalent. Every mutating action requires an "
            "operator decision and is written to the audit log."
        )
        self.ui.key_values(
            [
                ("Config", self.config.config_display),
                ("User", f"uid={os.geteuid()} ({os.environ.get('SUDO_USER') or 'direct'})"),
                ("Lock", self.config.lock_path),
            ]
        )
        for warning in self.config.warnings:
            self.ui.warn(warning)

    def _ensure_audit(self, *, quiet: bool = True) -> bool:
        try:
            self.audit.ensure_ready()
            self.audit_ready = True
            self.audit_error = None
            return True
        except AuditError as exc:
            self.audit_ready = False
            self.audit_error = str(exc)
            if not quiet:
                self.ui.error(f"Audit log unavailable: {exc}")
                self.ui.warn(
                    "Mutating actions are disabled until the audit log can be "
                    "written. Read-only views remain available."
                )
            return False

    def _require_audit(self) -> bool:
        if self._ensure_audit(quiet=True):
            return True
        self.ui.error(
            f"Audit log unavailable; mutating actions are disabled: {self.audit_error}"
        )
        return False

    @contextmanager
    def _locked(self) -> Iterator[None]:
        lock = OperationLock(self.config.lock_path)
        try:
            lock.acquire()
        except LockBusy as exc:
            raise DockerMgmtError(str(exc)) from exc
        except AuditError as exc:
            raise DockerMgmtError(str(exc)) from exc
        try:
            yield
        finally:
            lock.release()

    def _audit_action(
        self,
        action: str,
        target: str,
        result: str,
        *,
        detail: str = "",
        project: Optional[str] = None,
        started: Optional[float] = None,
    ) -> None:
        duration_ms = (
            int((time.monotonic() - started) * 1000) if started is not None else None
        )
        try:
            self.audit.log(
                action=action,
                target=target,
                result=result,
                detail=detail,
                project=project,
                duration_ms=duration_ms,
            )
        except AuditError as exc:
            self.audit_ready = False
            self.audit_error = str(exc)
            self.ui.error(f"Audit write failed: {exc}")
            raise

    def _show_result(self, label: str, result: object, started: float) -> None:
        duration = time.monotonic() - started
        ok = bool(getattr(result, "ok", False))
        if ok:
            self.ui.success(f"{label} succeeded ({duration:.1f}s).")
        else:
            self.ui.error(
                f"{label} failed (exit {getattr(result, 'returncode', '?')}, "
                f"{duration:.1f}s)."
            )
            self.ui.info(summarize_output(result))  # type: ignore[arg-type]
            return
        stdout = str(getattr(result, "stdout", "") or "").strip()
        stderr = str(getattr(result, "stderr", "") or "").strip()
        if stdout:
            self.ui.info(stdout)
        if stderr:
            self.ui.dim(stderr)

    def _containers(self, *, quiet: bool = False) -> list[Container]:
        try:
            return self.docker.list_containers(all_containers=True)
        except DockerError as exc:
            if not quiet:
                self.ui.error(str(exc))
            return []

    def _related(
        self, project: ComposeProject, containers: Sequence[Container]
    ) -> list[Container]:
        return [item for item in containers if item.project == project.project_name]

    def _trust_issues(self, project: ComposeProject) -> list[str]:
        return check_project_trust(
            project.files,
            project.env_files,
            project.build_contexts,
            project.extra_files,
        )

    def _preflight(
        self,
        project: ComposeProject,
        action: str,
        *,
        ask_high_risk: bool = True,
    ) -> bool:
        if not project.valid:
            self.ui.error(f"Cannot {action}: {project.error or 'invalid project'}")
            return False
        if project.blockers:
            self.ui.error(f"Cannot {action}: project has unresolved blockers.")
            self.ui.bullets(project.blockers)
            return False
        if not self._require_audit():
            return False

        try:
            valid, error = self.docker.compose_validate(
                project.files, project_name=project.project_name
            )
        except DockerError as exc:
            self.ui.error(f"Cannot {action}: {exc}")
            return False
        if not valid:
            self.ui.error(f"Cannot {action}: Compose validation failed.")
            self.ui.info(error or "unknown validation error")
            return False

        trust = self._trust_issues(project)
        if trust:
            if not self.config.allow_unsafe_ownership:
                self.ui.error(
                    "Blocked: files used by this project are not root-controlled."
                )
                self.ui.bullets(trust)
                self.ui.info(
                    "A non-root user able to edit these files could obtain root "
                    "through a container. Fix ownership/permissions (for example "
                    "`chown -R root:root` and `chmod 0644` on the files), or set "
                    "security.allow_unsafe_ownership=true only if you accept that risk."
                )
                return False
            self.ui.warn(
                "Unsafe file ownership is allowed by configuration for this project:"
            )
            self.ui.bullets(trust)
            if not self.ui.confirm(
                "Continue despite non-root-writable project files?", default=False
            ):
                return False

        if project.critical_warnings:
            self.ui.warn("High-risk Docker settings detected:")
            self.ui.bullets(project.critical_warnings)
            if ask_high_risk and not self.ui.confirm(
                f"Continue and {action} despite these settings?", default=False
            ):
                return False
        return True

    # ------------------------------------------------------------------
    # Scanning and dashboards
    # ------------------------------------------------------------------
    def _rescan(self, *, initial: bool = False) -> None:
        self.ui.info("Scanning configured roots and running projects...")
        result = scan_projects(self.config, self.docker)
        self.projects = result.projects
        self.scan_warnings = result.warnings
        self.scan_candidate_count = result.candidate_count
        self._recompute_duplicate_blockers()
        self.ui.success("Scan complete: " + summarize_scan(result))
        if result.warnings:
            self.ui.warn(f"{len(result.warnings)} scan warning(s):")
            self.ui.bullets(result.warnings[:10])
            if len(result.warnings) > 10:
                self.ui.dim(f"  ... and {len(result.warnings) - 10} more")
        if initial and not self.projects:
            self.ui.warn(
                "No Compose projects found. Check scan.roots in the config, or "
                "use Settings to review the active paths."
            )
        if self.scan_candidate_count and not initial:
            valid = sum(1 for project in self.projects if project.valid)
            self.ui.info(
                f"{len(self.projects)} project(s), {valid} valid, "
                f"{len(self.projects) - valid} invalid."
            )

    def _recompute_duplicate_blockers(self) -> None:
        grouped: dict[str, list[ComposeProject]] = {}
        for project in self.projects:
            grouped.setdefault(project.project_name, []).append(project)
        for name, group in grouped.items():
            if len(group) <= 1:
                continue
            paths = ", ".join(str(project.primary_file) for project in group)
            message = (
                f"project name {name!r} is shared by multiple Compose files: {paths}; "
                "give each project a unique top-level `name:` or move the files "
                "into separate directories"
            )
            for project in group:
                if message not in project.blockers:
                    project.blockers.append(message)

    def _scan_directory_menu(self) -> None:
        """Ad-hoc scan of one directory without editing the config file."""

        default = str(self.config.scan_roots[0]) if self.config.scan_roots else "."
        raw = self.ui.prompt("Directory to scan", default=default)
        path = Path(raw).expanduser()
        if not path.is_absolute():
            path = Path.cwd() / path
        try:
            path = path.resolve(strict=True)
        except OSError:
            self.ui.error(f"Directory does not exist: {path}")
            self.ui.pause()
            return
        if not path.is_dir():
            self.ui.error(f"Not a directory: {path}")
            self.ui.pause()
            return
        all_yaml = self.config.include_all_yaml
        if not all_yaml and self.ui.confirm(
            "Also validate non-Compose-named *.yml/*.yaml files in this directory?",
            default=False,
        ):
            all_yaml = True
        try:
            result = scan_projects(
                self.config,
                self.docker,
                roots=[path],
                all_yaml=all_yaml,
            )
        except (DockerMgmtError, OSError) as exc:
            self.ui.error(f"Scan failed: {exc}")
            self.ui.pause()
            return
        self.projects = result.projects
        self.scan_warnings = result.warnings
        self.scan_candidate_count = result.candidate_count
        self._recompute_duplicate_blockers()
        self.ui.success("Temporary scan complete: " + summarize_scan(result))
        if result.warnings:
            self.ui.warn(f"{len(result.warnings)} scan warning(s):")
            self.ui.bullets(result.warnings[:10])
        self.ui.info(
            "This list is temporary. Use 'Rescan configured roots' to restore "
            "the paths from the configuration file."
        )
        self.ui.pause()

    def _dashboard(self) -> None:
        containers = self._containers()
        running = [item for item in containers if item.running]
        unhealthy = [item for item in containers if item.unhealthy]
        restarting = [item for item in containers if item.state == "restarting"]
        invalid = [project for project in self.projects if not project.valid]
        blocked = [project for project in self.projects if project.blockers]
        critical = [
            project for project in self.projects if project.critical_warnings
        ]
        active_projects = {item.project for item in containers if item.project}

        self.ui.header("Dashboard")
        self.ui.key_values(
            [
                ("Compose projects", f"{len(self.projects)} discovered"),
                ("Active Compose projects", len(active_projects)),
                ("Invalid projects", len(invalid)),
                ("Containers", f"{len(containers)} total / {len(running)} running"),
                ("Unhealthy", len(unhealthy)),
                ("Restarting", len(restarting)),
                ("Projects with blockers", len(blocked)),
                ("Projects with high-risk settings", len(critical)),
            ]
        )

        if containers:
            self.ui.section("Containers")
            rows = []
            for item in containers[:80]:
                rows.append(
                    [
                        item.display_name,
                        item.project or "-",
                        item.service or "-",
                        item.state,
                        item.health or "-",
                        item.restart_count,
                        item.image,
                        ", ".join(item.ports[:3])
                        + (" ..." if len(item.ports) > 3 else ""),
                    ]
                )
            self.ui.print_table(
                ["NAME", "PROJECT", "SERVICE", "STATE", "HEALTH", "RESTARTS", "IMAGE", "PORTS"],
                rows,
                max_widths=[28, 18, 16, 12, 9, 8, 32, 28],
            )
            if len(containers) > 80:
                self.ui.dim(f"Showing 80 of {len(containers)} containers.")
        else:
            self.ui.info("No containers found.")

        if unhealthy:
            self.ui.section("Unhealthy containers")
            self.ui.bullets(
                [
                    f"{item.display_name} ({item.project or 'no project'}/{item.service or '-'})"
                    for item in unhealthy
                ]
            )
        if invalid:
            self.ui.section("Invalid Compose projects")
            self.ui.bullets(
                [
                    f"{project.project_name}: {project.primary_file}: {project.error}"
                    for project in invalid
                ]
            )
        if blocked:
            self.ui.section("Projects with blockers (mutations disabled)")
            for project in blocked:
                self.ui.info(f"  {project.project_name}:")
                self.ui.bullets(project.blockers, prefix="    - ")
        if self.scan_warnings:
            self.ui.section("Scan warnings")
            self.ui.bullets(self.scan_warnings[:10])
        self.ui.pause()

    # ------------------------------------------------------------------
    # Compose project menus
    # ------------------------------------------------------------------
    def _projects_menu(self) -> None:
        if not self.projects:
            self.ui.warn("No projects discovered.")
            if self.ui.confirm("Rescan now?", default=True):
                self._rescan()
                self.ui.pause()
            return

        while True:
            containers = self._containers()
            options: list[tuple[str, ComposeProject]] = []
            for project in self.projects:
                related = self._related(project, containers)
                running = sum(1 for item in related if item.running)
                status = "valid" if project.valid else "INVALID"
                blocked = " !BLOCKED" if project.blockers else ""
                options.append(
                    (
                        f"{project.project_name:<24} {running}/{len(related)} running  "
                        f"{status:<7} {project.primary_file}{blocked}",
                        project,
                    )
                )
            selected = self.ui.choose(
                "Compose projects",
                options,
                back_label="Back to main menu",
            )
            if selected is None:
                return
            try:
                self._project_menu(selected)
            except KeyboardInterrupt:
                self.ui.info("")
                self.ui.info("Interrupted.")
            except (DockerMgmtError, AuditError, LockBusy, OSError) as exc:
                self.ui.error(str(exc))
                self.ui.pause()

    def _project_menu(self, project: ComposeProject) -> None:
        while True:
            containers = self._containers(quiet=True)
            related = self._related(project, containers)
            running = sum(1 for item in related if item.running)
            trust = self._trust_issues(project)

            self.ui.header(f"Project: {project.project_name}")
            self.ui.key_values(
                [
                    ("Files", ", ".join(str(path) for path in project.files)),
                    ("Source", project.source),
                    ("Status", "valid" if project.valid else f"INVALID: {project.error}"),
                    ("Containers", f"{running}/{len(related)} running"),
                    ("Services", len(project.services)),
                    ("High-risk warnings", len(project.critical_warnings)),
                    ("Security warnings", len(project.warnings)),
                    ("Blockers", len(project.blockers)),
                    ("Root trust issues", len(trust)),
                ]
            )
            if project.services:
                self.ui.section("Services")
                self.ui.print_table(
                    ["SERVICE", "IMAGE", "BUILD", "WARNINGS"],
                    [
                        [
                            service.name,
                            service.image or "<build only>",
                            "yes" if service.has_build else "no",
                            len(service.critical_warnings) + len(service.warnings),
                        ]
                        for service in project.services
                    ],
                    max_widths=[28, 48, 8, 10],
                )
            if related:
                self.ui.section("Containers")
                self.ui.print_table(
                    ["NAME", "SERVICE", "STATE", "HEALTH", "RESTARTS", "IMAGE"],
                    [
                        [
                            item.display_name,
                            item.service or "-",
                            item.state,
                            item.health or "-",
                            item.restart_count,
                            item.image,
                        ]
                        for item in related
                    ],
                    max_widths=[28, 18, 12, 10, 8, 36],
                )
            if project.blockers:
                self.ui.section("Blockers")
                self.ui.bullets(project.blockers)
            if project.critical_warnings:
                self.ui.section("High-risk Docker settings")
                self.ui.bullets(project.critical_warnings)
            if project.warnings:
                self.ui.section("Security / configuration warnings")
                self.ui.bullets(project.warnings[:20])
                if len(project.warnings) > 20:
                    self.ui.dim(f"  ... and {len(project.warnings) - 20} more")
            if trust:
                self.ui.section("Root file-trust issues")
                self.ui.bullets(trust)
                if not self.config.allow_unsafe_ownership:
                    self.ui.warn(
                        "Mutating actions are blocked until these are fixed, or "
                        "security.allow_unsafe_ownership is set to true."
                    )

            options = [
                ("Check for updates (pull images; does not restart)", "check"),
                ("Pull and apply updates (pull + compose up -d)", "update"),
                ("Apply Compose changes only (compose up -d)", "apply"),
                ("Restart running containers (no pull)", "restart"),
                ("Stop containers (keep them on disk)", "stop"),
                ("View logs", "logs"),
                ("Validate / refresh project metadata", "validate"),
                ("Security review", "security"),
                ("Down: remove containers and networks (keep volumes)", "down"),
                ("Back", "back"),
            ]
            choice = self.ui.choose(
                f"Project {project.project_name}",
                options,
                back_label="Back to projects",
            )
            if choice in {None, "back"}:
                return
            try:
                if choice == "check":
                    self._check_one_project(project)
                elif choice == "update":
                    self._check_one_project(project, offer_apply=True)
                elif choice == "apply":
                    self._apply_project(project, pull=False)
                elif choice == "restart":
                    self._project_lifecycle(project, "restart")
                elif choice == "stop":
                    self._project_lifecycle(project, "stop")
                elif choice == "logs":
                    self._project_logs(project)
                elif choice == "validate":
                    self._validate_project(project)
                elif choice == "security":
                    self._security_review(project)
                elif choice == "down":
                    self._project_lifecycle(project, "down")
            except (DockerMgmtError, AuditError, LockBusy, OSError) as exc:
                self.ui.error(str(exc))
                self.ui.pause()

    def _check_one_project(
        self, project: ComposeProject, *, offer_apply: bool = False
    ) -> None:
        if not project.valid:
            self.ui.error(f"Cannot check: {project.error or 'invalid project'}")
            return
        if not self._require_audit():
            return
        pull_argv = self.docker.compose_argv(
            project.files,
            "pull",
            "--quiet",
            "--ignore-buildable",
            project_name=project.project_name,
        )
        self.ui.section("Planned command")
        self.ui.info("  " + self.docker.display_command(pull_argv))
        if not self.ui.confirm(
            f"Pull images for project {project.project_name}? "
            "This downloads updates but does not restart containers.",
            default=False,
        ):
            return

        containers = self._containers(quiet=True)
        started = time.monotonic()
        try:
            with self._locked():
                report = check_project(
                    self.docker,
                    project,
                    containers,
                    progress=self.ui.info,
                )
        except (DockerMgmtError, AuditError, LockBusy) as exc:
            self._audit_action(
                "compose.pull",
                str(project.primary_file),
                "error",
                detail=str(exc),
                project=project.project_name,
                started=started,
            )
            raise
        self._audit_action(
            "compose.pull",
            str(project.primary_file),
            "ok" if report.pull_ok else "error",
            detail=report.pull_error or f"{report.changed_services().__len__()} changed service(s)",
            project=project.project_name,
            started=started,
        )
        self._print_update_report([report])

        if not offer_apply:
            if report.has_updates:
                self.ui.info(
                    "Use 'Pull and apply updates' or 'Apply Compose changes only' "
                    "to recreate containers."
                )
            return

        if not report.pull_ok:
            if not self.ui.confirm(
                "Pull reported errors. Run compose up -d with existing images anyway?",
                default=False,
            ):
                return
        elif report.has_updates:
            if not self.ui.confirm(
                f"Apply updates now and recreate affected containers for "
                f"{project.project_name}?",
                default=True,
            ):
                return
        else:
            if not self.ui.confirm(
                "No image changes were found. Run compose up -d to apply any "
                "Compose file changes?",
                default=False,
            ):
                return
        self._apply_project(project, pull=False, interactive=False)

    def _apply_project(
        self, project: ComposeProject, *, pull: bool, interactive: bool = True
    ) -> bool:
        action = "pull and apply updates" if pull else "apply Compose changes"
        if not self._preflight(project, action, ask_high_risk=True):
            return False

        pull_argv = self.docker.compose_argv(
            project.files,
            "pull",
            "--quiet",
            "--ignore-buildable",
            project_name=project.project_name,
        )
        up_argv = self.docker.compose_argv(
            project.files,
            "up",
            "-d",
            "--pull",
            "never",
            project_name=project.project_name,
        )
        if self.config.wait_after_update:
            up_argv = self.docker.compose_argv(
                project.files,
                "up",
                "-d",
                "--pull",
                "never",
                "--wait",
                "--wait-timeout",
                str(self.config.wait_timeout),
                project_name=project.project_name,
            )

        self.ui.section("Planned commands")
        if pull:
            self.ui.info("  " + self.docker.display_command(pull_argv))
        self.ui.info("  " + self.docker.display_command(up_argv))
        if interactive and not self.ui.confirm(
            f"Run these commands for {project.project_name}?", default=False
        ):
            return False

        started = time.monotonic()
        try:
            with self._locked():
                result = apply_project(
                    self.docker,
                    project,
                    pull=pull,
                    wait=self.config.wait_after_update,
                    progress=self.ui.info,
                )
        except (DockerMgmtError, AuditError, LockBusy) as exc:
            self._audit_action(
                "compose.apply",
                str(project.primary_file),
                "error",
                detail=str(exc),
                project=project.project_name,
                started=started,
            )
            raise

        if result.pull_result is not None:
            self._audit_action(
                "compose.pull",
                str(project.primary_file),
                "ok" if result.pull_result.ok else "error",
                detail=summarize_output(result.pull_result),
                project=project.project_name,
            )
        if result.up_result is not None:
            self._audit_action(
                "compose.up",
                str(project.primary_file),
                "ok" if result.up_result.ok else "error",
                detail=summarize_output(result.up_result),
                project=project.project_name,
                started=started,
            )

        if result.pull_result is not None:
            self._show_result("Pull", result.pull_result, started)
        if result.up_result is not None:
            self._show_result("Compose up", result.up_result, started)

        containers = self._containers(quiet=True)
        self._show_project_containers(project, containers)
        if interactive:
            self.ui.pause()
        return result.ok

    def _project_lifecycle(self, project: ComposeProject, action: str) -> None:
        if not self._preflight(project, action, ask_high_risk=False):
            return
        related = self._related(project, self._containers(quiet=True))
        running = sum(1 for item in related if item.running)
        if action == "stop":
            message = (
                f"Stop {running} running container(s) in {project.project_name}? "
                "Containers remain on disk."
            )
            phrase = None
            command = self.docker.compose_argv(
                project.files, "stop", project_name=project.project_name
            )
        elif action == "restart":
            message = (
                f"Restart {running} running container(s) in {project.project_name}?"
            )
            phrase = None
            command = self.docker.compose_argv(
                project.files, "restart", project_name=project.project_name
            )
        else:
            message = (
                f"Remove containers and networks for {project.project_name}? "
                "Named and anonymous volumes are NOT removed by this command."
            )
            phrase = "DOWN"
            command = self.docker.compose_argv(
                project.files, "down", project_name=project.project_name
            )

        self.ui.section("Command")
        self.ui.info("  " + self.docker.display_command(command))
        if phrase:
            if not self.ui.confirm_phrase(message, phrase):
                self.ui.info("Cancelled.")
                return
        elif not self.ui.confirm(message, default=False):
            return

        started = time.monotonic()
        try:
            with self._locked():
                if action == "stop":
                    result = self.docker.stop(
                        project.files, project_name=project.project_name
                    )
                elif action == "restart":
                    result = self.docker.restart(
                        project.files, project_name=project.project_name
                    )
                else:
                    result = self.docker.down(
                        project.files, project_name=project.project_name
                    )
        except (DockerMgmtError, AuditError, LockBusy) as exc:
            self._audit_action(
                f"compose.{action}",
                str(project.primary_file),
                "error",
                detail=str(exc),
                project=project.project_name,
                started=started,
            )
            raise
        self._audit_action(
            f"compose.{action}",
            str(project.primary_file),
            "ok" if result.ok else "error",
            detail=summarize_output(result),
            project=project.project_name,
            started=started,
        )
        self._show_result(f"Compose {action}", result, started)
        self._show_project_containers(project, self._containers(quiet=True))
        self.ui.pause()

    def _project_logs(self, project: ComposeProject) -> None:
        choice = self.ui.choose(
            f"Logs for {project.project_name}",
            [
                ("Recent 200 lines", "recent"),
                ("Follow logs (Ctrl-C to stop)", "follow"),
            ],
        )
        if choice is None:
            return
        self.ui.info("")
        code = self.docker.stream_project_logs(
            project.files,
            tail=200,
            follow=(choice == "follow"),
            project_name=project.project_name,
        )
        self.ui.info("")
        if code not in {0, 130}:
            self.ui.warn(f"Log stream exited with code {code}.")
        if choice == "follow":
            self.ui.pause()

    def _validate_project(self, project: ComposeProject) -> None:
        self.ui.info(f"Revalidating {project.primary_file} ...")
        try:
            metadata = self.docker.compose_config(
                project.files, project_name=project.project_name
            )
        except ComposeConfigError as exc:
            project.valid = False
            project.error = exc.message
            self.ui.error(f"Validation failed: {exc.message}")
            self.ui.pause()
            return
        project.valid = True
        project.error = None
        project.project_name = metadata.project_name
        project.services = list(metadata.analysis.services)
        project.warnings = list(metadata.analysis.warnings)
        project.critical_warnings = list(metadata.analysis.critical_warnings)
        project.env_files = metadata.analysis.env_files
        project.build_contexts = metadata.analysis.build_contexts
        self._recompute_duplicate_blockers()
        self.ui.success(
            f"Valid: {len(project.services)} service(s), "
            f"{len(project.warnings)} warning(s), "
            f"{len(project.critical_warnings)} high-risk finding(s)."
        )
        self.ui.pause()

    def _security_review(self, project: ComposeProject) -> None:
        trust = self._trust_issues(project)
        self.ui.header(f"Security review: {project.project_name}")
        self.ui.key_values(
            [
                ("Files", ", ".join(str(path) for path in project.files)),
                ("High-risk findings", len(project.critical_warnings)),
                ("Warnings", len(project.warnings)),
                ("Root trust issues", len(trust)),
                (
                    "Unsafe ownership allowed",
                    "YES (dangerous)" if self.config.allow_unsafe_ownership else "no",
                ),
            ]
        )
        if project.critical_warnings:
            self.ui.section("High-risk findings")
            self.ui.bullets(project.critical_warnings)
        if project.warnings:
            self.ui.section("Warnings")
            self.ui.bullets(project.warnings)
        if trust:
            self.ui.section("Root file-trust issues")
            self.ui.bullets(trust)
        if not (project.critical_warnings or project.warnings or trust):
            self.ui.success("No static findings from the configured checks.")
        self.ui.section("What is checked")
        self.ui.bullets(
            [
                "privileged containers, host network/PID/IPC/user namespaces",
                "Docker socket, sensitive host mounts, dangerous capabilities",
                "disabled seccomp/AppArmor sandboxes and host devices",
                "floating image tags (latest/stable/main/...)",
                "ports published on all host interfaces",
                "root ownership and writability of Compose/.env/build-context files",
            ]
        )
        self.ui.pause()

    def _show_project_containers(
        self, project: ComposeProject, containers: Sequence[Container]
    ) -> None:
        related = self._related(project, containers)
        if not related:
            self.ui.warn("No containers found for this project.")
            return
        self.ui.section("Container status")
        self.ui.print_table(
            ["NAME", "SERVICE", "STATE", "HEALTH", "RESTARTS", "IMAGE"],
            [
                [
                    item.display_name,
                    item.service or "-",
                    item.state,
                    item.health or "-",
                    item.restart_count,
                    item.image,
                ]
                for item in related
            ],
            max_widths=[28, 18, 12, 10, 8, 36],
        )
        unhealthy = [item for item in related if item.unhealthy]
        if unhealthy:
            self.ui.warn(
                "Unhealthy: " + ", ".join(item.display_name for item in unhealthy)
            )

    # ------------------------------------------------------------------
    # Container menu
    # ------------------------------------------------------------------
    def _containers_menu(self) -> None:
        while True:
            containers = self._containers()
            if not containers:
                self.ui.warn("No containers found.")
                self.ui.pause()
                return
            options: list[tuple[str, Container]] = []
            for item in containers:
                flags = []
                if item.unhealthy:
                    flags.append("UNHEALTHY")
                if item.restart_count:
                    flags.append(f"restarts={item.restart_count}")
                suffix = f"  [{', '.join(flags)}]" if flags else ""
                options.append(
                    (
                        f"{item.display_name:<32} {item.project or '-':<18} "
                        f"{item.service or '-':<16} {item.state:<12} "
                        f"{item.image}{suffix}",
                        item,
                    )
                )
            selected = self.ui.choose(
                "Containers", options, back_label="Back to main menu"
            )
            if selected is None:
                return
            try:
                self._container_menu(selected)
            except (DockerMgmtError, AuditError, LockBusy, OSError) as exc:
                self.ui.error(str(exc))
                self.ui.pause()

    def _container_menu(self, container: Container) -> None:
        while True:
            self.ui.header(f"Container: {container.display_name}")
            self.ui.key_values(
                [
                    ("ID", container.id),
                    ("Image", container.image),
                    ("Image ID", container.image_id),
                    ("Project", container.project or "-"),
                    ("Service", container.service or "-"),
                    ("State", container.state),
                    ("Health", container.health or "-"),
                    ("Status", container.status),
                    ("Restarts", container.restart_count),
                    ("Exit code", container.exit_code if container.exit_code is not None else "-"),
                    ("Ports", ", ".join(container.ports) or "-"),
                    ("Created", container.created),
                    (
                        "Compose files",
                        ", ".join(str(path) for path in container.config_files) or "-",
                    ),
                ]
            )
            options = [
                ("Recent logs (200 lines)", "logs"),
                ("Follow logs (Ctrl-C to stop)", "follow"),
                ("Restart container", "restart"),
                ("Stop container", "stop"),
            ]
            if not container.running:
                options.append(("Start container", "start"))
            options.extend(
                [
                    ("Resource usage (docker stats)", "stats"),
                    ("Back", "back"),
                ]
            )
            choice = self.ui.choose("Container actions", options)
            if choice in {None, "back"}:
                return
            if choice in {"logs", "follow"}:
                self.ui.info("")
                code = self.docker.stream_container_logs(
                    container.id,
                    tail=200,
                    follow=(choice == "follow"),
                )
                self.ui.info("")
                if code not in {0, 130}:
                    self.ui.warn(f"Log stream exited with code {code}.")
                if choice == "follow":
                    self.ui.pause()
                continue
            if choice == "stats":
                self._container_stats(container)
                continue
            if choice in {"restart", "stop", "start"}:
                label = {
                    "restart": "Restart",
                    "stop": "Stop",
                    "start": "Start",
                }[choice]
                self.ui.section("Command")
                self.ui.info(f"  docker {choice} {container.name}")
                if not self.ui.confirm(
                    f"{label} container {container.display_name}?", default=False
                ):
                    continue
                if not self._require_audit():
                    continue
                started = time.monotonic()
                try:
                    with self._locked():
                        result = self.docker.container_action(choice, container.id)
                except (DockerMgmtError, AuditError, LockBusy) as exc:
                    self._audit_action(
                        f"container.{choice}",
                        container.name,
                        "error",
                        detail=str(exc),
                        project=container.project,
                        started=started,
                    )
                    raise
                self._audit_action(
                    f"container.{choice}",
                    container.name,
                    "ok" if result.ok else "error",
                    detail=summarize_output(result),
                    project=container.project,
                    started=started,
                )
                self._show_result(f"Container {choice}", result, started)
                self.ui.pause()
                return

    def _container_stats(self, container: Container) -> None:
        try:
            rows = self.docker.stats(container.name)
        except DockerError as exc:
            self.ui.error(str(exc))
            self.ui.pause()
            return
        if not rows:
            self.ui.warn("No stats returned.")
            self.ui.pause()
            return
        self.ui.section("Resource usage (snapshot)")
        self.ui.print_table(
            ["NAME", "CPU", "MEM USAGE", "MEM %", "NET I/O", "BLOCK I/O", "PIDS"],
            [
                [
                    row.get("Name", ""),
                    row.get("CPUPerc", ""),
                    row.get("MemUsage", ""),
                    row.get("MemPerc", ""),
                    row.get("NetIO", ""),
                    row.get("BlockIO", ""),
                    row.get("PIDs", ""),
                ]
                for row in rows
            ],
            max_widths=[26, 8, 20, 8, 18, 18, 6],
        )
        self.ui.pause()

    # ------------------------------------------------------------------
    # Global update check and apply
    # ------------------------------------------------------------------
    def _check_updates_menu(self) -> None:
        if not self.projects:
            self.ui.warn("No projects discovered. Rescan first.")
            self.ui.pause()
            return
        if not self._require_audit():
            return
        containers = self._containers(quiet=True)
        valid = [project for project in self.projects if project.valid]
        if not valid:
            self.ui.warn("No valid projects to check.")
            self.ui.pause()
            return

        self.ui.info(
            f"Ready to pull images for {len(valid)} project(s). This does not "
            "restart containers and may use significant bandwidth."
        )
        self.ui.info(
            "Each project runs: docker compose ... pull --quiet --ignore-buildable"
        )
        for project in valid:
            if project.blockers:
                self.ui.warn(f"Note: {project.project_name} has blockers; pull is allowed.")
        if not self.ui.confirm("Start update check?", default=False):
            return

        reports: list[ProjectUpdateReport] = []
        try:
            with self._locked():
                for project in valid:
                    project_started = time.monotonic()
                    report = check_project(
                        self.docker,
                        project,
                        containers,
                        progress=self.ui.info,
                    )
                    reports.append(report)
                    self._audit_action(
                        "compose.pull",
                        str(project.primary_file),
                        "ok" if report.pull_ok else "error",
                        detail=(
                            report.pull_error
                            or f"{len(report.changed_services())} changed service(s)"
                        ),
                        project=project.project_name,
                        started=project_started,
                    )
        except (DockerMgmtError, AuditError, LockBusy) as exc:
            self.ui.error(str(exc))
            self.ui.pause()
            return

        self._print_update_report(reports)
        self._offer_apply_reports(reports)
        self.ui.pause()

    def _print_update_report(self, reports: Sequence[ProjectUpdateReport]) -> None:
        self.ui.header("Update report")
        rows = []
        for report in reports:
            if report.skipped_reason:
                rows.append(
                    [
                        report.project.project_name,
                        "-",
                        "-",
                        "skipped",
                        report.skipped_reason,
                    ]
                )
                continue
            for service in report.services:
                rows.append(
                    [
                        report.project.project_name,
                        service.service,
                        service.image or "<build only>",
                        service.status,
                        service.detail,
                    ]
                )
        if rows:
            self.ui.print_table(
                ["PROJECT", "SERVICE", "IMAGE", "STATUS", "DETAIL"],
                rows,
                max_widths=[20, 20, 38, 18, 48],
            )
        else:
            self.ui.info("No services to report.")

        changed = sum(len(report.changed_services()) for report in reports)
        errors = [report for report in reports if report.has_errors]
        if changed:
            self.ui.warn(f"{changed} service(s) have image updates available.")
        else:
            self.ui.success("No image updates found.")
        for report in errors:
            if report.pull_error:
                self.ui.error(
                    f"{report.project.project_name}: pull failed: {report.pull_error}"
                )

    def _offer_apply_reports(self, reports: Sequence[ProjectUpdateReport]) -> None:
        changed = [
            report for report in reports if report.has_updates and report.pull_ok
        ]
        if not changed:
            return
        choice = self.ui.choose(
            "Apply updates",
            [
                ("Select one project to update", "select"),
                ("Apply all projects with updates (requires typing UPDATE)", "all"),
                ("Do nothing", "none"),
            ],
            back_label="Do nothing",
        )
        if choice in {None, "none"}:
            return
        if choice == "select":
            selected = self.ui.choose(
                "Select project to update",
                [
                    (
                        f"{report.project.project_name} ({len(report.changed_services())} changed service(s))",
                        report.project,
                    )
                    for report in changed
                ],
            )
            if selected is None:
                return
            self._apply_project(selected, pull=False, interactive=True)
            return

        if not self.ui.confirm_phrase(
            "This will run docker compose up -d for every project with updates. "
            "Containers will be recreated; high-risk settings and file trust are "
            "checked per project.",
            "UPDATE",
        ):
            self.ui.info("Cancelled.")
            return
        for report in changed:
            try:
                self._apply_project(report.project, pull=False, interactive=False)
            except (DockerMgmtError, AuditError, LockBusy) as exc:
                self.ui.error(f"{report.project.project_name}: {exc}")
        self.ui.pause()

    # ------------------------------------------------------------------
    # Disk management
    # ------------------------------------------------------------------
    def _disk_menu(self) -> None:
        while True:
            self.ui.header("Disk usage")
            df = self.docker.system_df()
            if df.ok:
                self.ui.info(df.stdout.strip() or "docker system df returned no data.")
            else:
                self.ui.error("docker system df failed: " + summarize_output(df))
            self.ui.info(
                "Volumes are never pruned by this tool; deleting volumes can "
                "destroy application data."
            )
            choice = self.ui.choose(
                "Disk cleanup",
                [
                    ("Remove dangling images only (docker image prune -f)", "images"),
                    ("Remove unused build cache (docker builder prune -f)", "cache"),
                    ("Remove stopped containers (docker container prune -f)", "containers"),
                    ("Remove unused networks (docker network prune -f)", "networks"),
                    ("Show volumes (read-only)", "volumes"),
                    ("Back", "back"),
                ],
                back_label="Back to main menu",
            )
            if choice in {None, "back"}:
                return
            if choice == "volumes":
                result = self.docker.volume_list()
                if result.ok:
                    lines = result.stdout.strip().splitlines()
                    self.ui.section(f"Volumes ({len(lines)})")
                    for line in lines:
                        self.ui.info("  " + line)
                    if not lines:
                        self.ui.info("  (none)")
                else:
                    self.ui.error(summarize_output(result))
                self.ui.pause()
                continue
            self._prune(choice)

    def _prune(self, target: str) -> None:
        details = {
            "images": (
                "Remove dangling (untagged, unused) images. Tagged images used by "
                "stopped or running containers are not removed.",
                "PRUNE IMAGES",
                self.docker.prune_images,
            ),
            "cache": (
                "Remove all unused Docker build cache.",
                "PRUNE CACHE",
                self.docker.prune_build_cache,
            ),
            "containers": (
                "Remove all stopped containers. This can remove stopped Compose "
                "containers; running containers are untouched.",
                "PRUNE CONTAINERS",
                self.docker.prune_containers,
            ),
            "networks": (
                "Remove unused Docker networks. Networks used by containers are "
                "not removed.",
                "PRUNE NETWORKS",
                self.docker.prune_networks,
            ),
        }
        if target not in details:
            return
        message, phrase, action = details[target]
        if not self._require_audit():
            return
        commands = {
            "images": "docker image prune -f",
            "cache": "docker builder prune -f",
            "containers": "docker container prune -f",
            "networks": "docker network prune -f",
        }
        self.ui.section("Command")
        self.ui.info("  " + commands[target])
        if not self.ui.confirm_phrase(message + " This cannot be undone.", phrase):
            self.ui.info("Cancelled.")
            return
        started = time.monotonic()
        try:
            with self._locked():
                result = action()
        except (DockerMgmtError, AuditError, LockBusy) as exc:
            self._audit_action(
                f"docker.prune.{target}",
                target,
                "error",
                detail=str(exc),
                started=started,
            )
            raise
        self._audit_action(
            f"docker.prune.{target}",
            target,
            "ok" if result.ok else "error",
            detail=summarize_output(result),
            started=started,
        )
        self._show_result(f"Prune {target}", result, started)
        after = self.docker.system_df()
        if after.ok:
            self.ui.section("Disk usage after cleanup")
            self.ui.info(after.stdout.strip())
        self.ui.pause()

    # ------------------------------------------------------------------
    # Validation, audit, settings
    # ------------------------------------------------------------------
    def _validate_menu(self) -> None:
        try:
            self._rescan()
        except (DockerMgmtError, OSError) as exc:
            self.ui.error(f"Scan failed: {exc}")
            self.ui.pause()
            return
        self.ui.header("Compose validation report")
        rows = []
        invalid: list[ComposeProject] = []
        critical: list[ComposeProject] = []
        blocked: list[ComposeProject] = []
        for project in self.projects:
            rows.append(
                [
                    project.project_name,
                    "yes" if project.valid else "NO",
                    len(project.services),
                    len(project.critical_warnings),
                    len(project.warnings),
                    len(project.blockers),
                    project.primary_file,
                ]
            )
            if not project.valid:
                invalid.append(project)
            if project.critical_warnings:
                critical.append(project)
            if project.blockers:
                blocked.append(project)
        if rows:
            self.ui.print_table(
                ["PROJECT", "VALID", "SERVICES", "HIGH-RISK", "WARNINGS", "BLOCKERS", "FILE"],
                rows,
                max_widths=[20, 7, 9, 10, 9, 9, 56],
            )
        else:
            self.ui.info("No projects discovered.")
        if invalid:
            self.ui.section("Invalid configurations")
            for project in invalid:
                self.ui.error(f"{project.project_name}: {project.error}")
        if critical:
            self.ui.section("High-risk findings")
            for project in critical:
                self.ui.info(f"  {project.project_name}:")
                self.ui.bullets(project.critical_warnings, prefix="    - ")
        if blocked:
            self.ui.section("Blockers")
            for project in blocked:
                self.ui.info(f"  {project.project_name}:")
                self.ui.bullets(project.blockers, prefix="    - ")
        trust = [
            (project, self._trust_issues(project))
            for project in self.projects
            if project.valid
        ]
        trust = [(project, issues) for project, issues in trust if issues]
        if trust:
            self.ui.section("Root file-trust issues")
            for project, issues in trust:
                self.ui.info(f"  {project.project_name}:")
                self.ui.bullets(issues, prefix="    - ")
        self.ui.pause()

    def _audit_menu(self) -> None:
        tail = 50
        while True:
            self.ui.header("Audit log")
            self.ui.key_values(
                [
                    ("Path", self.config.audit_path),
                    ("Status", "writable" if self._ensure_audit(quiet=True) else f"UNAVAILABLE: {self.audit_error}"),
                    ("Records shown", tail),
                ]
            )
            records = read_audit_records(self.config.audit_path, tail=tail)
            if records:
                self.ui.print_table(
                    ["TIME", "USER", "ACTION", "PROJECT", "RESULT", "DETAIL"],
                    [
                        [
                            record.timestamp,
                            record.sudo_user or record.user,
                            record.action,
                            record.project or "-",
                            record.result,
                            record.detail,
                        ]
                        for record in records
                    ],
                    max_widths=[24, 12, 22, 18, 8, 60],
                )
            else:
                self.ui.info("No audit records found.")
            choice = self.ui.choose(
                "Audit options",
                [
                    ("Change number of records", "tail"),
                    ("Refresh", "refresh"),
                    ("Back", "back"),
                ],
                back_label="Back to main menu",
            )
            if choice in {None, "back"}:
                return
            if choice == "tail":
                value = self.ui.prompt("Number of records", default=str(tail))
                try:
                    tail = max(1, min(1000, int(value)))
                except ValueError:
                    self.ui.warn("Invalid number.")
            elif choice == "refresh":
                continue

    def _settings_menu(self) -> None:
        self.ui.header("Settings and security notes")
        self.ui.key_values(
            [
                ("Config", self.config.config_display),
                ("Scan roots", ", ".join(str(path) for path in self.config.scan_roots)),
                ("Include all YAML", self.config.include_all_yaml),
                ("Max depth", self.config.max_depth),
                ("Hidden dirs", self.config.include_hidden),
                ("Follow dir symlinks", self.config.follow_symlinks),
                ("Excluded dirs", ", ".join(sorted(self.config.exclude_dirs))),
                ("Pull timeout", f"{self.config.pull_timeout}s"),
                ("Up timeout", f"{self.config.up_timeout}s"),
                ("Wait after update", self.config.wait_after_update),
                ("Audit log", self.config.audit_path),
                ("Operation lock", self.config.lock_path),
                ("DOCKER_HOST", os.environ.get("DOCKER_HOST", "(local socket)")),
                ("Allow unsafe ownership", self.config.allow_unsafe_ownership),
                ("Docker", self.docker.version_info()),
                ("Compose", self.docker.compose_version_string()),
            ]
        )
        if self.config.warnings:
            self.ui.section("Configuration warnings")
            self.ui.bullets(self.config.warnings)
        self.ui.section("Why this tool does not use Watchtower")
        self.ui.bullets(
            [
                "No long-running updater daemon with control of the Docker socket.",
                "Updates are pulled on demand, then a human explicitly approves recreation.",
                "No unattended restarts during traffic peaks or outside maintenance windows.",
                "Every mutating action is recorded in a local audit log.",
                "Mutable upstream tags are visible; pin versions/digests in Compose.",
            ]
        )
        self.ui.section("Safety controls")
        self.ui.bullets(
            [
                "No shell=True; Docker CLI arguments are passed as vectors.",
                "Host-wide non-blocking lock prevents concurrent mutating operations.",
                "Mutating actions are blocked if the audit log is not writable.",
                "Root-run Compose actions require root-owned, non-writable project files.",
                "Volumes are never pruned and `down -v` is never used.",
                "High-risk settings (privileged, host namespaces, Docker socket) require confirmation.",
            ]
        )
        self.ui.info("See SECURITY.md for the full threat model and rationale.")
        self.ui.pause()
