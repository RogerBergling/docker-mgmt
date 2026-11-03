"""Command-line entry point and non-interactive commands."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import traceback
from dataclasses import asdict
from typing import Optional, Sequence

from . import __version__
from .app import App
from .audit import (
    AuditError,
    AuditLogger,
    LockBusy,
    OperationLock,
    read_audit_records,
)
from .config import Config, ConfigError, load_config
from .discovery import (
    container_to_dict,
    project_to_dict,
    scan_candidates,
    scan_projects,
    select_projects,
    summarize_scan,
)
from .docker import (
    DockerClient,
    DockerUnavailable,
)
from .models import ComposeProject, ProjectUpdateReport
from .runner import CommandRunner, DockerMgmtError, summarize_output
from .security import check_project_trust
from .ui import UI
from .updates import (
    check_exit_code,
    check_project,
    report_to_dict,
)


def _common_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "--config",
        metavar="PATH",
        default=argparse.SUPPRESS,
        help="configuration file (default: /etc/docker-mgmt/config.ini or XDG)",
    )
    parser.add_argument(
        "--root",
        action="append",
        metavar="PATH",
        default=argparse.SUPPRESS,
        help="override scan roots; may be repeated",
    )
    parser.add_argument(
        "--all-yaml",
        action="store_true",
        default=argparse.SUPPRESS,
        help="validate every *.yml/*.yaml file, not just Compose-named files",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        default=argparse.SUPPRESS,
        help="disable ANSI color",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=argparse.SUPPRESS,
        help="show a Python traceback for unexpected errors",
    )
    return parser


def build_parser() -> argparse.ArgumentParser:
    common = _common_parser()
    parser = argparse.ArgumentParser(
        prog="docker-mgmt",
        description=(
            "Menu-driven, audited management of local Docker Compose projects. "
            "Updates are never automatic."
        ),
        parents=[common],
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("menu", parents=[common], help="start the interactive menu")

    scan = sub.add_parser(
        "scan", parents=[common], help="scan roots and list Compose projects"
    )
    scan.add_argument("--json", action="store_true", help="machine-readable output")

    status = sub.add_parser(
        "status", parents=[common], help="show containers and project status"
    )
    status.add_argument("--json", action="store_true", help="machine-readable output")
    status.add_argument(
        "--running", action="store_true", help="show only running containers"
    )

    check = sub.add_parser(
        "check",
        parents=[common],
        help="pull images and report updates (does not restart containers)",
    )
    check.add_argument("projects", nargs="*", help="project names or Compose file paths")
    check.add_argument("--yes", action="store_true", help="confirm pulling images")
    check.add_argument("--json", action="store_true", help="machine-readable output")

    update = sub.add_parser(
        "update",
        parents=[common],
        help="pull images and run docker compose up -d",
    )
    update.add_argument("projects", nargs="*", help="project names or Compose file paths")
    update.add_argument(
        "--all", action="store_true", help="update all discovered valid projects"
    )
    update.add_argument("--yes", action="store_true", help="non-interactive confirmation")

    validate = sub.add_parser(
        "validate",
        parents=[common],
        help="validate Compose files and report security findings",
    )
    validate.add_argument("--json", action="store_true", help="machine-readable output")

    prune = sub.add_parser(
        "prune", parents=[common], help="safe disk cleanup (volumes are never pruned)"
    )
    prune.add_argument(
        "target",
        choices=["images", "cache", "containers", "networks"],
        help="what to prune",
    )
    prune.add_argument("--yes", action="store_true", help="non-interactive confirmation")

    logs = sub.add_parser("logs", parents=[common], help="show container or project logs")
    logs.add_argument("target", help="container name/ID or Compose project name")
    logs.add_argument("--tail", type=int, default=200, help="number of lines (default: 200)")
    logs.add_argument("--follow", action="store_true", help="follow log output")

    audit = sub.add_parser("audit", parents=[common], help="show the local audit log")
    audit.add_argument("--tail", type=int, default=50, help="number of records")
    audit.add_argument("--json", action="store_true", help="machine-readable output")

    sub.add_parser("doctor", parents=[common], help="check prerequisites and configuration")

    return parser


def _runtime(args: argparse.Namespace) -> tuple[Config, DockerClient, AuditLogger]:
    config = load_config(
        getattr(args, "config", None),
        roots_override=getattr(args, "root", None),
        all_yaml_override=True if getattr(args, "all_yaml", False) else None,
        no_color=getattr(args, "no_color", False),
    )
    runner = CommandRunner()
    docker = DockerClient(runner, config)
    audit = AuditLogger(config.audit_path, config.audit_max_bytes)
    return config, docker, audit


def _print_config_warnings(config: Config) -> None:
    for warning in config.warnings:
        print(f"warning: {warning}", file=sys.stderr)


def _ui(config: Config) -> UI[str]:
    return UI(config.color, config.page_size)


def _load_projects(
    config: Config,
    docker: DockerClient,
    *,
    projects: Optional[Sequence[str]] = None,
) -> tuple[list[ComposeProject], list[str]]:
    result = scan_projects(config, docker)
    selected = result.projects
    errors: list[str] = []
    if projects:
        selected, errors = select_projects(result.projects, projects)
    return selected, errors + result.warnings


def _ensure_docker(docker: DockerClient) -> bool:
    try:
        docker.ensure_available()
        return True
    except DockerUnavailable as exc:
        print(f"error: {exc}", file=sys.stderr)
        print("Run `docker-mgmt doctor` for diagnostics.", file=sys.stderr)
        return False


def _ensure_audit(audit: AuditLogger) -> bool:
    try:
        audit.ensure_ready()
        return True
    except AuditError as exc:
        print(f"error: audit log is required for this command: {exc}", file=sys.stderr)
        return False


def _report_table(ui: UI[str], reports: Sequence[ProjectUpdateReport]) -> None:
    rows: list[list[object]] = []
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
        ui.print_table(
            ["PROJECT", "SERVICE", "IMAGE", "STATUS", "DETAIL"],
            rows,
            max_widths=[20, 20, 38, 18, 48],
        )
    else:
        ui.info("No services to report.")


def _print_security_findings(project: ComposeProject, config: Config) -> None:
    if project.blockers:
        print("  blockers:")
        for blocker in project.blockers:
            print(f"    - {blocker}")
    if project.critical_warnings:
        print("  high-risk settings:")
        for warning in project.critical_warnings:
            print(f"    - {warning}")
    if project.warnings:
        print("  warnings:")
        for warning in project.warnings:
            print(f"    - {warning}")
    trust = check_project_trust(
        project.files,
        project.env_files,
        project.build_contexts,
        project.extra_files,
    )
    if trust:
        print("  root file-trust issues:")
        for issue in trust:
            print(f"    - {issue}")


# ----------------------------------------------------------------------
# Commands
# ----------------------------------------------------------------------
def command_scan(args: argparse.Namespace, config: Config, docker: DockerClient) -> int:
    result = scan_projects(config, docker)
    if args.json:
        print(
            json.dumps(
                {
                    "projects": [project_to_dict(p) for p in result.projects],
                    "warnings": result.warnings,
                    "candidate_count": result.candidate_count,
                    "duration_seconds": round(result.duration_seconds, 3),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    ui = _ui(config)
    ui.header("Compose scan")
    print(summarize_scan(result))
    if result.projects:
        ui.print_table(
            ["PROJECT", "VALID", "SERVICES", "SOURCE", "FILE"],
            [
                [
                    project.project_name,
                    "yes" if project.valid else "NO",
                    len(project.services),
                    project.source,
                    project.primary_file,
                ]
                for project in result.projects
            ],
            max_widths=[20, 7, 9, 12, 64],
        )
    for project in result.projects:
        if not project.valid:
            ui.error(f"{project.project_name}: {project.error}")
    for warning in result.warnings:
        ui.warn(f"scan warning: {warning}")
    return 0


def command_status(args: argparse.Namespace, config: Config, docker: DockerClient) -> int:
    containers = docker.list_containers(all_containers=not args.running)
    if args.json:
        print(
            json.dumps(
                {
                    "containers": [container_to_dict(c) for c in containers],
                    "running": sum(1 for c in containers if c.running),
                    "unhealthy": sum(1 for c in containers if c.unhealthy),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    ui = _ui(config)
    ui.header("Container status")
    ui.key_values(
        [
            ("Containers", len(containers)),
            ("Running", sum(1 for c in containers if c.running)),
            ("Unhealthy", sum(1 for c in containers if c.unhealthy)),
        ]
    )
    if not containers:
        ui.info("No containers found.")
        return 0
    ui.print_table(
        ["NAME", "PROJECT", "SERVICE", "STATE", "HEALTH", "RESTARTS", "IMAGE", "PORTS"],
        [
            [
                c.display_name,
                c.project or "-",
                c.service or "-",
                c.state,
                c.health or "-",
                c.restart_count,
                c.image,
                ", ".join(c.ports[:3]) + (" ..." if len(c.ports) > 3 else ""),
            ]
            for c in containers
        ],
        max_widths=[28, 18, 16, 12, 9, 8, 32, 28],
    )
    return 0


def command_check(
    args: argparse.Namespace, config: Config, docker: DockerClient, audit: AuditLogger
) -> int:
    selected, warnings = _load_projects(config, docker, projects=args.projects)
    for warning in warnings:
        print(f"scan warning: {warning}", file=sys.stderr)
    selected = [project for project in selected if project.valid]
    if not selected:
        print("error: no valid projects selected", file=sys.stderr)
        return 2
    if not args.yes:
        if not sys.stdin.isatty():
            print(
                "error: refusing to pull images non-interactively without --yes",
                file=sys.stderr,
            )
            return 2
        if not _ui(config).confirm(
            f"Pull images for {len(selected)} project(s)? "
            "This does not restart containers.",
            default=False,
        ):
            return 0
    if not _ensure_audit(audit):
        return 2
    containers = docker.list_containers(all_containers=True)
    reports: list[ProjectUpdateReport] = []
    progress = (
        None
        if args.json
        else (lambda message: print(message, file=sys.stderr))
    )
    try:
        with OperationLock(config.lock_path):
            for project in selected:
                started = time.monotonic()
                report = check_project(
                    docker, project, containers, progress=progress
                )
                reports.append(report)
                try:
                    audit.log(
                        action="compose.pull",
                        target=str(project.primary_file),
                        result="ok" if report.pull_ok else "error",
                        detail=report.pull_error
                        or f"{len(report.changed_services())} changed service(s)",
                        project=project.project_name,
                        duration_ms=int((time.monotonic() - started) * 1000),
                    )
                except AuditError as exc:
                    print(f"error: audit write failed: {exc}", file=sys.stderr)
                    return 2
    except (LockBusy, AuditError, DockerMgmtError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(
            json.dumps(
                {
                    "reports": [report_to_dict(report) for report in reports],
                    "updates": sum(len(r.changed_services()) for r in reports),
                    "errors": sum(1 for r in reports if r.has_errors),
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        ui = _ui(config)
        ui.header("Update report")
        _report_table(ui, reports)
        changes = sum(len(r.changed_services()) for r in reports)
        if changes:
            ui.warn(f"{changes} service(s) have image updates available.")
        else:
            ui.success("No image updates found.")
        for report in reports:
            if report.pull_error:
                ui.error(f"{report.project.project_name}: {report.pull_error}")
    return check_exit_code(reports)


def command_update(
    args: argparse.Namespace, config: Config, docker: DockerClient, audit: AuditLogger
) -> int:
    if args.all and args.projects:
        print("error: use either project names or --all, not both", file=sys.stderr)
        return 2
    all_projects, warnings = _load_projects(config, docker, projects=args.projects)
    for warning in warnings:
        print(f"scan warning: {warning}", file=sys.stderr)
    if args.all:
        selected = [project for project in all_projects if project.valid]
    else:
        selected = all_projects
    if not selected:
        print("error: no projects selected", file=sys.stderr)
        return 2
    if not args.all and not args.projects:
        print("error: specify project names/paths or use --all", file=sys.stderr)
        return 2
    if not args.yes:
        if not sys.stdin.isatty():
            print(
                "error: refusing to update non-interactively without --yes",
                file=sys.stderr,
            )
            return 2
        ui = _ui(config)
        if args.all:
            if not ui.confirm_phrase(
                f"Pull and run compose up -d for {len(selected)} project(s).",
                "UPDATE",
            ):
                return 0
        elif not ui.confirm(
            f"Pull and run compose up -d for {len(selected)} project(s)?",
            default=False,
        ):
            return 0
    if not _ensure_audit(audit):
        return 2

    containers = docker.list_containers(all_containers=True)
    failures = 0
    for project in selected:
        if not project.valid:
            print(f"error: {project.project_name}: {project.error}", file=sys.stderr)
            failures += 1
            continue
        if project.blockers:
            print(
                f"error: {project.project_name}: blocked: "
                + "; ".join(project.blockers),
                file=sys.stderr,
            )
            failures += 1
            continue
        trust = check_project_trust(
            project.files,
            project.env_files,
            project.build_contexts,
            project.extra_files,
        )
        if trust and not config.allow_unsafe_ownership:
            print(
                f"error: {project.project_name}: files are not root-controlled:",
                file=sys.stderr,
            )
            for issue in trust:
                print(f"  - {issue}", file=sys.stderr)
            failures += 1
            continue
        if project.critical_warnings:
            print(
                f"warning: {project.project_name}: high-risk settings:",
                file=sys.stderr,
            )
            for warning in project.critical_warnings:
                print(f"  - {warning}", file=sys.stderr)
            if (
                not args.yes
                and sys.stdin.isatty()
                and not _ui(config).confirm(
                    f"Continue updating {project.project_name} despite high-risk settings?",
                    default=False,
                )
            ):
                failures += 1
                continue

        started = time.monotonic()
        try:
            with OperationLock(config.lock_path):
                report = check_project(
                    docker,
                    project,
                    containers,
                    progress=lambda message: print(message, file=sys.stderr),
                )
                try:
                    audit.log(
                        action="compose.pull",
                        target=str(project.primary_file),
                        result="ok" if report.pull_ok else "error",
                        detail=report.pull_error
                        or f"{len(report.changed_services())} changed service(s)",
                        project=project.project_name,
                        duration_ms=int((time.monotonic() - started) * 1000),
                    )
                except AuditError as exc:
                    print(f"error: audit write failed: {exc}", file=sys.stderr)
                    failures += 1
                    continue
                if not report.pull_ok:
                    print(
                        f"error: {project.project_name}: pull failed; "
                        "not applying up -d",
                        file=sys.stderr,
                    )
                    failures += 1
                    continue
                up_started = time.monotonic()
                up = docker.up(
                    project.files,
                    wait=config.wait_after_update,
                    project_name=project.project_name,
                    pull_policy="never",
                )
                try:
                    audit.log(
                        action="compose.up",
                        target=str(project.primary_file),
                        result="ok" if up.ok else "error",
                        detail=summarize_output(up),
                        project=project.project_name,
                        duration_ms=int((time.monotonic() - up_started) * 1000),
                    )
                except AuditError as exc:
                    print(f"error: audit write failed: {exc}", file=sys.stderr)
                    failures += 1
                if not up.ok:
                    failures += 1
                    print(
                        f"error: {project.project_name}: compose up failed: "
                        + summarize_output(up),
                        file=sys.stderr,
                    )
                else:
                    print(
                        f"updated: {project.project_name} "
                        f"({len(report.changed_services())} changed service(s))"
                    )
        except (LockBusy, AuditError, DockerMgmtError) as exc:
            print(f"error: {project.project_name}: {exc}", file=sys.stderr)
            failures += 1
    return 0 if failures == 0 else 1


def command_validate(
    args: argparse.Namespace, config: Config, docker: DockerClient
) -> int:
    result = scan_projects(config, docker)
    if args.json:
        print(
            json.dumps(
                {
                    "projects": [project_to_dict(p) for p in result.projects],
                    "warnings": result.warnings,
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        ui = _ui(config)
        ui.header("Compose validation")
        ui.print_table(
            ["PROJECT", "VALID", "SERVICES", "HIGH-RISK", "WARNINGS", "BLOCKERS", "FILE"],
            [
                [
                    project.project_name,
                    "yes" if project.valid else "NO",
                    len(project.services),
                    len(project.critical_warnings),
                    len(project.warnings),
                    len(project.blockers),
                    project.primary_file,
                ]
                for project in result.projects
            ],
            max_widths=[20, 7, 9, 10, 9, 9, 56],
        )
        for project in result.projects:
            if project.valid and not (
                project.critical_warnings
                or project.warnings
                or project.blockers
                or check_project_trust(
                    project.files,
                    project.env_files,
                    project.build_contexts,
                    project.extra_files,
                )
            ):
                continue
            print()
            print(f"{project.project_name} ({project.primary_file})")
            if not project.valid:
                print(f"  invalid: {project.error}")
            _print_security_findings(project, config)
        for warning in result.warnings:
            print(f"scan warning: {warning}", file=sys.stderr)

    invalid = [p for p in result.projects if not p.valid]
    risky = [p for p in result.projects if p.critical_warnings or p.blockers]
    trust = [
        p
        for p in result.projects
        if p.valid
        and check_project_trust(
            p.files, p.env_files, p.build_contexts, p.extra_files
        )
        and not config.allow_unsafe_ownership
    ]
    return 1 if invalid or risky or trust else 0


def command_prune(
    args: argparse.Namespace, config: Config, docker: DockerClient, audit: AuditLogger
) -> int:
    if not _ensure_audit(audit):
        return 2
    if not args.yes:
        if not sys.stdin.isatty():
            print(
                "error: refusing to prune non-interactively without --yes",
                file=sys.stderr,
            )
            return 2
        phrase = f"PRUNE {args.target.upper()}"
        if not _ui(config).confirm_phrase(
            f"Run docker {args.target} prune? This cannot be undone.", phrase
        ):
            return 0
    ui = _ui(config)
    before = docker.system_df()
    if before.ok:
        ui.header("Disk usage before cleanup")
        ui.info(before.stdout.strip())
    actions = {
        "images": docker.prune_images,
        "cache": docker.prune_build_cache,
        "containers": docker.prune_containers,
        "networks": docker.prune_networks,
    }
    action = actions[args.target]
    started = time.monotonic()
    try:
        with OperationLock(config.lock_path):
            result = action()
    except (LockBusy, AuditError, DockerMgmtError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        audit.log(
            action=f"docker.prune.{args.target}",
            target=args.target,
            result="ok" if result.ok else "error",
            detail=summarize_output(result),
            duration_ms=int((time.monotonic() - started) * 1000),
        )
    except AuditError as exc:
        print(f"error: audit write failed: {exc}", file=sys.stderr)
        return 2
    if not result.ok:
        print(f"error: prune failed: {summarize_output(result)}", file=sys.stderr)
        return 1
    ui.header("Prune result")
    ui.info(result.stdout.strip() or "done")
    after = docker.system_df()
    if after.ok:
        ui.header("Disk usage after cleanup")
        ui.info(after.stdout.strip())
    return 0


def command_logs(
    args: argparse.Namespace, config: Config, docker: DockerClient
) -> int:
    tail = max(1, int(args.tail))
    containers = docker.list_containers(all_containers=True)
    exact_containers = [
        c
        for c in containers
        if c.name == args.target or c.id == args.target or c.id.startswith(args.target)
    ]
    if len(exact_containers) == 1:
        code = docker.stream_container_logs(
            exact_containers[0].id, tail=tail, follow=args.follow
        )
        return 0 if code in {0, 130} else code

    result = scan_projects(config, docker)
    exact_projects = [
        p for p in result.projects if p.project_name == args.target
    ]
    if len(exact_projects) != 1:
        exact_projects = [
            p
            for p in result.projects
            if args.target.lower() in p.project_name.lower()
        ]
    if len(exact_projects) == 1:
        code = docker.stream_project_logs(
            exact_projects[0].files,
            tail=tail,
            follow=args.follow,
            project_name=exact_projects[0].project_name,
        )
        return 0 if code in {0, 130} else code

    if len(exact_containers) > 1:
        print(
            "error: target matches multiple containers: "
            + ", ".join(c.display_name for c in exact_containers),
            file=sys.stderr,
        )
        return 2
    if len(exact_projects) > 1:
        print(
            "error: target matches multiple projects: "
            + ", ".join(p.project_name for p in exact_projects),
            file=sys.stderr,
        )
        return 2
    print(f"error: no container or project matches {args.target!r}", file=sys.stderr)
    return 2


def command_audit(args: argparse.Namespace, config: Config) -> int:
    records = read_audit_records(config.audit_path, tail=max(1, args.tail))
    if args.json:
        print(
            json.dumps(
                [asdict(record) for record in records],
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    ui = _ui(config)
    ui.header("Audit log")
    ui.key_values(
        [
            ("Path", config.audit_path),
            ("Records", len(records)),
        ]
    )
    if not records:
        ui.info("No audit records found.")
        return 0
    ui.print_table(
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
    return 0


def command_doctor(
    config: Config, docker: DockerClient, audit: AuditLogger
) -> int:
    ui = _ui(config)
    ui.header("docker-mgmt doctor")
    docker_path = shutil_which("docker")
    compose_ok = False
    docker_ok = False
    if docker_path:
        docker_ok = True
        try:
            docker.ensure_available()
            docker_ok = True
            compose_ok = docker.compose_version() is not None
        except DockerUnavailable as exc:
            docker_ok = False
            ui.error(str(exc))
    else:
        ui.error("docker CLI not found in PATH")

    audit_ok = False
    try:
        audit.ensure_ready()
        audit_ok = True
    except AuditError as exc:
        ui.error(f"audit log: {exc}")

    lock_status = "ok"
    lock_ok = True
    try:
        probe = OperationLock(config.lock_path)
        probe.acquire()
        probe.release()
    except LockBusy:
        lock_status = "busy (another operation is running)"
    except (AuditError, OSError) as exc:
        lock_status = f"UNAVAILABLE: {exc}"
        lock_ok = False

    roots = []
    root_warnings: list[str] = []
    for root in config.scan_roots:
        exists = root.exists() and root.is_dir()
        roots.append(f"{root}{'' if exists else ' (missing)'}")
        if not exists:
            root_warnings.append(f"scan root missing: {root}")
    try:
        candidates, candidate_warnings = scan_candidates(config)
    except Exception as exc:  # doctor should never crash
        candidates = []
        candidate_warnings = [f"scan failed: {exc}"]

    ui.key_values(
        [
            ("Python", sys.version.split()[0]),
            ("User", f"uid={os.geteuid()}"),
            ("Config", config.config_display),
            ("Docker CLI", docker_path or "MISSING"),
            ("Docker daemon", "ok" if docker_ok else "unavailable"),
            ("Docker Compose", docker.compose_version_string() if compose_ok else "unavailable"),
            ("DOCKER_HOST", os.environ.get("DOCKER_HOST", "(local socket)")),
            ("Audit log", f"{config.audit_path} ({'writable' if audit_ok else 'NOT WRITABLE'})"),
            ("Lock file", f"{config.lock_path} ({lock_status})"),
            ("Scan roots", ", ".join(roots)),
            ("Candidate YAML files", len(candidates)),
            ("Allow unsafe ownership", config.allow_unsafe_ownership),
        ]
    )
    if config.warnings:
        ui.section("Configuration warnings")
        ui.bullets(config.warnings)
    if root_warnings:
        ui.section("Scan root warnings")
        ui.bullets(root_warnings)
    if candidate_warnings:
        ui.section("Scan warnings")
        ui.bullets(candidate_warnings[:20])
    ui.section("Security posture")
    ui.bullets(
        [
            "Updates are pull-on-demand; no automatic restart/update daemon is used.",
            "Mutating actions require the audit log to be writable.",
            "Root-run Compose actions require root-owned, non-writable files.",
            "Volumes are never pruned and `docker compose down -v` is never used.",
            "Docker access is root-equivalent; restrict who can run this tool.",
        ]
    )
    return 0 if docker_ok and compose_ok and audit_ok and lock_ok else 1


def shutil_which(name: str) -> Optional[str]:
    import shutil

    return shutil.which(name)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    debug = bool(getattr(args, "debug", False))
    try:
        config, docker, audit = _runtime(args)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    command = args.command or "menu"
    if command != "menu":
        _print_config_warnings(config)

    try:
        if command == "menu":
            return App(config, docker, audit).run()
        if command == "doctor":
            return command_doctor(config, docker, audit)
        if command == "audit":
            return command_audit(args, config)
        if not _ensure_docker(docker):
            return 2
        if command == "scan":
            return command_scan(args, config, docker)
        if command == "status":
            return command_status(args, config, docker)
        if command == "check":
            return command_check(args, config, docker, audit)
        if command == "update":
            return command_update(args, config, docker, audit)
        if command == "validate":
            return command_validate(args, config, docker)
        if command == "prune":
            return command_prune(args, config, docker, audit)
        if command == "logs":
            return command_logs(args, config, docker)
        parser.error(f"unknown command: {command}")
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except (ConfigError, DockerMgmtError, AuditError, LockBusy, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # pragma: no cover - defensive boundary
        if debug:
            traceback.print_exc()
        else:
            print(
                f"error: unexpected failure: {exc}. Re-run with --debug for a traceback.",
                file=sys.stderr,
            )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
