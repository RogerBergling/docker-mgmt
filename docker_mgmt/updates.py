"""Image update detection and application.

Update checks use the operator's chosen policy: pull images, then compare
local image IDs and running container image IDs. Pulling never restarts a
container. A separate, explicit action runs `docker compose up -d`.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Optional, Sequence

from .config import Config
from .discovery import reference_findings
from .docker import DockerClient
from .models import (
    ComposeProject,
    Container,
    ProjectUpdateReport,
    ServiceUpdate,
)
from .runner import CommandResult, summarize_output
from .security import check_project_trust

ProgressCallback = Callable[[str], None]


@dataclass
class PullPreflight:
    """Non-interactive checks required before `compose pull` runs."""

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def pull_preflight(project: ComposeProject, config: Config) -> PullPreflight:
    """Validate trust and block unsafe projects before an image pull.

    Pulling does not recreate containers, so high-risk Compose settings only
    produce warnings here. File trust, blockers, invalid projects and
    unverified include/extends references still block unless the corresponding
    dangerous configuration option is enabled.
    """

    result = PullPreflight()
    if not project.valid:
        result.errors.append(project.error or "invalid Compose configuration")
        return result
    if project.blockers:
        result.errors.append(
            "project has unresolved blockers: " + "; ".join(project.blockers)
        )

    reference_warnings, unverified = reference_findings(project.files)
    if unverified and not project.unverified_references:
        project.unverified_references = True
        for warning in reference_warnings:
            if warning not in project.warnings:
                project.warnings.append(warning)
    if project.unverified_references:
        if not config.allow_unverified_references:
            result.errors.append(
                "include/extends references cannot be individually trust-checked; "
                "keep the project tree controlled by root/current user or set "
                "security.allow_unverified_references=true after review"
            )
        else:
            result.warnings.append(
                "include/extends references are allowed by configuration but are "
                "not individually trust-checked"
            )

    trust = check_project_trust(
        project.files,
        project.env_files,
        project.build_contexts,
        project.extra_files,
    )
    if trust:
        if not config.allow_unsafe_ownership:
            result.errors.append(
                "files used by this project are not controlled by root/current user"
            )
            result.errors.extend(trust)
        else:
            result.warnings.append(
                "unsafe file ownership is allowed by configuration for this project"
            )
            result.warnings.extend(trust)

    if project.critical_warnings:
        result.warnings.append(
            "high-risk Docker settings are present; pull does not recreate containers"
        )
    return result


@dataclass
class ApplyResult:
    pull_result: Optional[CommandResult] = None
    up_result: Optional[CommandResult] = None

    @property
    def ok(self) -> bool:
        if self.pull_result is not None and not self.pull_result.ok:
            return False
        return self.up_result is not None and self.up_result.ok

    @property
    def error(self) -> Optional[str]:
        if self.pull_result is not None and not self.pull_result.ok:
            return "pull failed: " + summarize_output(self.pull_result)
        if self.up_result is not None and not self.up_result.ok:
            return "up failed: " + summarize_output(self.up_result)
        return None


def _short(image_id: Optional[str]) -> str:
    if not image_id:
        return "missing"
    return image_id.replace("sha256:", "")[:12]


def _running_ids(
    containers: Sequence[Container], project_name: str, service_name: str
) -> tuple[str, ...]:
    values: list[str] = []
    for container in containers:
        if (
            container.project == project_name
            and container.service == service_name
            and container.state in {"running", "restarting", "paused"}
            and container.image_id
        ):
            if container.image_id not in values:
                values.append(container.image_id)
    return tuple(sorted(values))


def check_project(
    docker: DockerClient,
    project: ComposeProject,
    containers: Sequence[Container],
    *,
    progress: Optional[ProgressCallback] = None,
) -> ProjectUpdateReport:
    """Pull images for one project and report which services changed."""

    report = ProjectUpdateReport(project=project)
    if not project.valid:
        report.skipped_reason = project.error or "invalid Compose configuration"
        report.skipped_error = True
        return report
    if not project.services:
        report.skipped_reason = "no services discovered"
        return report

    pullable = [service for service in project.services if service.image]
    if not pullable:
        report.skipped_reason = "all services build locally; nothing to pull"
        for service in project.services:
            report.services.append(
                ServiceUpdate(
                    service=service.name,
                    image=None,
                    before_id=None,
                    after_id=None,
                    running_ids=_running_ids(
                        containers, project.project_name, service.name
                    ),
                    status="build-only",
                    detail="built locally; pull skipped",
                )
            )
        return report

    unique_images: list[str] = []
    for service in project.services:
        if service.image and service.image not in unique_images:
            unique_images.append(service.image)

    before: dict[str, Optional[str]] = {}
    for image in unique_images:
        before[image] = docker.image_id(image)
    running = {
        service.name: _running_ids(containers, project.project_name, service.name)
        for service in project.services
    }

    if progress:
        progress(f"Pulling images for {project.project_name}...")
    pull_result = docker.pull(project.files, project_name=project.project_name)
    report.pull_ok = pull_result.ok
    if not pull_result.ok:
        report.pull_error = summarize_output(pull_result)

    after: dict[str, Optional[str]] = {}
    for image in unique_images:
        after[image] = docker.image_id(image)

    for service in project.services:
        if not service.image:
            report.services.append(
                ServiceUpdate(
                    service=service.name,
                    image=None,
                    before_id=None,
                    after_id=None,
                    running_ids=running.get(service.name, ()),
                    status="build-only",
                    detail="built locally; pull skipped",
                )
            )
            continue

        image = service.image
        before_id = before.get(image)
        after_id = after.get(image)
        running_ids = running.get(service.name, ())
        detail = ""
        if not pull_result.ok and before_id == after_id:
            status = "pull-failed"
            detail = report.pull_error or "pull failed"
        elif before_id is None and after_id is not None:
            status = "new-image"
            detail = f"pulled {_short(after_id)}"
        elif before_id != after_id:
            status = "image-updated"
            detail = f"{_short(before_id)} -> {_short(after_id)}"
            if not pull_result.ok:
                detail += " (pull reported errors)"
        elif running_ids and any(value != after_id for value in running_ids):
            status = "container-stale"
            detail = (
                "running container uses "
                + ", ".join(_short(value) for value in running_ids)
                + f"; local tag is {_short(after_id)}"
            )
        elif running_ids:
            status = "up-to-date"
            detail = _short(after_id)
        else:
            status = "not-running"
            detail = "image is current; no running container"

        report.services.append(
            ServiceUpdate(
                service=service.name,
                image=image,
                before_id=before_id,
                after_id=after_id,
                running_ids=running_ids,
                status=status,
                detail=detail,
            )
        )

    return report


def check_all(
    docker: DockerClient,
    projects: Sequence[ComposeProject],
    containers: Sequence[Container],
    *,
    progress: Optional[ProgressCallback] = None,
) -> list[ProjectUpdateReport]:
    reports: list[ProjectUpdateReport] = []
    for project in projects:
        reports.append(
            check_project(docker, project, containers, progress=progress)
        )
    return reports


def apply_project(
    docker: DockerClient,
    project: ComposeProject,
    *,
    pull: bool = True,
    wait: bool = False,
    progress: Optional[ProgressCallback] = None,
) -> ApplyResult:
    """Optionally pull, then run `docker compose up -d` for one project."""

    result = ApplyResult()
    if pull:
        if progress:
            progress(f"Pulling images for {project.project_name}...")
        result.pull_result = docker.pull(
            project.files, project_name=project.project_name
        )
        if not result.pull_result.ok:
            return result
    if progress:
        progress(f"Applying {project.project_name} with docker compose up -d...")
    result.up_result = docker.up(
        project.files,
        wait=wait,
        project_name=project.project_name,
        pull_policy="never",
    )
    return result


def report_to_dict(report: ProjectUpdateReport) -> dict[str, object]:
    return {
        "project": report.project.project_name,
        "files": [str(path) for path in report.project.files],
        "pull_ok": report.pull_ok,
        "pull_error": report.pull_error,
        "skipped_reason": report.skipped_reason,
        "skipped_error": report.skipped_error,
        "has_updates": report.has_updates,
        "services": [
            {
                "service": item.service,
                "image": item.image,
                "before_id": item.before_id,
                "after_id": item.after_id,
                "running_ids": list(item.running_ids),
                "status": item.status,
                "detail": item.detail,
                "changed": item.changed,
            }
            for item in report.services
        ],
    }


@dataclass
class CheckSummary:
    reports: list[ProjectUpdateReport] = field(default_factory=list)

    @property
    def update_count(self) -> int:
        return sum(len(report.changed_services()) for report in self.reports)

    @property
    def error_count(self) -> int:
        return sum(1 for report in self.reports if report.has_errors)

    @property
    def projects_with_updates(self) -> list[ProjectUpdateReport]:
        return [report for report in self.reports if report.has_updates]


def check_exit_code(reports: Sequence[ProjectUpdateReport]) -> int:
    """0 = clean, 10 = updates available, 1 = errors were encountered."""

    if any(report.has_errors for report in reports):
        return 1
    if any(report.has_updates for report in reports):
        return 10
    return 0


def elapsed_seconds(started: float) -> float:
    return time.monotonic() - started
