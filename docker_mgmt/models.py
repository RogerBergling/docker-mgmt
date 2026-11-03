"""Data models shared by docker-mgmt modules.

Only the minimum container fields needed for management are retained. In
particular, arbitrary container labels and environment variables are not
stored, because they frequently contain credentials or other secrets.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class ServiceInfo:
    """A single Compose service and its relevant security metadata."""

    name: str
    image: Optional[str] = None
    has_build: bool = False
    build_context: Optional[str] = None
    env_files: tuple[Path, ...] = ()
    warnings: list[str] = field(default_factory=list)
    critical_warnings: list[str] = field(default_factory=list)


@dataclass
class ComposeProject:
    """A resolved Compose project, either discovered by scanning or by labels."""

    files: tuple[Path, ...]
    project_name: str
    services: list[ServiceInfo] = field(default_factory=list)
    valid: bool = True
    error: Optional[str] = None
    warnings: list[str] = field(default_factory=list)
    critical_warnings: list[str] = field(default_factory=list)
    env_files: tuple[Path, ...] = ()
    build_contexts: tuple[Path, ...] = ()
    extra_files: tuple[Path, ...] = ()
    source: str = "scan"
    blockers: list[str] = field(default_factory=list)

    @property
    def primary_file(self) -> Path:
        return self.files[0]

    @property
    def directory(self) -> Path:
        return self.primary_file.parent

    @property
    def images(self) -> tuple[str, ...]:
        seen: list[str] = []
        for service in self.services:
            if service.image and service.image not in seen:
                seen.append(service.image)
        return tuple(seen)

    def service_by_name(self, name: str) -> Optional[ServiceInfo]:
        for service in self.services:
            if service.name == name:
                return service
        return None


@dataclass
class Container:
    """A container with only the fields docker-mgmt needs to display/act on."""

    id: str
    name: str
    image: str
    image_id: str
    state: str
    status: str
    health: str
    restart_count: int
    exit_code: Optional[int]
    project: Optional[str]
    service: Optional[str]
    config_files: tuple[Path, ...]
    working_dir: Optional[str]
    ports: tuple[str, ...]
    created: str
    config_hash: Optional[str]

    @property
    def running(self) -> bool:
        return self.state == "running"

    @property
    def unhealthy(self) -> bool:
        return self.health == "unhealthy"

    @property
    def short_id(self) -> str:
        return self.id[:12]

    @property
    def display_name(self) -> str:
        return self.name or self.short_id


@dataclass
class ServiceUpdate:
    """Result of comparing one service before/after an image pull."""

    service: str
    image: Optional[str]
    before_id: Optional[str]
    after_id: Optional[str]
    running_ids: tuple[str, ...]
    status: str
    detail: str = ""

    @property
    def changed(self) -> bool:
        return self.status in {
            "image-updated",
            "new-image",
            "container-stale",
        }


@dataclass
class ProjectUpdateReport:
    """Result of checking one project for image updates."""

    project: ComposeProject
    services: list[ServiceUpdate] = field(default_factory=list)
    pull_ok: bool = True
    pull_error: Optional[str] = None
    skipped_reason: Optional[str] = None
    skipped_error: bool = False

    @property
    def has_updates(self) -> bool:
        return any(service.changed for service in self.services)

    @property
    def has_errors(self) -> bool:
        return self.skipped_error or not self.pull_ok

    def changed_services(self) -> list[ServiceUpdate]:
        return [service for service in self.services if service.changed]
