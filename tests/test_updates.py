"""Update comparison and apply-flow tests."""

from __future__ import annotations

import unittest
from pathlib import Path

from docker_mgmt.models import ComposeProject, Container, ServiceInfo
from docker_mgmt.runner import CommandResult
from docker_mgmt.updates import apply_project, check_exit_code, check_project


def result(ok: bool, message: str = "") -> CommandResult:
    return CommandResult(
        argv=("docker",),
        returncode=0 if ok else 1,
        stdout=message if ok else "",
        stderr="" if ok else message,
        duration_seconds=0.1,
    )


class StubDocker:
    """Simulates image IDs before and after a pull."""

    def __init__(
        self,
        before: dict[str, str | None],
        after: dict[str, str | None] | None = None,
        *,
        pull_ok: bool = True,
    ) -> None:
        self.before = dict(before)
        self.after = dict(before if after is None else after)
        self.current = dict(before)
        self.pull_ok = pull_ok
        self.pull_calls = 0
        self.up_calls = 0

    def image_id(self, image: str):
        return self.current.get(image)

    def pull(self, files, project_name=None):
        self.pull_calls += 1
        if self.pull_ok:
            self.current = dict(self.after)
        return result(self.pull_ok, "" if self.pull_ok else "denied")

    def up(self, files, wait=False, project_name=None, pull_policy=None):
        self.up_calls += 1
        return result(True)


def project(image: str = "nginx:1.27") -> ComposeProject:
    return ComposeProject(
        files=(Path("/srv/app/compose.yaml"),),
        project_name="app",
        services=[ServiceInfo(name="web", image=image)],
    )


def container(image_id: str = "sha256:" + "1" * 64, state: str = "running") -> Container:
    return Container(
        id="a" * 64,
        name="app-web-1",
        image="nginx:1.27",
        image_id=image_id,
        state=state,
        status=state,
        health="healthy",
        restart_count=0,
        exit_code=0,
        project="app",
        service="web",
        config_files=(Path("/srv/app/compose.yaml"),),
        working_dir="/srv/app",
        ports=(),
        created="",
        config_hash="hash",
    )


OLD = "sha256:" + "1" * 64
NEW = "sha256:" + "2" * 64


class CheckProjectTests(unittest.TestCase):
    def test_image_updated(self) -> None:
        docker = StubDocker({"nginx:1.27": OLD}, {"nginx:1.27": NEW})
        report = check_project(docker, project(), [container(OLD)])
        self.assertTrue(report.pull_ok)
        self.assertEqual(report.services[0].status, "image-updated")
        self.assertTrue(report.has_updates)

    def test_container_stale_without_image_change(self) -> None:
        docker = StubDocker({"nginx:1.27": NEW}, {"nginx:1.27": NEW})
        report = check_project(docker, project(), [container(OLD)])
        self.assertEqual(report.services[0].status, "container-stale")
        self.assertTrue(report.has_updates)

    def test_up_to_date(self) -> None:
        docker = StubDocker({"nginx:1.27": NEW}, {"nginx:1.27": NEW})
        report = check_project(docker, project(), [container(NEW)])
        self.assertEqual(report.services[0].status, "up-to-date")
        self.assertFalse(report.has_updates)

    def test_pull_failure_is_reported(self) -> None:
        docker = StubDocker({"nginx:1.27": OLD}, {"nginx:1.27": OLD}, pull_ok=False)
        report = check_project(docker, project(), [container(OLD)])
        self.assertFalse(report.pull_ok)
        self.assertEqual(report.services[0].status, "pull-failed")
        self.assertTrue(report.has_errors)

    def test_new_image(self) -> None:
        docker = StubDocker({}, {"nginx:1.27": NEW})
        report = check_project(docker, project(), [])
        self.assertEqual(report.services[0].status, "new-image")
        self.assertTrue(report.has_updates)

    def test_build_only_project_skips_pull(self) -> None:
        build_project = ComposeProject(
            files=(Path("/srv/app/compose.yaml"),),
            project_name="app",
            services=[ServiceInfo(name="web", image=None, has_build=True)],
        )
        docker = StubDocker({})
        report = check_project(docker, build_project, [])
        self.assertEqual(docker.pull_calls, 0)
        self.assertEqual(report.services[0].status, "build-only")
        self.assertIn("build locally", report.skipped_reason or "")
        self.assertFalse(report.has_errors)
        self.assertEqual(check_exit_code([report]), 0)

    def test_apply_pulls_then_up(self) -> None:
        docker = StubDocker({"nginx:1.27": OLD}, {"nginx:1.27": NEW})
        applied = apply_project(docker, project(), pull=True)
        self.assertTrue(applied.ok)
        self.assertEqual(docker.pull_calls, 1)
        self.assertEqual(docker.up_calls, 1)

    def test_apply_does_not_up_after_pull_failure(self) -> None:
        docker = StubDocker({}, {}, pull_ok=False)
        applied = apply_project(docker, project(), pull=True)
        self.assertFalse(applied.ok)
        self.assertEqual(docker.up_calls, 0)

    def test_exit_codes(self) -> None:
        docker = StubDocker({}, {"nginx:1.27": NEW})
        report = check_project(docker, project(), [])
        self.assertEqual(check_exit_code([report]), 10)
        clean = check_project(
            StubDocker({"nginx:1.27": NEW}, {"nginx:1.27": NEW}),
            project(),
            [container(NEW)],
        )
        self.assertEqual(check_exit_code([clean]), 0)


if __name__ == "__main__":
    unittest.main()
