"""Compose discovery and project merge tests."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from docker_mgmt.config import DEFAULT_EXCLUDES, Config
from docker_mgmt.discovery import scan_candidates

try:  # works with `unittest discover -s tests -t .`
    from tests.support import (
        compose_config,
        container,
        fake_environment,
        run_cli,
        write_config,
        write_state,
    )
except ImportError:  # works with `unittest discover -s tests`
    from support import (  # type: ignore
        compose_config,
        container,
        fake_environment,
        run_cli,
        write_config,
        write_state,
    )


def _config(tmp: Path, *, all_yaml: bool = False, depth: int = 5) -> Config:
    return Config(
        config_path=None,
        scan_roots=(tmp.resolve(),),
        include_all_yaml=all_yaml,
        max_depth=depth,
        exclude_dirs=DEFAULT_EXCLUDES,
        color=False,
    )


class CandidateTests(unittest.TestCase):
    def test_standard_files_overrides_and_exclusions(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            app = tmp / "apps" / "app"
            app.mkdir(parents=True)
            (app / "compose.yaml").write_text("services: {web: {image: nginx:1}}\n")
            (app / "compose.override.yaml").write_text("services: {}\n")
            hidden = tmp / "apps" / ".hidden"
            hidden.mkdir()
            (hidden / "compose.yaml").write_text("services: {}\n")
            modules = tmp / "apps" / "node_modules"
            modules.mkdir()
            (modules / "compose.yaml").write_text("services: {}\n")
            custom = tmp / "apps" / "custom"
            custom.mkdir()
            (custom / "stack.yaml").write_text("services: {}\n")
            not_compose = tmp / "apps" / "not-compose.yaml"
            not_compose.write_text("key: value\n")

            files, warnings = scan_candidates(_config(tmp / "apps"))
            self.assertEqual(files, [(app / "compose.yaml").resolve()])
            self.assertFalse(any("override" in warning for warning in warnings))

            files, _ = scan_candidates(_config(tmp / "apps", all_yaml=True))
            self.assertIn((custom / "stack.yaml").resolve(), files)
            self.assertNotIn(not_compose.resolve(), files)

    def test_override_without_base_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            app = tmp / "app"
            app.mkdir()
            (app / "compose.override.yaml").write_text("services: {}\n")
            files, warnings = scan_candidates(_config(tmp))
            self.assertEqual(files, [])
            self.assertTrue(any("because no base" in warning for warning in warnings))

    def test_multiple_base_files_use_precedence(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            app = tmp / "app"
            app.mkdir()
            (app / "compose.yaml").write_text("services: {}\n")
            (app / "docker-compose.yml").write_text("services: {}\n")
            files, warnings = scan_candidates(_config(tmp))
            self.assertEqual(files, [(app / "compose.yaml").resolve()])
            self.assertTrue(any("multiple base" in warning for warning in warnings))

    def test_symlink_escape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            root = tmp / "root"
            root.mkdir()
            outside = tmp / "outside.yaml"
            outside.write_text("services: {}\n")
            link = root / "compose.yaml"
            os.symlink(outside, link)
            files, warnings = scan_candidates(_config(root))
            self.assertEqual(files, [])
            self.assertTrue(any("escapes" in warning for warning in warnings))


class ScanProjectTests(unittest.TestCase):
    def test_scan_cli_merges_running_projects(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            apps = tmp / "apps"
            app = apps / "app"
            app.mkdir(parents=True)
            compose = app / "compose.yaml"
            compose.write_text("services:\n  web:\n    image: nginx:1.27\n")
            outside = tmp / "outside"
            outside.mkdir()
            outside_compose = outside / "compose.yaml"
            outside_compose.write_text("services:\n  api:\n    image: app:1\n")

            config_path = write_config(tmp, roots=[str(apps)])
            env = fake_environment(tmp)
            state = {
                "images": {"nginx:1.27": "sha256:" + "1" * 64, "app:1": "sha256:" + "2" * 64},
                "containers": [],
                "compose": {
                    str(compose.resolve()): compose_config("app", "nginx:1.27"),
                    str(outside_compose.resolve()): compose_config("outside", "app:1"),
                },
                "invalid": {},
                "compose_ls": [],
                "pull_updates": {},
                "stats": [],
            }
            running = container(
                name="outside-api-1",
                project="outside",
                service="api",
                image="app:1",
                image_id="sha256:" + "2" * 64,
            )
            running["Config"]["Labels"]["com.docker.compose.project.config_files"] = str(
                outside_compose.resolve()
            )
            state["containers"] = [running]
            write_state(env, state)

            proc = run_cli(["scan", "--json", "--config", str(config_path)], env)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            names = {item["project"] for item in payload["projects"]}
            self.assertIn("app", names)
            self.assertIn("outside", names)
            outside_project = next(
                item for item in payload["projects"] if item["project"] == "outside"
            )
            self.assertEqual(outside_project["source"], "running")

    def test_running_project_name_is_adopted_when_p_was_used(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            apps = tmp / "apps"
            app = apps / "app"
            app.mkdir(parents=True)
            compose = app / "compose.yaml"
            compose.write_text("services:\n  web:\n    image: nginx:1\n")
            config_path = write_config(tmp, roots=[str(apps)])
            env = fake_environment(tmp)
            running = container(
                name="custom-web-1",
                project="custom",
                service="web",
                image="nginx:1",
                image_id="sha256:" + "1" * 64,
            )
            running["Config"]["Labels"]["com.docker.compose.project.config_files"] = str(
                compose.resolve()
            )
            state = {
                "images": {"nginx:1": "sha256:" + "1" * 64},
                "containers": [running],
                "compose": {str(compose.resolve()): compose_config("app", "nginx:1")},
                "invalid": {},
                "compose_ls": [],
                "pull_updates": {},
                "stats": [],
            }
            write_state(env, state)
            proc = run_cli(["scan", "--json", "--config", str(config_path)], env)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(len(payload["projects"]), 1)
            project = payload["projects"][0]
            self.assertEqual(project["project"], "custom")
            self.assertEqual(project["source"], "scan+running")
            self.assertTrue(
                any("using running project name" in w for w in payload["warnings"])
            )

    def test_duplicate_project_names_are_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            apps = tmp / "apps"
            first = apps / "a" / "compose.yaml"
            second = apps / "b" / "compose.yaml"
            first.parent.mkdir(parents=True)
            second.parent.mkdir(parents=True)
            first.write_text("services:\n  web:\n    image: nginx:1\n")
            second.write_text("services:\n  web:\n    image: nginx:1\n")
            config_path = write_config(tmp, roots=[str(apps)])
            env = fake_environment(tmp)
            state = {
                "images": {},
                "containers": [],
                "compose": {
                    str(first.resolve()): compose_config("shared", "nginx:1"),
                    str(second.resolve()): compose_config("shared", "nginx:1"),
                },
                "invalid": {},
                "compose_ls": [],
                "pull_updates": {},
                "stats": [],
            }
            write_state(env, state)
            proc = run_cli(["scan", "--json", "--config", str(config_path)], env)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            projects = json.loads(proc.stdout)["projects"]
            self.assertEqual(len(projects), 2)
            self.assertTrue(all(project["blockers"] for project in projects))


if __name__ == "__main__":
    unittest.main()
