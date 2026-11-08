"""Security-hardening regression tests."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from docker_mgmt.config import ConfigError, load_config
from docker_mgmt.runner import CommandRunner
from docker_mgmt.security import check_path_trust
from docker_mgmt.ui import UI

try:
    from tests.support import (
        compose_config,
        fake_environment,
        run_cli,
        write_config,
        write_state,
    )
except ImportError:
    from support import (  # type: ignore
        compose_config,
        fake_environment,
        run_cli,
        write_config,
        write_state,
    )


class RunnerHardeningTests(unittest.TestCase):
    def test_large_stdout_is_not_truncated_to_terminal_size(self) -> None:
        runner = CommandRunner()
        result = runner.run(
            [sys.executable, "-c", "print('x' * 5000)"],
            timeout=10,
        )
        self.assertTrue(result.ok)
        self.assertGreater(len(result.stdout), 4000)


class ConfigHardeningTests(unittest.TestCase):
    def test_group_writable_config_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "config.ini"
            path.write_text("[scan]\nroots = /opt\n", encoding="utf-8")
            os.chmod(path, 0o666)
            with self.assertRaises(ConfigError):
                load_config(str(path))

    def test_group_writable_config_parent_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw) / "config-dir"
            parent.mkdir()
            path = parent / "config.ini"
            path.write_text("[scan]\nroots = /opt\n", encoding="utf-8")
            os.chmod(path, 0o644)
            os.chmod(parent, 0o775)
            with self.assertRaises(ConfigError):
                load_config(str(path))

    def test_unverified_references_setting(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "config.ini"
            path.write_text(
                "[security]\nallow_unverified_references = true\n",
                encoding="utf-8",
            )
            os.chmod(path, 0o644)
            config = load_config(str(path))
            self.assertTrue(config.allow_unverified_references)


class DockerBinaryHardeningTests(unittest.TestCase):
    def test_user_writable_docker_binary_is_refused_for_root(self) -> None:
        from docker_mgmt.config import Config
        from docker_mgmt.docker import DockerClient, DockerUnavailable
        from docker_mgmt.runner import CommandRunner

        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "docker"
            path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            os.chmod(path, 0o666)
            config = Config(config_path=None, scan_roots=())
            client = DockerClient(CommandRunner(), config)
            client.docker = str(path.resolve())
            with self.assertRaises(DockerUnavailable):
                client._validate_docker_binary()


class TrustHardeningTests(unittest.TestCase):
    def test_other_user_owned_file_is_rejected_for_non_root_operator(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "compose.yaml"
            path.write_text("services: {}\n", encoding="utf-8")
            os.chmod(path, 0o644)
            issues = check_path_trust(path, euid=9999)
            self.assertTrue(any("owned by uid" in issue for issue in issues))


class ProjectHardeningTests(unittest.TestCase):
    def _project(self, tmp: Path, compose_text: str) -> tuple[Path, Path, dict, dict]:
        apps = tmp / "apps"
        app = apps / "app"
        app.mkdir(parents=True)
        compose = app / "compose.yaml"
        compose.write_text(compose_text, encoding="utf-8")
        config_path = write_config(tmp, roots=[str(apps)], allow_unsafe=True)
        env = fake_environment(tmp)
        state = {
            "images": {},
            "containers": [],
            "compose": {str(compose.resolve()): compose_config("demo", "nginx:1")},
            "invalid": {},
            "compose_ls": [],
            "pull_updates": {},
            "stats": [],
        }
        write_state(env, state)
        return compose, config_path, env, state

    def test_standard_override_is_included_in_project_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            compose, config_path, env, state = self._project(
                tmp,
                "services:\n  web:\n    image: nginx:1\n",
            )
            override = compose.parent / "compose.override.yaml"
            override.write_text(
                "services:\n  web:\n    environment:\n      DEBUG: '1'\n",
                encoding="utf-8",
            )
            proc = run_cli(["scan", "--json", "--config", str(config_path)], env)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            project = json.loads(proc.stdout)["projects"][0]
            self.assertIn(str(compose.resolve()), project["files"])
            self.assertIn(str(override.resolve()), project["files"])

    def test_include_marks_project_unverified(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            compose, config_path, env, state = self._project(
                tmp,
                "include:\n  - ./shared.yaml\nservices:\n  web:\n    image: nginx:1\n",
            )
            proc = run_cli(["scan", "--json", "--config", str(config_path)], env)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            project = json.loads(proc.stdout)["projects"][0]
            self.assertTrue(project["unverified_references"])
            proc = run_cli(["validate", "--json", "--config", str(config_path)], env)
            self.assertEqual(proc.returncode, 1, proc.stderr)

    def test_include_blocks_update(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            compose, config_path, env, state = self._project(
                tmp,
                "include:\n  - ./shared.yaml\nservices:\n  web:\n    image: nginx:1\n",
            )
            proc = run_cli(
                ["update", "--all", "--yes", "--config", str(config_path)], env
            )
            self.assertEqual(proc.returncode, 1, proc.stderr)
            try:
                from tests.support import docker_log
            except ImportError:
                from support import docker_log  # type: ignore

            commands = docker_log(env)
            self.assertFalse(
                any(cmd[:1] == ["compose"] and "up" in cmd for cmd in commands),
                commands,
            )

    def test_standard_override_is_used_by_update_command(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            compose, config_path, env, state = self._project(
                tmp,
                "services:\n  web:\n    image: nginx:1\n",
            )
            override = compose.parent / "compose.override.yaml"
            override.write_text(
                "services:\n  web:\n    environment:\n      DEBUG: '1'\n",
                encoding="utf-8",
            )
            proc = run_cli(
                ["update", "--all", "--yes", "--config", str(config_path)], env
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            try:
                from tests.support import docker_log
            except ImportError:
                from support import docker_log  # type: ignore

            commands = docker_log(env)
            up = next(
                cmd for cmd in commands if cmd[:1] == ["compose"] and "up" in cmd
            )
            self.assertIn(str(compose.resolve()), up)
            self.assertIn(str(override.resolve()), up)

    def test_large_compose_config_is_parsed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            compose, config_path, env, state = self._project(
                tmp,
                "services:\n  web:\n    image: nginx:1\n",
            )
            services = {
                f"service{i}": {"image": "nginx:1", "environment": {"KEY": "x" * 40}}
                for i in range(120)
            }
            state["compose"][str(compose.resolve())] = {
                "name": "demo",
                "services": services,
            }
            write_state(env, state)
            proc = run_cli(["scan", "--json", "--config", str(config_path)], env)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            project = json.loads(proc.stdout)["projects"][0]
            self.assertTrue(project["valid"])
            self.assertEqual(len(project["services"]), 120)

    def test_check_blocks_untrusted_file_without_allow_unsafe(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            compose, config_path, env, state = self._project(
                tmp,
                "services:\n  web:\n    image: nginx:1\n",
            )
            config_path = write_config(tmp, roots=[str(tmp / "apps")], allow_unsafe=False)
            os.chmod(compose, 0o666)
            proc = run_cli(
                ["check", "--yes", "--json", "--config", str(config_path)], env
            )
            self.assertEqual(proc.returncode, 1, proc.stderr)
            self.assertIn("preflight", proc.stderr.lower())
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["errors"], 1)
            try:
                from tests.support import docker_log
            except ImportError:
                from support import docker_log  # type: ignore

            commands = docker_log(env)
            self.assertFalse(
                any(cmd[:1] == ["compose"] and "pull" in cmd for cmd in commands),
                commands,
            )

    def test_check_warns_but_allows_untrusted_file_when_configured(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            compose, config_path, env, state = self._project(
                tmp,
                "services:\n  web:\n    image: nginx:1\n",
            )
            os.chmod(compose, 0o666)
            proc = run_cli(
                ["check", "--yes", "--json", "--config", str(config_path)], env
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("unsafe file ownership", proc.stderr.lower())
            try:
                from tests.support import docker_log
            except ImportError:
                from support import docker_log  # type: ignore

            commands = docker_log(env)
            self.assertTrue(
                any(cmd[:1] == ["compose"] and "pull" in cmd for cmd in commands),
                commands,
            )
            self.assertFalse(
                any(cmd[:1] == ["compose"] and "up" in cmd for cmd in commands),
                commands,
            )

    def test_check_blocks_unverified_include_reference(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            compose, config_path, env, state = self._project(
                tmp,
                "include:\n  - ./shared.yaml\nservices:\n  web:\n    image: nginx:1\n",
            )
            proc = run_cli(
                ["check", "--yes", "--json", "--config", str(config_path)], env
            )
            self.assertEqual(proc.returncode, 1, proc.stderr)
            self.assertIn("include/extends", proc.stderr)
            try:
                from tests.support import docker_log
            except ImportError:
                from support import docker_log  # type: ignore

            commands = docker_log(env)
            self.assertFalse(
                any(cmd[:1] == ["compose"] and "pull" in cmd for cmd in commands),
                commands,
            )

    def test_check_allows_unverified_include_when_configured(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            compose, config_path, env, state = self._project(
                tmp,
                "include:\n  - ./shared.yaml\nservices:\n  web:\n    image: nginx:1\n",
            )
            config_path = write_config(
                tmp,
                roots=[str(tmp / "apps")],
                allow_unsafe=True,
                extra="allow_unverified_references = true",
            )
            proc = run_cli(
                ["check", "--yes", "--json", "--config", str(config_path)], env
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("include/extends", proc.stderr)
            try:
                from tests.support import docker_log
            except ImportError:
                from support import docker_log  # type: ignore

            commands = docker_log(env)
            self.assertTrue(
                any(cmd[:1] == ["compose"] and "pull" in cmd for cmd in commands),
                commands,
            )


class UIHardeningTests(unittest.TestCase):
    def test_table_strips_terminal_escape_sequences(self) -> None:
        ui = UI(color=False)
        table = ui.table(
            ["NAME"],
            [["\x1b[31mred\x1b[0m"]],
        )
        self.assertNotIn("\x1b", table)


if __name__ == "__main__":
    unittest.main()
