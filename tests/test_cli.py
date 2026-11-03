"""End-to-end CLI tests using the fake Docker executable."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

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


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.apps = self.tmp / "apps"
        self.app = self.apps / "app"
        self.app.mkdir(parents=True)
        self.compose = self.app / "compose.yaml"
        self.compose.write_text("services:\n  web:\n    image: nginx:1.27\n")
        self.config = write_config(self.tmp, roots=[str(self.apps)], allow_unsafe=True)
        self.env = fake_environment(self.tmp)
        self.image_id = "sha256:" + "1" * 64
        self.new_image_id = "sha256:" + "2" * 64
        self.state = {
            "images": {"nginx:1.27": self.image_id},
            "containers": [],
            "compose": {str(self.compose.resolve()): compose_config("demo", "nginx:1.27")},
            "invalid": {},
            "compose_ls": [],
            "pull_updates": {"nginx:1.27": self.new_image_id},
            "stats": [],
        }
        running = container(
            name="demo-web-1",
            project="demo",
            service="web",
            image="nginx:1.27",
            image_id=self.image_id,
        )
        running["Config"]["Labels"]["com.docker.compose.project.config_files"] = str(
            self.compose.resolve()
        )
        self.state["containers"] = [running]
        write_state(self.env, self.state)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def invoke(self, *args: str, input_text: str | None = None):
        return run_cli(
            [*args, "--config", str(self.config)],
            self.env,
            input_text=input_text,
        )

    def test_help_and_version(self) -> None:
        proc = run_cli(["--help"], self.env)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("menu-driven", proc.stdout.lower())
        proc = run_cli(["--version"], self.env)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("docker-mgmt", proc.stdout)

    def test_menu_starts_and_exits(self) -> None:
        proc = self.invoke("menu", input_text="0\n")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Main menu", proc.stdout)

    def test_scan_json(self) -> None:
        proc = self.invoke("scan", "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(len(payload["projects"]), 1)
        self.assertEqual(payload["projects"][0]["project"], "demo")
        self.assertTrue(payload["projects"][0]["valid"])

    def test_scan_includes_project_dotenv_for_trust_checks(self) -> None:
        (self.app / ".env").write_text("IMAGE=nginx:1.27\n", encoding="utf-8")
        proc = self.invoke("scan", "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        project = json.loads(proc.stdout)["projects"][0]
        self.assertIn(str((self.app / ".env").resolve()), project["env_files"])

    def test_scan_path_with_spaces(self) -> None:
        spaced = self.apps / "with space"
        spaced.mkdir()
        compose = spaced / "compose.yaml"
        compose.write_text("services:\n  web:\n    image: nginx:1\n")
        state = self.state
        state["compose"][str(compose.resolve())] = compose_config("spaced", "nginx:1")
        write_state(self.env, state)
        proc = self.invoke("scan", "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        files = [
            path
            for project in json.loads(proc.stdout)["projects"]
            for path in project["files"]
        ]
        self.assertIn(str(compose.resolve()), files)

    def test_status_json(self) -> None:
        proc = self.invoke("status", "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["running"], 1)
        self.assertEqual(payload["containers"][0]["project"], "demo")

    def test_check_detects_update(self) -> None:
        proc = self.invoke("check", "--yes", "--json")
        self.assertEqual(proc.returncode, 10, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["updates"], 1)
        self.assertEqual(
            payload["reports"][0]["services"][0]["status"], "image-updated"
        )

    def test_check_requires_yes_noninteractively(self) -> None:
        proc = self.invoke("check", "--json")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("--yes", proc.stderr)

    def test_update_all_runs_up_and_audits(self) -> None:
        proc = self.invoke("update", "--all", "--yes")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        from tests.support import docker_log

        commands = docker_log(self.env)
        self.assertTrue(
            any(cmd[:1] == ["compose"] and "up" in cmd for cmd in commands),
            commands,
        )
        self.assertTrue(
            any(
                cmd[:1] == ["compose"]
                and "-p" in cmd
                and cmd[cmd.index("-p") + 1] == "demo"
                and "--pull" in cmd
                and cmd[cmd.index("--pull") + 1] == "never"
                for cmd in commands
            ),
            commands,
        )
        proc = self.invoke("audit", "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        records = json.loads(proc.stdout)
        actions = {record["action"] for record in records}
        self.assertIn("compose.pull", actions)
        self.assertIn("compose.up", actions)

    def test_validate_clean_and_invalid(self) -> None:
        proc = self.invoke("validate", "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertTrue(payload["projects"][0]["valid"])

        state = self.state
        state["invalid"][str(self.compose.resolve())] = "services.web.image is required"
        write_state(self.env, state)
        proc = self.invoke("validate", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertFalse(payload["projects"][0]["valid"])

    def test_validate_high_risk(self) -> None:
        state = self.state
        config = compose_config("demo", "nginx:latest")
        config["services"]["web"]["privileged"] = True
        state["compose"][str(self.compose.resolve())] = config
        write_state(self.env, state)
        proc = self.invoke("validate", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertTrue(payload["projects"][0]["critical_warnings"])

    def test_prune_images(self) -> None:
        proc = self.invoke("prune", "images", "--yes")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Prune result", proc.stdout)

    def test_logs_project(self) -> None:
        proc = self.invoke("logs", "demo")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("fake compose log line", proc.stdout)

    def test_doctor(self) -> None:
        proc = self.invoke("doctor")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Docker Compose", proc.stdout)
        self.assertIn("Security posture", proc.stdout)

    def test_audit_without_docker(self) -> None:
        # The audit viewer must not require a Docker daemon.
        env = dict(self.env)
        env["PATH"] = "/usr/bin:/bin"
        proc = run_cli(["audit", "--config", str(self.config)], env)
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
