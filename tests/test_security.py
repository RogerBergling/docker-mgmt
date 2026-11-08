"""Security analysis and file-trust tests."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from docker_mgmt.security import (
    analyze_compose,
    check_path_trust,
    check_project_trust,
    image_is_mutable,
)


class ImageMutableTests(unittest.TestCase):
    def test_floating_tags(self) -> None:
        self.assertTrue(image_is_mutable("nginx"))
        self.assertTrue(image_is_mutable("nginx:latest"))
        self.assertTrue(image_is_mutable("registry.example.com/team/app:stable"))
        self.assertFalse(image_is_mutable("nginx:1.27.3"))
        self.assertFalse(image_is_mutable("nginx@sha256:" + "a" * 64))

    def test_registry_port_is_not_a_tag(self) -> None:
        self.assertTrue(image_is_mutable("registry.example.com:5000/team/app"))
        self.assertFalse(image_is_mutable("registry.example.com:5000/team/app:1.2.3"))


class ComposeAnalysisTests(unittest.TestCase):
    def test_high_risk_findings(self) -> None:
        data = {
            "name": "demo",
            "services": {
                "web": {
                    "image": "nginx:latest",
                    "privileged": True,
                    "network_mode": "host",
                    "cap_add": ["SYS_ADMIN"],
                    "security_opt": ["seccomp=unconfined"],
                    "ports": [
                        {"target": 80, "published": "8080", "host_ip": "0.0.0.0"}
                    ],
                    "volumes": [
                        {"type": "bind", "source": "/var/run/docker.sock", "target": "/sock"},
                        {"type": "bind", "source": "/etc", "target": "/host-etc"},
                    ],
                    "environment": {"PASSWORD": "do-not-leak-me"},
                },
                "builder": {"build": {"context": "./builder"}},
            },
        }
        analysis = analyze_compose(data, Path("/tmp/example"))
        joined = "\n".join(analysis.critical_warnings + analysis.warnings)
        self.assertIn("privileged", joined)
        self.assertIn("host network_mode", joined)
        self.assertIn("docker.sock", joined)
        self.assertIn("/etc", joined)
        self.assertIn("SYS_ADMIN", joined)
        self.assertIn("seccomp=unconfined", joined)
        self.assertIn("floating tag", joined)
        self.assertIn("all host interfaces", joined)
        self.assertNotIn("do-not-leak-me", joined)
        self.assertTrue(any(service.has_build for service in analysis.services))
        self.assertTrue(analysis.build_contexts)
        self.assertTrue(analysis.env_files == ())

    def test_env_file_discovery(self) -> None:
        data = {
            "services": {
                "app": {
                    "image": "app:1",
                    "env_file": [{"path": "./app.env", "required": True}],
                }
            }
        }
        analysis = analyze_compose(data, Path("/srv/app"))
        self.assertEqual(
            analysis.env_files, (Path("/srv/app/app.env").resolve(strict=False),)
        )

    def test_build_dockerfile_and_secret_files_are_collected(self) -> None:
        data = {
            "services": {
                "app": {
                    "build": {"context": "./app", "dockerfile": "Dockerfile.prod"}
                }
            },
            "secrets": {"db": {"file": "./secrets/db.txt"}},
            "configs": {"cfg": {"file": "./configs/app.yaml"}},
        }
        analysis = analyze_compose(data, Path("/srv/project"))
        self.assertIn(
            Path("/srv/project/app/Dockerfile.prod").resolve(strict=False),
            analysis.extra_files,
        )
        self.assertIn(
            Path("/srv/project/secrets/db.txt").resolve(strict=False),
            analysis.extra_files,
        )
        self.assertIn(
            Path("/srv/project/configs/app.yaml").resolve(strict=False),
            analysis.extra_files,
        )


class TrustTests(unittest.TestCase):
    def test_world_writable_file_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "compose.yaml"
            path.write_text("services: {}\n", encoding="utf-8")
            os.chmod(path, 0o666)
            issues = check_path_trust(path, euid=os.geteuid())
            self.assertTrue(any("world-writable" in issue for issue in issues))

    def test_root_owned_check_reports_non_root_owner(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "compose.yaml"
            path.write_text("services: {}\n", encoding="utf-8")
            os.chmod(path, 0o666)
            issues = check_path_trust(path, euid=0)
            self.assertTrue(issues)
            self.assertTrue(
                any("owned by uid" in issue or "group/world-writable" in issue for issue in issues)
            )

    def test_project_trust_deduplicates(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "compose.yaml"
            path.write_text("services: {}\n", encoding="utf-8")
            issues = check_project_trust(
                [path, path], [path], [Path(raw)], euid=os.geteuid()
            )
            self.assertEqual(len(issues), len(set(issues)))

    def test_sticky_world_writable_target_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            target = Path(raw) / "shared-build-context"
            target.mkdir()
            os.chmod(target, 0o1777)
            issues = check_path_trust(target, euid=os.geteuid())
            self.assertTrue(
                any("sticky" in issue and "target directory" in issue for issue in issues),
                issues,
            )

    def test_sticky_parent_directory_is_allowed_for_a_file(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw) / "shared"
            parent.mkdir()
            os.chmod(parent, 0o1777)
            path = parent / "compose.yaml"
            path.write_text("services: {}\n", encoding="utf-8")
            os.chmod(path, 0o644)
            issues = check_path_trust(path, euid=os.geteuid())
            self.assertFalse(
                any("sticky" in issue or "group/world-writable" in issue for issue in issues),
                issues,
            )


if __name__ == "__main__":
    unittest.main()
