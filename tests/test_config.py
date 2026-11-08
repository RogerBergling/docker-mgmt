"""Configuration parsing tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from docker_mgmt.config import (
    DEFAULT_EXCLUDES,
    ConfigError,
    load_config,
)


def _write_secure(path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o644)


class ConfigTests(unittest.TestCase):
    def test_loads_values_and_extra_excludes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            config_path = tmp / "config.ini"
            _write_secure(
                config_path,
                f"""
[scan]
roots = {tmp / "apps"}, {tmp / "srv"}
include_all_yaml = yes
max_depth = 4
include_hidden = true
follow_symlinks = true
exclude_dirs = .cache, custom

[compose]
command_timeout_seconds = 30
pull_timeout_seconds = 60
up_timeout_seconds = 90
wait_after_update = true
wait_timeout_seconds = 40

[audit]
path = {tmp / "audit.log"}
max_bytes = 8192

[ui]
color = always
page_size = 25

[security]
allow_unsafe_ownership = true
""",
            )
            config = load_config(str(config_path))
            self.assertEqual(config.config_path, config_path)
            self.assertEqual(len(config.scan_roots), 2)
            self.assertTrue(config.include_all_yaml)
            self.assertEqual(config.max_depth, 4)
            self.assertTrue(config.include_hidden)
            self.assertTrue(config.follow_symlinks)
            self.assertIn("custom", config.exclude_dirs)
            self.assertTrue(set(DEFAULT_EXCLUDES).issubset(config.exclude_dirs))
            self.assertEqual(config.command_timeout, 30)
            self.assertEqual(config.pull_timeout, 60)
            self.assertEqual(config.up_timeout, 90)
            self.assertTrue(config.wait_after_update)
            self.assertEqual(config.wait_timeout, 40)
            self.assertEqual(config.audit_path, tmp / "audit.log")
            self.assertEqual(config.audit_max_bytes, 8192)
            self.assertTrue(config.color)
            self.assertEqual(config.page_size, 25)
            self.assertTrue(config.allow_unsafe_ownership)

    def test_cli_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            config_path = tmp / "config.ini"
            _write_secure(config_path, "[scan]\nroots = /one\n")
            config = load_config(
                str(config_path),
                roots_override=["/two"],
                all_yaml_override=True,
                no_color=True,
            )
            self.assertEqual(config.scan_roots, (Path("/two").resolve(),))
            self.assertTrue(config.include_all_yaml)
            self.assertFalse(config.color)

    def test_invalid_values_warn_and_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            config_path = tmp / "config.ini"
            _write_secure(
                config_path,
                """
[scan]
include_all_yaml = maybe
max_depth = 999
[unknown]
key = value
[ui]
color = rainbow
page_size = 1
""",
            )
            config = load_config(str(config_path))
            warnings = "\n".join(config.warnings)
            self.assertIn("invalid boolean", warnings)
            self.assertIn("outside", warnings)
            self.assertIn("unknown config section", warnings)
            self.assertIn("invalid ui.color", warnings)
            self.assertEqual(config.max_depth, 8)
            self.assertEqual(config.page_size, 20)

    def test_explicit_missing_config_is_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            missing = Path(raw) / "missing.ini"
            with self.assertRaises(ConfigError):
                load_config(str(missing))

    def test_relative_audit_path_is_resolved_against_config(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            config_path = tmp / "config.ini"
            _write_secure(
                config_path,
                "[scan]\nroots = /opt\n[audit]\npath = logs/audit.log\n",
            )
            config = load_config(str(config_path))
            self.assertEqual(config.audit_path, (tmp / "logs" / "audit.log").resolve())


if __name__ == "__main__":
    unittest.main()
