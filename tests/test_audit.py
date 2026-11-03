"""Audit log and operation lock tests."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from docker_mgmt.audit import (
    AuditError,
    AuditLogger,
    LockBusy,
    OperationLock,
    read_audit_records,
)


class AuditTests(unittest.TestCase):
    def test_write_and_read(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "audit.log"
            logger = AuditLogger(path)
            logger.log(
                action="compose.pull",
                target="/srv/app/compose.yaml",
                project="app",
                result="ok",
                detail="password=secret-value",
                duration_ms=12,
            )
            records = read_audit_records(path, tail=10)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].action, "compose.pull")
            self.assertEqual(records[0].project, "app")
            self.assertNotIn("secret-value", records[0].detail)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            target = tmp / "target.log"
            target.write_text("", encoding="utf-8")
            link = tmp / "audit.log"
            os.symlink(target, link)
            logger = AuditLogger(link)
            with self.assertRaises(AuditError):
                logger.ensure_ready()

    def test_lock_is_exclusive(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "lock"
            first = OperationLock(path)
            first.acquire()
            try:
                second = OperationLock(path)
                with self.assertRaises(LockBusy):
                    second.acquire()
            finally:
                first.release()
            third = OperationLock(path)
            third.acquire()
            third.release()

    def test_missing_audit_log_read_is_empty(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            self.assertEqual(read_audit_records(Path(raw) / "missing.log"), [])


if __name__ == "__main__":
    unittest.main()
