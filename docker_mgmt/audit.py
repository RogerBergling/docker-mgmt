"""Append-only audit logging and a per-host operation lock.

Audit records are JSON Lines, mode 0600. The logger refuses to write through
symlinks, through group/world-writable parent directories, or to a file owned
by another user. Mutating commands are blocked if the audit log cannot be
written, because the audit trail is treated as a security control.
"""

from __future__ import annotations

import fcntl
import getpass
import json
import os
import stat
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .runner import DockerMgmtError, redact_text, sanitize_text


class AuditError(DockerMgmtError):
    """The audit log is missing, unsafe, or unwritable."""


class LockBusy(DockerMgmtError):
    """Another docker-mgmt operation holds the host lock."""


@dataclass
class AuditRecord:
    timestamp: str
    user: str
    sudo_user: Optional[str]
    uid: int
    action: str
    target: str
    project: Optional[str]
    result: str
    detail: str
    duration_ms: Optional[int]

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "AuditRecord":
        try:
            uid = int(value.get("uid", -1))
        except (TypeError, ValueError):
            uid = -1
        duration = value.get("duration_ms")
        try:
            duration_ms = int(duration) if duration is not None else None
        except (TypeError, ValueError):
            duration_ms = None
        return cls(
            timestamp=str(value.get("ts", "")),
            user=str(value.get("user", "")),
            sudo_user=(
                str(value["sudo_user"]) if value.get("sudo_user") else None
            ),
            uid=uid,
            action=str(value.get("action", "")),
            target=str(value.get("target", "")),
            project=(
                str(value["project"]) if value.get("project") else None
            ),
            result=str(value.get("result", "")),
            detail=str(value.get("detail", "")),
            duration_ms=duration_ms,
        )


def _secure_parent(path: Path) -> None:
    parent = path.parent
    try:
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    except OSError as exc:
        raise AuditError(f"cannot create audit directory {parent}: {exc}") from exc

    try:
        parent_stat = parent.stat()
    except OSError as exc:
        raise AuditError(f"cannot stat audit directory {parent}: {exc}") from exc

    euid = os.geteuid()
    expected_uid = 0 if euid == 0 else euid
    if parent_stat.st_uid not in {expected_uid, 0}:
        raise AuditError(
            f"audit directory {parent} is owned by uid {parent_stat.st_uid}, "
            f"expected {expected_uid}"
        )
    if parent_stat.st_mode & 0o022:
        raise AuditError(
            f"audit directory {parent} is group/world-writable "
            f"(mode {parent_stat.st_mode & 0o777:04o}); choose a private directory"
        )


def _ensure_secure_file(path: Path) -> None:
    try:
        file_stat = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise AuditError(f"cannot stat audit log {path}: {exc}") from exc

    if stat.S_ISLNK(file_stat.st_mode):
        raise AuditError(f"refusing to use symlink as audit log: {path}")
    if not stat.S_ISREG(file_stat.st_mode):
        raise AuditError(f"audit log is not a regular file: {path}")

    euid = os.geteuid()
    expected_uid = 0 if euid == 0 else euid
    if file_stat.st_uid != expected_uid:
        raise AuditError(
            f"audit log {path} is owned by uid {file_stat.st_uid}, "
            f"expected {expected_uid}"
        )
    if file_stat.st_mode & 0o077:
        try:
            os.chmod(path, 0o600)
        except OSError as exc:
            raise AuditError(f"cannot restrict permissions on {path}: {exc}") from exc


class AuditLogger:
    def __init__(self, path: Path, max_bytes: int = 10 * 1024 * 1024) -> None:
        self.path = Path(path)
        self.max_bytes = max_bytes
        self._ready: Optional[bool] = None
        self._error: Optional[str] = None

    def ensure_ready(self) -> None:
        if self._ready is True:
            return

        try:
            _secure_parent(self.path)
            _ensure_secure_file(self.path)
            fd = os.open(
                str(self.path),
                os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
            )
            try:
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)
        except (OSError, AuditError) as exc:
            self._ready = False
            self._error = str(exc)
            if isinstance(exc, AuditError):
                raise
            raise AuditError(f"cannot prepare audit log {self.path}: {exc}") from exc

        self._ready = True

    def _rotate_if_needed(self) -> None:
        try:
            size = self.path.stat().st_size
        except OSError:
            return
        if size <= self.max_bytes:
            return
        rotated = self.path.with_name(self.path.name + ".1")
        try:
            if rotated.exists() and rotated.is_symlink():
                raise AuditError(f"refusing to rotate onto symlink {rotated}")
            os.replace(self.path, rotated)
            os.chmod(rotated, 0o600)
        except OSError as exc:
            raise AuditError(f"cannot rotate audit log {self.path}: {exc}") from exc

    def log(
        self,
        *,
        action: str,
        target: str,
        result: str,
        detail: str = "",
        project: Optional[str] = None,
        duration_ms: Optional[int] = None,
    ) -> None:
        self.ensure_ready()
        self._rotate_if_needed()

        record = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "user": getpass.getuser(),
            "sudo_user": os.environ.get("SUDO_USER") or None,
            "uid": os.geteuid(),
            "action": action,
            "target": sanitize_text(str(target), max_length=1000),
            "project": sanitize_text(str(project), max_length=200) if project else None,
            "result": result,
            "detail": redact_text(sanitize_text(detail, max_length=1200)),
            "duration_ms": duration_ms,
        }
        line = json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"

        try:
            fd = os.open(
                str(self.path),
                os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
            )
        except OSError as exc:
            raise AuditError(f"cannot open audit log {self.path}: {exc}") from exc
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            os.write(fd, line.encode("utf-8"))
            os.fsync(fd)
        except OSError as exc:
            raise AuditError(f"cannot write audit log {self.path}: {exc}") from exc
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)


def read_audit_records(path: Path, tail: int = 50) -> list[AuditRecord]:
    """Read the last *tail* valid JSONL records. Read-only and tolerant."""

    path = Path(path)
    if not path.exists():
        return []
    records: deque[AuditRecord] = deque(maxlen=max(0, tail))
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(value, dict):
                    records.append(AuditRecord.from_mapping(value))
    except OSError:
        return []
    return list(records)


class OperationLock:
    """Non-blocking host-wide lock for mutating Docker operations."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._fd: Optional[int] = None

    def acquire(self) -> None:
        _secure_parent(self.path)
        try:
            fd = os.open(
                str(self.path),
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
            )
        except OSError as exc:
            raise LockBusy(f"cannot open lock file {self.path}: {exc}") from exc

        try:
            file_stat = os.fstat(fd)
            expected_uid = 0 if os.geteuid() == 0 else os.geteuid()
            if file_stat.st_uid != expected_uid:
                raise LockBusy(
                    f"lock file {self.path} is owned by uid {file_stat.st_uid}"
                )
            os.fchmod(fd, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise LockBusy(
                    f"another docker-mgmt operation holds {self.path}"
                ) from exc
        except Exception:
            os.close(fd)
            raise

        self._fd = fd

    def release(self) -> None:
        if self._fd is None:
            return
        try:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
        finally:
            os.close(self._fd)
            self._fd = None

    def __enter__(self) -> "OperationLock":
        self.acquire()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.release()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def elapsed_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)
