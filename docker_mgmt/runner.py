"""Safe subprocess execution and output sanitisation.

Commands are always executed as argument vectors with shell=False. Output is
sanitised and redacted before it is shown in errors or written to the audit
log, to reduce accidental secret disclosure.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import time
from dataclasses import dataclass
from typing import Iterable, Optional, Sequence


class DockerMgmtError(Exception):
    """Base class for expected, user-facing errors."""


class CommandUnavailable(DockerMgmtError):
    """Raised when an executable cannot be found."""


class CommandError(DockerMgmtError):
    """Raised when a command fails and the caller requested check=True."""

    def __init__(self, result: "CommandResult") -> None:
        self.result = result
        super().__init__(
            f"command failed with exit code {result.returncode}: "
            f"{summarize_output(result)}"
        )


@dataclass
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization|auth)"
    r"(\s*[:=]\s*)([^\s,;]+)"
)
_URL_CREDENTIAL_RE = re.compile(r"(https?://)([^/@\s]+)@")
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)


def sanitize_text(text: str, max_length: int = 4000) -> str:
    """Remove terminal control sequences and cap the size of untrusted output."""

    text = _ANSI_RE.sub("", text or "")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = "".join(
        char for char in text if char in "\n\t" or ord(char) >= 32
    )
    if len(text) > max_length:
        text = text[:max_length] + "\n[output truncated]"
    return text


def redact_text(text: str) -> str:
    """Best-effort redaction of common secret shapes in command output."""

    text = _PRIVATE_KEY_RE.sub("<redacted private key>", text)
    text = _SECRET_RE.sub(r"\1\2<redacted>", text)
    text = _URL_CREDENTIAL_RE.sub(r"\1<redacted>@", text)
    return text


def summarize_output(result: CommandResult, max_length: int = 800) -> str:
    """Return a short, redacted error message suitable for display/audit."""

    text = result.stderr.strip() or result.stdout.strip()
    if not text:
        if result.timed_out:
            return "command timed out"
        return f"exit code {result.returncode}"
    text = redact_text(sanitize_text(text, max_length=max_length * 2))
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    text = "\n".join(lines[:8])
    if len(text) > max_length:
        text = text[:max_length] + "..."
    return text


def format_command(argv: Sequence[str]) -> str:
    """Render a command for display without invoking a shell."""

    return redact_text(shlex.join(str(part) for part in argv))


class CommandRunner:
    """Small wrapper around subprocess with no shell and bounded timeouts."""

    def __init__(self, base_env: Optional[dict[str, str]] = None) -> None:
        self._base_env = dict(base_env or {})

    def _env(self, extra: Optional[dict[str, Optional[str]]]) -> dict[str, str]:
        env = os.environ.copy()
        env["DOCKER_CLI_HINTS"] = "false"
        env.update(self._base_env)
        if extra:
            for key, value in extra.items():
                if value is None:
                    env.pop(key, None)
                else:
                    env[key] = value
        return env

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: Optional[float] = None,
        cwd: Optional[os.PathLike[str]] = None,
        env: Optional[dict[str, Optional[str]]] = None,
        capture: bool = True,
        input_text: Optional[str] = None,
        check: bool = False,
    ) -> CommandResult:
        """Run a command and capture its output.

        Raises CommandUnavailable if the executable is missing. A timeout is
        returned as a failed CommandResult (exit code 124) rather than raising.
        """

        cmd = tuple(str(part) for part in argv)
        started = time.monotonic()
        try:
            completed = subprocess.run(
                cmd,
                cwd=str(cwd) if cwd else None,
                env=self._env(env),
                input=input_text,
                stdout=subprocess.PIPE if capture else None,
                stderr=subprocess.PIPE if capture else None,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                shell=False,
            )
        except FileNotFoundError as exc:
            raise CommandUnavailable(
                f"executable not found: {cmd[0]}" if cmd else "empty command"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode("utf-8", "replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode("utf-8", "replace")
            result = CommandResult(
                argv=cmd,
                returncode=124,
                stdout=sanitize_text(stdout),
                stderr=sanitize_text(
                    (stderr + f"\ntimed out after {timeout} seconds").strip()
                ),
                duration_seconds=time.monotonic() - started,
                timed_out=True,
            )
            if check:
                raise CommandError(result)
            return result

        result = CommandResult(
            argv=cmd,
            returncode=completed.returncode,
            stdout=sanitize_text(completed.stdout or ""),
            stderr=sanitize_text(completed.stderr or ""),
            duration_seconds=time.monotonic() - started,
        )
        if check and not result.ok:
            raise CommandError(result)
        return result

    def stream(
        self,
        argv: Sequence[str],
        *,
        cwd: Optional[os.PathLike[str]] = None,
        env: Optional[dict[str, Optional[str]]] = None,
    ) -> int:
        """Run a command with inherited stdio, for interactive/following output."""

        cmd = tuple(str(part) for part in argv)
        try:
            completed = subprocess.run(
                cmd,
                cwd=str(cwd) if cwd else None,
                env=self._env(env),
                shell=False,
            )
        except FileNotFoundError as exc:
            raise CommandUnavailable(
                f"executable not found: {cmd[0]}" if cmd else "empty command"
            ) from exc
        except KeyboardInterrupt:
            return 130
        return completed.returncode


def first_lines(text: str, limit: int = 6) -> str:
    """Return the first non-empty lines of a block of text."""

    lines = [line.strip() for line in sanitize_text(text).splitlines() if line.strip()]
    return "\n".join(lines[:limit])


def split_lines(values: Iterable[str]) -> list[str]:
    """Flatten an iterable of possibly multi-line strings into clean lines."""

    result: list[str] = []
    for value in values:
        for line in str(value).splitlines():
            line = line.strip()
            if line:
                result.append(line)
    return result
