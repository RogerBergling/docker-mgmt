"""Shared test helpers: temporary fake Docker CLI and state builders."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
FAKE_DOCKER = Path(__file__).resolve().parent / "fake_docker.py"


def fake_environment(tmp: Path) -> dict[str, str]:
    bin_dir = tmp / "bin"
    bin_dir.mkdir(exist_ok=True)
    docker_link = bin_dir / "docker"
    if docker_link.exists() or docker_link.is_symlink():
        docker_link.unlink()
    # Copy rather than symlink so the fake binary is owned by the test process
    # even when the suite is run as root.
    shutil.copy2(FAKE_DOCKER, docker_link)
    os.chmod(docker_link, 0o755)
    state = tmp / "docker-state.json"
    log = tmp / "docker-argv.log"
    state.write_text(
        json.dumps(
            {
                "images": {},
                "containers": [],
                "compose": {},
                "invalid": {},
                "compose_ls": [],
                "pull_updates": {},
                "stats": [],
            }
        ),
        encoding="utf-8",
    )
    env = os.environ.copy()
    # Keep tests deterministic when the suite is run as root: the fake binary
    # directory plus standard root-owned system paths.
    env["PATH"] = str(bin_dir) + ":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    env["FAKE_DOCKER_STATE"] = str(state)
    env["FAKE_DOCKER_LOG"] = str(log)
    env["DOCKER_MGMT_LOCK"] = str(tmp / "docker-mgmt.lock")
    env["NO_COLOR"] = "1"
    for name in (
        "DOCKER_CONFIG",
        "DOCKER_CONTEXT",
        "DOCKER_HOST",
        "COMPOSE_FILE",
        "COMPOSE_PROJECT_NAME",
        "COMPOSE_PROFILES",
        "COMPOSE_ENV_FILES",
    ):
        env.pop(name, None)
    return env


def read_state(env: dict[str, str]) -> dict:
    return json.loads(Path(env["FAKE_DOCKER_STATE"]).read_text(encoding="utf-8"))


def write_state(env: dict[str, str], state: dict) -> None:
    Path(env["FAKE_DOCKER_STATE"]).write_text(
        json.dumps(state, indent=2), encoding="utf-8"
    )


def docker_log(env: dict[str, str]) -> list[list[str]]:
    path = Path(env["FAKE_DOCKER_LOG"])
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def run_cli(
    args: list[str],
    env: dict[str, str],
    *,
    cwd: Optional[Path] = None,
    input_text: Optional[str] = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "docker_mgmt", *args],
        cwd=str(cwd or REPO_ROOT),
        env=env,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
    )


def write_config(
    tmp: Path,
    *,
    roots: Optional[list[str]] = None,
    allow_unsafe: bool = True,
    extra: str = "",
) -> Path:
    roots = roots or [str(tmp / "apps")]
    content = f"""
[scan]
roots = {", ".join(roots)}
include_all_yaml = false
max_depth = 6
include_hidden = false
follow_symlinks = false

[audit]
path = {tmp / "audit.log"}

[ui]
color = never
page_size = 10

[security]
allow_unsafe_ownership = {"true" if allow_unsafe else "false"}

{extra}
"""
    path = tmp / "config.ini"
    path.write_text(content, encoding="utf-8")
    os.chmod(path, 0o644)
    return path


def compose_config(name: str = "demo", image: str = "nginx:1.27") -> dict:
    return {
        "name": name,
        "services": {
            "web": {
                "image": image,
                "ports": [{"target": 80, "published": "8080", "host_ip": "127.0.0.1"}],
            }
        },
    }


def container(
    *,
    container_id: str = "a" * 64,
    name: str = "demo-web-1",
    project: str = "demo",
    service: str = "web",
    image: str = "nginx:1.27",
    image_id: str = "sha256:" + "1" * 64,
    state: str = "running",
    health: Optional[str] = "healthy",
    restart_count: int = 0,
) -> dict:
    health_obj = {"Status": health} if health else {}
    return {
        "Id": container_id,
        "Name": "/" + name,
        "Image": image_id,
        "Created": "2026-01-01T00:00:00Z",
        "State": {
            "Status": state,
            "Health": health_obj,
            "ExitCode": 0,
        },
        "RestartCount": restart_count,
        "Config": {
            "Image": image,
            "Labels": {
                "com.docker.compose.project": project,
                "com.docker.compose.service": service,
                "com.docker.compose.project.config_files": "",
                "com.docker.compose.project.working_dir": "",
                "com.docker.compose.config-hash": "hash",
            },
        },
        "HostConfig": {
            "PortBindings": {
                "80/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]
            }
        },
    }
