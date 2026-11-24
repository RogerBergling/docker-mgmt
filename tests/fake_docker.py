#!/usr/bin/env python3
"""A small fake `docker` CLI used by the unit tests.

Set FAKE_DOCKER_STATE to a JSON state file and FAKE_DOCKER_LOG to an argv log.
It implements only the commands docker-mgmt invokes.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def load_state() -> dict:
    path = os.environ.get("FAKE_DOCKER_STATE")
    if not path:
        return {}
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}


def save_state(state: dict) -> None:
    path = os.environ.get("FAKE_DOCKER_STATE")
    if path:
        Path(path).write_text(json.dumps(state, indent=2), encoding="utf-8")


def log(argv: list[str]) -> None:
    path = os.environ.get("FAKE_DOCKER_LOG")
    if path:
        with Path(path).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(argv) + "\n")


def fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def compose_parse(argv: list[str]) -> tuple[list[Path], str, list[str]]:
    """Strip global compose options and return (files, subcommand, rest)."""

    files: list[Path] = []
    index = 1  # argv[0] == "compose"
    while index < len(argv):
        token = argv[index]
        if token in {
            "--ansi",
            "--project-directory",
            "--progress",
            "-f",
            "--file",
            "-p",
            "--project-name",
        }:
            if token in {"-f", "--file"} and index + 1 < len(argv):
                files.append(Path(argv[index + 1]))
            index += 2
            continue
        if (
            token.startswith("--ansi=")
            or token.startswith("--project-directory=")
            or token.startswith("--project-name=")
            or token.startswith("-p=")
        ):
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        break
    if index >= len(argv):
        return files, "", []
    return files, argv[index], argv[index + 1 :]


def main(argv: list[str]) -> int:
    log(argv)
    if not argv:
        return fail("fake docker: no arguments")
    state = load_state()

    if argv[0] == "--version":
        print("Docker version 27.0.0, build fake")
        return 0

    if argv[0] == "version":
        if "--format" in argv:
            fmt = argv[argv.index("--format") + 1] if argv.index("--format") + 1 < len(argv) else ""
            if "client=" in fmt:
                print("client=27.0.0 server=27.0.0")
            else:
                print("27.0.0")
        else:
            print("Client: Docker Engine - Community\n Version: 27.0.0\nServer: Docker Engine - Community\n Engine:\n  Version: 27.0.0")
        return 0

    if argv[0] == "compose":
        files, sub, rest = compose_parse(argv)
        if sub == "version":
            print("2.29.7" if "--short" in rest else "Docker Compose version v2.29.7")
            return 0
        if sub == "config":
            target = str(files[0]) if files else ""
            invalid = state.get("invalid", {})
            if target in invalid:
                return fail(str(invalid[target]))
            config = state.get("compose", {}).get(target)
            if config is None:
                return fail(f"fake docker: no compose config for {target}")
            if "--quiet" in rest:
                return 0
            if "--services" in rest:
                print("\n".join(config.get("services", {}).keys()))
                return 0
            if "--images" in rest:
                images = []
                for service in config.get("services", {}).values():
                    image = service.get("image")
                    if image and image not in images:
                        images.append(image)
                print("\n".join(images))
                return 0
            if "--format" in rest:
                print(json.dumps(config))
                return 0
            print(json.dumps(config))
            return 0
        if sub == "pull":
            if state.get("pull_fail"):
                return fail(str(state.get("pull_error", "pull failed")))
            updates = state.get("pull_updates", {})
            images = state.setdefault("images", {})
            for image, image_id in updates.items():
                images[image] = image_id
            save_state(state)
            print("pulled")
            return 0
        if sub in {"up", "stop", "restart", "down"}:
            print(f"{sub} ok")
            return 0
        if sub == "logs":
            print("fake compose log line")
            return 0
        if sub == "ls":
            print(json.dumps(state.get("compose_ls", [])))
            return 0
        if sub in {"ps", "images"}:
            project = ""
            for index, token in enumerate(argv):
                if token in {"-p", "--project-name"} and index + 1 < len(argv):
                    project = argv[index + 1]
                elif token.startswith("--project-name=") or token.startswith("-p="):
                    project = token.split("=", 1)[1]
            target = str(files[0]) if files else ""
            if not project:
                project = (
                    (state.get("compose", {}).get(target) or {}).get("name", "")
                )
            selected = [
                container
                for container in state.get("containers", [])
                if container.get("Config", {})
                .get("Labels", {})
                .get("com.docker.compose.project")
                == project
            ]
            if sub == "ps":
                for container in selected:
                    labels = container.get("Config", {}).get("Labels", {}) or {}
                    state_obj = container.get("State", {}) or {}
                    health_obj = state_obj.get("Health", {}) or {}
                    print(
                        json.dumps(
                            {
                                "ID": container.get("Id", ""),
                                "Name": container.get("Name", "").lstrip("/"),
                                "Image": container.get("Config", {}).get(
                                    "Image", ""
                                ),
                                "Project": project,
                                "Service": labels.get(
                                    "com.docker.compose.service", ""
                                ),
                                "State": state_obj.get("Status", ""),
                                "Status": "Up",
                                "Health": health_obj.get("Status", ""),
                                "ExitCode": state_obj.get("ExitCode", 0),
                                "Publishers": [],
                            }
                        )
                    )
                return 0
            images = [
                {
                    "ID": container.get("Image", ""),
                    "ContainerName": container.get("Name", "").lstrip("/"),
                    "Repository": "",
                    "Tag": "",
                    "Size": 0,
                }
                for container in selected
            ]
            print(json.dumps(images))
            return 0
        return fail(f"fake docker: unsupported compose subcommand {sub!r}")

    if argv[0] == "ps":
        if state.get("ps_empty"):
            return 0
        containers = state.get("containers", [])
        if "-a" not in argv:
            containers = [c for c in containers if c.get("State", {}).get("Status") == "running"]
        for container in containers:
            print(container.get("Id", ""))
        return 0

    if argv[0] == "inspect" or argv[:2] == ["container", "inspect"]:
        if state.get("inspect_fail"):
            return fail(str(state.get("inspect_error", "fake docker: inspect failed")))
        args = argv[1:] if argv[0] == "inspect" else argv[2:]
        if state.get("compact_inspect_fail") and "--format" in args:
            return fail("fake docker: unknown flag: --format")
        ids: list[str] = []
        format_value = ""
        index = 0
        while index < len(args):
            value = args[index]
            if value in {"--format", "-f"}:
                if index + 1 < len(args):
                    format_value = args[index + 1]
                index += 2
                continue
            if value == "--type":
                index += 2
                continue
            if value in {"--", "container"} or value.startswith("-"):
                index += 1
                continue
            ids.append(value)
            index += 1
        containers = state.get("containers", [])
        selected = [c for c in containers if c.get("Id") in ids]
        if not selected:
            return fail("fake docker: no such container")
        if format_value:
            for item in selected:
                config = item.get("Config", {})
                state_obj = item.get("State", {})
                health_obj = state_obj.get("Health", {}) or {}
                labels = config.get("Labels", {}) or {}
                record = {
                    "id": item.get("Id", ""),
                    "image_id": item.get("Image", ""),
                    "image": config.get("Image", ""),
                    "state": state_obj.get("Status", ""),
                    "health": health_obj.get("Status", ""),
                    "restart_count": item.get("RestartCount", 0),
                    "exit_code": state_obj.get("ExitCode", 0),
                    "name": item.get("Name", ""),
                    "created": item.get("Created", ""),
                    "labels": labels,
                    "port_bindings": item.get("HostConfig", {}).get(
                        "PortBindings", {}
                    )
                    or {},
                }
                print(json.dumps(record, sort_keys=True))
            return 0
        print(json.dumps(selected))
        return 0

    if argv[0] == "image":
        if len(argv) >= 2 and argv[1] == "inspect":
            values = [value for value in argv[2:] if not value.startswith("-")]
            if not values:
                return fail("fake docker: image inspect requires an image")
            image = values[-1]
            image_id = state.get("images", {}).get(image)
            if not image_id:
                return fail(f"fake docker: no such image {image}")
            print(image_id)
            return 0
        if len(argv) >= 2 and argv[1] == "prune":
            print("Deleted Images:\nfake")
            return 0

    if argv[:2] == ["builder", "prune"]:
        print("Total reclaimed space: 0B")
        return 0
    if argv[:2] == ["container", "prune"]:
        print("Total reclaimed space: 0B")
        return 0
    if argv[:2] == ["network", "prune"]:
        print("Deleted Networks:\nfake")
        return 0
    if argv[:2] == ["system", "df"]:
        print("TYPE            TOTAL     ACTIVE    SIZE      RECLAIMABLE")
        print("Images          1         1         10MB      0B (0%)")
        return 0
    if argv[:2] == ["volume", "ls"]:
        print("data\tlocal")
        return 0
    if argv[:1] == ["stats"]:
        for row in state.get("stats", []):
            print(json.dumps(row))
        return 0
    if argv[0] in {"start", "stop", "restart"}:
        print("ok")
        return 0
    if argv[0] == "logs":
        print("fake container log line")
        return 0

    return fail(f"fake docker: unsupported command: {' '.join(argv)}")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
