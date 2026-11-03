# docker-mgmt

Menu-driven, audited management of local Docker Compose projects.

`docker-mgmt` is a Python 3 tool for a single Docker host. It scans directories
for Compose files, shows what is running, checks for image updates by pulling
and comparing image IDs, and lets an operator explicitly apply updates with
`docker compose up -d`. It also covers container logs/actions, health, disk
cleanup, Compose validation, a security review, and an append-only audit log.

It deliberately does **not** implement Watchtower-style automatic updates. See
[Why not Watchtower?](#why-not-watchtower) and [SECURITY.md](SECURITY.md).

> **Privilege warning:** Docker access is effectively root access. Anyone who
> can run this tool, or run `docker` directly, can control the host. Restrict
> access to trusted administrators and protect the configuration file.

---

## Contents

- [What it does](#what-it-does)
- [Why not Watchtower?](#why-not-watchtower)
- [Requirements](#requirements)
- [Install and run](#install-and-run)
- [Configuration](#configuration)
- [Interactive menu](#interactive-menu)
- [Command-line interface](#command-line-interface)
- [How update checks work](#how-update-checks-work)
- [Security model](#security-model)
- [Scheduling a check](#scheduling-a-check)
- [Development and validation](#development-and-validation)
- [Troubleshooting](#troubleshooting)
- [Repository layout](#repository-layout)
- [Non-goals and limitations](#non-goals-and-limitations)

---

## What it does

- **Scans** configured directories for `compose.yaml`, `compose.yml`,
  `docker-compose.yaml`, `docker-compose.yml`, files with `compose` in the name,
  or optionally every `*.yml`/`*.yaml` file. Each candidate is validated with
  `docker compose config`.
- **Merges running projects** discovered from container labels and
  `docker compose ls`, including projects whose Compose files are outside the
  configured scan roots.
- **Shows a dashboard** of Compose projects, containers, health, restart counts,
  and published ports.
- **Pulls and compares** images without restarting anything, and reports whether
  a service's image changed or a running container is stale.
- **Applies updates** only after explicit confirmation, using
  `docker compose up -d`.
- **Manages projects**: validate, pull, apply, restart, stop, view logs, and
  `down` (without deleting volumes).
- **Manages containers**: logs, follow logs, start/stop/restart, and one-shot
  resource usage.
- **Cleans disk safely**: dangling images, unused build cache, stopped
  containers, and unused networks. Volumes are never pruned.
- **Validates and reviews security**: Compose syntax, floating image tags,
  privileged containers, host namespaces, Docker socket mounts, dangerous
  capabilities, disabled sandboxes, wildcard ports, and root file-trust issues.
- **Audits** all mutating actions to a JSON Lines log with mode `0600`.
- **Serialises** mutating operations with a host-wide non-blocking lock.

## Why not Watchtower?

Watchtower is convenient, but it is a poor fit for a security-sensitive web
server for several reasons:

1. **It is a long-running process with Docker socket access.** The Docker
   socket is equivalent to root. A vulnerability or supply-chain compromise in
   the updater is a host compromise.
2. **It updates without human review.** A compromised upstream tag, a bad
   release, or a breaking change can be deployed automatically. There is no
   change window, no approval, and no chance to read release notes.
3. **It restarts containers on its own schedule.** Restarts can happen during
   peak traffic or in the middle of a database migration, and can cascade
   through dependent services.
4. **Mutable tags are treated as trusted.** `latest`, `stable`, `main`, and
   similar tags can move at any time. Automated pulls turn an upstream registry
   compromise into an immediate deployment.
5. **There is no built-in change control or audit trail.** It is hard to answer
   who approved an update, what image was running before, or why a service
   restarted at 03:00.
6. **Notification/API credentials** often live in the updater's environment,
   adding another secret store and another network-facing component.

`docker-mgmt` is not a daemon and does not watch anything. It runs when an
operator invokes it, pulls only after confirmation, shows what changed, and
requires a separate confirmation before containers are recreated. The audit log
records the action and result. That does not make upstream images trustworthy —
operators must still pin versions/digests, use trusted registries, scan images,
and take backups.

## Requirements

- Linux (uses `fcntl` file locking and POSIX permissions).
- Python **3.9 or newer**, standard library only. No pip packages are required
  to run the tool.
- Docker Engine with the **Docker Compose v2 plugin** (`docker compose`).
  - Compose v2.6+ is required for `docker compose config --format json`.
  - `compose.wait_after_update` additionally needs a Compose version that
    supports `up --wait` (v2.17+); if unsupported, the tool retries without it.
- Root or `sudo` is recommended. A user in the `docker` group works too, but
  that group is root-equivalent.

The development workstation used to build this repository did **not** have
Docker installed. The automated tests use a fake `docker` executable. Run the
read-only checks (`doctor`, `scan`, `validate`, `status`) on the real server
before using any mutating action.

## Install and run

### Directly from the checkout (recommended for a root-run server)

```bash
git clone <your-repo-url> docker-mgmt
cd docker-mgmt

# Read-only diagnostics first:
sudo ./docker-mgmt doctor

# Create the root-controlled configuration:
sudo mkdir -p /etc/docker-mgmt
sudo cp config.example.ini /etc/docker-mgmt/config.ini
sudo chown root:root /etc/docker-mgmt/config.ini
sudo chmod 0644 /etc/docker-mgmt/config.ini
sudo editor /etc/docker-mgmt/config.ini

# Start the menu:
sudo ./docker-mgmt
```

`./docker-mgmt` and `python3 -m docker_mgmt` are equivalent. No build step is
needed.

### Optional installation

The repository includes a `pyproject.toml` (PEP 517/setuptools) and a
`docker-mgmt` console script, with **zero runtime dependencies**:

```bash
python3 -m pip install .
# or, for an isolated user install:
pipx install .
```

When installing for root, be deliberate about which Python environment is used.
Running the checkout directly avoids that ambiguity.

## Configuration

The tool reads an INI file. Configuration is a security boundary because it
controls which paths root will read and which commands will be run.

Default locations:

| User | Config path | Default audit log |
|---|---|---|
| root | `/etc/docker-mgmt/config.ini` | `/var/log/docker-mgmt/audit.log` |
| non-root | `~/.config/docker-mgmt/config.ini` | `~/.local/state/docker-mgmt/audit.log` |

Overrides:

- `--config PATH`
- `DOCKER_MGMT_CONFIG` environment variable
- `--root PATH` (repeatable) to override scan roots
- `--all-yaml` to scan every `*.yml`/`*.yaml` file
- `DOCKER_MGMT_LOCK` environment variable (advanced/testing only) to override the
  operation-lock path. The lock is a coordination mechanism, not an
  authorization boundary.

When running as root, the config file and every parent directory up to `/` must
be root-owned and not group- or world-writable. Sticky root-owned directories
such as `/tmp` are tolerated because non-owners cannot remove a root-owned entry
there. This prevents a local user from changing scan roots or other settings
used by a root process. When running as
non-root, a world-writable config produces a warning.

### Configuration reference

| Section | Key | Default | Meaning |
|---|---|---|---|
| `scan` | `roots` | `/opt, /srv, /var/www, /home, /root` | Comma/newline-separated directories to scan. |
| `scan` | `include_all_yaml` | `false` | Validate every `*.yml`/`*.yaml` file, not only Compose-named files. |
| `scan` | `max_depth` | `8` | Maximum directory depth below each root. |
| `scan` | `include_hidden` | `false` | Descend into hidden directories such as `.config`. |
| `scan` | `follow_symlinks` | `false` | Follow directory symlinks. File symlinks are always resolved and must stay inside a root. |
| `scan` | `exclude_dirs` | built-in list | Additional directory names to skip. Built-in safety exclusions always apply. |
| `compose` | `command_timeout_seconds` | `120` | Timeout for normal Docker commands. |
| `compose` | `pull_timeout_seconds` | `900` | Timeout for `docker compose pull`. |
| `compose` | `up_timeout_seconds` | `300` | Timeout for `docker compose up -d`. |
| `compose` | `wait_after_update` | `false` | Add `--wait --wait-timeout` to `up -d`. |
| `compose` | `wait_timeout_seconds` | `120` | Value for `--wait-timeout`. |
| `audit` | `path` | user-dependent | Audit log path. Parent directory must be private and not group/world-writable. |
| `audit` | `max_bytes` | `10485760` | Rotate to `<name>.1` above this size. |
| `ui` | `color` | `auto` | `auto`, `always`, or `never`. `NO_COLOR` always wins. |
| `ui` | `page_size` | `20` | Menu page size (5–100). |
| `security` | `allow_unsafe_ownership` | `false` | **Dangerous.** Allow mutating actions when project files are owned by non-root users or are writable by them. |

The operation lock path is not configurable:

- root: `/run/docker-mgmt/docker-mgmt.lock`
- non-root: `$XDG_RUNTIME_DIR/docker-mgmt.lock`, or a private directory under
  the system temporary directory

See [`config.example.ini`](config.example.ini) for a commented example.

### Scan behaviour

- Standard Compose files are recognised. Standard override files
  (`compose.override.yaml`, etc.) are automatically loaded by Compose and are
  not treated as separate projects.
- If multiple base files exist in one directory, the highest-precedence name is
  used (`compose.yaml` first) and a warning is shown.
- If two different Compose files resolve to the same project name, both are
  marked **blocked** for project-scoped mutations. Compose would otherwise act
  on the same project for both files. Give each file a unique top-level `name:`
  or move them into separate directories.
- If a running project's files differ from a scanned project with the same name,
  the scanned project is also blocked.
- If a project was started with an explicit `-p NAME` and no top-level `name:`,
  the running name is adopted and passed explicitly to Compose. A warning asks
  you to add a top-level `name:` so the intent is visible in the file.
- `/proc`, `/sys`, `/dev`, `/run`, `/var/run`, `/var/lib/docker`,
  `/var/lib/containers`, `/snap`, `/boot`, and `/lost+found` are never scanned.
- Directory symlinks are not followed by default. File symlinks are resolved and
  rejected if they escape all scan roots.

## Interactive menu

Run:

```bash
sudo ./docker-mgmt
# or
sudo python3 -m docker_mgmt
```

Main menu:

1. Dashboard
2. Compose projects
3. Containers
4. Check for updates
5. Disk usage and safe cleanup
6. Validate Compose files and security review
7. Audit log
8. Rescan configured roots
9. Scan a directory temporarily (without editing the config)
10. Settings and security notes
11. Exit (or `0`)

Menus are numbered, support paging, and support `/text` filtering for large
servers. Every interactive mutating action shows the exact `docker`/`docker compose`
command and asks for confirmation. Destructive cleanup and `down` require a
typed phrase.

### Project actions

- **Check for updates** — pulls images; does not restart containers.
- **Pull and apply updates** — pulls, shows detection results, then asks before
  running `docker compose up -d`.
- **Apply Compose changes only** — runs `up -d --pull never` without a pull.
- **Restart running containers** — `docker compose restart`.
- **Stop containers** — `docker compose stop`; containers stay on disk.
- **View logs** — recent 200 lines or follow with Ctrl-C.
- **Validate / refresh metadata** — re-runs `config --format json`.
- **Security review** — file trust plus static Compose findings.
- **Down** — removes containers and networks; **named/anonymous volumes are not
  removed**. A typed `DOWN` confirmation is required.

## Command-line interface

The menu is the primary interface, but non-interactive commands are available
for automation. Mutating commands require `--yes` when stdin is not a TTY.

```bash
# Read-only
sudo ./docker-mgmt doctor
sudo ./docker-mgmt scan
sudo ./docker-mgmt scan --json
sudo ./docker-mgmt status
sudo ./docker-mgmt status --json --running
sudo ./docker-mgmt validate
sudo ./docker-mgmt audit --tail 100

# Pull and compare only; never restarts containers
sudo ./docker-mgmt check --yes
sudo ./docker-mgmt check --yes --json

# Explicitly pull and recreate
sudo ./docker-mgmt update myproject --yes
sudo ./docker-mgmt update --all --yes       # high impact; requires --yes

# Logs
sudo ./docker-mgmt logs myproject --tail 200
sudo ./docker-mgmt logs myproject --follow
sudo ./docker-mgmt logs my-container --follow

# Safe cleanup; volumes are never included
sudo ./docker-mgmt prune images --yes
sudo ./docker-mgmt prune cache --yes
sudo ./docker-mgmt prune containers --yes
sudo ./docker-mgmt prune networks --yes

# Temporary scan without editing config
sudo ./docker-mgmt scan --root /srv/stacks --all-yaml --json
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success; for `check`, no updates found. |
| `1` | Validation problems, command failures, or `check` completed with errors. |
| `2` | Usage/configuration error, Docker unavailable, audit unavailable, or operation blocked. |
| `10` | `check` completed and image updates are available. |
| `130` | Interrupted (Ctrl-C). |

`check --json` is useful in monitoring: exit `10` means "updates available",
while `1` means "errors occurred and the result may be incomplete".

## How update checks work

`check` does this for each project:

1. Records the local image ID for every service image.
2. Runs `docker compose pull --quiet --ignore-buildable`.
3. Records the local image ID again.
4. Records the image IDs of running containers for the project.
5. Compares them.

Service statuses:

| Status | Meaning |
|---|---|
| `image-updated` | The local tag now points to a different image ID. |
| `new-image` | The image was missing locally and was pulled. |
| `container-stale` | The local tag did not move, but a running container uses an older image ID. |
| `up-to-date` | Local image and running container match. |
| `not-running` | Image is current, but no running container was found. |
| `build-only` | The service has a build section and no pullable image; skipped. |
| `pull-failed` | The pull failed and no change could be confirmed. |
| `skipped` | The project was invalid or had no services to check. |

Important details:

- **Pulling changes local tags but does not restart containers.** The running
  image ID can therefore differ from the newly pulled tag. This is reported as
  `container-stale`.
- **`up -d` is authoritative.** It also applies Compose file changes that do not
  involve an image change. A check with no image updates does not mean the
  Compose configuration is unchanged.
- **Apply actions use `--pull never`.** The tool pulls explicitly first, or you
  choose "apply changes only". If a required image is missing, the apply fails
  rather than silently pulling during `up -d`.
- The tool does not compare `compose config --hash` with container labels,
  because Compose has had bugs where those hashes do not match (especially with
  `env_file`). This avoids false "configuration drift" alarms; use `up -d` after
  reviewing Compose changes.
- Build-only services are not pulled. `up -d` may build them, depending on your
  Compose configuration.
- Floating tags (`latest`, `stable`, `main`, ...) are flagged. For reproducible
  updates, pin a version or an image digest.
- A pull failure is reported and `update` does not continue to `up -d` for that
  project.

## Security model

Full details and a threat model are in [SECURITY.md](SECURITY.md). Key controls:

- **No automatic updates.** No Watchtower, no watcher daemon, no scheduled
  restart. Updates are pulled only when an operator runs a check, and containers
  are recreated only after a separate confirmation.
- **No shell.** Docker commands are executed as argument vectors with
  `shell=False`. Paths and project names cannot break out into a shell.
- **Deterministic project selection.** Compose child processes inherit the
  Docker environment but have `COMPOSE_PROJECT_NAME`, `COMPOSE_FILE`,
  `COMPOSE_PROFILES`, and `COMPOSE_ENV_FILES` cleared. Project names are passed
  explicitly with `-p`. Compose profiles are not currently enabled by this tool,
  so services behind profiles are left unstarted; use a separate reviewed
  command if you need profiles.
- **Audit trail.** All mutating actions are appended to a JSON Lines log with
  mode `0600`. The log records timestamp, user, action, target, project, result,
  duration, and a redacted/truncated detail. Mutating actions are disabled if
  the audit log cannot be written.
- **Host-wide lock.** A non-blocking `flock` prevents two operators from running
  mutating operations at the same time.
- **Root file-trust checks.** Before a project-scoped mutation, root-run
  Compose files, the automatically loaded project `.env`, service `env_file`
  paths, build contexts, build Dockerfiles, and local Compose `secrets`/`configs`
  files are checked. If any path or parent directory is owned by a non-root user
  or is group/world-writable (except sticky root-owned directories such as
  `/tmp`), the action is blocked. Otherwise a local user
  could modify a file and get root through a container. Compose `include` and
  service `extends` references cannot be fully enumerated without a YAML
  parser; the tool warns when they are present, and the entire project tree
  should remain root-controlled.
- **High-risk confirmation.** Privileged containers, host network/PID/IPC/user
  namespaces, Docker socket mounts, dangerous capabilities, disabled
  seccomp/AppArmor, and sensitive host mounts are shown and require confirmation
  before `up -d`.
- **No volume destruction.** `docker compose down -v` is never used, and volume
  prune is intentionally absent. `down` keeps volumes.
- **Secrets handling.** The resolved Compose JSON may contain environment
  values, but only selected metadata (images, build contexts, security flags,
  env-file paths) is retained. Raw Compose JSON is not printed or logged. Error
  output is redacted and truncated.
- **Config and audit protection.** As root, config and audit paths must be
  root-owned and not writable by group/others. Symlinked audit logs are refused.

These controls reduce risk; they do not make untrusted Compose files safe. The
operator remains responsible for the contents of every Compose file and image
that is deployed.

## Scheduling a check

You can schedule a **pull-and-compare** check without restarting anything:

```cron
# Run at 04:15 as root; JSON to a root-only file.
15 4 * * * /usr/local/bin/docker-mgmt check --yes --json > /var/log/docker-mgmt/update-check.json 2>&1
```

Do not schedule `update` for unattended deployment if the goal is to avoid
Watchtower-style risk. Review the report and apply updates deliberately (or
build a separate, reviewed deployment pipeline with its own controls).

## Development and validation

The project uses only the Python standard library at runtime.

```bash
# Byte-compile the package and tests
python3 -m compileall -q docker_mgmt tests

# Run all unit/integration tests with the fake Docker CLI
python3 -m unittest discover -s tests -t . -v

# Or both:
make check
```

Tests cover:

- Compose file discovery, standard overrides, exclusions, symlink escape,
  duplicate project names, and merging running projects.
- Compose static security analysis and root file-trust checks.
- Update comparison statuses and apply flow.
- Config parsing and permission-related behaviour.
- Audit logging, symlink refusal, log permissions, and lock exclusivity.
- Menu table/filter/confirmation logic.
- End-to-end CLI commands against a fake `docker` executable, including scans,
  update checks, `up -d`, audit, prune, logs, and doctor.

The fake Docker CLI lives in `tests/fake_docker.py`. It implements only the
commands the tool uses. It does not replace a real integration test on the
target server.

### Suggested server validation sequence

```bash
sudo ./docker-mgmt doctor
sudo ./docker-mgmt scan --json
sudo ./docker-mgmt validate
sudo ./docker-mgmt status
# Then try a single non-critical project:
sudo ./docker-mgmt check my-test-project --yes
```

Before applying updates to production, verify that:

- You have a tested backup of databases and named volumes.
- Images are pinned to reviewed versions/digests.
- The Compose files and `.env` files are root-owned and not writable by deploy
  users.
- Your registry credentials are available to the root/Docker context.
- You have a maintenance window and a rollback plan.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `docker CLI not found in PATH` | Install Docker Engine or fix `PATH`; run `doctor`. |
| `cannot talk to the Docker daemon` / permission denied | Run with `sudo`, or use an account in the `docker` group (root-equivalent). |
| `Docker Compose v2 is required` | Install the Compose v2 plugin and verify `docker compose version`. |
| `config --format json` unsupported | Upgrade Docker Compose to v2.6 or newer. |
| `up` fails with `unknown flag: --pull` | Upgrade Docker Compose; apply actions use `--pull never` to prevent silent pulls. |
| `Audit log unavailable` | Fix the audit path permissions/ownership; mutating actions are disabled by design. |
| `refusing to load ... not root-controlled` | `chown root:root` the file and its parent directories; remove group/world write. |
| `refusing to load symlinked config ... as root` | Replace the symlink with a root-owned regular file (for example, copy the target to `/etc/docker-mgmt/config.ini`). |
| Project marked blocked | Two Compose files share a project name, or a running project has different config files. Give each a unique `name:` or separate directories. |
| Root file-trust issues | `chown -R root:root` the Compose project and `chmod 0644` files; check `.env` and build contexts. Do not enable `allow_unsafe_ownership` on production unless you accept the risk. |
| No projects found | Check `scan.roots`, `max_depth`, hidden dirs, and file names; try `--root /path --all-yaml`. |
| `another docker-mgmt operation holds ...` | Wait for the other operation or inspect the lock owner; the lock is non-blocking by design. |
| Pull fails with auth errors | Run `docker login` in the same user context; check registry/credential helper configuration. |
| Scan is slow | Reduce roots/depth, keep `include_all_yaml=false`, and exclude large directories. |
| `DOCKER_HOST is set` warning | Unset it for a local daemon, or confirm the remote daemon is the intended target. |

## Repository layout

```
docker-mgmt                 executable source-checkout entry point
docker_mgmt/
  __main__.py               python -m docker_mgmt
  cli.py                    argument parsing and non-interactive commands
  app.py                    interactive menu and action flow
  config.py                 INI config and permission checks
  discovery.py              Compose scanning, validation, running-project merge
  docker.py                 Docker/Compose CLI wrapper
  updates.py                pull/compare logic and apply flow
  security.py               static Compose review and file-trust checks
  audit.py                  JSONL audit log, rotation, operation lock
  runner.py                 safe subprocess execution, redaction, sanitisation
  models.py                 project/container/update data models
  ui.py                     tables, paged/filterable menus, confirmations
tests/
  fake_docker.py            fake Docker CLI for tests
  test_*.py                 unit and end-to-end tests
config.example.ini          commented configuration example
SECURITY.md                 threat model and security rationale
Makefile                    test/lint/check/run targets
pyproject.toml              optional PEP 517 packaging, zero runtime deps
```

## Non-goals and limitations

- Single host only. There is no multi-host orchestration, Kubernetes, or Swarm
  support.
- Standalone containers started with `docker run` are visible and can be
  restarted/stopped/logged, but image update checking and safe recreation are
  Compose-focused. Recreating a standalone container would require preserving
  its original run configuration manually.
- No automatic update/rollback. Rollback should be planned through image
  pinning and your deployment process.
- No vulnerability scanning of images. Use a scanner such as Trivy/Grype in a
  separate, reviewed pipeline.
- Compose files can run arbitrary commands and mount host paths by design. The
  tool validates and warns, but it cannot make a malicious Compose file safe.
- Compose `include`/`extends` files are not individually enumerated for trust
  checks. A warning is shown; keep the entire project tree root-owned and
  non-writable.
- Image updates are detected by pulling tags. If an upstream registry changes an
  image under the same tag and digest, or you use a digest pin, there may be
  nothing to detect.
- The audit log is local. It is not tamper-proof against a root attacker; ship
  it to a remote log collector if you need stronger guarantees.
- No notifications are sent. `check --json` is designed to be consumed by an
  external monitoring system.
