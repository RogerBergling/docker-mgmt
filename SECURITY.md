# Security

`docker-mgmt` runs Docker commands on a server. Docker access is equivalent to
root access, so this document describes the threat model, the controls that are
implemented, and the limits of those controls.

## Threat model

### Assets

- The Docker host and everything it can reach.
- Compose files, `.env` files, build contexts, images, containers, networks, and
  named/anonymous volumes.
- Registry credentials and any secrets referenced by containers.
- The audit trail of administrative actions.

### Adversaries and failure modes

- A local user who can modify a Compose file, `.env` file, or build context that
  root later deploys.
- A compromised or malicious upstream image/tag.
- An operator mistake: restarting during peak traffic, deleting a volume, or
  applying an unreviewed update.
- A compromised dependency or long-running updater with Docker socket access.
- Concurrent operations racing each other.
- Secret leakage through logs, error output, or the Compose model.

## Why Watchtower is not used

Watchtower is intentionally excluded, not because automatic updates are
technically difficult, but because the security properties conflict with this
tool's purpose:

1. **Long-running Docker socket access.** The Docker socket grants host control.
   A vulnerability or supply-chain compromise in a constantly running updater
   has a much larger blast radius than an interactive tool invoked for a
   specific action.
2. **No human approval.** An upstream tag can be repointed to a compromised or
   broken image. Automatic deployment turns that into an immediate production
   incident. Release notes, changelogs, and compatibility checks are bypassed.
3. **No maintenance window.** Containers restart whenever the updater decides,
   potentially during peak load, a backup, or a database migration. Dependent
   services can fail in a cascade.
4. **Mutable tags as trust anchors.** `latest`, `stable`, `main`, and `edge` are
   not immutable. Digest pinning and a reviewed rollout are safer.
5. **No reliable change control or audit.** It is difficult to reconstruct who
   approved a change, what was running before, or why a restart happened.
6. **Extra credential exposure.** Notifications and registry auth add secret
   stores and network clients to a privileged daemon.

This tool is not a daemon. It runs on demand, performs a pull only after
confirmation, shows what changed, and requires another explicit confirmation
before `up -d`. Pulling alone never restarts a container.

## Implemented controls

### 1. Explicit, interactive actions

- No auto-update, no watch loop, no timer.
- Every interactive mutating action shows the exact command and asks for confirmation.
- Destructive actions (`down`, prune) require a typed phrase.
- `--yes` is only accepted for non-interactive CLI use; it is an explicit
  operator choice.

### 2. Shell-free command execution

- All commands are argument vectors with `subprocess.run(..., shell=False)`.
- Project names, paths, image names, and container names cannot inject shell
  metacharacters.
- `COMPOSE_PROJECT_NAME`, `COMPOSE_FILE`, `COMPOSE_PROFILES`, and
  `COMPOSE_ENV_FILES` are removed from the child environment so an operator's
  shell cannot silently redirect Compose to a different project.
- `DOCKER_HOST` is not overridden. If it is set, the menu warns that actions may
  target a remote daemon.

### 3. File-trust checks

Before a project-scoped mutation, Docker-privileged runs (root or a user in the
`docker` group) check:

- The Compose file(s), including standard override files; the automatically
  loaded project `.env`; service `env_file` paths; local build contexts; build
  Dockerfiles; and local Compose `secrets`/`configs` files.
- The file/directory and its parent chain must be owned by root or the current
  user.
- No component may be group- or world-writable; sticky root-owned directories
  such as `/tmp` are tolerated because non-owners cannot remove a root-owned
  entry there.
- Paths that do not exist, symlink escapes outside scan roots, and unexpected
  ownership are rejected.
- Compose `include` and service `extends` references are difficult to enumerate
  without a YAML parser. Projects using them are blocked from mutating actions
  by default. `security.allow_unverified_references=true` is an explicit
  residual-risk override; keep the whole project tree controlled by root/user.
- Standard override files are included explicitly in the Compose file list so
  `compose up` uses the same merged configuration that was validated and
  trust-checked.
- Build-context directories and Dockerfiles are checked, but the entire
  build-context tree is not recursively verified. Keep all files in a build
  context controlled by root/current user and non-writable by others.
- Trust checks inspect POSIX owner/mode bits. They do not inspect POSIX ACLs,
  SELinux labels, mount options, or immutable attributes. A host using those
  controls should verify them separately.

Why this matters: if a deploy user can edit a Compose file that root runs with
`docker compose up`, that user can mount `/`, add `privileged: true`, or
otherwise obtain root. The check is intentionally strict. Use
`security.allow_unsafe_ownership=true` only if you understand and accept that
risk; it is never the default.

When running as a non-root user with Docker access, the same ownership policy
applies with the current user added as an allowed owner. Docker group membership
is itself root-equivalent, so group-writable project files are not accepted by
default.

### 4. High-risk Compose review

The resolved Compose model is inspected for:

- `privileged: true`
- `network_mode: host`, `pid: host`, `ipc: host`, `userns_mode: host`
- `cap_add` containing `SYS_ADMIN`, `SYS_PTRACE`, or `ALL`
- `security_opt` disabling seccomp/AppArmor (`*unconfined*`)
- mounts of the Docker socket
- sensitive host mounts (`/`, `/etc`, `/root`, `/var/lib/docker`, `/var/run`,
  `/run`, `/boot`, `/dev`, `/proc`, `/sys`)
- devices mapped into containers
- ports published on all host interfaces
- floating image tags (`latest`, `stable`, `main`, `master`, `edge`, `nightly`,
  `dev`, `rolling`)

High-risk findings are shown before `up -d` and require confirmation in the
menu. They are reported by `validate` and in the project security review.

These are static checks, not a container sandbox or image scanner. A Compose
file can still deploy a malicious image or a dangerous configuration that the
checks do not enumerate.

### 5. Audit logging

- JSON Lines, one record per mutating action.
- Default path:
  - root: `/var/log/docker-mgmt/audit.log`
  - non-root: XDG state directory
- Mode `0600`; symlinks, non-regular files, and group/world-writable parent
  directories are refused.
- Records include timestamp, user, `SUDO_USER`, uid, action, target, project,
  result, duration, and a redacted/truncated detail.
- Details are capped and redacted for common secret patterns. Raw environment
  variables and full command output are not logged.
- Mutating actions are blocked when the audit log cannot be written. Read-only
  views remain available.
- The log rotates to `<name>.1` above `audit.max_bytes`.

The audit log is local and controlled by its owner, but a root attacker can
alter or delete it. Ship logs to a remote collector if you need tamper resistance.

### 6. Host-wide operation lock

- Non-blocking `flock` at a fixed path per privilege level.
- Prevents two docker-mgmt processes from mutating Docker at the same time.
- The lock is coordination, not authorization. It does not stop an operator
  from running `docker` manually; that is outside the tool's control.

### 7. Destructive-action limits

- `docker compose down -v` is never used.
- Volume prune is not implemented anywhere in the code or CLI.
- Image prune removes only dangling images, not all unused tagged images.
- Container prune removes stopped containers only.
- Build-cache and network prune are explicit, separate actions.
- No automatic removal of orphans or unused volumes.

### 8. Configuration and state protection

- As root, the config file and all parent directories must be root-owned and not
  group/world-writable. A symlinked config is rejected so a writable parent
  cannot redirect root to attacker-controlled settings.
- As a non-root user with Docker access, the config must be owned by the user or
  root and must not be group/world-writable. Another local user who can modify
  the config could redirect the operator to attacker-controlled Compose files.
- When running as root, the resolved `docker` executable and its parent path
  must be root-controlled. Root runs also refuse a `PATH` or
  `DOCKER_CONFIG`/`HOME/.docker` path not controlled by root, because Docker
  can load credential helpers and CLI plugins from them. Remote
  `DOCKER_HOST`/`DOCKER_CONTEXT` settings are reported as warnings, not blocked.
- The audit path is similarly validated.
- Lock files use `O_NOFOLLOW`, mode `0600`, and an ownership check.
- The config file cannot specify an arbitrary executable. Docker is located
  through `PATH` but resolved to an absolute path, and root runs verify that the
  executable and its parent chain are root-controlled.

### 9. Secret handling

- Compose is invoked with `config --format json` for validation and metadata
  extraction. That JSON can contain environment values.
- The tool parses only selected fields and discards the rest. Raw resolved
  Compose JSON is never printed or audited.
- Command output is sanitized (ANSI/control characters removed), redacted for
  common `password=`, `token=`, URL-credential, and private-key patterns, and
  truncated before display or audit.
- Container labels and environment variables are not stored wholesale in the
  data model.
- Audit details are capped at 1200 characters.

This is defense in depth, not a guarantee that arbitrary command output cannot
contain a secret. Avoid printing full Compose configuration or container
environments in a shared terminal.

## Trust boundaries

1. **The Docker CLI and daemon.** Root runs verify the resolved `docker`
   binary path, but the daemon and its plugins are still trusted. A compromised
   Docker installation defeats every control here.
2. **The Compose files and build contexts.** Docker-privileged Compose actions
   require files controlled by root or the current user. The contents are still
   trusted to be operationally correct; the tool cannot make
   `privileged: true` safe.
3. **The image supply chain.** Pulling an image does not execute it, but
   `up -d` does. Pin digests, use trusted registries, scan images, and review
   upstream changes.
4. **The configuration file.** It is root-controlled when running as root. If a
   non-root user can change it, they can change scan roots and the unsafe
   ownership setting.
5. **The audit destination.** Local logs are not tamper-proof against root.
6. **The docker-mgmt installation.** Root must execute code from a root-owned
   directory. Running `sudo` on a user-writable checkout lets anyone who can
   edit that checkout execute code as root. The tool warns when it detects this,
   but the operator must install it safely.
6. **The operator.** The tool reduces accidental risk and provides an audit
   trail; it does not replace change management, backups, or monitoring.

## Recommended host hardening

- Run the tool as root via `sudo`, not as a shared unprivileged account.
- Keep `/etc/docker-mgmt/config.ini` root-owned and mode `0644`.
- Keep Compose projects, `.env` files, and build contexts root-owned. Deploy
  application files through a root-controlled process, not by letting a web
  user edit the Compose file.
- Do not add untrusted users to the `docker` group.
- Use a private registry and `docker login` with a credential helper; avoid
  storing registry passwords in shell history or Compose files.
- Pin images to versions or digests. Treat floating tags as a risk finding.
- Keep Docker Engine, the Compose plugin, and the host patched.
- Restrict published ports with a host firewall; bind internal services to
  `127.0.0.1` where possible.
- Back up databases and named volumes before applying updates.
- Monitor `check` results and audit logs. `check --json` exits `10` when updates
  are available.
- Keep the audit log on a filesystem with enough space and rotate/ship it.
- Do not set `DOCKER_HOST` unless you intend to manage a remote daemon; the
  local-socket assumption is part of the security model.

## Verification checklist

Before using mutating actions on a production server:

- [ ] `sudo ./docker-mgmt doctor` passes.
- [ ] `sudo ./docker-mgmt scan --json` finds the expected projects.
- [ ] `sudo ./docker-mgmt validate` reports no invalid configurations or
      unexplained high-risk findings.
- [ ] Config, Compose files, `.env` files, and build contexts are root-owned and
      not group/world-writable.
- [ ] Audit path is writable and private.
- [ ] Backups exist for databases and volumes.
- [ ] Images are pinned/reviewed and registry authentication works.
- [ ] The update is applied to one non-critical project first.
- [ ] A rollback plan (previous image tags/digests) exists.

## Reporting security issues

This repository does not define a private security contact. If it is published,
add a contact address or use your organization's private vulnerability reporting
process. Do not open a public issue containing exploit details or secrets.
