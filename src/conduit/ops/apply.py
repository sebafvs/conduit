from __future__ import annotations

import shlex
import subprocess
from pathlib import Path

from .. import log
from ..core.config import Config, InstallTarget, RedirectorType
from .ssh import KitError, run, torsocks_prefix

# Package data lives at src/conduit/resources/ansible/, apply.py lives at
# src/conduit/ops/apply.py. Walk up one level to find resources/.
_CONDUIT_ROOT = Path(__file__).resolve().parent.parent
_ANSIBLE_DIR = _CONDUIT_ROOT / "resources" / "ansible"

# SSH options passed to every ansible run as ansible_ssh_common_args.
# - ControlMaster + ControlPersist reuse one SSH connection across all tasks,
#   which matters hugely over torsocks because each new Tor circuit costs seconds.
# - ServerAliveInterval + ServerAliveCountMax send a keepalive every 30s and
#   consider the link dead after 5 silent intervals, so idle TCP connections do
#   not get killed by Tor exit nodes mid-run.
# - StrictHostKeyChecking + BatchMode match the rest of Conduit's SSH posture.
_SSH_ARGS = (
    "-o ControlMaster=auto -o ControlPersist=600s "
    "-o ServerAliveInterval=30 -o ServerAliveCountMax=5 "
    "-o StrictHostKeyChecking=accept-new -o BatchMode=yes"
)


def _ssh_cmd(cfg: Config) -> list[str]:
    if cfg.install.target != InstallTarget.remote:
        raise KitError("_ssh_cmd requires install.target=remote")
    th = cfg.install.target_host
    assert th is not None
    cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-i", str(th.ssh_key),
           "-p", str(th.ssh_port)]
    cmd.append(f"{th.ssh_user}@{th.address}")
    return cmd


def _rsync_to_target(cfg: Config, staging_dir: Path, dest: str) -> None:
    th = cfg.install.target_host
    assert th is not None
    cmd = ["rsync", "-a", "--delete",
           "-e", f"ssh -i {shlex.quote(str(th.ssh_key))} -o StrictHostKeyChecking=accept-new -p {th.ssh_port}",
           f"{str(staging_dir).rstrip('/')}/",
           f"{th.ssh_user}@{th.address}:{dest.rstrip('/')}/"]
    run(cmd)


def _is_local(addr: str) -> bool:
    """Loopback deploy targets (ts-onion lives at 127.0.0.1) must bypass torsocks.
    torsocks refuses local-address connections as a DNS-leak guard, which otherwise
    breaks the ansible SSH to the deploy target."""
    return addr in ("127.0.0.1", "localhost", "::1")


def _have(tool: str) -> bool:
    return subprocess.run(["which", tool], capture_output=True).returncode == 0


def _docker_ok() -> bool:
    if not _have("docker"):
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


def preflight(cfg: Config, need_docker: bool = True) -> list[str]:
    """Return a list of problems. Empty list = ready to apply."""
    problems: list[str] = []

    for tool in ("git", "rsync", "ansible-playbook"):
        if not _have(tool):
            problems.append(f"workstation: '{tool}' not on PATH")

    if cfg.install.target == InstallTarget.remote and need_docker:
        th = cfg.install.target_host
        if th is None:
            problems.append("install.target=remote but target_host is unset")
            return problems
        if not Path(str(th.ssh_key)).expanduser().exists():
            problems.append(f"ssh_key does not exist: {th.ssh_key}")
            return problems
        try:
            probe = subprocess.run(
                _ssh_cmd(cfg) + ["--", "true"],
                capture_output=True, text=True, timeout=15,
            )
            if probe.returncode != 0:
                problems.append(
                    f"ssh probe failed to {th.ssh_user}@{th.address}: {probe.stderr.strip()}"
                )
        except subprocess.TimeoutExpired:
            problems.append(f"ssh probe timed out to {th.ssh_user}@{th.address}")
    else:
        if need_docker and not _docker_ok():
            problems.append("workstation: docker daemon not reachable (local target)")

    return problems


def transfer(cfg: Config, staging_dir: Path) -> None:
    """Push staging dir to the install root on the target."""
    if cfg.install.target == InstallTarget.local:
        root = Path(cfg.install.root).expanduser()
        root.mkdir(parents=True, exist_ok=True)
        run(["rsync", "-a", f"{str(staging_dir).rstrip('/')}/", f"{str(root).rstrip('/')}/"])
    else:
        _rsync_to_target(cfg, staging_dir, str(cfg.install.root))


def clone_sources(cfg: Config) -> None:
    """Clone the AdaptixC2 fork (+ Extension-Kit) into install.root on target."""
    root = str(cfg.install.root)
    tor = "torsocks " if cfg.management.torsocks_management else ""

    def _git_cmd(repo_dir: str, url: str, ref: str) -> list[str]:
        # Clone with --recurse-submodules on first run. On re-runs, fetch,
        # checkout, and then sync submodules too so a changed submodule ref in
        # the parent repo gets pulled (otherwise the submodule drifts).
        return [
            "bash", "-lc",
            f"test -d {shlex.quote(repo_dir)}/.git "
            f"&& {tor}git -C {shlex.quote(repo_dir)} fetch --all --tags "
            f"&& git -C {shlex.quote(repo_dir)} checkout {shlex.quote(ref)} "
            f"&& {tor}git -C {shlex.quote(repo_dir)} submodule update --init --recursive "
            f"|| {tor}git clone --recurse-submodules {shlex.quote(url)} {shlex.quote(repo_dir)}"
        ]

    src = cfg.install.adaptix_source
    adaptix_dir = f"{root}/AdaptixC2"
    cmd = _git_cmd(adaptix_dir, src.url, src.ref)
    _dispatch(cfg, cmd)

    if cfg.install.extension_kit_source:
        ek = cfg.install.extension_kit_source
        ek_dir = f"{root}/Extension Kit"
        cmd = _git_cmd(ek_dir, ek.url, ek.ref)
        _dispatch(cfg, cmd)


def compose_build(cfg: Config) -> None:
    """Run `docker compose --profile build up --build` for every enabled builder.

    `--build` on `up` tells compose to check whether the image needs rebuilding
    before running the container. Docker's layer cache then decides what to
    actually re-run inside the build: if the COPY layer sees a changed source
    tree, it invalidates from that layer forward. If nothing changed, nothing
    rebuilds. This picks up source-tree changes (new submodules, new extenders)
    without the 25-minute cost of a cold rebuild every apply.

    `install.rebuild: true` escapes the layer cache entirely via `--no-cache`
    on the build calls. Use when docker's cache is lying about freshness.
    """
    root = str(cfg.install.root)
    no_cache = " --no-cache" if cfg.install.rebuild else ""
    if cfg.features.build.server:
        # 1. compile the server + default extenders into ./AdaptixC2/AdaptixServer/server-dist
        _dispatch(cfg, ["bash", "-lc",
                        f"cd {shlex.quote(root)} && docker compose --profile build build{no_cache} server-ext-builder && "
                        f"docker compose --profile build up --exit-code-from server-ext-builder server-ext-builder"])
        # 2. build the runtime image, which tags adaptix/server:local. Needed by
        #    adaptix-server (compose up) and by extensions-builder (BOFs).
        _dispatch(cfg, ["bash", "-lc",
                        f"cd {shlex.quote(root)} && docker compose build{no_cache} adaptix-server"])
    if cfg.features.build.bofs:
        _dispatch(cfg, ["bash", "-lc",
                        f"cd {shlex.quote(root)} && docker compose --profile build build{no_cache} extensions-builder && "
                        f"docker compose --profile build up --exit-code-from extensions-builder extensions-builder"])
    if cfg.features.build.client:
        _dispatch(cfg, ["bash", "-lc",
                        f"cd {shlex.quote(root)} && docker compose --profile build build{no_cache} client-builder && "
                        f"docker compose --profile build up --exit-code-from client-builder client-builder"])


def compose_up(cfg: Config) -> None:
    """Start the runtime services (adaptix-server + adaptix-payload)."""
    root = str(cfg.install.root)
    services = "adaptix-server"
    if cfg.payload and cfg.payload.enabled:
        services = "adaptix-server adaptix-payload"
    _dispatch(cfg, ["bash", "-lc", f"cd {shlex.quote(root)} && docker compose up -d {services}"])


def _dispatch(cfg: Config, cmd: list[str]) -> None:
    if cfg.install.target == InstallTarget.remote:
        run(_ssh_cmd(cfg) + ["--"] + cmd)
    else:
        run(cmd)


def deploy_relays(
    cfg: Config,
    staging_dir: Path,
    *,
    only: str | None = None,
    no_torsocks: bool = False,
    playbook_tags: str | None = None,
    playbook_skip_tags: str | None = None,
) -> None:
    """For each enabled relay, run the relay_node ansible playbook."""
    for rl in cfg.relays:
        if only and rl.name != only:
            log.detail(f"skip relay '{rl.name}' (--only {only})")
            continue
        if not rl.enabled:
            log.detail(f"skip relay '{rl.name}' (disabled)")
            continue
        _deploy_relay(
            cfg, rl, staging_dir,
            no_torsocks=no_torsocks,
            playbook_tags=playbook_tags,
            playbook_skip_tags=playbook_skip_tags,
        )


def _resolve_relay_playbook() -> Path:
    """Find the relay playbook inside conduit/ansible/."""
    playbook = _ANSIBLE_DIR / "relay.yml"
    if not playbook.exists():
        raise KitError(f"relay playbook not found at {playbook}")
    return playbook


def _deploy_relay(
    cfg, rl, staging_dir: Path,
    *,
    no_torsocks: bool = False,
    playbook_tags: str | None = None,
    playbook_skip_tags: str | None = None,
) -> None:
    rldir = staging_dir / "relays" / rl.name
    vars_file = rldir / "ansible-vars.yml"
    if not vars_file.exists():
        raise KitError(f"missing {vars_file} (render first)")

    inv_file = rldir / "inventory.ini"
    inv_file.write_text(_inventory_line("relay", rl.deploy))

    playbook = _resolve_relay_playbook()
    log.info(f"deploying relay '{rl.name}' ({rl.deploy.address})")
    tor = [] if (no_torsocks or _is_local(rl.deploy.address)) else torsocks_prefix(cfg)
    run(tor + _ansible_playbook_cmd(inv_file, vars_file, playbook, playbook_tags, playbook_skip_tags))
    log.ok(f"relay '{rl.name}' deployed")


def _inventory_line(group: str, deploy) -> str:
    """Build an ansible inventory block for one deploy target.

    For loopback targets, use `ansible_connection=local` so no SSH setup is
    required and no SSH keys are consulted. For remote targets, write the full
    SSH tuple (user, port, key, common args) that ansible-playbook needs.
    """
    if _is_local(deploy.address):
        return (
            f"[{group}]\n"
            f"{deploy.address} ansible_connection=local\n"
        )
    return (
        f"[{group}]\n"
        f"{deploy.address} ansible_user={deploy.ssh_user} "
        f"ansible_port={deploy.ssh_port} "
        f"ansible_ssh_private_key_file={deploy.ssh_key or '~/.ssh/id_ed25519'} "
        f"ansible_ssh_common_args='{_SSH_ARGS}'\n"
    )


def _ansible_playbook_cmd(
    inv_file: Path,
    vars_file: Path,
    playbook: Path,
    playbook_tags: str | None,
    playbook_skip_tags: str | None,
) -> list[str]:
    """Build the ansible-playbook argv, injecting --tags / --skip-tags when set."""
    cmd = [
        "ansible-playbook",
        "-i", str(inv_file),
        "-e", f"@{vars_file}",
    ]
    if playbook_tags:
        cmd += ["--tags", playbook_tags]
    if playbook_skip_tags:
        cmd += ["--skip-tags", playbook_skip_tags]
    cmd.append(str(playbook))
    return cmd


def deploy_redirectors(
    cfg: Config,
    staging_dir: Path,
    *,
    only: str | None = None,
    no_torsocks: bool = False,
    playbook_tags: str | None = None,
    playbook_skip_tags: str | None = None,
) -> None:
    """For each enabled redirector, run the appropriate ansible playbook."""
    for r in cfg.redirectors:
        if only and r.name != only:
            log.detail(f"skip redirector '{r.name}' (--only {only})")
            continue
        if not r.enabled:
            log.detail(f"skip redirector '{r.name}' (disabled)")
            continue

        if r.type == RedirectorType.openresty_vps:
            _deploy_openresty_vps(
                cfg, r, staging_dir,
                no_torsocks=no_torsocks,
                playbook_tags=playbook_tags,
                playbook_skip_tags=playbook_skip_tags,
            )
        elif r.type == RedirectorType.tor_hidden_service:
            _deploy_tor_hidden_service(
                cfg, r, staging_dir,
                no_torsocks=no_torsocks,
                playbook_tags=playbook_tags,
                playbook_skip_tags=playbook_skip_tags,
            )
        else:
            log.warn(
                f"skip redirector '{r.name}' (type={r.type.value}): "
                f"apply not implemented yet, needs a per-type ansible role"
            )


def _deploy_openresty_vps(
    cfg, r, staging_dir: Path,
    *,
    no_torsocks: bool = False,
    playbook_tags: str | None = None,
    playbook_skip_tags: str | None = None,
) -> None:
    rdir = staging_dir / "redirectors" / r.name
    vars_file = rdir / "ansible-vars.yml"
    if not vars_file.exists():
        raise KitError(f"missing {vars_file} (render first)")

    inv_file = rdir / "inventory.ini"
    inv_file.write_text(_inventory_line("redirector", r.deploy))

    playbook = _ANSIBLE_DIR / "redirector.yml"
    if not playbook.exists():
        raise KitError(f"redirector playbook not found: {playbook}")

    log.info(f"deploying redirector '{r.name}' ({r.deploy.address})")
    tor = [] if (no_torsocks or _is_local(r.deploy.address)) else torsocks_prefix(cfg)
    run(tor + _ansible_playbook_cmd(inv_file, vars_file, playbook, playbook_tags, playbook_skip_tags))
    log.ok(f"redirector '{r.name}' deployed")


def _deploy_tor_hidden_service(
    cfg, r, staging_dir: Path,
    *,
    no_torsocks: bool = False,
    playbook_tags: str | None = None,
    playbook_skip_tags: str | None = None,
) -> None:
    rdir = staging_dir / "redirectors" / r.name
    vars_file = rdir / "ansible-vars.yml"
    if not vars_file.exists():
        raise KitError(f"missing {vars_file} (render first)")

    inv_file = rdir / "inventory.ini"
    inv_file.write_text(_inventory_line("tor_hidden_service", r.deploy))

    playbook = _ANSIBLE_DIR / "tor_hidden_service.yml"
    if not playbook.exists():
        raise KitError(f"tor_hidden_service playbook not found: {playbook}")

    log.info(f"deploying tor hidden service '{r.name}' ({r.deploy.address})")
    tor = [] if (no_torsocks or _is_local(r.deploy.address)) else torsocks_prefix(cfg)
    run(tor + _ansible_playbook_cmd(inv_file, vars_file, playbook, playbook_tags, playbook_skip_tags))
    log.ok(f"tor hidden service '{r.name}' deployed")
