from __future__ import annotations

import shlex

from .. import log
from ..core.config import Config
from .ssh import KitError, run, torsocks_prefix


def _relay_for_hop(cfg: Config) -> tuple[str, str, str | None, int]:
    """Return (user, address, key_path, port) of the first enabled lighthouse."""
    for rl in cfg.relays:
        if rl.enabled and rl.nebula.is_lighthouse:
            return (
                rl.deploy.ssh_user,
                rl.deploy.address,
                str(rl.deploy.ssh_key) if rl.deploy.ssh_key else None,
                rl.deploy.ssh_port,
            )
    raise KitError("no enabled lighthouse relay found; cannot route via relay")


def push_payloads(cfg: Config, *, only: str | None = None) -> None:
    """Push payloads from the local staging_dir to each redirector's payload_dir."""
    pd = cfg.management.payload_distribution
    if not pd.enabled:
        log.warn("payload_distribution.enabled is false, skipping")
        return

    staging = str(pd.staging_dir)
    result = run(["ls", staging], check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise KitError(f"staging directory does not exist: {staging}")

    targets = []
    for r in cfg.redirectors:
        if not r.enabled:
            continue
        if only and r.name != only:
            continue
        if r.payload_dir is None:
            log.detail(f"skip '{r.name}': no payload_dir configured")
            continue
        targets.append(r)

    if not targets:
        log.info("no eligible redirectors for payload push")
        return

    log.info(f"staging dir: {staging}")
    log.info(f"targets: {len(targets)} redirector(s)")

    if pd.via_relay:
        _push_via_relay(cfg, staging, targets)
    else:
        _push_direct(cfg, staging, targets)


def _push_via_relay(cfg: Config, staging: str, targets: list) -> None:
    """Two-hop push: rsync to relay tmp, then relay rsync to each redirector."""
    user, address, key_path, port = _relay_for_hop(cfg)
    relay_tmp = "/tmp/c2-payloads"

    relay_ssh_flag = f"ssh -o StrictHostKeyChecking=accept-new"
    if key_path:
        relay_ssh_flag += f" -i {shlex.quote(key_path)}"
    relay_ssh_flag += f" -p {port}"

    log.info(f"step 1: rsync staging to relay ({address}:{relay_tmp})")
    run(torsocks_prefix(cfg) + [
        "rsync", "-avz", "--delete",
        "-e", relay_ssh_flag,
        f"{staging.rstrip('/')}/",
        f"{user}@{address}:{relay_tmp}/",
    ])

    for r in targets:
        overlay_ip = r.nebula.overlay_ip.split("/")[0]
        dest = str(r.payload_dir)
        log.info(f"step 2: relay rsync to '{r.name}' ({overlay_ip}:{dest})")

        relay_to_redir_cmd = (
            f"rsync -avz --delete "
            f"-e 'ssh -o StrictHostKeyChecking=accept-new' "
            f"{shlex.quote(relay_tmp)}/ "
            f"ubuntu@{overlay_ip}:{shlex.quote(dest)}/"
        )

        hop_cmd = torsocks_prefix(cfg) + [
            "ssh", "-o", "StrictHostKeyChecking=accept-new",
        ]
        if key_path:
            hop_cmd += ["-i", key_path]
        hop_cmd += ["-p", str(port)]
        hop_cmd.append(f"{user}@{address}")
        hop_cmd += ["--", "bash", "-c", shlex.quote(relay_to_redir_cmd)]
        run(hop_cmd)
        log.ok(f"payloads pushed to '{r.name}'")


def _push_direct(cfg: Config, staging: str, targets: list) -> None:
    """Single-hop push: torsocks rsync directly to each redirector's public IP."""
    for r in targets:
        dest = str(r.payload_dir)
        ssh_flag = "ssh -o StrictHostKeyChecking=accept-new"
        if r.deploy.ssh_key:
            ssh_flag += f" -i {shlex.quote(str(r.deploy.ssh_key))}"
        ssh_flag += f" -p {r.deploy.ssh_port}"

        log.info(f"rsync to '{r.name}' ({r.deploy.address}:{dest})")
        run(torsocks_prefix(cfg) + [
            "rsync", "-avz", "--delete",
            "-e", ssh_flag,
            f"{staging.rstrip('/')}/",
            f"{r.deploy.ssh_user}@{r.deploy.address}:{dest}/",
        ])
        log.ok(f"payloads pushed to '{r.name}'")


def list_payloads(cfg: Config, *, only: str | None = None) -> None:
    """List payload files on each redirector (via relay hop)."""
    pd = cfg.management.payload_distribution
    if not pd.enabled:
        log.warn("payload_distribution not enabled")
        return

    user, address, key_path, port = _relay_for_hop(cfg)

    for r in cfg.redirectors:
        if not r.enabled or not r.nebula.enabled:
            continue
        if only and r.name != only:
            continue
        if r.payload_dir is None:
            continue

        overlay_ip = r.nebula.overlay_ip.split("/")[0]
        dest = str(r.payload_dir)
        log.info(f"'{r.name}' ({overlay_ip}:{dest}):")

        hop_cmd = torsocks_prefix(cfg) + [
            "ssh", "-o", "StrictHostKeyChecking=accept-new",
        ]
        if key_path:
            hop_cmd += ["-i", key_path]
        hop_cmd += ["-p", str(port)]
        hop_cmd.append(f"{user}@{address}")
        hop_cmd += [
            "--", "ssh", "-o", "StrictHostKeyChecking=accept-new",
            f"ubuntu@{overlay_ip}",
            "--", "ls", "-lah", dest,
        ]
        result = run(hop_cmd, check=False, capture_output=True, text=True)
        if result.returncode == 0:
            for line in result.stdout.strip().splitlines():
                log.always(line)
        else:
            log.warn(f"failed: {result.stderr.strip()}")
