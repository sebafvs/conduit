from __future__ import annotations

import shlex
import subprocess

from .. import log
from ..core.config import Config, Relay


class KitError(RuntimeError):
    """Single exception type for all conduit operational errors."""


def run(cmd: list[str], check: bool = True, **kw) -> subprocess.CompletedProcess:
    """Run a local command. Logs the command line in verbose mode."""
    log.cmd(cmd)
    return subprocess.run(cmd, check=check, **kw)


def torsocks_prefix(cfg: Config) -> list[str]:
    """Return ['torsocks'] when torsocks_management is enabled, else []."""
    if cfg.management.torsocks_management:
        return ["torsocks"]
    return []


def find_lighthouse(cfg: Config) -> Relay:
    """Return the first enabled lighthouse relay, or raise."""
    for rl in cfg.relays:
        if rl.enabled and rl.nebula.is_lighthouse:
            return rl
    raise KitError("no enabled lighthouse relay in config")


def relay_ssh_base(cfg: Config) -> list[str]:
    """SSH command prefix to reach the lighthouse relay."""
    rl = find_lighthouse(cfg)
    return _ssh_for_relay(rl)


def ssh_for_relay(cfg: Config, rl: Relay) -> list[str]:
    """SSH command prefix to reach a specific relay (with torsocks)."""
    return torsocks_prefix(cfg) + _ssh_for_relay(rl)


def _ssh_for_relay(rl: Relay) -> list[str]:
    """Raw SSH command for a relay (no torsocks)."""
    cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes"]
    if rl.deploy.ssh_key:
        cmd += ["-i", str(rl.deploy.ssh_key)]
    cmd += ["-p", str(rl.deploy.ssh_port)]
    cmd.append(f"{rl.deploy.ssh_user}@{rl.deploy.address}")
    return cmd


def ssh_to_redirector(cfg: Config, overlay_ip: str) -> list[str]:
    """Full SSH command to reach a redirector via relay hop (with torsocks).

    No leading '--' before the inner ssh: when the outer ssh joins argv-after-
    host with spaces to send as the remote command, the relay's shell would
    try to execute '--' as its first command (exit 127) and never actually
    run the inner ssh. The '--' that remote_exec appends after the inner
    'ubuntu@<overlay_ip>' host is the correct separator.
    """
    return torsocks_prefix(cfg) + relay_ssh_base(cfg) + [
        "ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes",
        f"ubuntu@{overlay_ip}",
    ]


def ssh_direct_to_redirector(r) -> list[str]:
    """Direct SSH to a redirector's public deploy address, no relay/nebula hop, no torsocks.

    Used when nebula isn't up yet (post-apply scrub for a fresh deploy) or when
    nebula is intentionally not deployed. Matches the SSH route conduit uses
    during an openresty-vps apply.
    """
    cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes"]
    if r.deploy.ssh_key:
        cmd += ["-i", str(r.deploy.ssh_key)]
    cmd += ["-p", str(r.deploy.ssh_port)]
    cmd.append(f"{r.deploy.ssh_user}@{r.deploy.address}")
    return cmd


def redirector_overlay_ip(cfg: Config, name: str) -> str:
    """Get the bare overlay IP (no CIDR mask) for a named redirector."""
    for r in cfg.redirectors:
        if r.name == name and r.nebula.enabled:
            return r.nebula.overlay_ip.split("/")[0]
    raise KitError(f"redirector '{name}' not found or nebula not enabled")


def remote_exec(ssh_cmd: list[str], script: str, check: bool = False, **kw) -> subprocess.CompletedProcess:
    """Run a bash script on a remote host via SSH, delivering the script via stdin.

    We pass the script as stdin to `sudo bash -s` instead of embedding it in
    argv as `-c '<script>'`. Argv-based scripting does not survive nested SSH:
    each ssh hop joins its args-after-destination with single spaces to form
    one remote command string, and the enclosing single quotes get stripped
    by the intermediate shell. For single-hop paths (teamserver -> relay)
    that one join is survivable; for via-relay paths (teamserver -> relay ->
    redirector) the second join exposes the raw newlines as command
    separators and `sudo bash -c` arrives with no argument. Stdin is forwarded
    untouched through any number of SSH hops.
    """
    full = ssh_cmd + ["--", "sudo", "bash", "-s"]
    kw.setdefault("text", True)
    kw["input"] = script
    return run(full, check=check, **kw)
