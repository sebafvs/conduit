from __future__ import annotations

import shlex
import subprocess
from pathlib import Path

from .. import log
from ..core.config import Config
from .ssh import KitError, run, torsocks_prefix, relay_ssh_base, ssh_to_redirector

# Local directory on the controller where pulled nebula certs land, so the
# renderer can point ansible `copy src:` tasks at them during redirector deploy.
_LOCAL_NEBULA_CERTS = Path("/opt/conduit/nebula-certs")


def _relay_ssh(cfg: Config) -> list[str]:
    """SSH command to reach the lighthouse relay (where the Nebula CA lives)."""
    return torsocks_prefix(cfg) + relay_ssh_base(cfg)


def _pull_cert_from_lighthouse(cfg: Config, remote_path: str, local_path: Path) -> None:
    """Copy a file from the lighthouse to a local path.

    Uses `sudo cat` over SSH so we can read root-owned files inside
    /opt/nebula/ca/ (dir perms are 700 root). One SSH round trip per file.
    """
    local_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = _relay_ssh(cfg) + ["--", "sudo", "cat", remote_path]
    result = subprocess.run(cmd, capture_output=True, check=True)
    local_path.write_bytes(result.stdout)


def ca_init(cfg: Config) -> None:
    """Initialize the Nebula CA on the lighthouse relay.

    Creates /opt/nebula/ca/ with ca.crt + ca.key. Idempotent: skips if
    CA already exists. Also installs the nebula binary if missing.
    """
    neb = cfg.management.nebula
    version = neb.version
    ca_name = neb.ca_name
    validity = f"{neb.ca_validity_hours}h"

    init_script = (
        f"set -e && "
        f"if ! command -v nebula-cert >/dev/null 2>&1; then "
        f"  cd /tmp && "
        f"  curl -sL -o nebula.tar.gz "
        f"  'https://github.com/slackhq/nebula/releases/download/v{version}/nebula-linux-amd64.tar.gz' && "
        f"  tar xzf nebula.tar.gz && "
        f"  sudo mv nebula /usr/local/bin/nebula && "
        f"  sudo mv nebula-cert /usr/local/bin/nebula-cert && "
        f"  sudo chmod +x /usr/local/bin/nebula /usr/local/bin/nebula-cert && "
        f"  rm -f nebula.tar.gz && "
        f"  echo '[+] nebula installed'; "
        f"fi && "
        f"sudo mkdir -p /opt/nebula/ca && "
        f"if [ -f /opt/nebula/ca/ca.crt ]; then "
        f"  echo '[+] CA already exists' && "
        f"  nebula-cert print -path /opt/nebula/ca/ca.crt; "
        f"else "
        f"  sudo nebula-cert ca -name {shlex.quote(ca_name)} -duration {validity} "
        f"    -out-crt /opt/nebula/ca/ca.crt -out-key /opt/nebula/ca/ca.key && "
        f"  sudo chmod 600 /opt/nebula/ca/ca.key && "
        f"  echo '[+] CA created' && "
        f"  sudo nebula-cert print -path /opt/nebula/ca/ca.crt; "
        f"fi"
    )

    log.info(f"initializing Nebula CA on lighthouse relay (name={ca_name}, validity={validity})")
    run(_relay_ssh(cfg) + ["--", "sudo", "bash", "-c", shlex.quote(init_script)])
    log.ok("nebula CA init complete")


def sign_cert(cfg: Config, name: str, ip: str, groups: str) -> None:
    """Sign a nebula host certificate on the lighthouse relay."""
    sign_script = (
        f"set -e && "
        f"if [ -f /opt/nebula/ca/{shlex.quote(name)}.crt ]; then "
        f"  echo '[+] cert already exists for {name}' && "
        f"  nebula-cert print -path /opt/nebula/ca/{shlex.quote(name)}.crt; "
        f"else "
        f"  sudo nebula-cert sign "
        f"    -name {shlex.quote(name)} "
        f"    -ip {shlex.quote(ip)} "
        f"    -groups {shlex.quote(groups)} "
        f"    -ca-crt /opt/nebula/ca/ca.crt -ca-key /opt/nebula/ca/ca.key "
        f"    -out-crt /opt/nebula/ca/{shlex.quote(name)}.crt "
        f"    -out-key /opt/nebula/ca/{shlex.quote(name)}.key && "
        f"  sudo chmod 600 /opt/nebula/ca/{shlex.quote(name)}.key && "
        f"  echo '[+] signed: {name}' && "
        f"  sudo nebula-cert print -path /opt/nebula/ca/{shlex.quote(name)}.crt; "
        f"fi"
    )

    log.info(f"signing nebula cert: {name} ({ip}, groups={groups})")
    run(_relay_ssh(cfg) + ["--", "sudo", "bash", "-c", shlex.quote(sign_script)])
    log.ok(f"nebula cert signed: {name}")

    # Pull signed cert + CA back to the controller so the renderer can inject
    # their paths into per-redirector ansible-vars.yml for the deploy copy task.
    log.info(f"pulling certs to {_LOCAL_NEBULA_CERTS}/")
    _pull_cert_from_lighthouse(cfg, "/opt/nebula/ca/ca.crt", _LOCAL_NEBULA_CERTS / "ca.crt")
    _pull_cert_from_lighthouse(cfg, f"/opt/nebula/ca/{name}.crt", _LOCAL_NEBULA_CERTS / f"{name}.crt")
    _pull_cert_from_lighthouse(cfg, f"/opt/nebula/ca/{name}.key", _LOCAL_NEBULA_CERTS / f"{name}.key")
    (_LOCAL_NEBULA_CERTS / f"{name}.key").chmod(0o600)
    log.ok(f"nebula certs cached locally for {name}")


def mesh_status(cfg: Config) -> None:
    """Ping each node's overlay IP from the lighthouse relay to check mesh health."""
    targets: list[tuple[str, str, str]] = []
    for rl in cfg.relays:
        if not rl.enabled:
            continue
        overlay = rl.nebula.overlay_ip.split("/")[0]
        targets.append((rl.name, overlay, "relay"))

    for r in cfg.redirectors:
        if not r.enabled or not r.nebula.enabled:
            continue
        overlay = r.nebula.overlay_ip.split("/")[0]
        targets.append((r.name, overlay, "redirector"))

    if not targets:
        log.warn("no nebula nodes configured")
        return

    ping_parts = ["set -e"]
    for name, ip, role in targets:
        ping_parts.append(
            f"printf '%-15s %-18s %-12s ' {shlex.quote(name)} {shlex.quote(ip)} {shlex.quote(role)} && "
            f"(ping -c 1 -W 3 {ip} >/dev/null 2>&1 && echo 'UP' || echo 'DOWN')"
        )

    log.info("nebula mesh status (pinging from lighthouse relay)")
    run(_relay_ssh(cfg) + ["--", "bash", "-c", shlex.quote(" && ".join(ping_parts))])


def list_certs(cfg: Config) -> None:
    """List all signed nebula certificates on the lighthouse relay."""
    list_script = (
        "for crt in /opt/nebula/ca/*.crt; do "
        "  [ \"$(basename $crt)\" = 'ca.crt' ] && continue; "
        "  echo \"--- $(basename $crt .crt) ---\"; "
        "  nebula-cert print -path $crt 2>/dev/null | grep -E '(Name|Ips|Groups|Not After)'; "
        "  echo; "
        "done"
    )

    log.info("nebula certificates on lighthouse relay")
    run(_relay_ssh(cfg) + ["--", "bash", "-c", shlex.quote(list_script)])


def rotate_certs(cfg: Config, *, only: str | None = None) -> None:
    """Re-sign nebula certs for all nodes from the existing CA, push, and restart.

    For each enabled relay/redirector:
      1. Back up the old cert on the lighthouse CA dir
      2. Re-sign with the same name/ip/groups
      3. SCP the new cert+key to the node
      4. Restart nebula on the node

    The CA itself is not rotated (that would require re-trusting on every node).
    """
    lh_ssh = _relay_ssh(cfg)

    nodes: list[dict] = []
    for rl in cfg.relays:
        if not rl.enabled:
            continue
        if rl.nebula.is_lighthouse:
            nodes.append({
                "name": rl.name,
                "ip": rl.nebula.overlay_ip,
                "groups": ",".join(rl.nebula.groups),
                "role": "relay",
                "ssh_target": None,
            })
        else:
            nodes.append({
                "name": rl.name,
                "ip": rl.nebula.overlay_ip,
                "groups": ",".join(rl.nebula.groups),
                "role": "relay",
                "ssh_target": f"{rl.deploy.ssh_user}@{rl.deploy.address}",
            })

    for r in cfg.redirectors:
        if not r.enabled or not r.nebula.enabled:
            continue
        overlay = r.nebula.overlay_ip.split("/")[0]
        nodes.append({
            "name": r.name,
            "ip": r.nebula.overlay_ip,
            "groups": ",".join(r.nebula.groups),
            "role": "redirector",
            "overlay_ip": overlay,
        })

    if not nodes:
        log.warn("no nebula nodes to rotate")
        return

    for node in nodes:
        if only and node["name"] != only:
            log.detail(f"skip '{node['name']}' (--only {only})")
            continue

        name = node["name"]
        ip = node["ip"]
        groups = node["groups"]
        log.info(f"rotating cert: {name} (ip={ip}, groups={groups})")

        rotate_script = (
            f"set -e && "
            f"cd /opt/nebula/ca && "
            f"if [ -f {shlex.quote(name)}.crt ]; then "
            f"  sudo mv {shlex.quote(name)}.crt {shlex.quote(name)}.crt.bak && "
            f"  sudo mv {shlex.quote(name)}.key {shlex.quote(name)}.key.bak; "
            f"fi && "
            f"sudo nebula-cert sign "
            f"  -name {shlex.quote(name)} "
            f"  -ip {shlex.quote(ip)} "
            f"  -groups {shlex.quote(groups)} "
            f"  -ca-crt ca.crt -ca-key ca.key && "
            f"sudo chmod 600 {shlex.quote(name)}.key && "
            f"echo 'signed' && "
            f"nebula-cert print -path {shlex.quote(name)}.crt | grep 'Not After'"
        )

        result = subprocess.run(
            lh_ssh + ["--", "bash", "-c", shlex.quote(rotate_script)],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            log.warn(f"failed to re-sign cert for {name}: {result.stderr.strip()}")
            continue

        for line in result.stdout.strip().splitlines():
            if line.strip():
                log.always(line.strip())

        if node["role"] == "relay" and node.get("ssh_target") is None:
            # lighthouse itself: cert is already local, just copy and restart
            push_script = (
                f"set -e && "
                f"sudo cp /opt/nebula/ca/{shlex.quote(name)}.crt /etc/nebula/host.crt && "
                f"sudo cp /opt/nebula/ca/{shlex.quote(name)}.key /etc/nebula/host.key && "
                f"sudo chmod 600 /etc/nebula/host.key && "
                f"sudo systemctl restart nebula && "
                f"echo 'restarted'"
            )
            run(lh_ssh + ["--", "bash", "-c", shlex.quote(push_script)])
            log.ok(f"{name}: cert rotated + nebula restarted (lighthouse, local)")
        elif node["role"] == "redirector":
            overlay = node["overlay_ip"]
            push_script = (
                f"set -e && "
                f"scp -o StrictHostKeyChecking=accept-new -o BatchMode=yes "
                f"  /opt/nebula/ca/{shlex.quote(name)}.crt "
                f"  /opt/nebula/ca/{shlex.quote(name)}.key "
                f"  ubuntu@{overlay}:/tmp/ && "
                f"ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes ubuntu@{overlay} "
                f"  'sudo mv /tmp/{shlex.quote(name)}.crt /etc/nebula/host.crt && "
                f"   sudo mv /tmp/{shlex.quote(name)}.key /etc/nebula/host.key && "
                f"   sudo chmod 600 /etc/nebula/host.key && "
                f"   sudo systemctl restart nebula' && "
                f"echo 'restarted'"
            )
            run(lh_ssh + ["--", "bash", "-c", shlex.quote(push_script)])
            log.ok(f"{name}: cert rotated + nebula restarted (via relay hop)")
        else:
            # non-lighthouse relay: push via direct SSH from lighthouse
            target = node["ssh_target"]
            push_script = (
                f"set -e && "
                f"scp -o StrictHostKeyChecking=accept-new -o BatchMode=yes "
                f"  /opt/nebula/ca/{shlex.quote(name)}.crt "
                f"  /opt/nebula/ca/{shlex.quote(name)}.key "
                f"  {target}:/tmp/ && "
                f"ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes {target} "
                f"  'sudo mv /tmp/{shlex.quote(name)}.crt /etc/nebula/host.crt && "
                f"   sudo mv /tmp/{shlex.quote(name)}.key /etc/nebula/host.key && "
                f"   sudo chmod 600 /etc/nebula/host.key && "
                f"   sudo systemctl restart nebula' && "
                f"echo 'restarted'"
            )
            run(lh_ssh + ["--", "bash", "-c", shlex.quote(push_script)])
            log.ok(f"{name}: cert rotated + nebula restarted (via direct SSH)")

    log.ok("nebula cert rotation complete")
