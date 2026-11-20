from __future__ import annotations

import shlex
import subprocess
from datetime import datetime, timezone

from .. import log
from ..core.config import Config, InstallTarget, RedirectorType
from .ssh import (
    KitError,
    find_lighthouse,
    relay_ssh_base,
    run,
    ssh_to_redirector,
    torsocks_prefix,
)


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _probe(cmd: list[str], timeout: int = 15, stdin: str | None = None) -> tuple[bool, str]:
    """Run cmd, return (ok, stdout_or_stderr).

    When stdin is given it is piped into cmd. For nested SSH chains
    (teamserver -> relay -> redirector), callers MUST deliver scripts via
    stdin to `bash -s` because `bash -c <quoted>` drops its quoting on the
    inner hop and the script falls apart (CONDUIT-001).
    """
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, input=stdin,
        )
        if r.returncode == 0:
            return True, r.stdout.strip()
        return False, r.stderr.strip() or r.stdout.strip()
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except FileNotFoundError as e:
        return False, f"binary not found: {e.filename}"
    except Exception as e:
        return False, str(e)


def _check_service(ssh_cmd: list[str], svc: str) -> str:
    """Check a systemd service on a remote host. Returns 'active', 'inactive', 'missing', or 'error'."""
    ok, out = _probe(ssh_cmd + ["--", "systemctl", "is-active", svc])
    if ok:
        return out.strip()
    if "inactive" in out or "could not be found" in out:
        return out.strip().split("\n")[0]
    return "error"


def _check_services(ssh_cmd: list[str], services: list[str]) -> dict[str, str]:
    script = " && ".join(
        f"printf '{svc}=' && systemctl is-active {svc} 2>/dev/null || echo 'missing'"
        for svc in services
    )
    ok, out = _probe(ssh_cmd + ["--", "bash", "-s"], timeout=20, stdin=script)
    result = {}
    if ok or out:
        for line in out.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                result[k.strip()] = v.strip()
    for svc in services:
        if svc not in result:
            result[svc] = "unknown"
    return result


def _cert_expiry_nebula(ssh_cmd: list[str], cert_name: str) -> str:
    """Get 'Not After' from a nebula cert. Returns the date string or 'unknown'."""
    ok, out = _probe(
        ssh_cmd + ["--", "nebula-cert", "print", "-path", f"/opt/nebula/ca/{cert_name}.crt"],
        timeout=10,
    )
    if not ok:
        return "unknown"
    for line in out.splitlines():
        if "Not After" in line:
            return line.split("Not After:", 1)[1].strip() if ":" in line else line.strip()
    return "unknown"


def _cert_expiry_le(ssh_cmd: list[str], domain: str) -> str:
    """Get LE cert expiry from certbot on a redirector."""
    script = f"certbot certificates -d {shlex.quote(domain)} 2>/dev/null | grep 'Expiry Date' || echo 'unknown'"
    ok, out = _probe(ssh_cmd + ["--", "sudo", "bash", "-s"], timeout=15, stdin=script)
    if ok and "Expiry Date" in out:
        return out.split("Expiry Date:", 1)[1].strip().split("(")[0].strip()
    return "unknown"


def _ssh_reachable(ssh_cmd: list[str]) -> bool:
    ok, _ = _probe(ssh_cmd + ["--", "true"], timeout=10)
    return ok


def full_status(cfg: Config) -> None:
    """Print a unified status table for all nodes."""
    log.info(f"C2 stack status at {_now_utc()}")
    print()

    lh = find_lighthouse(cfg)
    lh_ssh = torsocks_prefix(cfg) + relay_ssh_base(cfg)

    # relay status
    print("=== RELAYS ===")
    for rl in cfg.relays:
        if not rl.enabled:
            continue
        rl_ssh = torsocks_prefix(cfg) + relay_ssh_base(cfg)
        reachable = _ssh_reachable(rl_ssh)
        print(f"  {rl.name:<16} {rl.deploy.address:<20} SSH={'OK' if reachable else 'FAIL'}")
        if reachable:
            svcs = _check_services(rl_ssh, ["nebula", "fail2ban", "tor"])
            for svc, state in svcs.items():
                marker = "+" if state == "active" else "!"
                print(f"    [{marker}] {svc}: {state}")
            ca_expiry = _cert_expiry_nebula(rl_ssh, "ca")
            print(f"    [*] nebula CA expiry: {ca_expiry}")
    print()

    # redirector status
    print("=== REDIRECTORS ===")
    for r in cfg.redirectors:
        if not r.enabled:
            continue
        if not r.nebula.enabled:
            print(f"  {r.name:<16} {r.deploy.address:<20} (no nebula, skip)")
            continue

        overlay_ip = r.nebula.overlay_ip.split("/")[0]
        rd_ssh = ssh_to_redirector(cfg, overlay_ip)
        reachable = _ssh_reachable(rd_ssh)
        print(f"  {r.name:<16} {r.deploy.address:<20} overlay={overlay_ip}  SSH={'OK' if reachable else 'FAIL'}")

        if not reachable:
            continue

        services = ["openresty", "nebula", "fail2ban"]
        typed = r.typed_config() if r.type == RedirectorType.openresty_vps else None
        if typed and hasattr(typed, "tor_client") and typed.tor_client.enabled:
            services.extend(["tor", "gost"])

        svcs = _check_services(rd_ssh, services)
        for svc, state in svcs.items():
            marker = "+" if state == "active" else "!"
            print(f"    [{marker}] {svc}: {state}")

        node_cert_name = r.name.replace("-", "_")
        neb_expiry = _cert_expiry_nebula(lh_ssh, node_cert_name)
        if neb_expiry == "unknown":
            neb_expiry = _cert_expiry_nebula(lh_ssh, r.name)
        print(f"    [*] nebula cert expiry: {neb_expiry}")

        if r.type == RedirectorType.openresty_vps:
            le_domain = ""
            if typed and hasattr(typed, "openresty"):
                pass
            for attr_name in ("cert_letsencrypt_domain", "cert_cn"):
                if hasattr(r, attr_name):
                    le_domain = getattr(r, attr_name)
                    break
            if not le_domain:
                ok, out = _probe(
                    rd_ssh + ["--", "sudo", "bash", "-c",
                              shlex.quote("certbot certificates 2>/dev/null | grep 'Domains:' | head -1")],
                    timeout=15,
                )
                if ok and "Domains:" in out:
                    le_domain = out.split("Domains:", 1)[1].strip().split()[0]
            if le_domain:
                le_expiry = _cert_expiry_le(rd_ssh, le_domain)
                print(f"    [*] LE cert expiry ({le_domain}): {le_expiry}")
    print()

    # teamserver status
    print("=== TEAMSERVER ===")
    if cfg.install.target == InstallTarget.remote:
        th = cfg.install.target_host
        if th:
            ts_ssh = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes",
                       "-i", str(th.ssh_key), "-p", str(th.ssh_port),
                       f"{th.ssh_user}@{th.address}"]
            reachable = _ssh_reachable(ts_ssh)
            print(f"  teamserver     {th.address:<20} SSH={'OK' if reachable else 'FAIL'}")
            if reachable:
                svcs = _check_services(ts_ssh, ["docker"])
                for svc, state in svcs.items():
                    marker = "+" if state == "active" else "!"
                    print(f"    [{marker}] {svc}: {state}")
                ok, out = _probe(
                    ts_ssh + ["--", "docker", "ps", "--format", "{{.Names}}: {{.Status}}"],
                    timeout=15,
                )
                if ok:
                    for line in out.splitlines():
                        if line.strip():
                            print(f"    [+] {line.strip()}")
                ok, out = _probe(
                    ts_ssh + ["--", "bash", "-c",
                              shlex.quote("cat /opt/adaptix/.onion 2>/dev/null || "
                                          "cat /var/lib/tor/hidden_service/hostname 2>/dev/null || "
                                          "echo 'unknown'")],
                    timeout=10,
                )
                if ok and out != "unknown":
                    print(f"    [*] .onion: {out}")
    else:
        print("  teamserver     localhost")
        ok, out = _probe(["docker", "ps", "--format", "{{.Names}}: {{.Status}}"], timeout=10)
        if ok:
            for line in out.splitlines():
                if line.strip():
                    print(f"    [+] {line.strip()}")
    print()

    # nebula mesh
    print("=== NEBULA MESH ===")
    targets: list[tuple[str, str, str]] = []
    for rl in cfg.relays:
        if rl.enabled:
            targets.append((rl.name, rl.nebula.overlay_ip.split("/")[0], "relay"))
    for r in cfg.redirectors:
        if r.enabled and r.nebula.enabled:
            targets.append((r.name, r.nebula.overlay_ip.split("/")[0], "redirector"))

    if targets:
        ping_parts = []
        for name, ip, role in targets:
            ping_parts.append(
                f"printf '  %-16s %-18s %-12s ' {shlex.quote(name)} {shlex.quote(ip)} {shlex.quote(role)} && "
                f"(ping -c 1 -W 3 {ip} >/dev/null 2>&1 && echo 'UP' || echo 'DOWN')"
            )
        try:
            run(lh_ssh + ["--", "bash", "-c", shlex.quote(" && ".join(ping_parts))], check=False)
        except FileNotFoundError:
            print("  (skipped: torsocks not installed on this host)")
    print()

    log.ok("status complete")
