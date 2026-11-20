from __future__ import annotations

import shlex
import subprocess
import tempfile
from pathlib import Path

from .. import log
from ..core.config import Config
from .ssh import (
    KitError,
    run,
    torsocks_prefix,
    relay_ssh_base,
    ssh_for_relay,
    ssh_to_redirector,
)


def ca_status(cfg: Config) -> None:
    """Show CA public key and signed cert log on the teamserver."""
    ca_dir = cfg.management.ssh_ca.ca_dir
    ca_pub = f"{ca_dir}/ca.pub"

    log.info(f"SSH CA at {ca_dir}")
    log.always(f"default_principals: {cfg.management.ssh_ca.default_principals}")
    log.always(f"default_validity:   {cfg.management.ssh_ca.default_validity}")

    result = run(["cat", ca_pub], check=False, capture_output=True, text=True)
    if result.returncode == 0:
        log.ok(f"CA public key:\n    {result.stdout.strip()}")
    else:
        log.warn(f"CA not found at {ca_pub}")

    log_file = f"{ca_dir}/signed.log"
    result = run(["cat", log_file], check=False, capture_output=True, text=True)
    if result.returncode == 0 and result.stdout.strip():
        log.ok("signed certificates:")
        for line in result.stdout.strip().splitlines():
            log.always(line)
    else:
        log.info("no signed certificates logged yet")


def sign_user_key(
    cfg: Config,
    pubkey_path: Path,
    identity: str = "c2-operator",
    principals: str | None = None,
    validity: str | None = None,
) -> Path:
    """Sign a user public key with the CA. Returns path to the cert file."""
    ca = cfg.management.ssh_ca
    ca_key = f"{ca.ca_dir}/ca"
    if principals is None:
        principals = ca.default_principals
    if validity is None:
        validity = ca.default_validity

    if not pubkey_path.exists():
        raise KitError(f"public key not found: {pubkey_path}")

    log.info(f"signing user key: {pubkey_path} (identity={identity}, principals={principals})")
    run([
        "ssh-keygen", "-s", ca_key,
        "-I", identity, "-n", principals, "-V", validity,
        str(pubkey_path),
    ])

    cert_path = Path(str(pubkey_path).replace(".pub", "-cert.pub"))
    log.ok(f"certificate: {cert_path}")
    run(["ssh-keygen", "-L", "-f", str(cert_path)])

    log_file = f"{ca.ca_dir}/signed.log"
    run([
        "bash", "-c",
        f"echo \"$(date -u +%Y-%m-%dT%H:%M:%SZ) identity={identity} "
        f"principals={principals} validity={validity} "
        f"cert={cert_path}\" >> {shlex.quote(log_file)}",
    ])

    return cert_path


def sign_host_key(
    cfg: Config,
    pubkey_path: Path,
    hostname: str,
    validity: str | None = None,
) -> Path:
    """Sign a host public key with the CA. Returns path to the cert file."""
    ca = cfg.management.ssh_ca
    ca_key = f"{ca.ca_dir}/ca"
    if validity is None:
        validity = ca.default_validity

    if not pubkey_path.exists():
        raise KitError(f"public key not found: {pubkey_path}")

    log.info(f"signing host key: {pubkey_path} (hostname={hostname})")
    run([
        "ssh-keygen", "-s", ca_key,
        "-I", f"host-{hostname}", "-h", "-n", hostname, "-V", validity,
        str(pubkey_path),
    ])

    cert_path = Path(str(pubkey_path).replace(".pub", "-cert.pub"))
    log.ok(f"host certificate: {cert_path}")
    run(["ssh-keygen", "-L", "-f", str(cert_path)])
    return cert_path


def deploy_ca_trust(cfg: Config, *, only: str | None = None) -> None:
    """Deploy the CA public key to all nebula-enabled nodes.

    Routing: relays via torsocks SSH direct, redirectors via relay hop.
    """
    ca_pub = f"{cfg.management.ssh_ca.ca_dir}/ca.pub"
    result = run(["cat", ca_pub], check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise KitError(f"cannot read CA pubkey at {ca_pub}")
    ca_content = result.stdout.strip()

    trust_script = (
        "sudo mkdir -p /etc/ssh/ca && "
        f"echo '{ca_content}' | sudo tee /etc/ssh/ca/c2-ca.pub > /dev/null && "
        "sudo chmod 644 /etc/ssh/ca/c2-ca.pub && "
        "grep -q 'TrustedUserCAKeys /etc/ssh/ca/c2-ca.pub' /etc/ssh/sshd_config || "
        "echo 'TrustedUserCAKeys /etc/ssh/ca/c2-ca.pub' | sudo tee -a /etc/ssh/sshd_config > /dev/null && "
        "sudo systemctl restart ssh 2>/dev/null || sudo systemctl restart sshd"
    )

    for rl in cfg.relays:
        if not rl.enabled:
            continue
        if only and rl.name != only:
            continue
        log.info(f"deploying CA trust to relay '{rl.name}' ({rl.deploy.address})")
        ssh = ssh_for_relay(cfg, rl)
        run(ssh + ["--", "bash", "-c", shlex.quote(trust_script)])
        log.ok(f"CA trusted on relay '{rl.name}'")

    relay_base = relay_ssh_base(cfg)
    for r in cfg.redirectors:
        if not r.enabled or not r.nebula.enabled:
            continue
        if only and r.name != only:
            continue
        overlay_ip = r.nebula.overlay_ip.split("/")[0]
        log.info(f"deploying CA trust to redirector '{r.name}' ({overlay_ip}) via relay")
        hop_ssh = torsocks_prefix(cfg) + relay_base + [
            "--", "ssh", "-o", "StrictHostKeyChecking=accept-new",
            f"ubuntu@{overlay_ip}",
            "--", "bash", "-c", shlex.quote(trust_script),
        ]
        run(hop_ssh)
        log.ok(f"CA trusted on redirector '{r.name}'")


def check_cert_auth(cfg: Config, *, only: str | None = None) -> None:
    """Test cert-based SSH to each node."""
    for rl in cfg.relays:
        if not rl.enabled:
            continue
        if only and rl.name != only:
            continue
        log.info(f"checking relay '{rl.name}'")
        ssh = ssh_for_relay(cfg, rl)
        result = run(
            ssh + ["--", "echo", "cert-ok"],
            check=False, capture_output=True, text=True,
        )
        if result.returncode == 0 and "cert-ok" in result.stdout:
            log.ok(f"relay '{rl.name}': cert auth OK")
        else:
            log.warn(f"relay '{rl.name}': cert auth FAILED")
            if result.stderr.strip():
                log.always(result.stderr.strip())

    relay_base = relay_ssh_base(cfg)
    for r in cfg.redirectors:
        if not r.enabled or not r.nebula.enabled:
            continue
        if only and r.name != only:
            continue
        overlay_ip = r.nebula.overlay_ip.split("/")[0]
        log.info(f"checking redirector '{r.name}' ({overlay_ip}) via relay")
        hop_ssh = torsocks_prefix(cfg) + relay_base + [
            "--", "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
            f"ubuntu@{overlay_ip}",
            "--", "echo", "cert-ok",
        ]
        result = run(hop_ssh, check=False, capture_output=True, text=True)
        if result.returncode == 0 and "cert-ok" in result.stdout:
            log.ok(f"redirector '{r.name}': cert auth OK")
        else:
            log.warn(f"redirector '{r.name}': cert auth FAILED")
            if result.stderr.strip():
                log.always(result.stderr.strip())


# ── short-lived cert renewal ──────────────────────────────────────

def renew_user_cert(
    cfg: Config,
    pubkey_path: Path | None = None,
    identity: str = "c2-operator",
    principals: str | None = None,
) -> Path:
    """Re-sign the operator's user cert with short_validity (default +24h).

    If pubkey_path is None, looks for ~/.ssh/id_ed25519.pub.
    """
    ca = cfg.management.ssh_ca
    if pubkey_path is None:
        pubkey_path = Path.home() / ".ssh" / "id_ed25519.pub"
    return sign_user_key(cfg, pubkey_path, identity=identity, principals=principals, validity=ca.short_validity)


def enable_relay_hop(
    cfg: Config,
    *,
    only: str | None = None,
    validity: str | None = None,
) -> None:
    """Issue a user cert to each relay so it can SSH to redirectors over the overlay.

    Per enabled relay:
      1. Ensure ~ubuntu/.ssh/id_ed25519 exists (generate if missing)
      2. Pull the pubkey back to the teamserver
      3. Sign it with the SSH CA (principal `ubuntu`, identity `relay-hop-<name>`)
      4. Push the resulting cert to ~ubuntu/.ssh/id_ed25519-cert.pub on the relay

    Redirectors already trust the SSH CA via `TrustedUserCAKeys`, so cert
    auth from relay to redirector just works after this.

    Idempotent: if a cert already exists and is still inside `short_validity`
    (checked via `ssh-keygen -L`), the sign is skipped.
    """
    ca = cfg.management.ssh_ca
    ca_key = f"{ca.ca_dir}/ca"
    val = validity or ca.short_validity

    if not Path(ca_key).exists():
        raise KitError(f"CA private key not found at {ca_key}")

    for rl in cfg.relays:
        if not rl.enabled:
            continue
        if only and rl.name != only:
            continue

        ssh = ssh_for_relay(cfg, rl)
        log.info(f"enabling relay-hop cert on '{rl.name}' ({rl.deploy.address})")

        gen_script = (
            "set -e && "
            "mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
            "test -f ~/.ssh/id_ed25519 || "
            "ssh-keygen -t ed25519 -N '' -f ~/.ssh/id_ed25519 "
            f"  -C 'conduit-relay-hop-{rl.name}' > /dev/null && "
            "cat ~/.ssh/id_ed25519.pub"
        )
        result = subprocess.run(
            ssh + ["--", "bash", "-c", shlex.quote(gen_script)],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            log.warn(f"{rl.name}: keypair step failed: {result.stderr.strip()}")
            continue

        pubkey_content = result.stdout.strip()
        if not pubkey_content:
            log.warn(f"{rl.name}: empty pubkey from relay")
            continue

        with tempfile.TemporaryDirectory() as tmpdir:
            pub_file = Path(tmpdir) / "relay.pub"
            pub_file.write_text(pubkey_content + "\n")

            run([
                "ssh-keygen", "-s", ca_key,
                "-I", f"relay-hop-{rl.name}",
                "-n", "ubuntu",
                "-V", val,
                str(pub_file),
            ])

            cert_file = Path(tmpdir) / "relay-cert.pub"
            cert_content = cert_file.read_text().strip()

        push_script = (
            f"echo {shlex.quote(cert_content)} > ~/.ssh/id_ed25519-cert.pub && "
            f"chmod 644 ~/.ssh/id_ed25519-cert.pub && "
            f"ssh-keygen -L -f ~/.ssh/id_ed25519-cert.pub | head -10"
        )
        push_result = subprocess.run(
            ssh + ["--", "bash", "-c", shlex.quote(push_script)],
            capture_output=True, text=True, timeout=15,
        )
        if push_result.returncode != 0:
            log.warn(f"{rl.name}: cert push failed: {push_result.stderr.strip()}")
            continue

        log.ok(f"{rl.name}: relay-hop cert installed (validity={val})")
        for line in push_result.stdout.strip().splitlines():
            if line.strip():
                log.always(f"  {line.strip()}")

    log.ok("relay-hop enablement complete")


def renew_host_certs(cfg: Config, *, only: str | None = None) -> None:
    """Pull host pubkeys from all nodes, sign with short_validity, push back, restart sshd.

    For each relay: direct SSH (with torsocks).
    For each redirector: via relay hop.
    """
    ca = cfg.management.ssh_ca
    ca_key = f"{ca.ca_dir}/ca"
    validity = ca.short_validity

    if not Path(ca_key).exists():
        raise KitError(f"CA private key not found at {ca_key}")

    for rl in cfg.relays:
        if not rl.enabled:
            continue
        if only and rl.name != only:
            continue
        ssh = ssh_for_relay(cfg, rl)
        _renew_host_cert_on_node(ssh, rl.name, ca_key, validity)

    relay_base = relay_ssh_base(cfg)
    for r in cfg.redirectors:
        if not r.enabled or not r.nebula.enabled:
            continue
        if only and r.name != only:
            continue
        overlay_ip = r.nebula.overlay_ip.split("/")[0]
        hop_ssh = torsocks_prefix(cfg) + relay_base + [
            "--", "ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes",
            f"ubuntu@{overlay_ip}",
        ]
        _renew_host_cert_on_node(hop_ssh, r.name, ca_key, validity)


def _renew_host_cert_on_node(ssh_cmd: list[str], name: str, ca_key: str, validity: str) -> None:
    """Pull ed25519 host pubkey, sign locally, push cert back, restart sshd."""
    log.info(f"renewing host cert: {name} (validity={validity})")

    result = subprocess.run(
        ssh_cmd + ["--", "cat", "/etc/ssh/ssh_host_ed25519_key.pub"],
        capture_output=True, text=True, timeout=15,
    )
    if result.returncode != 0:
        log.warn(f"{name}: cannot read host pubkey: {result.stderr.strip()}")
        return

    pubkey_content = result.stdout.strip()
    if not pubkey_content:
        log.warn(f"{name}: empty host pubkey")
        return

    with tempfile.TemporaryDirectory() as tmpdir:
        pub_file = Path(tmpdir) / "host.pub"
        pub_file.write_text(pubkey_content + "\n")

        run([
            "ssh-keygen", "-s", ca_key,
            "-I", f"host-{name}", "-h", "-n", name, "-V", validity,
            str(pub_file),
        ])

        cert_file = Path(tmpdir) / "host-cert.pub"
        cert_content = cert_file.read_text().strip()

    push_script = (
        f"echo {shlex.quote(cert_content)} | sudo tee /etc/ssh/ssh_host_ed25519_key-cert.pub > /dev/null && "
        f"sudo chmod 644 /etc/ssh/ssh_host_ed25519_key-cert.pub && "
        f"grep -q 'HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub' /etc/ssh/sshd_config || "
        f"echo 'HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub' | sudo tee -a /etc/ssh/sshd_config > /dev/null && "
        f"sudo systemctl restart ssh 2>/dev/null || sudo systemctl restart sshd"
    )

    subprocess.run(
        ssh_cmd + ["--", "bash", "-c", shlex.quote(push_script)],
        check=True, timeout=30,
    )
    log.ok(f"{name}: host cert renewed (validity={validity})")


def enable_renewal_timer(cfg: Config, config_path: Path) -> None:
    """Install a systemd timer on the local machine (teamserver) that auto-renews host certs.

    Creates:
      /etc/systemd/system/c2-cert-renew.service
      /etc/systemd/system/c2-cert-renew.timer
    """
    ca = cfg.management.ssh_ca
    interval = ca.renewal_interval

    kit_cmd = f"python3 -m conduit ca renew-hosts --config {shlex.quote(str(config_path.resolve()))} --yes"

    service_unit = (
        "[Unit]\n"
        "Description=Renew SSH host certs for C2 nodes\n"
        "After=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"ExecStart=/bin/bash -c '{kit_cmd}'\n"
        f"WorkingDirectory={shlex.quote(str(config_path.resolve().parent))}\n"
    )

    timer_unit = (
        "[Unit]\n"
        "Description=Periodic SSH host cert renewal for C2 nodes\n"
        "\n"
        "[Timer]\n"
        f"OnCalendar=*-*-* 00/12:00:00\n"
        "Persistent=true\n"
        "RandomizedDelaySec=300\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )

    service_path = Path("/etc/systemd/system/c2-cert-renew.service")
    timer_path = Path("/etc/systemd/system/c2-cert-renew.timer")

    service_path.write_text(service_unit)
    timer_path.write_text(timer_unit)
    log.ok(f"wrote {service_path}")
    log.ok(f"wrote {timer_path}")

    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "--now", "c2-cert-renew.timer"])
    log.ok(f"renewal timer enabled (interval: {interval})")

    result = run(["systemctl", "list-timers", "c2-cert-renew.timer", "--no-pager"], check=False, capture_output=True, text=True)
    if result.returncode == 0:
        log.always(result.stdout.strip())


def disable_renewal_timer() -> None:
    """Disable and remove the systemd renewal timer."""
    run(["systemctl", "disable", "--now", "c2-cert-renew.timer"], check=False)
    for p in ("/etc/systemd/system/c2-cert-renew.service", "/etc/systemd/system/c2-cert-renew.timer"):
        path = Path(p)
        if path.exists():
            path.unlink()
            log.ok(f"removed {p}")
    run(["systemctl", "daemon-reload"])
    log.ok("renewal timer disabled")
