from __future__ import annotations

from pathlib import Path

import click
from pydantic import ValidationError

from .. import __version__
from .. import log
from ..ops import apply as applymod
from ..ops import clean as cleanmod
from ..core import config as cfgmod
from ..core import state as state_mod
from ..ops import deploy as deploymod
from ..ops import monitor as monitormod
from ..ops import nebula as nebulamod
from ..ops import payload as payloadmod
from ..core import renderer
from ..ops import rotate as rotatemod
from ..ops import sshca as sshcamod
from ..ops import status as statusmod


def _load_or_exit(config_path: Path):
    try:
        return cfgmod.load(config_path)
    except ValidationError as e:
        click.echo(f"[!] validation failed:\n{e}", err=True)
        raise SystemExit(1)
    except ValueError as e:
        click.echo(f"[!] {e}", err=True)
        raise SystemExit(1)


@click.group()
@click.version_option(__version__, prog_name="conduit")
@click.option("-v", "--verbose", is_flag=True, help="Log every command and action.")
def main(verbose: bool) -> None:
    """Conduit: deploy and manage AdaptixC2 operator infrastructure from one YAML config."""
    log.set_verbose(verbose)


@main.command()
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
def validate(config_path: Path) -> None:
    """Load the config, run schema + cross-ref validation, print summary."""
    cfg = _load_or_exit(config_path)

    click.echo(f"[+] {config_path} valid")
    click.echo(f"    meta.name          {cfg.meta.name}")
    click.echo(f"    install.target     {cfg.install.target.value}")
    click.echo(f"    install.root       {cfg.install.root}")
    click.echo(f"    operators          {len(cfg.operators)}")
    click.echo(f"    pki.ca.source      {cfg.pki.ca.source.value}")
    click.echo(f"    pki.leaves         {len(cfg.pki.leaves)}")
    click.echo(f"    listeners          {len(cfg.listeners)}")
    click.echo(f"    redirectors        {len(cfg.redirectors)}")
    for r in cfg.redirectors:
        neb = f"  nebula={r.nebula.overlay_ip}" if r.nebula.enabled else ""
        click.echo(f"      - {r.name}  type={r.type.value}  deploy={r.deploy.address}{neb}")
    click.echo(f"    relays             {len(cfg.relays)}")
    for rl in cfg.relays:
        role = "lighthouse" if rl.nebula.is_lighthouse else "host"
        click.echo(f"      - {rl.name}  {rl.nebula.overlay_ip}  {role}  deploy={rl.deploy.address}")
    click.echo(f"    management.nebula  {cfg.management.nebula.enabled}")
    click.echo(f"    management.torsocks {cfg.management.torsocks_management}")


@main.command()
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--out", "out_dir", type=click.Path(path_type=Path), required=True)
def render(config_path: Path, out_dir: Path) -> None:
    """Render every target to --out. No side effects on the live stack."""
    cfg = _load_or_exit(config_path)
    written = renderer.render_all(cfg, out_dir)
    click.echo(f"[+] rendered {len(written)} file(s) under {out_dir}")
    for p in written:
        click.echo(f"    {p}")


@main.command()
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
def preflight(config_path: Path) -> None:
    """Check that the apply phase has what it needs. Reports problems only."""
    cfg = _load_or_exit(config_path)
    problems = applymod.preflight(cfg)
    if not problems:
        click.echo("[+] preflight: ready to apply")
        return
    click.echo(f"[!] preflight found {len(problems)} problem(s):")
    for p in problems:
        click.echo(f"    - {p}")
    raise SystemExit(1)


@main.command()
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
def status(config_path: Path) -> None:
    """Unified status dashboard: nodes, services, certs, mesh, tor."""
    cfg = _load_or_exit(config_path)
    statusmod.full_status(cfg)


@main.command()
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
def dashboard(config_path: Path) -> None:
    """Interactive TUI dashboard (requires: pip install textual)."""
    try:
        from .. import tui
    except ImportError:
        click.echo("[!] textual not installed. Run: pip install textual", err=True)
        raise SystemExit(1)
    cfg = _load_or_exit(config_path)
    tui.run_dashboard(cfg, config_path)


@main.command()
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--only", default=None, help="Rotate only the named node.")
@click.option("--yes", "assume_yes", is_flag=True, help="Skip confirmation.")
def rotate(config_path: Path, only: str | None, assume_yes: bool) -> None:
    """Rotate all certs: nebula + SSH host certs + Let's Encrypt."""
    cfg = _load_or_exit(config_path)
    if not assume_yes:
        target = only or "all enabled nodes"
        click.confirm(f"[?] rotate all certs for {target}?", abort=True)
    rotatemod.rotate_all(cfg, only=only)


@main.group()
def ingress() -> None:
    """Operator ingress tunnel management."""


@ingress.command("setup")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
def ingress_setup(config_path: Path) -> None:
    """Print the SSH tunnel command for operator access to the teamserver."""
    cfg = _load_or_exit(config_path)
    if cfg.ingress.document_only:
        click.echo("[*] ingress.document_only=true, printing tunnel command only")

    ts_port = cfg.teamserver.publish_port
    local_port = cfg.ingress.ssh_tunnel.local_port

    if cfg.ingress.ssh_tunnel.relay_hop and cfg.relays:
        rl = next((r for r in cfg.relays if r.enabled), None)
        if rl:
            ts_host = cfg.install.target_host
            ts_addr = ts_host.address if ts_host else "127.0.0.1"
            relay_addr = rl.deploy.address
            relay_user = rl.deploy.ssh_user
            relay_port = rl.deploy.ssh_port
            relay_key = rl.deploy.ssh_key or "~/.ssh/id_ed25519"

            click.echo(f"[+] SSH tunnel via relay '{rl.name}' ({relay_addr})")
            click.echo(f"    Local port {local_port} -> relay -> teamserver {ts_addr}:{ts_port}")
            click.echo()
            cmd = (
                f"ssh -L {local_port}:{ts_addr}:{ts_port} "
                f"-i {relay_key} -p {relay_port} "
                f"-o StrictHostKeyChecking=accept-new "
                f"-N {relay_user}@{relay_addr}"
            )
            click.echo(f"    {cmd}")
            click.echo()
            click.echo(f"    Then connect Adaptix client to https://127.0.0.1:{local_port}")
            return

    ts_host = cfg.install.target_host
    if ts_host:
        cmd = (
            f"ssh -L {local_port}:127.0.0.1:{ts_port} "
            f"-i {ts_host.ssh_key} -p {ts_host.ssh_port} "
            f"-o StrictHostKeyChecking=accept-new "
            f"-N {ts_host.ssh_user}@{ts_host.address}"
        )
        click.echo(f"[+] Direct SSH tunnel to teamserver ({ts_host.address})")
        click.echo(f"    {cmd}")
    else:
        click.echo(f"[+] Local install, teamserver at 127.0.0.1:{ts_port}")


@ingress.command("connect")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--yes", "assume_yes", is_flag=True, help="Skip confirmation.")
def ingress_connect(config_path: Path, assume_yes: bool) -> None:
    """Open the SSH tunnel (foreground, Ctrl+C to close)."""
    cfg = _load_or_exit(config_path)
    ts_port = cfg.teamserver.publish_port
    local_port = cfg.ingress.ssh_tunnel.local_port

    if cfg.ingress.ssh_tunnel.relay_hop and cfg.relays:
        rl = next((r for r in cfg.relays if r.enabled), None)
        if rl:
            ts_host = cfg.install.target_host
            ts_addr = ts_host.address if ts_host else "127.0.0.1"
            relay_addr = rl.deploy.address
            relay_user = rl.deploy.ssh_user
            relay_port = rl.deploy.ssh_port
            relay_key = str(rl.deploy.ssh_key or "~/.ssh/id_ed25519")

            if not assume_yes:
                click.confirm(
                    f"[?] open tunnel {local_port} -> {rl.name} -> {ts_addr}:{ts_port}?",
                    abort=True,
                )
            click.echo(f"[*] tunnel open on 127.0.0.1:{local_port}, Ctrl+C to close")
            import subprocess
            try:
                subprocess.run([
                    "ssh", "-L", f"{local_port}:{ts_addr}:{ts_port}",
                    "-i", relay_key, "-p", str(relay_port),
                    "-o", "StrictHostKeyChecking=accept-new",
                    "-o", "ServerAliveInterval=30",
                    "-N", f"{relay_user}@{relay_addr}",
                ])
            except KeyboardInterrupt:
                click.echo("\n[+] tunnel closed")
            return

    click.echo("[!] no relay available for tunnel hop", err=True)
    raise SystemExit(1)


@main.group("cf-worker")
def cf_worker() -> None:
    """Cloudflare Worker management."""


@cf_worker.command("render")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--out", "out_dir", type=click.Path(path_type=Path), required=True)
def cf_worker_render(config_path: Path, out_dir: Path) -> None:
    """Render the CF Worker JS + wrangler.toml from the config's filter profile."""
    cfg = _load_or_exit(config_path)
    if not cfg.cf_worker.enabled:
        click.echo("[!] cf_worker is not enabled in config", err=True)
        raise SystemExit(1)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "worker.js").write_text(renderer.render_cf_worker(cfg))
    (out_dir / "wrangler.toml").write_text(renderer.render_cf_wrangler(cfg))
    click.echo(f"[+] rendered cf-worker to {out_dir}")


@cf_worker.command("deploy")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--out", "out_dir", type=click.Path(path_type=Path), required=True)
@click.option("--yes", "assume_yes", is_flag=True, help="Skip confirmation.")
def cf_worker_deploy(config_path: Path, out_dir: Path, assume_yes: bool) -> None:
    """Render and deploy the CF Worker via wrangler."""
    cfg = _load_or_exit(config_path)
    if not cfg.cf_worker.enabled:
        click.echo("[!] cf_worker is not enabled in config", err=True)
        raise SystemExit(1)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "worker.js").write_text(renderer.render_cf_worker(cfg))
    (out_dir / "wrangler.toml").write_text(renderer.render_cf_wrangler(cfg))
    if not assume_yes:
        click.confirm(f"[?] deploy CF Worker '{cfg.cf_worker.name}' to {cfg.cf_worker.route}?", abort=True)
    import subprocess
    result = subprocess.run(
        ["npx", "wrangler", "deploy", "--config", str(out_dir / "wrangler.toml")],
        cwd=str(out_dir),
    )
    if result.returncode != 0:
        click.echo("[!] wrangler deploy failed", err=True)
        raise SystemExit(1)
    click.echo("[+] CF Worker deployed")


@main.command()
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--staging", "staging_dir", type=click.Path(path_type=Path), default=None,
              help="Existing staging dir to compare. If omitted, renders to a temp dir.")
def diff(config_path: Path, staging_dir: Path | None) -> None:
    """Diff the rendered config against the live install root."""
    import subprocess
    import tempfile

    cfg = _load_or_exit(config_path)

    if staging_dir is None:
        tmp = tempfile.mkdtemp(prefix="conduit-diff-")
        staging_dir = Path(tmp)
        renderer.render_all(cfg, staging_dir)
        click.echo(f"[*] rendered to {staging_dir}")
    elif not staging_dir.exists():
        click.echo(f"[!] staging dir does not exist: {staging_dir}", err=True)
        raise SystemExit(1)

    live_root = Path(cfg.install.root).expanduser()
    if not live_root.exists():
        click.echo(f"[!] install root does not exist: {live_root}", err=True)
        raise SystemExit(1)

    pairs = [
        (staging_dir / "config" / "profile.yaml", live_root / "config" / "profile.yaml", "profile.yaml"),
        (staging_dir / "docker-compose.yml", live_root / "docker-compose.yml", "docker-compose.yml"),
    ]

    if cfg.payload and cfg.payload.enabled:
        pairs.append((
            staging_dir / "staging" / "conf" / "nginx.conf",
            live_root / "staging" / "conf" / "nginx.conf",
            "payload nginx.conf",
        ))

    found_diff = False
    for rendered, live, label in pairs:
        if not rendered.exists():
            continue
        if not live.exists():
            click.echo(f"[+] {label}: NEW (not on live)")
            found_diff = True
            continue
        result = subprocess.run(
            ["diff", "-u", "--label", f"live/{label}", str(live),
             "--label", f"rendered/{label}", str(rendered)],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            click.echo(f"[+] {label}:")
            click.echo(result.stdout)
            found_diff = True

    if not found_diff:
        click.echo("[+] no differences found")


@main.group()
def relay() -> None:
    """Manage relay / lighthouse nodes."""


@relay.command("deploy")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--staging", "staging_dir", type=click.Path(path_type=Path), required=True,
              help="Render output dir (contains relays/<name>/ansible-vars.yml).")
@click.option("--only", "only_relay", default=None, help="Deploy only the named relay (exact match on relays[].name).")
@click.option("--no-torsocks", "no_torsocks", is_flag=True,
              help="Bypass torsocks for this run (fast first-apply or dev iteration). "
                   "WARNING: relay SSH logs will contain the teamserver's clearnet IP.")
@click.option("--playbook-tags", "playbook_tags", default=None,
              help="Pass --tags to the inner ansible-playbook (comma-separated).")
@click.option("--playbook-skip-tags", "playbook_skip_tags", default=None,
              help="Pass --skip-tags to the inner ansible-playbook (comma-separated).")
@click.option("--yes", "assume_yes", is_flag=True, help="Skip confirmation prompt.")
def relay_deploy(
    config_path: Path,
    staging_dir: Path,
    only_relay: str | None,
    no_torsocks: bool,
    playbook_tags: str | None,
    playbook_skip_tags: str | None,
    assume_yes: bool,
) -> None:
    """Render + deploy relay nodes via ansible."""
    cfg = _load_or_exit(config_path)

    click.echo("[*] 1/2 render")
    written = renderer.render_all(cfg, staging_dir)
    click.echo(f"    rendered {len(written)} file(s)")

    if not assume_yes:
        target = only_relay or "all enabled relays"
        click.confirm(f"[?] deploy {target}?", abort=True)

    click.echo("[*] 2/2 deploy relays")
    applymod.deploy_relays(
        cfg, staging_dir, only=only_relay,
        no_torsocks=no_torsocks,
        playbook_tags=playbook_tags,
        playbook_skip_tags=playbook_skip_tags,
    )
    click.echo("[+] relay deploy complete")


@main.group()
def ca() -> None:
    """SSH Certificate Authority management."""


@ca.command("status")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
def ca_status(config_path: Path) -> None:
    """Show CA public key and signed cert log."""
    cfg = _load_or_exit(config_path)
    sshcamod.ca_status(cfg)


@ca.command("sign")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.argument("pubkey", type=click.Path(exists=True, path_type=Path))
@click.option("-i", "--identity", default="c2-operator", help="Certificate identity string.")
@click.option("-n", "--principals", default=None, help="Comma-separated principals (default from config).")
@click.option("-V", "--validity", default=None, help="Validity period (default from config, e.g. +8760h).")
def ca_sign(config_path: Path, pubkey: Path, identity: str, principals: str | None, validity: str | None) -> None:
    """Sign a user public key with the CA."""
    cfg = _load_or_exit(config_path)
    sshcamod.sign_user_key(cfg, pubkey, identity=identity, principals=principals, validity=validity)


@ca.command("sign-host")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.argument("pubkey", type=click.Path(exists=True, path_type=Path))
@click.option("--hostname", required=True, help="Hostname for the host certificate.")
@click.option("-V", "--validity", default=None, help="Validity period (default from config).")
def ca_sign_host(config_path: Path, pubkey: Path, hostname: str, validity: str | None) -> None:
    """Sign a host public key with the CA."""
    cfg = _load_or_exit(config_path)
    sshcamod.sign_host_key(cfg, pubkey, hostname, validity=validity)


@ca.command("deploy")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--only", default=None, help="Deploy CA trust to only the named node.")
@click.option("--yes", "assume_yes", is_flag=True, help="Skip confirmation.")
def ca_deploy(config_path: Path, only: str | None, assume_yes: bool) -> None:
    """Push CA trust (pubkey + sshd_config) to all nodes via relay hop."""
    cfg = _load_or_exit(config_path)
    if not assume_yes:
        target = only or "all enabled relays + redirectors"
        click.confirm(f"[?] deploy CA trust to {target}?", abort=True)
    sshcamod.deploy_ca_trust(cfg, only=only)


@ca.command("check")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--only", default=None, help="Check only the named node.")
def ca_check(config_path: Path, only: str | None) -> None:
    """Test cert-based SSH to each node."""
    cfg = _load_or_exit(config_path)
    sshcamod.check_cert_auth(cfg, only=only)


@ca.command("renew")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--pubkey", type=click.Path(path_type=Path), default=None, help="User pubkey (default ~/.ssh/id_ed25519.pub).")
@click.option("-i", "--identity", default="c2-operator", help="Certificate identity string.")
@click.option("-n", "--principals", default=None, help="Comma-separated principals (default from config).")
def ca_renew(config_path: Path, pubkey: Path | None, identity: str, principals: str | None) -> None:
    """Re-sign operator user cert with short_validity (default +24h)."""
    cfg = _load_or_exit(config_path)
    sshcamod.renew_user_cert(cfg, pubkey_path=pubkey, identity=identity, principals=principals)


@ca.command("renew-hosts")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--only", default=None, help="Renew only the named node.")
@click.option("--yes", "assume_yes", is_flag=True, help="Skip confirmation.")
def ca_renew_hosts(config_path: Path, only: str | None, assume_yes: bool) -> None:
    """Pull host pubkeys, sign with short_validity, push certs, restart sshd."""
    cfg = _load_or_exit(config_path)
    if not assume_yes:
        target = only or "all enabled nodes"
        click.confirm(f"[?] renew host certs for {target}?", abort=True)
    sshcamod.renew_host_certs(cfg, only=only)


@ca.command("enable-relay-hop")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--only", default=None, help="Enable on only the named relay.")
@click.option("--validity", default=None, help="Cert validity (e.g. +24h). Defaults to management.ssh_ca.short_validity.")
def ca_enable_relay_hop(config_path: Path, only: str | None, validity: str | None) -> None:
    """Give each relay a signed user cert so it can SSH to redirectors over the overlay."""
    cfg = _load_or_exit(config_path)
    sshcamod.enable_relay_hop(cfg, only=only, validity=validity)


@ca.command("enable-renewal")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
def ca_enable_renewal(config_path: Path) -> None:
    """Install systemd timer for automatic host cert renewal on the teamserver."""
    cfg = _load_or_exit(config_path)
    sshcamod.enable_renewal_timer(cfg, config_path)


@ca.command("disable-renewal")
def ca_disable_renewal() -> None:
    """Remove the systemd renewal timer."""
    sshcamod.disable_renewal_timer()


@main.group()
def payload() -> None:
    """Payload distribution to redirectors."""


@payload.command("push")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--only", default=None, help="Push to only the named redirector.")
@click.option("--yes", "assume_yes", is_flag=True, help="Skip confirmation.")
def payload_push(config_path: Path, only: str | None, assume_yes: bool) -> None:
    """Push payloads from staging_dir to all redirectors."""
    cfg = _load_or_exit(config_path)
    if not assume_yes:
        target = only or "all redirectors with payload_dir"
        click.confirm(f"[?] push payloads to {target}?", abort=True)
    payloadmod.push_payloads(cfg, only=only)


@payload.command("list")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--only", default=None, help="List payloads on only the named redirector.")
def payload_list(config_path: Path, only: str | None) -> None:
    """List payload files on each redirector (via relay hop)."""
    cfg = _load_or_exit(config_path)
    payloadmod.list_payloads(cfg, only=only)


@main.group()
def monitor() -> None:
    """Health checks and log pulling for redirectors."""


@monitor.command("enable")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
def monitor_enable(config_path: Path) -> None:
    """Install systemd timers for automatic health checks and log pulling."""
    cfg = _load_or_exit(config_path)
    monitormod.install_timers(cfg, config_path)
    click.echo("[+] monitoring timers installed and started")


@monitor.command("disable")
def monitor_disable() -> None:
    """Remove the monitoring systemd timers."""
    monitormod.remove_timers()
    click.echo("[+] monitoring timers removed")


@monitor.command("health")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--only", default=None, help="Check only the named redirector.")
def monitor_health(config_path: Path, only: str | None) -> None:
    """Check each redirector's health_url (torsocks curl, state tracking, telegram alerts)."""
    cfg = _load_or_exit(config_path)
    failed = monitormod.health_check(cfg, only=only)
    if failed:
        raise SystemExit(1)


@monitor.command("logpull")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--only", default=None, help="Pull logs from only the named redirector.")
def monitor_logpull(config_path: Path, only: str | None) -> None:
    """Pull logs from each redirector via relay hop."""
    cfg = _load_or_exit(config_path)
    monitormod.logpull(cfg, only=only)


@monitor.command("tor")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--only", default=None, help="Check only the named redirector.")
def monitor_tor(config_path: Path, only: str | None) -> None:
    """Check tor service, SOCKS proxy, gost chain, and circuit count on each redirector."""
    cfg = _load_or_exit(config_path)
    failed = monitormod.tor_status(cfg, only=only)
    if failed:
        raise SystemExit(1)


@main.group()
def nebula() -> None:
    """Nebula mesh VPN management on the lighthouse relay."""


@nebula.command("init")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
def nebula_init(config_path: Path) -> None:
    """Initialize the Nebula CA on the lighthouse relay (idempotent)."""
    cfg = _load_or_exit(config_path)
    nebulamod.ca_init(cfg)


@nebula.command("sign")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--name", required=True, help="Host name for the certificate.")
@click.option("--ip", required=True, help="Overlay IP with CIDR (e.g. 10.99.0.20/24).")
@click.option("--groups", required=True, help="Comma-separated nebula groups.")
def nebula_sign(config_path: Path, name: str, ip: str, groups: str) -> None:
    """Sign a nebula host certificate on the lighthouse relay."""
    cfg = _load_or_exit(config_path)
    nebulamod.sign_cert(cfg, name=name, ip=ip, groups=groups)


@nebula.command("status")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
def nebula_status(config_path: Path) -> None:
    """Ping each overlay IP from the lighthouse relay to check mesh health."""
    cfg = _load_or_exit(config_path)
    nebulamod.mesh_status(cfg)


@nebula.command("list")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
def nebula_list(config_path: Path) -> None:
    """List all signed nebula certificates on the lighthouse relay."""
    cfg = _load_or_exit(config_path)
    nebulamod.list_certs(cfg)


@nebula.command("rotate")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--only", default=None, help="Rotate only the named node.")
@click.option("--yes", "assume_yes", is_flag=True, help="Skip confirmation.")
def nebula_rotate(config_path: Path, only: str | None, assume_yes: bool) -> None:
    """Re-sign nebula certs from the existing CA, push to nodes, restart nebula."""
    cfg = _load_or_exit(config_path)
    if not assume_yes:
        target = only or "all enabled nodes"
        click.confirm(f"[?] rotate nebula certs for {target}?", abort=True)
    nebulamod.rotate_certs(cfg, only=only)


@main.group()
def clean() -> None:
    """Post-engagement cleanup and evidence destruction."""


@clean.command("logs")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
# Positive selectors (preferred). No selector given = clean everything (same as --all).
@click.option("--all", "run_all", is_flag=True,
              help="Clean every node: teamserver + every enabled relay + every enabled redirector. "
                   "Same as passing no selector.")
@click.option("--teamserver", "run_teamserver", is_flag=True,
              help="Clean only the teamserver's own logs (local).")
@click.option("--redirector", "run_redirector", default=None,
              help="Clean a single named redirector.")
@click.option("--relay", "run_relay", default=None,
              help="Clean a single named relay.")
# Cross-cutting
@click.option("--direct", "direct", is_flag=True,
              help="For redirectors: reach them over their public deploy address instead of the relay / nebula hop. "
                   "Use post-apply before nebula is up, or when nebula is not deployed.")
@click.option("--no-torsocks", "no_torsocks", is_flag=True,
              help="Bypass torsocks for the scrub itself (default: torsocks on, per config). "
                   "Only disable when debugging the scrub route; the whole point of running the "
                   "scrub is to not reappear the IP in the one log entry the scrub session makes.")
@click.option("--yes", "assume_yes", is_flag=True, help="Skip confirmation.")
# DEPRECATED legacy flags.
@click.option("--only", default=None,
              help="DEPRECATED: use --redirector <name>, --relay <name>, or --teamserver.")
@click.option("--skip-teamserver", is_flag=True,
              help="DEPRECATED: positive selectors already exclude the teamserver unless --teamserver or --all is passed.")
def clean_logs(
    config_path: Path,
    run_all: bool,
    run_teamserver: bool,
    run_redirector: str | None,
    run_relay: str | None,
    direct: bool,
    no_torsocks: bool,
    assume_yes: bool,
    only: str | None,
    skip_teamserver: bool,
) -> None:
    """Wipe SSH logs, shell history, known_hosts, journal, tmp artifacts.

    Prefer positive selectors to pick which nodes to clean:
      --all                     every node (teamserver + relays + redirectors)
      --teamserver              teamserver only
      --redirector <name>       one redirector
      --relay <name>            one relay
    No selector = --all. Legacy --only / --skip-teamserver still work but
    print a deprecation warning.

    Safe to run mid-engagement. Removes IP traces from initial provisioning.
    Does NOT touch crypto material, application configs, or payloads.
    """
    cfg = _load_or_exit(config_path)

    positive_used = bool(run_all or run_teamserver or run_redirector or run_relay)
    legacy_used = bool(only or skip_teamserver)

    if positive_used and legacy_used:
        click.echo(
            "[!] Cannot mix positive selectors (--all, --teamserver, --redirector, --relay) "
            "with legacy flags (--only, --skip-teamserver).",
            err=True,
        )
        raise SystemExit(2)

    if legacy_used:
        click.echo(
            "[!] WARNING: --only and --skip-teamserver are deprecated. "
            "Use --teamserver / --redirector <name> / --relay <name> / --all."
        )

    # Translate positive selectors to the internal (only, include_teamserver) model.
    if positive_used:
        if run_all:
            resolved_only = None
            include_teamserver = True
        else:
            # Only one target per invocation; mixing requires explicit --all.
            selectors = [bool(run_teamserver), bool(run_redirector), bool(run_relay)]
            if sum(selectors) > 1:
                click.echo(
                    "[!] Combine multiple nodes with --all, or run `clean logs` once per node.",
                    err=True,
                )
                raise SystemExit(2)
            if run_teamserver:
                resolved_only = "teamserver"
                include_teamserver = True
            elif run_redirector:
                resolved_only = run_redirector
                include_teamserver = False
            else:
                resolved_only = run_relay
                include_teamserver = False
    else:
        # Legacy or no-flags default.
        resolved_only = only
        include_teamserver = not skip_teamserver

    if not assume_yes:
        target = resolved_only or "all nodes (teamserver + relays + redirectors)"
        bits = []
        if direct:
            bits.append("direct SSH")
        if no_torsocks:
            bits.append("no torsocks")
        route = f" ({', '.join(bits)})" if bits else ""
        click.confirm(f"[?] wipe logs on {target}{route}?", abort=True)
    cleanmod.clean_logs(
        cfg,
        only=resolved_only,
        include_teamserver=include_teamserver,
        direct=direct,
        no_torsocks=no_torsocks,
    )
    click.echo("[+] log cleanup complete")


@clean.command("destroy")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--only", default=None,
              help="Target a single node by name, or 'relays'/'redirectors'/'teamserver' for a group.")
@click.option("--skip-teamserver", is_flag=True, help="Skip the local teamserver destruction.")
@click.option("--yes", "assume_yes", is_flag=True, help="Skip confirmation.")
def clean_destroy(config_path: Path, only: str | None, skip_teamserver: bool, assume_yes: bool) -> None:
    """Full evidence destruction before VM termination.

    Wipes everything from 'logs' PLUS: shreds crypto material (nebula certs,
    SSH CA keys, host keys), wipes application logs/configs, payloads,
    cloud-init data, docker volumes, and zeros free space.

    Order: redirectors first, then relays, then teamserver.
    """
    cfg = _load_or_exit(config_path)
    if not assume_yes:
        target = only or "ALL nodes (redirectors -> relays -> teamserver)"
        click.confirm(
            f"[!] DESTROY evidence on {target}? This is irreversible.", abort=True,
        )
    cleanmod.clean_destroy(cfg, only=only, include_teamserver=not skip_teamserver)
    click.echo("[+] evidence destruction complete")


@main.command()
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--staging", "staging_dir", type=click.Path(path_type=Path), required=True,
              help="Where to render artifacts. Also used as the source for transfer to target.")
@click.option("--yes", "assume_yes", is_flag=True,
              help="Skip confirmation before docker and ansible calls.")
# Positive selectors. At least one is required; apply never runs everything in one shot.
# Use `conduit deploy --all` for orchestrated one-shot deploys.
@click.option("--teamserver", "run_teamserver", is_flag=True,
              help="Run the teamserver stack (transfer + docker build + docker up).")
@click.option("--ts-onion", "run_ts_onion", is_flag=True,
              help="Run ts-onion (Tor hidden service on the teamserver). Mutually exclusive with --redirector.")
@click.option("--redirector", "run_redirector", default=None,
              help="Run a single named openresty redirector (exact match on redirectors[].name).")
@click.option("--relay", "run_relay", default=None,
              help="Run a single named relay (exact match on relays[].name).")
# Cross-cutting
@click.option("--no-torsocks", "no_torsocks", is_flag=True,
              help="Bypass torsocks for this apply only (fast first-apply or dev iteration). "
                   "WARNING: redirector SSH logs will contain the teamserver's clearnet IP. "
                   "Scrub with `conduit clean logs --redirector <name> --direct` after.")
@click.option("--playbook-tags", "playbook_tags", default=None,
              help="Pass --tags to the inner ansible-playbook (comma-separated: cert,config,tor).")
@click.option("--playbook-skip-tags", "playbook_skip_tags", default=None,
              help="Pass --skip-tags to the inner ansible-playbook (comma-separated).")
# DEPRECATED legacy flags. Keep working for one release, print a warning when used.
@click.option("--skip-build", is_flag=True,
              help="DEPRECATED: use positive selectors (--teamserver, --redirector <name>, ...).")
@click.option("--skip-start", is_flag=True,
              help="DEPRECATED: use positive selectors.")
@click.option("--skip-redirectors", is_flag=True,
              help="DEPRECATED: use positive selectors.")
@click.option("--skip-relays", is_flag=True,
              help="DEPRECATED: use positive selectors.")
@click.option("--only", "only_redirector", default=None,
              help="DEPRECATED: use --redirector <name>.")
@click.option("--only-relay", default=None,
              help="DEPRECATED: use --relay <name>.")
def apply(
    config_path: Path,
    staging_dir: Path,
    assume_yes: bool,
    run_teamserver: bool,
    run_ts_onion: bool,
    run_redirector: str | None,
    run_relay: str | None,
    no_torsocks: bool,
    playbook_tags: str | None,
    playbook_skip_tags: str | None,
    skip_build: bool,
    skip_start: bool,
    skip_redirectors: bool,
    skip_relays: bool,
    only_redirector: str | None,
    only_relay: str | None,
) -> None:
    """Apply one node at a time. Pick one selector:

      --teamserver              teamserver docker stack
      --ts-onion                Tor hidden service on the teamserver
      --redirector <name>       one openresty redirector
      --relay <name>            one relay

    Combinations like --relay + --redirector compose. For a one-shot full
    deploy, use `conduit deploy --all` which has proper stage ordering,
    resume support, and interactive confirmation.

    Legacy --skip-* / --only flags still work but print a deprecation warning.
    """
    cfg = _load_or_exit(config_path)

    # Resolve positive vs legacy selector mode.
    positive_used = bool(run_teamserver or run_ts_onion or run_redirector or run_relay)
    legacy_used = bool(
        skip_build or skip_start or skip_redirectors or skip_relays
        or only_redirector or only_relay
    )

    if not positive_used and not legacy_used:
        click.echo(
            "[!] `conduit apply` requires at least one selector. Pick one of:\n"
            "      --teamserver            teamserver docker stack\n"
            "      --ts-onion              Tor hidden service on the teamserver\n"
            "      --redirector <name>     one openresty redirector\n"
            "      --relay <name>          one relay\n"
            "    For a one-shot full deploy, use `conduit deploy --all`.",
            err=True,
        )
        raise SystemExit(2)

    if positive_used and legacy_used:
        click.echo(
            "[!] Cannot mix positive selectors (--all, --teamserver, --ts-onion, --redirector, --relay) "
            "with legacy flags (--skip-build, --skip-start, --skip-redirectors, --skip-relays, --only, --only-relay).",
            err=True,
        )
        raise SystemExit(2)

    if legacy_used:
        click.echo(
            "[!] WARNING: --skip-* and --only flags are deprecated. "
            "Prefer --teamserver / --ts-onion / --redirector <name> / --relay <name>."
        )

    # Translate positive selectors to the internal (skip_*, only_*) model
    # so the existing phase code below stays unchanged.
    if positive_used:
        if run_ts_onion and run_redirector:
            click.echo(
                "[!] --ts-onion and --redirector are mutually exclusive. "
                "Run them in separate `conduit apply` invocations.",
                err=True,
            )
            raise SystemExit(2)

        # Default to "nothing runs"; each selector flips its phase on.
        skip_build = not run_teamserver
        skip_start = not run_teamserver

        if run_ts_onion:
            ts_name = next(
                (r.name for r in cfg.redirectors
                 if r.type.value == "tor-hidden-service" and r.enabled),
                None,
            )
            if ts_name is None:
                click.echo(
                    "[!] --ts-onion requested but no enabled tor-hidden-service "
                    "entry found in redirectors[]. Check the config.",
                    err=True,
                )
                raise SystemExit(2)
            skip_redirectors = False
            only_redirector = ts_name
        elif run_redirector:
            skip_redirectors = False
            only_redirector = run_redirector
        else:
            skip_redirectors = True
            only_redirector = None

        if run_relay:
            skip_relays = False
            only_relay = run_relay
        else:
            skip_relays = True
            only_relay = None

    click.echo("[*] 1/6 render")
    written = renderer.render_all(cfg, staging_dir)
    click.echo(f"    rendered {len(written)} file(s) under {staging_dir}")

    click.echo("[*] 2/6 preflight")
    need_docker = not (skip_build and skip_start)
    problems = applymod.preflight(cfg, need_docker=need_docker)
    if problems:
        click.echo(f"[!] preflight found {len(problems)} problem(s):")
        for p in problems:
            click.echo(f"    - {p}")
        raise SystemExit(1)

    if not assume_yes:
        click.confirm(
            f"[?] apply to {cfg.install.target.value} target "
            f"({cfg.install.target_host.address if cfg.install.target_host else 'localhost'})?",
            abort=True,
        )

    if need_docker:
        click.echo("[*] 3/6 transfer + clone sources")
        applymod.transfer(cfg, staging_dir)
        applymod.clone_sources(cfg)
    else:
        click.echo("[*] 3/6 transfer + clone sources (skipped, redirector-only run)")

    if not skip_build:
        click.echo("[*] 4a/6 docker compose build")
        applymod.compose_build(cfg)
    else:
        click.echo("[*] 4a/6 docker compose build (skipped)")

    if not skip_start:
        click.echo("[*] 4b/6 docker compose up -d")
        applymod.compose_up(cfg)
    else:
        click.echo("[*] 4b/6 docker compose up -d (skipped)")

    if not skip_relays:
        click.echo("[*] 5/6 deploy relays")
        applymod.deploy_relays(
            cfg, staging_dir, only=only_relay,
            no_torsocks=no_torsocks,
            playbook_tags=playbook_tags,
            playbook_skip_tags=playbook_skip_tags,
        )
    else:
        click.echo("[*] 5/6 deploy relays (skipped)")

    if not skip_redirectors:
        click.echo("[*] 6/6 deploy redirectors")
        applymod.deploy_redirectors(
            cfg, staging_dir, only=only_redirector,
            no_torsocks=no_torsocks,
            playbook_tags=playbook_tags,
            playbook_skip_tags=playbook_skip_tags,
        )
        if run_ts_onion:
            discovered = state_mod.refresh_after_ts_onion(config_path, cfg)
            if discovered:
                for key, onion in discovered.items():
                    click.echo(f"    state: {key} = {onion}")
            else:
                log.warn("state: no ts_onion discovered (non-loopback deploy or hostname file missing)")
    else:
        click.echo("[*] 6/6 deploy redirectors (skipped)")

    click.echo("[+] apply complete")

    if no_torsocks:
        click.echo("")
        click.echo("[!] --no-torsocks was used. Node SSH logs now contain the teamserver's clearnet IP.")
        click.echo("    Scrub each node you just touched with:")
        if only_relay:
            click.echo(f"      conduit clean logs --config {config_path} --relay {only_relay} --skip-teamserver --yes")
        if only_redirector:
            click.echo(f"      conduit clean logs --config {config_path} --redirector {only_redirector} --direct --skip-teamserver --yes")
        if not only_relay and not only_redirector:
            click.echo(f"      conduit clean logs --config {config_path} --all --direct --yes")


@main.command()
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--staging", "staging_dir", type=click.Path(path_type=Path), required=True,
              help="Where to render artifacts between stages.")
@click.option("--stage", "stage",
              type=click.Choice(deploymod.STAGES, case_sensitive=False),
              default=None,
              help="Run one named stage. Mutually exclusive with --all.")
@click.option("--all", "run_all", is_flag=True,
              help="Run every stage in order (teamserver → nebula → relays → redirectors → mesh).")
@click.option("--from", "from_stage",
              type=click.Choice(deploymod.STAGES, case_sensitive=False),
              default=None,
              help="With --all: resume starting from this stage.")
@click.option("--interactive", is_flag=True,
              help="With --all: pause between stages for operator confirmation. Default is non-interactive.")
@click.option("--yes", "assume_yes", is_flag=True,
              help="Accept any confirmation prompts without asking.")
@click.option("--dry-run", "dry_run", is_flag=True,
              help="Print the plan without executing anything.")
@click.option("--only", "only_node", default=None,
              help="With --stage relays or --stage redirectors or --stage scrub: act on just this one named node.")
@click.option("--skip-docker", "skip_docker", is_flag=True,
              help="With --stage teamserver: skip docker build + start (the stack is already running).")
@click.option("--direct", "direct", is_flag=True,
              help="With --stage scrub: scrub redirectors via direct public-IP SSH (bypass overlay). Required when the mesh is down.")
@click.option("--include-teamserver", "include_teamserver", is_flag=True,
              help="With --stage scrub: also run cleanup on the teamserver (local). Off by default.")
@click.option("-v", "--verbose", "verbose_count", count=True,
              help="Repeat for more verbosity (-v, -vv, -vvv). Passed through to downstream ops.")
def deploy(
    config_path: Path,
    staging_dir: Path,
    stage: str | None,
    run_all: bool,
    from_stage: str | None,
    interactive: bool,
    assume_yes: bool,
    dry_run: bool,
    only_node: str | None,
    skip_docker: bool,
    direct: bool,
    include_teamserver: bool,
    verbose_count: int,
) -> None:
    """High-level orchestrator: 5 stages that wrap the manual step-by-step.

    Typical first deploy without --all (5 commands):

        conduit deploy --stage teamserver   --config local.yml --staging /tmp/conduit-staging
        conduit deploy --stage nebula       --config local.yml --staging /tmp/conduit-staging
        conduit deploy --stage relays       --config local.yml --staging /tmp/conduit-staging
        conduit deploy --stage redirectors  --config local.yml --staging /tmp/conduit-staging
        conduit deploy --stage mesh         --config local.yml --staging /tmp/conduit-staging

    Or in one shot:

        conduit deploy --all                --config local.yml --staging /tmp/conduit-staging

    The low-level primitives (`conduit apply`, `conduit nebula`, `conduit clean`,
    `conduit ca`) remain available for surgical operations.
    """
    if bool(stage) == bool(run_all):
        click.echo("[!] pass exactly one of --stage <name> or --all", err=True)
        raise SystemExit(2)

    if from_stage and not run_all:
        click.echo("[!] --from requires --all", err=True)
        raise SystemExit(2)

    if interactive and not run_all:
        click.echo("[!] --interactive requires --all", err=True)
        raise SystemExit(2)

    if verbose_count > 0:
        log.set_verbose(True)

    cfg = _load_or_exit(config_path)

    def _confirm(st: str) -> bool:
        if assume_yes:
            return True
        return click.confirm(f"[?] run stage '{st}'?", default=True)

    try:
        if run_all:
            deploymod.run_all(
                cfg, config_path, staging_dir,
                from_stage=from_stage,
                interactive=interactive,
                dry_run=dry_run,
                verbose=verbose_count,
                only=only_node,
                skip_docker=skip_docker,
                direct=direct,
                include_teamserver=include_teamserver,
                confirm_fn=_confirm,
            )
        else:
            deploymod.run_stage(
                cfg, config_path, staging_dir,
                stage=stage,
                dry_run=dry_run,
                verbose=verbose_count,
                only=only_node,
                skip_docker=skip_docker,
                direct=direct,
                include_teamserver=include_teamserver,
            )
    except deploymod.StageError as e:
        click.echo(f"[!] {e}", err=True)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
