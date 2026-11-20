from __future__ import annotations

from .. import log
from ..core.config import Config
from .ssh import KitError, run, ssh_for_relay, ssh_to_redirector, ssh_direct_to_redirector, remote_exec, torsocks_prefix


# Shared: wiped by both `logs` and `destroy`
_LOG_SCRIPT = """
set +e

# 1. SSH / auth logs (source IPs from every inbound connection)
rm -f /var/log/auth.log* /var/log/secure* /var/log/btmp* /var/log/wtmp* /var/log/lastlog
> /var/log/auth.log 2>/dev/null
> /var/log/btmp 2>/dev/null
> /var/log/wtmp 2>/dev/null
> /var/log/lastlog 2>/dev/null

# 2. systemd journal.
#
# CONDUIT-001: we previously stopped systemd-journald, rm'd /var/log/journal,
# then restarted it. That dance killed every service whose stderr feeds
# journald (gost, nebula, tor) via SIGPIPE, and systemd treats SIGPIPE as
# a clean exit so Restart=on-failure does NOT recover. See RHBZ 1300076.
#
# New design (also per CONDUIT-001):
#   1. Volatile journald storage is deployed by the ansible role, so the
#      journal lives in /run/log/journal (tmpfs). A reboot wipes it.
#   2. sshd runs with LogLevel QUIET, openresty log_format drops $remote_addr.
#      Operator IPs never land in logs in the first place.
#   3. Scrub becomes a rotate-and-vacuum against the running daemon, not a
#      stop-restart. SIGUSR2 is journald's documented rotate signal; streams
#      stay connected, no SIGPIPE cascade.
journalctl --sync 2>/dev/null
systemctl kill --signal=SIGUSR2 systemd-journald 2>/dev/null
journalctl --rotate --vacuum-size=1K --vacuum-time=1s 2>/dev/null

# 3. shell history (commands typed interactively or by ansible)
rm -f /root/.bash_history /root/.zsh_history
rm -f /home/*/.bash_history /home/*/.zsh_history
for u in /root /home/*; do
    [ -d "$u" ] && : > "$u/.bash_history" 2>/dev/null
done

# 4. known_hosts (contains fingerprints + IPs of nodes we connected to)
rm -f /root/.ssh/known_hosts /home/*/.ssh/known_hosts

# 5. ansible / tmp artifacts
rm -rf /tmp/.ansible* /tmp/ansible* /tmp/c2-* /var/tmp/.ansible*
rm -f /root/.ansible/tmp/* 2>/dev/null

# 6. syslog / daemon / kern logs (may contain IP or process info)
rm -f /var/log/syslog* /var/log/daemon.log* /var/log/kern.log* /var/log/messages*
> /var/log/syslog 2>/dev/null

# 7. apt / dpkg logs (package install traces from provisioning)
rm -f /var/log/apt/*.log* /var/log/dpkg.log*

# 8. sudo / cron logs
rm -f /var/log/cron* /var/log/sudo.log*

# 9. utmp (current login records)
> /var/run/utmp 2>/dev/null

echo '[+] log cleanup done'
"""

# Destroy-only: crypto, app data, cloud-init, free space zeroing
_DESTROY_EXTRA_SCRIPT = """
set +e

# 10. nebula certificates + CA material (overlay mesh identity)
rm -rf /opt/nebula/ca /opt/nebula/*.crt /opt/nebula/*.key
rm -f /etc/nebula/*.crt /etc/nebula/*.key /etc/nebula/config.yaml
systemctl stop nebula 2>/dev/null
systemctl disable nebula 2>/dev/null

# 11. SSH CA trust (certificate authority public key)
rm -f /etc/ssh/ca/c2-ca.pub
sed -i '/TrustedUserCAKeys/d' /etc/ssh/sshd_config 2>/dev/null

# 12. SSH host keys (regenerated on next boot, but we are destroying)
rm -f /etc/ssh/ssh_host_*

# 13. authorized_keys (public keys that grant access)
rm -f /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys

# 14. SSH signed certificates (user + host certs from our CA)
find /root/.ssh /home/*/.ssh /etc/ssh -name '*-cert.pub' -delete 2>/dev/null

# 15. application logs (openresty, fail2ban, tor, gost, adaptix)
rm -rf /var/log/openresty /var/log/nginx
rm -f /var/log/fail2ban.log* /var/log/tor/log*
rm -rf /var/log/gost*
rm -rf /opt/adaptix/logs 2>/dev/null

# 16. payload files on redirectors
rm -rf /opt/payloads/*

# 17. cloud-init data (user-data scripts, instance metadata cache)
rm -rf /var/lib/cloud/instance /var/lib/cloud/data
rm -f /var/log/cloud-init*.log*

# 18. nftables / iptables state (reveals firewall topology)
rm -f /etc/nftables.conf.bak /var/log/nftables*

# 19. tor state + hidden service keys (if redirector runs tor)
rm -rf /var/lib/tor/hidden_service /var/lib/tor/state /var/lib/tor/cached-*

# 20. gost proxy state
rm -rf /opt/gost /usr/local/bin/gost

# 21. openresty config (reveals upstream teamserver onion address)
rm -rf /etc/openresty/conf.d/* /usr/local/openresty/nginx/conf/vhosts/*

# 22. systemd service files we deployed
rm -f /etc/systemd/system/nebula.service
rm -f /etc/systemd/system/gost.service
rm -f /etc/systemd/system/c2-health.service /etc/systemd/system/c2-health.timer
rm -f /etc/systemd/system/c2-logpull.service /etc/systemd/system/c2-logpull.timer
systemctl daemon-reload 2>/dev/null

# 23. zero free space (makes forensic recovery of deleted files harder)
dd if=/dev/zero of=/var/tmp/.zero bs=1M 2>/dev/null || true
sync
rm -f /var/tmp/.zero

echo '[+] destroy cleanup done'
"""

# Teamserver-specific cleanup
_TEAMSERVER_LOG_SCRIPT = """
set +e

# SSH / auth logs
rm -f /var/log/auth.log* /var/log/secure* /var/log/btmp* /var/log/wtmp* /var/log/lastlog
> /var/log/auth.log 2>/dev/null
> /var/log/btmp 2>/dev/null
> /var/log/wtmp 2>/dev/null
> /var/log/lastlog 2>/dev/null

# systemd journal: SIGUSR2 rotate against the running daemon.
# See CONDUIT-001 for the full rationale; mirror of _LOG_SCRIPT behavior.
journalctl --sync 2>/dev/null
systemctl kill --signal=SIGUSR2 systemd-journald 2>/dev/null
journalctl --rotate --vacuum-size=1K --vacuum-time=1s 2>/dev/null

# shell history
rm -f /root/.bash_history /root/.zsh_history
rm -f /home/*/.bash_history /home/*/.zsh_history
for u in /root /home/*; do
    [ -d "$u" ] && : > "$u/.bash_history" 2>/dev/null
done

# known_hosts
rm -f /root/.ssh/known_hosts /home/*/.ssh/known_hosts

# ansible artifacts + stale SSH ControlMaster sockets. The sockets at
# ~/.ansible/cp/ hang around after a killed/interrupted apply and make the
# next apply hang at "Gathering Facts" when ansible tries to reuse a dead
# mux socket (we spent real time debugging this once).
rm -rf /tmp/.ansible* /tmp/ansible* /tmp/c2-* /var/tmp/.ansible*
rm -rf /root/.ansible/cp/* /root/.ssh/cm-* /root/.ssh/mux-* 2>/dev/null

# syslog
rm -f /var/log/syslog* /var/log/daemon.log* /var/log/kern.log*
> /var/log/syslog 2>/dev/null

# conduit health-check and pull-log state (contain redirector names, timestamps)
# NOTE: do NOT wipe /opt/conduit/state/ here. It holds operational discovery
# values like ts_onion that the renderer needs to produce a correct config on
# every subsequent apply. Wiping it mid-engagement forces a hand-populate step
# before the next deploy can run (chicken-and-egg with the validator).
# `conduit clean destroy` is the right place to nuke everything, not log scrub.
rm -f /opt/conduit/*.log
rm -rf /opt/conduit/logs/*

# apt / dpkg
rm -f /var/log/apt/*.log* /var/log/dpkg.log*

# utmp
> /var/run/utmp 2>/dev/null

echo '[+] teamserver log cleanup done'
"""

_TEAMSERVER_DESTROY_EXTRA_SCRIPT = """
set +e

# SSH CA private key + signed cert log (the crown jewel)
rm -rf /opt/conduit/ssh-ca

# SSH host keys
rm -f /etc/ssh/ssh_host_*

# SSH signed certificates
find /root/.ssh /home/*/.ssh /etc/ssh -name '*-cert.pub' -delete 2>/dev/null

# authorized_keys
rm -f /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys

# docker volumes + images (adaptix data, beacon builds, operator DB)
docker compose -f /opt/adaptix/docker-compose.yml down -v 2>/dev/null
docker system prune -af --volumes 2>/dev/null

# adaptix install root
rm -rf /opt/adaptix

# payload staging
rm -rf /opt/adaptix/payloads /opt/payloads

# tor hidden service keys + state on teamserver
rm -rf /var/lib/tor/hidden_service /var/lib/tor/state /var/lib/tor/cached-*

# conduit controller state (ssh-ca, state, logs, keys, dashboard caches)
rm -rf /opt/conduit

# cloud-init
rm -rf /var/lib/cloud/instance /var/lib/cloud/data
rm -f /var/log/cloud-init*.log*

# systemd journal: SIGUSR2 rotate. Destroy path: after destruction we
# don't care about service survival, but the SIGUSR2 pattern is still
# correct (no reason to kill + risk hang during pre-termination cleanup).
# See CONDUIT-001.
journalctl --sync 2>/dev/null
systemctl kill --signal=SIGUSR2 systemd-journald 2>/dev/null
journalctl --rotate --vacuum-size=1K --vacuum-time=1s 2>/dev/null
# After vacuum, with volatile storage, /run/log/journal/ is nearly empty
# anyway. If the box is being nuked next, that is final.

# zero free space
dd if=/dev/zero of=/var/tmp/.zero bs=1M 2>/dev/null || true
sync
rm -f /var/tmp/.zero

echo '[+] teamserver destroy cleanup done'
"""


def clean_logs(
    cfg: Config,
    *,
    only: str | None = None,
    include_teamserver: bool = True,
    direct: bool = False,
    no_torsocks: bool = False,
) -> None:
    """Wipe logs and IP traces from all nodes. Safe to run mid-engagement.

    `direct=True` reaches redirectors via their public deploy address instead
    of the relay / nebula overlay hop. Needed post-apply before the mesh is up,
    or when nebula is intentionally not deployed.

    `no_torsocks=True` disables the torsocks wrapper for the scrub itself.
    The default (torsocks on, per `management.torsocks_management`) is almost
    always what you want: the scrub session's own SSH login then shows up on
    the target as coming from a Tor exit instead of from the teamserver's
    clearnet IP, so the IP being scrubbed does not reappear in the one log
    entry the scrub session itself creates.
    """

    failures: list[tuple[str, str]] = []

    def _attempt(label: str, runner) -> None:
        try:
            result = runner()
        except Exception as exc:
            failures.append((label, str(exc)))
            log.warn(f"{label}: {exc}")
            return
        if result.returncode != 0:
            err = (getattr(result, "stderr", "") or "").strip() or f"exit {result.returncode}"
            failures.append((label, err))
            log.warn(f"{label}: {err}")
            return
        log.ok(f"{label}: cleaned")

    # In verbose mode, stream remote stdout/stderr live. Without this, every
    # internal failure (sudo permission denied, systemctl refused, etc.) stays
    # silent because `capture_output=True` swallows both streams and the outer
    # script exits 0 (final `echo` succeeds under `set +e`). Keep the default
    # as captured so routine runs stay quiet.
    capture = not log.is_verbose()

    if include_teamserver and (only is None or only == "teamserver"):
        log.info("cleaning logs on teamserver (local)")
        _attempt(
            "teamserver",
            lambda: run(
                ["sudo", "bash", "-c", _TEAMSERVER_LOG_SCRIPT],
                check=False, capture_output=capture, text=True,
            ),
        )

    for rl in cfg.relays:
        if not rl.enabled:
            continue
        if only and only not in (rl.name, "relays"):
            continue
        log.info(f"cleaning logs on relay '{rl.name}' ({rl.deploy.address})")
        ssh = ssh_for_relay(cfg, rl)
        _attempt(f"relay '{rl.name}'", lambda s=ssh: remote_exec(s, _LOG_SCRIPT, capture_output=capture, text=True))

    for r in cfg.redirectors:
        if not r.enabled:
            continue
        if only and only not in (r.name, "redirectors"):
            continue
        # A loopback redirector (ts-onion is the canonical case) lives on the
        # teamserver filesystem; its logs ARE teamserver logs. The teamserver
        # local scrub already covers them, so we skip them here unless the
        # caller explicitly disables teamserver scrub and names the redirector
        # with --only (then we still skip but log, to avoid a false "cleaned").
        if str(r.deploy.address) in {"127.0.0.1", "localhost", "::1"}:
            if include_teamserver:
                log.detail(
                    f"skip redirector '{r.name}' (loopback target; "
                    f"logs covered by teamserver scrub)"
                )
            else:
                log.warn(
                    f"skip redirector '{r.name}' (loopback target; "
                    f"pass --include-teamserver to actually scrub its logs)"
                )
            continue
        if direct:
            tor = [] if no_torsocks else torsocks_prefix(cfg)
            route = "direct" if no_torsocks or not tor else "direct (torsocks)"
            log.info(f"cleaning logs on redirector '{r.name}' ({r.deploy.address}) {route}")
            ssh = tor + ssh_direct_to_redirector(r)
            _attempt(f"redirector '{r.name}' ({route})", lambda s=ssh: remote_exec(s, _LOG_SCRIPT, capture_output=capture, text=True))
        else:
            if not r.nebula.enabled:
                log.warn(
                    f"skip redirector '{r.name}' (nebula disabled; pass --direct to clean over the deploy address)"
                )
                continue
            overlay_ip = r.nebula.overlay_ip.split("/")[0]
            log.info(f"cleaning logs on redirector '{r.name}' ({overlay_ip}) via relay")
            ssh = ssh_to_redirector(cfg, overlay_ip)
            _attempt(f"redirector '{r.name}' (via relay)", lambda s=ssh: remote_exec(s, _LOG_SCRIPT, capture_output=capture, text=True))

    if failures:
        names = ", ".join(label for label, _ in failures)
        raise KitError(f"log cleanup failed on: {names}")


def clean_destroy(cfg: Config, *, only: str | None = None, include_teamserver: bool = True) -> None:
    """Full evidence destruction. Run before VM termination.

    Order: redirectors first (they depend on relay for connectivity),
    then relays, then teamserver last (it runs the commands).
    """

    for r in cfg.redirectors:
        if not r.enabled or not r.nebula.enabled:
            continue
        if only and only not in (r.name, "redirectors"):
            continue
        overlay_ip = r.nebula.overlay_ip.split("/")[0]
        log.info(f"destroying evidence on redirector '{r.name}' ({overlay_ip}) via relay")
        ssh = ssh_to_redirector(cfg, overlay_ip)
        remote_exec(ssh, _LOG_SCRIPT + _DESTROY_EXTRA_SCRIPT)

    for rl in cfg.relays:
        if not rl.enabled:
            continue
        if only and only not in (rl.name, "relays"):
            continue
        log.info(f"destroying evidence on relay '{rl.name}' ({rl.deploy.address})")
        ssh = ssh_for_relay(cfg, rl)
        remote_exec(ssh, _LOG_SCRIPT + _DESTROY_EXTRA_SCRIPT)

    if include_teamserver and (only is None or only == "teamserver"):
        log.info("destroying evidence on teamserver (local)")
        run(["sudo", "bash", "-c", _TEAMSERVER_LOG_SCRIPT + _TEAMSERVER_DESTROY_EXTRA_SCRIPT], check=False)
