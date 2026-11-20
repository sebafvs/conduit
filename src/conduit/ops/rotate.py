from __future__ import annotations

import shlex
import subprocess

from .. import log
from ..core.config import Config
from .ssh import torsocks_prefix, relay_ssh_base, ssh_for_relay, ssh_to_redirector
from . import nebula as nebulamod
from . import sshca as sshcamod


def rotate_all(cfg: Config, *, only: str | None = None) -> None:
    """Run all rotation steps: nebula certs, SSH host certs, LE certs."""
    log.info("=== nebula cert rotation ===")
    try:
        nebulamod.rotate_certs(cfg, only=only)
    except Exception as e:
        log.warn(f"nebula rotation failed: {e}")

    log.info("=== SSH host cert renewal ===")
    try:
        sshcamod.renew_host_certs(cfg, only=only)
    except Exception as e:
        log.warn(f"SSH host cert renewal failed: {e}")

    log.info("=== Let's Encrypt cert renewal ===")
    _renew_le_certs(cfg, only=only)

    log.ok("rotation complete")


def _renew_le_certs(cfg: Config, *, only: str | None = None) -> None:
    """Run certbot renew on each redirector that has LE certs."""
    relay_base = relay_ssh_base(cfg)

    for r in cfg.redirectors:
        if not r.enabled or not r.nebula.enabled:
            continue
        if only and r.name != only:
            continue

        overlay_ip = r.nebula.overlay_ip.split("/")[0]
        rd_ssh = ssh_to_redirector(cfg, overlay_ip)

        log.info(f"LE renewal: {r.name} ({overlay_ip})")
        try:
            result = subprocess.run(
                rd_ssh + ["--", "sudo", "certbot", "renew", "--non-interactive", "--quiet"],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0:
                log.ok(f"{r.name}: certbot renew OK")
            else:
                stderr = result.stderr.strip()
                if "no renewals were attempted" in stderr.lower() or "not yet due" in stderr.lower():
                    log.ok(f"{r.name}: certs not yet due for renewal")
                else:
                    log.warn(f"{r.name}: certbot renew failed (rc={result.returncode})")
                    if stderr:
                        log.always(stderr[:300])
        except FileNotFoundError:
            log.warn(f"{r.name}: cannot reach (torsocks not installed on this host)")
            continue
        except subprocess.TimeoutExpired:
            log.warn(f"{r.name}: certbot renew timed out")
            continue
