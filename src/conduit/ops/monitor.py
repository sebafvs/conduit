from __future__ import annotations

import json
import shlex
import subprocess
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from .. import log
from ..core.config import Config, RedirectorType
from .ssh import KitError, run, torsocks_prefix, relay_ssh_base, ssh_to_redirector


_TIMER_NAMES = ["conduit-health", "conduit-logpull"]


def _parse_interval(interval: str) -> int:
    """Convert a human interval like '5m' or '30m' to seconds."""
    s = interval.strip().lower()
    if s.endswith("m"):
        return int(s[:-1]) * 60
    if s.endswith("h"):
        return int(s[:-1]) * 3600
    if s.endswith("s"):
        return int(s[:-1])
    return int(s)


def install_timers(cfg: Config, config_path: Path) -> None:
    """Install systemd timer + service units for health check and logpull."""
    import shutil
    conduit_bin = shutil.which("conduit")
    if not conduit_bin:
        conduit_bin = "conduit"
    abs_config = str(config_path.resolve())

    units = []

    hc = cfg.management.monitoring.health_check
    if hc.enabled:
        hc_sec = _parse_interval(hc.interval)
        units.append(("conduit-health", f"{conduit_bin} monitor health --config {abs_config}", hc_sec))

    lp = cfg.management.monitoring.logpull
    if lp.enabled:
        lp_sec = _parse_interval(lp.interval)
        units.append(("conduit-logpull", f"{conduit_bin} monitor logpull --config {abs_config}", lp_sec))

    for name, exec_start, interval_sec in units:
        svc = (
            f"[Unit]\n"
            f"Description=conduit {name}\n\n"
            f"[Service]\n"
            f"Type=oneshot\n"
            f"ExecStart={exec_start}\n"
        )
        timer = (
            f"[Unit]\n"
            f"Description=conduit {name} timer\n\n"
            f"[Timer]\n"
            f"OnBootSec=60\n"
            f"OnUnitActiveSec={interval_sec}\n"
            f"Persistent=true\n\n"
            f"[Install]\n"
            f"WantedBy=timers.target\n"
        )
        svc_path = Path(f"/etc/systemd/system/{name}.service")
        timer_path = Path(f"/etc/systemd/system/{name}.timer")
        svc_path.write_text(svc)
        timer_path.write_text(timer)
        log.info(f"wrote {svc_path} + {timer_path}")

    subprocess.run(["systemctl", "daemon-reload"], check=True)
    for name, _, _ in units:
        subprocess.run(["systemctl", "enable", "--now", f"{name}.timer"], check=True)
        log.ok(f"enabled {name}.timer")


def remove_timers() -> None:
    """Stop and remove monitoring systemd timers."""
    for name in _TIMER_NAMES:
        timer_path = Path(f"/etc/systemd/system/{name}.timer")
        svc_path = Path(f"/etc/systemd/system/{name}.service")
        if timer_path.exists():
            subprocess.run(["systemctl", "disable", "--now", f"{name}.timer"], check=False)
            timer_path.unlink()
            log.info(f"removed {timer_path}")
        if svc_path.exists():
            svc_path.unlink()
            log.info(f"removed {svc_path}")
    subprocess.run(["systemctl", "daemon-reload"], check=True)


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _send_telegram(cfg: Config, message: str) -> None:
    tg = cfg.management.monitoring.telegram
    if not tg.enabled:
        return
    try:
        data = json.dumps({
            "chat_id": tg.chat_id,
            "text": message,
            "parse_mode": "Markdown",
        }).encode()
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{tg.token}/sendMessage",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=10)
        log.detail("telegram alert sent")
    except Exception as e:
        log.warn(f"telegram send failed: {e}")


def health_check(cfg: Config, *, only: str | None = None) -> int:
    """Check each redirector's health_url. Returns count of failures.

    Tracks up/down state so transitions trigger telegram alerts.
    """
    hc = cfg.management.monitoring.health_check
    state_dir = Path("/opt/conduit/state")
    state_dir.mkdir(parents=True, exist_ok=True)
    log_file = Path("/opt/conduit/health.log")

    def _log(msg: str) -> None:
        line = f"{_now_utc()} {msg}\n"
        log.always(line.strip())
        try:
            with open(log_file, "a") as f:
                f.write(line)
        except OSError:
            pass

    failed = 0
    checked = 0

    for r in cfg.redirectors:
        if not r.enabled:
            continue
        if only and r.name != only:
            continue
        if not r.health_url:
            log.detail(f"skip '{r.name}': no health_url")
            continue

        checked += 1
        log.info(f"checking '{r.name}' ({r.health_url})")
        state_file = state_dir / f"{r.name}.state"
        prev_state = state_file.read_text().strip() if state_file.exists() else "up"

        torsocks = "torsocks " if hc.torsocks else ""
        curl_cmd = (
            f"{torsocks}curl -sk -D - -o /dev/null "
            f"-w '\\nHTTP_CODE=%{{http_code}}' "
            f"--connect-timeout {hc.connect_timeout} "
            f"--max-time {hc.max_time} "
            f"{shlex.quote(r.health_url)}"
        )

        result = run(["bash", "-c", curl_cmd], check=False, capture_output=True, text=True)

        errors: list[str] = []
        if result.returncode != 0:
            errors.append("connection failed")
        else:
            output = result.stdout
            status = ""
            for line in output.splitlines():
                if line.startswith("HTTP_CODE="):
                    status = line.split("=", 1)[1]

            if status != "302":
                errors.append(f"expected HTTP 302, got {status}")
            if "server: cloudflare" not in output.lower():
                errors.append("missing Server: cloudflare header")
            if "location:" in output.lower() and "wikipedia" not in output.lower():
                errors.append("missing Wikipedia redirect")

        if errors:
            state_file.write_text("down")
            error_str = ", ".join(errors)
            _log(f"FAIL {r.name}: {error_str}")
            if prev_state == "up":
                _send_telegram(cfg, f"*{r.name} DOWN*\n{r.health_url}\n{error_str}")
            failed += 1
        else:
            state_file.write_text("up")
            if prev_state == "down":
                _log(f"RECOVERED {r.name}")
                _send_telegram(cfg, f"*{r.name} RECOVERED*\n{r.health_url}")
            else:
                _log(f"OK {r.name}")

    if failed > 0:
        _log(f"SUMMARY: {failed}/{checked} redirectors down")

    return failed


def logpull(cfg: Config, *, only: str | None = None) -> None:
    """Pull logs from each redirector via relay hop."""
    lp = cfg.management.monitoring.logpull
    log_dir = Path(str(lp.log_dir))
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = Path("/opt/conduit/logpull.log")

    def _log(msg: str) -> None:
        line = f"{_now_utc()} {msg}\n"
        log.always(line.strip())
        try:
            with open(log_file, "a") as f:
                f.write(line)
        except OSError:
            pass

    relay_ssh = relay_ssh_base(cfg)

    for r in cfg.redirectors:
        if not r.enabled or not r.nebula.enabled:
            continue
        if only and r.name != only:
            continue

        overlay_ip = r.nebula.overlay_ip.split("/")[0]
        dest_base = log_dir / r.name
        dest_base.mkdir(parents=True, exist_ok=True)
        log.info(f"pulling logs from '{r.name}' ({overlay_ip})")

        for remote_path in lp.log_paths:
            dir_part = str(Path(remote_path).parent).replace("/", "_")
            local_dir = dest_base / dir_part
            local_dir.mkdir(parents=True, exist_ok=True)

            rsync_inner = (
                f"rsync -az --rsync-path='sudo rsync' "
                f"-e 'ssh -o ConnectTimeout={lp.connect_timeout} "
                f"-o BatchMode=yes -o StrictHostKeyChecking=accept-new' "
                f"ubuntu@{overlay_ip}:{shlex.quote(remote_path)} "
                f"/tmp/c2-logpull-staging/"
            )

            fetch_cmd = torsocks_prefix(cfg) + relay_ssh + [
                "--", "bash", "-c",
                shlex.quote(
                    f"mkdir -p /tmp/c2-logpull-staging && {rsync_inner} && "
                    f"cat /tmp/c2-logpull-staging/$(basename {shlex.quote(remote_path)})"
                ),
            ]

            result = run(fetch_cmd, check=False, capture_output=True, text=True)
            if result.returncode == 0:
                filename = Path(remote_path).name
                out_file = local_dir / filename
                out_file.write_text(result.stdout)
                _log(f"OK {r.name} {remote_path}")
            else:
                _log(f"FAIL {r.name} {remote_path}")
                if result.stderr.strip():
                    log.always(result.stderr.strip()[:200])


def tor_status(cfg: Config, *, only: str | None = None) -> int:
    """Check tor + gost on each redirector that has tor_client enabled.

    For each:
      1. tor service status
      2. gost service status
      3. tor SOCKS connectivity (curl through local SOCKS5)
      4. full chain round-trip: curl through gost listen port to the .onion

    Returns count of failures.
    """
    failed = 0
    checked = 0

    for r in cfg.redirectors:
        if not r.enabled or not r.nebula.enabled:
            continue
        if only and r.name != only:
            continue
        if r.type != RedirectorType.openresty_vps:
            continue

        typed = r.typed_config()
        if not hasattr(typed, "tor_client") or not typed.tor_client.enabled:
            log.detail(f"skip '{r.name}': tor_client not enabled")
            continue

        checked += 1
        overlay_ip = r.nebula.overlay_ip.split("/")[0]
        rd_ssh = ssh_to_redirector(cfg, overlay_ip)
        tc = typed.tor_client

        log.info(f"tor check: {r.name} ({overlay_ip})")
        node_ok = True

        # 1. tor service
        try:
            svc_check = subprocess.run(
                rd_ssh + ["--", "systemctl", "is-active", "tor"],
                capture_output=True, text=True, timeout=15,
            )
            tor_active = svc_check.returncode == 0
        except FileNotFoundError:
            print(f"  [!] cannot reach {r.name}: torsocks not installed on this host")
            failed += 1
            continue
        except subprocess.TimeoutExpired:
            print(f"  [!] cannot reach {r.name}: SSH timeout")
            failed += 1
            continue
        marker = "+" if tor_active else "!"
        print(f"  [{marker}] tor service: {'active' if tor_active else svc_check.stdout.strip()}")
        if not tor_active:
            node_ok = False

        # 2. gost service
        svc_check = subprocess.run(
            rd_ssh + ["--", "systemctl", "is-active", "gost"],
            capture_output=True, text=True, timeout=15,
        )
        gost_active = svc_check.returncode == 0
        marker = "+" if gost_active else "!"
        print(f"  [{marker}] gost service: {'active' if gost_active else svc_check.stdout.strip()}")
        if not gost_active:
            node_ok = False

        # Probes deliver scripts via stdin to `bash -s` because this SSH chain
        # is nested (teamserver -> relay -> redirector). `bash -c <quoted>`
        # only survives a single hop: the inner ssh re-tokenizes the command
        # string and strips the outer quoting, so `bash -c` receives only the
        # first word and the rest become positional args (curl usage error).
        # Same bug class and fix as remote_exec in ops/ssh.py (CONDUIT-001).
        rd_shell = rd_ssh + ["--", "bash", "-s"]

        # 3. tor SOCKS5 probe (connect through tor on 9050)
        socks_script = (
            "curl -s --socks5-hostname 127.0.0.1:9050 "
            "--connect-timeout 15 --max-time 20 "
            "-o /dev/null -w '%{http_code}' "
            "https://check.torproject.org/ 2>/dev/null || echo 'FAIL'"
        )
        socks_result = subprocess.run(
            rd_shell, input=socks_script, text=True,
            capture_output=True, timeout=30,
        )
        socks_out = socks_result.stdout.strip()
        socks_ok = socks_result.returncode == 0 and socks_out not in ("FAIL", "", "000")
        marker = "+" if socks_ok else "!"
        print(f"  [{marker}] tor SOCKS5 probe: HTTP {socks_out}")
        if not socks_ok:
            node_ok = False

        # 4. gost round-trip: curl through gost listen port (which forwards to .onion via tor)
        gost_port = tc.gost_listen_port
        onion = tc.onion_address
        gost_script = (
            f"curl -sk --connect-timeout 15 --max-time 25 "
            f"-o /dev/null -w '%{{http_code}}' "
            f"https://127.0.0.1:{gost_port}/ 2>/dev/null || echo 'FAIL'"
        )
        gost_result = subprocess.run(
            rd_shell, input=gost_script, text=True,
            capture_output=True, timeout=35,
        )
        gost_out = gost_result.stdout.strip()
        gost_ok = gost_result.returncode == 0 and gost_out not in ("FAIL", "", "000")
        marker = "+" if gost_ok else "!"
        print(f"  [{marker}] gost chain ({onion}:{tc.onion_port} via :{gost_port}): HTTP {gost_out}")
        if not gost_ok:
            node_ok = False

        # 5. tor control port circuit info (if cookie auth)
        if tc.control_port and tc.cookie_auth:
            circuit_script = (
                f"echo -e 'AUTHENTICATE \"\"\\r\\nGETINFO circuit-status\\r\\nQUIT\\r' | "
                f"nc -q 1 127.0.0.1 {tc.control_port} 2>/dev/null | "
                f"grep -c BUILT; true"
            )
            circ_result = subprocess.run(
                rd_shell, input=circuit_script, text=True,
                capture_output=True, timeout=15,
            )
            circ_count = (circ_result.stdout.strip().split("\n")[0] or "0")
            print(f"  [*] tor circuits BUILT: {circ_count}")

        if not node_ok:
            failed += 1
        print()

    if checked == 0:
        log.warn("no redirectors with tor_client enabled")
    elif failed == 0:
        log.ok(f"all {checked} tor redirector(s) healthy")
    else:
        log.warn(f"{failed}/{checked} tor redirector(s) have issues")

    return failed
