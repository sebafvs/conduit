from __future__ import annotations

import io
import json
import logging
import os
import re
import shlex
import subprocess
import sys
import threading
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

from rich.markup import escape as rich_escape
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.theme import Theme
from textual.widgets import Footer, Header, Input, RichLog, Static, Tab, Tabs

from ..core.config import Config

def _pick_state_dir() -> Path:
    """State dir resolution: /opt/conduit (preferred), else ~/.cache/conduit."""
    for candidate in (
        Path("/opt/conduit"),
        Path.home() / ".cache" / "conduit",
    ):
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            # Writable test
            probe = candidate / ".write-test"
            probe.touch()
            probe.unlink()
            return candidate
        except Exception:
            continue
    return Path("/tmp")


_STATE_DIR = _pick_state_dir()

_LOG_PATH = Path("/tmp/conduit-tui.log")
_COPY_PATH = Path("/tmp/conduit-output.txt")
_CACHE_PATH = _STATE_DIR / "dashboard-cache.json"
_SETTINGS_PATH = _STATE_DIR / "dashboard-settings.json"
_HEALTH_LOG = Path("/opt/conduit/health.log")
_EXPORT_DIR = Path("/tmp")
_log = logging.getLogger("conduit-tui")

_ANSI = re.compile(r"\x1b\[[0-9;]*m")

BLACK = "#000000"
PANEL = "#050505"
BORDER = "#1e293b"
MUTED = "#64748b"
FG = "#e2e8f0"
FG_DIM = "#94a3b8"

BLUE = "#60a5fa"
CYAN = "#22d3ee"
GREEN = "#4ade80"
RED = "#f87171"
AMBER = "#fbbf24"
PURPLE = "#a78bfa"


KIT_THEME = Theme(
    name="conduit-black",
    primary=BLUE,
    secondary=CYAN,
    accent=BLUE,
    foreground=FG,
    background=BLACK,
    surface=BLACK,
    panel=BLACK,
    boost="#0a0a0a",
    warning=AMBER,
    error=RED,
    success=GREEN,
    dark=True,
    variables={
        "footer-key-foreground": BLUE,
        "footer-key-background": BLACK,
        "footer-foreground": MUTED,
        "footer-background": BLACK,
        "footer-description-foreground": FG_DIM,
        "footer-description-background": BLACK,
        "block-cursor-background": BLUE,
        "block-cursor-foreground": BLACK,
        "block-cursor-blurred-background": BORDER,
    },
)

V_NORMAL = 0
V_VERBOSE = 1
V_DEBUG = 2
V_NAMES = ["NORMAL", "VERBOSE", "DEBUG"]

PROBE_TIMEOUT = 30
AUTO_REFRESH_INTERVALS = [15, 30, 60, 120, 300]

VIEWS = [
    ("overview",   "Overview",   "status.full_status"),
    ("tor",        "Tor",        "monitor.tor_status"),
    ("health",     "Health",     "monitor.health_check"),
    ("certs",      "Certs",      "sshca.ca_status"),
    ("logs",       "Logs",       "health events + ssh tail"),
    ("containers", "Containers", "docker ps"),
    ("config",     "Config",     "(local)"),
]
VIEW_KEYS = [v[0] for v in VIEWS]
VIEW_LABELS = {k: l for k, l, _ in VIEWS}
VIEW_PROBES = {k: p for k, _, p in VIEWS}


def _strip(text: str) -> str:
    return _ANSI.sub("", text)


def _markup(line: str, search_term: str = "") -> str:
    s = _strip(line)
    if not s.strip():
        return ""
    safe = rich_escape(s)
    if search_term and search_term.lower() in s.lower():
        # Highlight the match
        pat = re.compile(re.escape(search_term), re.IGNORECASE)
        safe = pat.sub(lambda m: f"[reverse {AMBER}]{rich_escape(m.group(0))}[/]", safe)

    if "TIMEOUT" in s or "COMMAND NOT FOUND" in s:
        return f"[bold {AMBER}]{safe}[/]"
    if "[+]" in s or "RECOVERED" in s:
        return f"[bold {GREEN}]{safe}[/]"
    if "[!]" in s or "FAIL" in s:
        return f"[bold {RED}]{safe}[/]"
    if "[*]" in s:
        return f"[{CYAN}]{safe}[/]"
    if s.startswith("  $ "):
        return f"[{FG_DIM}]{safe}[/]"
    if s.startswith("==="):
        return f"[bold {BLUE}]{safe}[/]"
    return f"[{FG}]{safe}[/]"


def _shortcmd(cmd) -> str:
    if not isinstance(cmd, (list, tuple)):
        return str(cmd)[:120]
    if len(cmd) > 6:
        head = " ".join(str(x) for x in cmd[:4])
        return f"{head} ... ({len(cmd)} args)"
    return " ".join(str(x) for x in cmd)


class StreamBuffer:
    """Thread-safe growing text buffer, drained incrementally by the UI."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._parts: list[str] = []

    def write(self, s) -> int:
        if not isinstance(s, str):
            try: s = s.decode("utf-8", errors="replace")
            except Exception: s = str(s)
        with self._lock:
            self._parts.append(s)
        return len(s)

    def flush(self) -> None:
        return

    def take_since(self, pos: int) -> tuple[str, int]:
        with self._lock:
            text = "".join(self._parts)
        if pos >= len(text):
            return "", len(text)
        return text[pos:], len(text)

    def getvalue(self) -> str:
        with self._lock:
            return "".join(self._parts)


def _run_capture(fn, cfg, stream: StreamBuffer, verbosity: int) -> None:
    """Monkey-patch subprocess.run + redirect sys.stdout to the StreamBuffer."""
    original_run = subprocess.run
    saved_sys_stdout = sys.stdout
    saved_sys_stderr = sys.stderr

    def patched_run(cmd, timeout=None, check=True, **kw):
        user_handles = any(k in kw for k in ("capture_output", "stdout", "stderr"))
        if timeout is None:
            timeout = PROBE_TIMEOUT
        if user_handles:
            try:
                return original_run(cmd, timeout=timeout, check=check, **kw)
            except subprocess.TimeoutExpired:
                stream.write(f"[!] TIMEOUT after {timeout}s: {_shortcmd(cmd)}\n")
                raise
        kw["capture_output"] = True
        kw["text"] = True
        try:
            result = original_run(cmd, timeout=timeout, check=False, **kw)
        except subprocess.TimeoutExpired as e:
            stream.write(f"[!] TIMEOUT after {timeout}s: {_shortcmd(cmd)}\n")
            if check: raise
            return subprocess.CompletedProcess(cmd, 124, "", str(e))
        except FileNotFoundError:
            stream.write(f"[!] COMMAND NOT FOUND: {cmd[0] if cmd else '(empty)'}\n")
            if check: raise
            return subprocess.CompletedProcess(cmd, 127, "", "command not found")
        if result.stdout: stream.write(result.stdout)
        if result.stderr: stream.write(result.stderr)
        if check and result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode, cmd, result.stdout, result.stderr
            )
        return result

    from .. import log as logmod
    old_verbose = logmod.is_verbose()
    try:
        subprocess.run = patched_run
        sys.stdout = stream
        sys.stderr = stream
        logmod.set_verbose(verbosity >= V_VERBOSE)
        stream.write(f"[*] probe: {fn.__module__}.{fn.__name__}\n")
        stream.write(f"[*] verbosity: {V_NAMES[verbosity]}, timeout: {PROBE_TIMEOUT}s\n\n")
        t0 = time.monotonic()
        try:
            fn(cfg)
        except SystemExit:
            pass
        except Exception as e:
            stream.write(f"[!] {type(e).__name__}: {e}\n")
            if verbosity >= V_DEBUG:
                stream.write(traceback.format_exc())
        dt = time.monotonic() - t0
        stream.write(f"\n[*] probe finished in {dt:.2f}s\n")
    finally:
        subprocess.run = original_run
        sys.stdout = saved_sys_stdout
        sys.stderr = saved_sys_stderr
        logmod.set_verbose(old_verbose)


def _load_settings() -> dict:
    try:
        return json.loads(_SETTINGS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_settings(settings: dict) -> None:
    try:
        _SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
        _SETTINGS_PATH.write_text(json.dumps(settings, indent=2), encoding="utf-8")
    except Exception as e:
        _log.debug("settings save failed: %s", e)


def _load_cache() -> dict:
    try: return json.loads(_CACHE_PATH.read_text(encoding="utf-8"))
    except Exception: return {}


def _save_cache(cache: dict) -> None:
    try:
        _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _CACHE_PATH.write_text(json.dumps(cache, indent=2), encoding="utf-8")
    except Exception as e:
        _log.debug("cache save failed: %s", e)


def render_alerts(cfg: Config) -> None:
    """Read the local health log and show recent events."""
    print(f"[*] health log: {_HEALTH_LOG}")
    print()
    if not _HEALTH_LOG.exists():
        print(f"[!] no log yet. Enable monitoring: conduit monitor enable --config <path>")
        return
    try:
        text = _HEALTH_LOG.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        print(f"[!] cannot read: {e}")
        return
    lines = text.strip().splitlines()
    tail = lines[-100:]
    fails = sum(1 for l in tail if "FAIL" in l)
    recovered = sum(1 for l in tail if "RECOVERED" in l)
    oks = sum(1 for l in tail if " OK " in l)
    print(f"=== last 100 events: {oks} OK, {fails} FAIL, {recovered} RECOVERED ===")
    print()
    for line in tail:
        print(line)


def render_containers(cfg: Config) -> None:
    """docker ps + stats on the teamserver (local).

    No `stream` arg: _run_capture redirects sys.stdout so print() lands in it.
    """
    print("[*] docker ps on teamserver")
    print()
    try:
        subprocess.run(["docker", "ps", "--format",
            "table {{.Names}}\t{{.Status}}\t{{.Ports}}"],
            timeout=10, check=False)
    except Exception as e:
        print(f"[!] {e}")
    print()
    print("[*] docker stats (one-shot)")
    print()
    try:
        subprocess.run(["docker", "stats", "--no-stream", "--format",
            "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"],
            timeout=10, check=False)
    except Exception as e:
        print(f"[!] {e}")


def render_logs(cfg: Config) -> None:
    """Show health events + tail logs on each redirector via relay hop."""
    from ..ops.ssh import ssh_to_redirector

    render_alerts(cfg)
    print()
    print("=" * 60)
    print()
    tail_script = (
        "echo '=== openresty access.log (last 20) ==='; "
        "tail -n 20 /var/log/openresty/access.log 2>/dev/null; "
        "echo; echo '=== gost.log (last 20) ==='; "
        "tail -n 20 /var/log/gost.log 2>/dev/null; "
        "echo; echo '=== tor (journalctl -n 10) ==='; "
        "journalctl -u tor -n 10 --no-pager 2>/dev/null"
    )
    for r in cfg.redirectors:
        if not r.enabled or not r.nebula.enabled:
            continue
        overlay = r.nebula.overlay_ip.split("/")[0]
        print(f"=== {r.name} ({overlay}) ===")
        ssh_cmd = ssh_to_redirector(cfg, overlay) + ["--", "sudo", "bash", "-s"]
        try:
            subprocess.run(ssh_cmd, input=tail_script, text=True, timeout=20, check=False)
        except Exception as e:
            print(f"[!] {e}")
        print()


def ssh_commands_for_nodes(cfg: Config) -> list[tuple[str, str]]:
    """Return [(label, ssh_command_line)] for every node, as the user asked:
    just the SSH command text, ready to copy-paste."""
    from ..ops.ssh import _ssh_for_relay, torsocks_prefix

    out: list[tuple[str, str]] = []
    tp = " ".join(torsocks_prefix(cfg))
    tp_prefix = tp + " " if tp else ""

    out.append(("# OPERATOR (direct, no tor): relays and teamserver", ""))
    for rl in cfg.relays:
        if not rl.enabled: continue
        cmd = _ssh_for_relay(rl)
        label = f"{rl.name}  ({'lighthouse' if rl.nebula.is_lighthouse else 'host'})  {rl.deploy.address}"
        out.append((label, " ".join(shlex.quote(x) for x in cmd)))

    ts_addr = getattr(cfg.teamserver, "address", None)
    if ts_addr:
        out.append(("teamserver", f"ssh root@{ts_addr}  # or your operator user"))
    else:
        out.append(("teamserver", "# cfg.teamserver has no address attribute"))

    out.append(("", ""))
    out.append(("# TEAMSERVER (through Tor): reach relays via torsocks", ""))
    for rl in cfg.relays:
        if not rl.enabled: continue
        cmd = _ssh_for_relay(rl)
        line = tp_prefix + " ".join(shlex.quote(x) for x in cmd)
        out.append((f"{rl.name} (via tor)", line))

    out.append(("", ""))
    out.append(("# TEAMSERVER (two-hop): reach redirectors through relay over Nebula", ""))
    try:
        from ..ops.ssh import relay_ssh_base
        rbase = relay_ssh_base(cfg)
        for r in cfg.redirectors:
            if not r.enabled or not r.nebula.enabled: continue
            overlay = r.nebula.overlay_ip.split("/")[0]
            inner = ["ssh", "-o", "StrictHostKeyChecking=accept-new",
                     "-o", "BatchMode=yes", f"ubuntu@{overlay}"]
            full = tp_prefix + " ".join(shlex.quote(x) for x in rbase) + \
                   " -- " + " ".join(shlex.quote(x) for x in inner)
            label = f"{r.name}  (overlay {overlay})  {r.deploy.address}"
            out.append((label, full))
    except Exception as e:
        out.append(("[!] no lighthouse configured", str(e)))

    return out


HELP_TEXT = f"""[bold {BLUE}]conduit dashboard: keybindings[/]

[bold {CYAN}]Navigation[/]
  1 2 3 4 5 6 7 8 9 0    jump to tab
  ← →                    previous / next tab
  q                      quit

[bold {CYAN}]Probe[/]
  r                      refresh current tab
  a                      toggle auto-refresh (cycles interval)
  v                      cycle verbosity: NORMAL → VERBOSE → DEBUG

[bold {CYAN}]Pane[/]
  /                      search in pane  (n / N to repeat)
  c                      copy raw to {_COPY_PATH}
  e                      export markdown to {_EXPORT_DIR}

[bold {CYAN}]Operator[/]
  s                      show SSH command lines for every node

[bold {CYAN}]Dialogs[/]
  ?                      this help
  Esc                    dismiss modal

[bold {CYAN}]Settings[/]
  Persisted at {_SETTINGS_PATH}
  Cache     at {_CACHE_PATH}
  Log       at {_LOG_PATH}

[dim]Press any key to close[/]
"""


class HelpModal(ModalScreen[None]):
    DEFAULT_CSS = f"""
    HelpModal {{
        align: center middle;
        background: {BLACK} 70%;
    }}
    #help-box {{
        width: 72;
        height: auto;
        max-height: 90%;
        background: {BLACK};
        border: solid {BLUE};
        padding: 1 2;
    }}
    #help-content {{
        background: {BLACK};
        color: {FG};
    }}
    """

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="help-box"):
            yield Static(HELP_TEXT, id="help-content")

    def on_key(self, event) -> None:
        self.dismiss()


class ShellCommandsModal(ModalScreen[None]):
    DEFAULT_CSS = f"""
    ShellCommandsModal {{
        align: center middle;
        background: {BLACK} 70%;
    }}
    #ssh-box {{
        width: 90%;
        height: 80%;
        background: {BLACK};
        border: solid {BLUE};
        padding: 1 2;
    }}
    RichLog {{
        background: {BLACK};
        color: {FG};
        scrollbar-background: {BLACK};
        scrollbar-color: {BORDER};
    }}
    """

    def __init__(self, cfg: Config):
        super().__init__()
        self.cfg = cfg

    def compose(self) -> ComposeResult:
        with Vertical(id="ssh-box"):
            yield Static(
                f"[bold {BLUE}]SSH command lines (copy / paste)[/]  "
                f"[{MUTED}]any key to close[/]",
                id="ssh-title",
            )
            yield RichLog(id="ssh-log", markup=True, wrap=False, auto_scroll=False)

    def on_mount(self) -> None:
        log_w = self.query_one("#ssh-log", RichLog)
        for label, cmd in ssh_commands_for_nodes(self.cfg):
            if label.startswith("#"):
                log_w.write(f"[bold {CYAN}]{rich_escape(label)}[/]")
                continue
            if not label and not cmd:
                log_w.write("")
                continue
            if label and not cmd:
                log_w.write(f"[{AMBER}]{rich_escape(label)}[/]")
                continue
            log_w.write(f"[{FG_DIM}]{rich_escape(label)}[/]")
            log_w.write(f"  [{GREEN}]{rich_escape(cmd)}[/]")
            log_w.write("")

    def on_key(self, event) -> None:
        self.dismiss()


class SearchModal(ModalScreen[str]):
    DEFAULT_CSS = f"""
    SearchModal {{
        align: center bottom;
        background: {BLACK} 50%;
    }}
    #search-box {{
        width: 60;
        height: 3;
        background: {BLACK};
        border: solid {BLUE};
        padding: 0 1;
    }}
    Input {{
        background: {BLACK};
        color: {FG};
    }}
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="search-box"):
            yield Input(placeholder="search in pane...  (Enter / Esc)", id="search-input")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value)

    def on_key(self, event) -> None:
        if event.key == "escape":
            self.dismiss("")


class DashboardApp(App):

    TITLE = "conduit"

    CSS = f"""
    Screen {{
        background: {BLACK};
        color: {FG};
    }}

    Header, HeaderIcon, HeaderTitle, HeaderClock {{
        background: {BLACK};
    }}

    HeaderTitle {{ color: {BLUE}; }}
    HeaderClock {{ color: {MUTED}; }}

    Footer, FooterKey {{
        background: {BLACK};
        color: {MUTED};
    }}

    Tabs, Tab {{
        background: {BLACK};
        color: {FG_DIM};
    }}

    Tabs > #tabs-scroll, Tabs > #tabs-scroll > #tabs-list {{
        background: {BLACK};
    }}

    Tab {{ padding: 0 1; }}

    Tab.-active {{
        color: {BLUE};
        text-style: bold;
    }}

    Underline > .underline--bar {{
        color: {BLUE};
        background: {BLACK};
    }}

    #pane {{
        width: 100%;
        height: 1fr;
        background: {BLACK};
        color: {FG};
        padding: 1 2;
        scrollbar-background: {BLACK};
        scrollbar-color: {BORDER};
        scrollbar-color-hover: {MUTED};
        scrollbar-color-active: {BLUE};
        scrollbar-size: 1 1;
        overflow-y: scroll;
        overflow-x: hidden;
    }}

    #status-bar {{
        width: 100%;
        height: 1;
        background: {PANEL};
        color: {MUTED};
        padding: 0 2;
    }}
    """

    BINDINGS = [
        Binding("r", "run_probe", "Refresh", show=True),
        Binding("a", "cycle_auto_refresh", "Auto", show=True),
        Binding("v", "cycle_verbosity", "Verb", show=True),
        Binding("slash", "search", "/", show=True),
        Binding("n", "search_next", "Next", show=False),
        Binding("N", "search_prev", "Prev", show=False),
        Binding("s", "shell_commands", "Shell", show=True),
        Binding("e", "export_pane", "Export", show=True),
        Binding("c", "copy_panel", "Copy", show=True),
        Binding("question_mark", "help", "?", show=True),
        Binding("q", "quit", "Quit", show=True),
        Binding("1", "go(0)", "1", show=False),
        Binding("2", "go(1)", "2", show=False),
        Binding("3", "go(2)", "3", show=False),
        Binding("4", "go(3)", "4", show=False),
        Binding("5", "go(4)", "5", show=False),
        Binding("6", "go(5)", "6", show=False),
        Binding("7", "go(6)", "7", show=False),
        Binding("8", "go(7)", "8", show=False),
        Binding("9", "go(8)", "9", show=False),
        Binding("0", "go(9)", "0", show=False),
    ]

    def __init__(self, cfg: Config, config_path: Path):
        super().__init__()
        self.cfg = cfg
        self.config_path = config_path

        settings = _load_settings()
        self._view = settings.get("last_view", "overview")
        if self._view not in VIEW_KEYS:
            self._view = "overview"
        self._verbosity = settings.get("verbosity", V_NORMAL)
        if self._verbosity not in (0, 1, 2):
            self._verbosity = V_NORMAL
        self._auto_refresh_idx = settings.get("auto_refresh_idx", -1)  # -1 = off

        self._cache: dict = _load_cache()
        self._loading = False
        self._dom_ready = False

        self._stream: StreamBuffer | None = None
        self._stream_pos = 0
        self._stream_timer = None
        self._tick_timer = None
        self._auto_timer = None
        self._probe_started_at = 0.0

        self._search_term = ""
        self._search_matches: list[int] = []
        self._search_cursor = 0

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Tabs(
            *[Tab(f"{i+1 if i<9 else 0} {label}", id=f"tab-{key}")
              for i, (key, label, _) in enumerate(VIEWS)],
            active=f"tab-{self._view}",
            id="tabs",
        )
        yield RichLog(
            id="pane",
            highlight=False,
            markup=True,
            wrap=False,
            max_lines=10000,
            auto_scroll=True,
        )
        yield Static("", id="status-bar")
        yield Footer()

    def on_mount(self) -> None:
        self.register_theme(KIT_THEME)
        self.theme = "conduit-black"
        self.sub_title = f"{self.cfg.meta.name}  ·  {self.config_path.name}"

    def on_ready(self) -> None:
        self._dom_ready = True
        self._paint_view(self._view)
        self._set_idle_status()
        if self._auto_refresh_idx >= 0:
            self._schedule_next_auto_refresh()

    def _persist(self) -> None:
        _save_settings({
            "last_view": self._view,
            "verbosity": self._verbosity,
            "auto_refresh_idx": self._auto_refresh_idx,
        })

    def _set_idle_status(self) -> None:
        auto = "OFF" if self._auto_refresh_idx < 0 else f"{AUTO_REFRESH_INTERVALS[self._auto_refresh_idx]}s"
        search = f"  search=\"{self._search_term}\"" if self._search_term else ""
        self._set_status(
            f"[{self._view}]  verb={V_NAMES[self._verbosity]}  auto={auto}{search}"
        )

    def _paint_view(self, view_key: str) -> None:
        if not self._dom_ready:
            return
        try:
            pane = self.query_one("#pane", RichLog)
        except Exception:
            return
        pane.clear()
        label = VIEW_LABELS.get(view_key, view_key)
        probe = VIEW_PROBES.get(view_key, "")
        cached = self._cache.get(view_key)
        header = f"[bold {BLUE}]{label}[/]  [{MUTED}]{probe}[/]"
        if cached:
            ts = cached.get("ts", "unknown")
            header += f"  [{MUTED}]cached {ts}[/]"
        pane.write(header)
        pane.write("")

        if cached:
            raw_lines = cached.get("raw", [])
            for line in raw_lines:
                mu = _markup(line, self._search_term)
                if mu:
                    pane.write(mu)
            self._recompute_search_matches(raw_lines)
        else:
            pane.write(f"[{MUTED}]No data yet. Press r to fetch.[/]")

        pane.scroll_home(animate=False)


    @on(Tabs.TabActivated)
    def _on_tab_activated(self, event: Tabs.TabActivated) -> None:
        if event.tab is None: return
        tab_id = event.tab.id or ""
        if not tab_id.startswith("tab-"): return
        key = tab_id[4:]
        if key in VIEW_KEYS and key != self._view:
            self._view = key
            self._paint_view(key)
            self._set_idle_status()
            self._persist()

    def action_go(self, index: int) -> None:
        if 0 <= index < len(VIEW_KEYS):
            try:
                self.query_one(Tabs).active = f"tab-{VIEW_KEYS[index]}"
            except Exception:
                pass

    def action_cycle_verbosity(self) -> None:
        self._verbosity = (self._verbosity + 1) % len(V_NAMES)
        self._set_status(f"verbosity = {V_NAMES[self._verbosity]}  (applies on next probe)")
        self._persist()

    def action_cycle_auto_refresh(self) -> None:
        """Cycle: OFF → 15s → 30s → 60s → 120s → 300s → OFF."""
        self._auto_refresh_idx += 1
        if self._auto_refresh_idx >= len(AUTO_REFRESH_INTERVALS):
            self._auto_refresh_idx = -1
        if self._auto_timer is not None:
            try: self._auto_timer.stop()
            except Exception: pass
            self._auto_timer = None
        if self._auto_refresh_idx < 0:
            self._set_status("auto-refresh = OFF")
        else:
            self._schedule_next_auto_refresh()
            self._set_status(
                f"auto-refresh = every {AUTO_REFRESH_INTERVALS[self._auto_refresh_idx]}s"
            )
        self._persist()

    def _schedule_next_auto_refresh(self) -> None:
        if self._auto_refresh_idx < 0:
            return
        delay = AUTO_REFRESH_INTERVALS[self._auto_refresh_idx]
        self._auto_timer = self.set_timer(delay, self._auto_fire)

    def _auto_fire(self) -> None:
        if self._auto_refresh_idx < 0:
            return
        if not self._loading:
            self.action_run_probe()
        else:
            # try again shortly, probe still running
            self.set_timer(5, self._auto_fire)


    def action_help(self) -> None:
        self.push_screen(HelpModal())

    def action_shell_commands(self) -> None:
        self.push_screen(ShellCommandsModal(self.cfg))

    def action_search(self) -> None:
        def done(term: str | None) -> None:
            self._search_term = (term or "").strip()
            self._paint_view(self._view)
            if self._search_term:
                if self._search_matches:
                    self._search_cursor = 0
                    self._set_status(
                        f"'{self._search_term}': {len(self._search_matches)} match(es)   "
                        f"n=next  N=prev"
                    )
                else:
                    self._set_status(f"'{self._search_term}': no matches")
            else:
                self._set_idle_status()
        self.push_screen(SearchModal(), done)

    def action_search_next(self) -> None:
        if not self._search_matches or not self._search_term:
            return
        self._search_cursor = (self._search_cursor + 1) % len(self._search_matches)
        self._set_status(
            f"'{self._search_term}': match {self._search_cursor + 1}/{len(self._search_matches)}"
        )

    def action_search_prev(self) -> None:
        if not self._search_matches or not self._search_term:
            return
        self._search_cursor = (self._search_cursor - 1) % len(self._search_matches)
        self._set_status(
            f"'{self._search_term}': match {self._search_cursor + 1}/{len(self._search_matches)}"
        )

    def _recompute_search_matches(self, raw_lines: list[str]) -> None:
        if not self._search_term:
            self._search_matches = []
            return
        term = self._search_term.lower()
        self._search_matches = [i for i, l in enumerate(raw_lines) if term in l.lower()]
        self._search_cursor = 0

    def action_export_pane(self) -> None:
        cached = self._cache.get(self._view) or {}
        raw = cached.get("raw", [])
        if not raw:
            self._set_status("nothing to export (empty cache)")
            return
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        out_path = _EXPORT_DIR / f"conduit-{self._view}-{ts}.md"
        try:
            with out_path.open("w", encoding="utf-8") as f:
                f.write(f"# conduit / {VIEW_LABELS.get(self._view)}\n\n")
                f.write(f"- probe: `{VIEW_PROBES.get(self._view)}`\n")
                f.write(f"- cached: {cached.get('ts', 'unknown')}\n")
                f.write(f"- exported: {datetime.now(timezone.utc).isoformat()}\n")
                f.write(f"- config: `{self.config_path}`\n\n")
                f.write("```\n")
                for l in raw:
                    f.write(l + "\n")
                f.write("```\n")
            self._set_status(f"exported → {out_path}")
        except Exception as e:
            self._set_status(f"export failed: {e}")


    def action_run_probe(self) -> None:
        if self._loading or not self._dom_ready:
            return
        self._loading = True
        self._probe_started_at = time.monotonic()
        self._stream = StreamBuffer()
        self._stream_pos = 0

        pane = self.query_one("#pane", RichLog)
        pane.clear()
        label = VIEW_LABELS.get(self._view, self._view)
        probe = VIEW_PROBES.get(self._view, "")
        pane.write(f"[bold {BLUE}]{label}[/]  [{MUTED}]{probe}[/]")
        pane.write("")
        pane.write(f"[{CYAN}]▶ running probe  (verb={V_NAMES[self._verbosity]}, timeout={PROBE_TIMEOUT}s/step)[/]")
        pane.write(f"[{MUTED}]  config: {self.config_path}[/]")
        hint = self._loading_targets_hint()
        if hint:
            pane.write(f"[{MUTED}]  {hint}[/]")
        pane.write("")

        self._set_status(f"[{self._view}]  running {probe}...  0s")
        self._stream_timer = self.set_interval(0.3, self._stream_tick)
        self._tick_timer = self.set_interval(1.0, self._tick_elapsed)

        getattr(self, f"_load_{self._view}")()

    def _loading_targets_hint(self) -> str:
        cfg = self.cfg
        v = self._view
        if v == "overview":
            names = [rl.name for rl in cfg.relays if rl.enabled] + \
                    [r.name for r in cfg.redirectors if r.enabled] + ["teamserver"]
            return f"targets: {', '.join(names)}"
        if v in ("tor", "health"):
            names = [r.name for r in cfg.redirectors if r.enabled]
            return f"targets: {', '.join(names)}" if names else ""
        if v == "logs":
            names = [r.name for r in cfg.redirectors if r.enabled]
            tail = f"targets: {', '.join(names)}" if names else "no redirectors"
            return f"health log: {_HEALTH_LOG}  +  {tail}"
        if v == "certs":
            return f"ca_dir: {cfg.management.ssh_ca.ca_dir}"
        if v == "containers":
            return "local docker daemon"
        return ""

    def _tick_elapsed(self) -> None:
        if not self._loading:
            return
        elapsed = int(time.monotonic() - self._probe_started_at)
        probe = VIEW_PROBES.get(self._view, "")
        extra = ""
        if self._auto_refresh_idx >= 0:
            extra = f"   auto={AUTO_REFRESH_INTERVALS[self._auto_refresh_idx]}s"
        self._set_status(
            f"[{self._view}]  running {probe}...  {elapsed}s elapsed   "
            f"verb={V_NAMES[self._verbosity]}{extra}"
        )

    def _stream_tick(self) -> None:
        if self._stream is None:
            return
        new_text, new_pos = self._stream.take_since(self._stream_pos)
        self._stream_pos = new_pos
        if not new_text:
            return
        try:
            pane = self.query_one("#pane", RichLog)
        except Exception:
            return
        for line in new_text.splitlines():
            s = _strip(line)
            if not s.strip():
                continue
            mu = _markup(line, self._search_term)
            if mu:
                pane.write(mu)

    def action_copy_panel(self) -> None:
        cached = self._cache.get(self._view) or {}
        raw = cached.get("raw", [])
        try:
            _COPY_PATH.write_text("\n".join(raw), encoding="utf-8")
            self._set_status(f"copied to {_COPY_PATH}")
        except Exception as e:
            self._set_status(f"copy failed: {e}")

    def _set_status(self, msg: str) -> None:
        try:
            self.query_one("#status-bar", Static).update(msg)
        except Exception:
            pass

    def _finish_probe(self, view_key: str) -> None:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        elapsed = time.monotonic() - self._probe_started_at
        full_text = self._stream.getvalue() if self._stream else ""
        lines = full_text.splitlines()
        raw = [_strip(l) for l in lines]
        self._cache[view_key] = {"ts": now, "raw": raw}
        _save_cache(self._cache)

        def _do():
            if self._stream_timer is not None:
                try: self._stream_timer.stop()
                except Exception: pass
                self._stream_timer = None
            if self._tick_timer is not None:
                try: self._tick_timer.stop()
                except Exception: pass
                self._tick_timer = None
            self._stream_tick()
            self._loading = False
            if self._view == view_key:
                try:
                    pane = self.query_one("#pane", RichLog)
                    pane.write("")
                    pane.write(f"[bold {GREEN}]done in {elapsed:.2f}s[/]  [{MUTED}]{now}[/]")
                    self._recompute_search_matches(raw)
                except Exception:
                    pass
                self._set_idle_status()
            if self._auto_refresh_idx >= 0:
                self._schedule_next_auto_refresh()
        self.call_from_thread(_do)


    @work(thread=True, exclusive=True, group="probe")
    def _load_overview(self) -> None:
        from ..ops import status as statusmod
        _run_capture(statusmod.full_status, self.cfg, self._stream, self._verbosity)
        self._finish_probe("overview")

    @work(thread=True, exclusive=True, group="probe")
    def _load_tor(self) -> None:
        from ..ops import monitor as monitormod
        _run_capture(monitormod.tor_status, self.cfg, self._stream, self._verbosity)
        self._finish_probe("tor")

    @work(thread=True, exclusive=True, group="probe")
    def _load_health(self) -> None:
        from ..ops import monitor as monitormod
        _run_capture(monitormod.health_check, self.cfg, self._stream, self._verbosity)
        self._finish_probe("health")

    @work(thread=True, exclusive=True, group="probe")
    def _load_certs(self) -> None:
        from ..ops import sshca as sshcamod
        _run_capture(sshcamod.ca_status, self.cfg, self._stream, self._verbosity)
        self._finish_probe("certs")

    @work(thread=True, exclusive=True, group="probe")
    def _load_logs(self) -> None:
        _run_capture(render_logs, self.cfg, self._stream, self._verbosity)
        self._finish_probe("logs")

    @work(thread=True, exclusive=True, group="probe")
    def _load_containers(self) -> None:
        _run_capture(render_containers, self.cfg, self._stream, self._verbosity)
        self._finish_probe("containers")

    @work(thread=True, exclusive=True, group="probe")
    def _load_config(self) -> None:
        cfg = self.cfg
        stream = self._stream
        if stream is None: return

        def kv(key: str, val: str) -> None:
            stream.write(f"  {key:<22s}  {val}\n")

        def section(title: str) -> None:
            stream.write(f"\n=== {title} ===\n")

        stream.write(f"[*] config: {self.config_path}\n\n")
        section("General")
        kv("meta.name", cfg.meta.name)
        kv("install.target", cfg.install.target.value)
        kv("install.root", str(cfg.install.root))
        kv("operators", str(len(cfg.operators)))

        section("Relays")
        for rl in cfg.relays:
            role = "lighthouse" if rl.nebula.is_lighthouse else "host"
            flag = "on " if rl.enabled else "off"
            stream.write(
                f"  [{flag}]  {rl.name:<16s}  {rl.nebula.overlay_ip:<16s}  "
                f"{role:<10s}  {rl.deploy.address}\n"
            )

        section("Redirectors")
        for r in cfg.redirectors:
            neb = r.nebula.overlay_ip if r.nebula.enabled else "no-nebula"
            flag = "on " if r.enabled else "off"
            stream.write(
                f"  [{flag}]  {r.name:<16s}  {neb:<16s}  "
                f"{r.type.value:<16s}  {r.deploy.address}\n"
            )

        section("Management")
        kv("nebula", "enabled" if cfg.management.nebula.enabled else "disabled")
        kv("torsocks", str(cfg.management.torsocks_management))
        kv("ssh_ca.ca_dir", str(cfg.management.ssh_ca.ca_dir))
        kv("short_validity", cfg.management.ssh_ca.short_validity)
        kv("renewal_interval", cfg.management.ssh_ca.renewal_interval)
        if cfg.management.monitoring.telegram.enabled:
            kv("telegram", "enabled")

        section("PKI")
        kv("ca.source", cfg.pki.ca.source.value)
        for leaf in cfg.pki.leaves:
            stream.write(f"    {leaf.name:<18s}  {leaf.source.value}\n")

        cf = getattr(cfg, "cf_worker", None)
        if cf is not None and getattr(cf, "enabled", False):
            section("Cloudflare Worker")
            kv("name", cf.name)
            kv("route", cf.route)
            kv("filter_ref", cf.filter_ref or "")

        self._finish_probe("config")


def run_dashboard(cfg: Config, config_path: Path) -> None:
    logging.basicConfig(
        filename=str(_LOG_PATH),
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s %(message)s",
        force=True,
    )
    _log.info("dashboard starting, config=%s", config_path)
    app = DashboardApp(cfg, config_path)
    app.run()
