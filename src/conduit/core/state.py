from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


STATE_VERSION = 1
_STATE_ROOT = Path("/opt/conduit/state")


def default_state_path(config_path: Path) -> Path:
    """Return the state file path that corresponds to a given config file."""
    return _STATE_ROOT / f"{config_path.stem}.state.yml"


def load_state(state_path: Path) -> dict:
    """Load state. Returns a fresh shell if the file does not exist or is malformed."""
    if not state_path.exists():
        return {"version": STATE_VERSION, "discovered": {}}
    try:
        with state_path.open() as f:
            data = yaml.safe_load(f) or {}
    except (yaml.YAMLError, OSError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    data.setdefault("version", STATE_VERSION)
    data.setdefault("discovered", {})
    if not isinstance(data["discovered"], dict):
        data["discovered"] = {}
    return data


def save_state(state_path: Path, state: dict) -> None:
    """Write state atomically, chmod 600."""
    state_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = state_path.with_suffix(state_path.suffix + ".tmp")
    with tmp.open("w") as f:
        f.write("# Managed by conduit. Do not hand-edit.\n")
        yaml.safe_dump(state, f, default_flow_style=False, sort_keys=False)
    tmp.chmod(0o600)
    tmp.replace(state_path)


def set_discovered(config_path: Path, key: str, value: Any) -> None:
    """Merge one key into the discovered section of the state file."""
    state_path = default_state_path(config_path)
    state = load_state(state_path)
    state["discovered"][key] = value
    save_state(state_path, state)


def get_discovered(config_path: Path, key: str, default: Any = None) -> Any:
    state_path = default_state_path(config_path)
    state = load_state(state_path)
    return state["discovered"].get(key, default)


def refresh_after_ts_onion(config_path: Path, cfg) -> dict[str, str]:
    """Read every discovered .onion from the live tor hidden-service dirs
    on the teamserver.

    Only handles the loopback ts-onion case (the common one in the shipped
    local.yml). For a remote-hosted ts-onion, state is left untouched and
    the operator must populate it by hand or via another path.

    Writes two flavors of state key per service:
        ts_onion_<service-name>   e.g. ts_onion_adaptix-cdn
        ts_onion                  (alias for the FIRST service; legacy)

    Redirectors that reference `!state ts_onion_<name>` pick up the right
    hostname for their profile. Configs still using the legacy single
    `!state ts_onion` resolve to the first service, which matches the
    pre-multi-onion shape.

    Returns a dict of {state_key: onion_hostname} for logging + callers.
    """
    found: dict[str, str] = {}
    first_onion: str | None = None

    for r in cfg.redirectors:
        if r.type.value != "tor-hidden-service" or not r.enabled:
            continue
        if str(r.deploy.address) not in {"127.0.0.1", "localhost", "::1"}:
            continue
        typed = r.typed_config()
        for svc in typed.services:
            hostname_file = Path(svc.hs_dir) / "hostname"
            if not hostname_file.exists():
                continue
            onion = hostname_file.read_text().strip()
            if not onion:
                continue
            key = f"ts_onion_{svc.name}"
            set_discovered(config_path, key, onion)
            found[key] = onion
            if first_onion is None:
                first_onion = onion

    # Legacy alias: `!state ts_onion` resolves to the first discovered service.
    # Keeps pre-multi-onion configs working with no edits.
    if first_onion is not None:
        set_discovered(config_path, "ts_onion", first_onion)
        found["ts_onion"] = first_onion

    return found


def refresh_after_nebula_sign(config_path: Path, cert_dir: Path) -> None:
    """Persist the cached Nebula cert dir path if it looks populated."""
    if cert_dir.exists() and any(cert_dir.iterdir()):
        set_discovered(config_path, "nebula_cert_dir", str(cert_dir))
