"""Unit tests for conduit.core.state."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from conduit.core import state as st


def test_default_state_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(st, "_STATE_ROOT", tmp_path)
    assert st.default_state_path(Path("/root/conduit/examples/_private/local.yml")) == tmp_path / "full.state.yml"
    assert st.default_state_path(Path("foo.yml")) == tmp_path / "foo.state.yml"


def test_load_state_missing_returns_shell(tmp_path: Path):
    state = st.load_state(tmp_path / "does-not-exist.state.yml")
    assert state == {"version": 1, "discovered": {}}


def test_load_state_malformed_recovers(tmp_path: Path):
    bad = tmp_path / "bad.state.yml"
    bad.write_text("not: valid: yaml: at all: [[")
    state = st.load_state(bad)
    assert state["version"] == 1
    assert state["discovered"] == {}


def test_save_then_load_roundtrip(tmp_path: Path):
    path = tmp_path / "rt.state.yml"
    st.save_state(path, {"version": 1, "discovered": {"ts_onion": "abc.onion"}})
    assert path.stat().st_mode & 0o777 == 0o600
    loaded = st.load_state(path)
    assert loaded["discovered"]["ts_onion"] == "abc.onion"


def test_set_discovered_merges_without_clobbering(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(st, "_STATE_ROOT", tmp_path)
    cfg_path = Path("engagement.yml")
    st.set_discovered(cfg_path, "ts_onion", "vuhb.onion")
    st.set_discovered(cfg_path, "nebula_cert_dir", "/opt/conduit/nebula-certs")

    assert st.get_discovered(cfg_path, "ts_onion") == "vuhb.onion"
    assert st.get_discovered(cfg_path, "nebula_cert_dir") == "/opt/conduit/nebula-certs"
    assert st.get_discovered(cfg_path, "missing", default="x") == "x"


def test_state_yaml_tag_resolves_in_config_load(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Load a tiny config with !state tags and confirm resolution."""
    monkeypatch.setattr(st, "_STATE_ROOT", tmp_path)

    cfg_file = tmp_path / "mini.yml"
    cfg_file.write_text(
        "a: !state ts_onion\n"
        "b: !state nebula_cert_dir\n"
        "c: !state missing_key\n"
    )
    st.set_discovered(cfg_file, "ts_onion", "aaa.onion")
    st.set_discovered(cfg_file, "nebula_cert_dir", "/opt/conduit/nebula-certs")

    # Use the real loader wiring (not the public load() which requires a full Config).
    from conduit.core.config import _ConduitLoader
    import conduit.core.config as cfg_mod
    cfg_mod._active_state = st.load_state(st.default_state_path(cfg_file))

    with cfg_file.open() as f:
        doc = yaml.load(f, Loader=_ConduitLoader)
    assert doc == {
        "a": "aaa.onion",
        "b": "/opt/conduit/nebula-certs",
        "c": "",
    }
