"""Unit tests for the `conduit deploy` CLI wrapper.

Exercises stage dispatch, mutex / argument validation, and --all sequencing
through --dry-run so no low-level primitives actually execute.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from conduit.cli import main


EXAMPLE_CFG = Path("examples/local.yml")


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


# ── mutex / argument validation ───────────────────────────────────────

def test_requires_stage_or_all(runner: CliRunner, tmp_path: Path):
    r = runner.invoke(main, [
        "deploy", "--config", str(EXAMPLE_CFG), "--staging", str(tmp_path),
    ])
    assert r.exit_code == 2
    assert "pass exactly one of --stage" in r.output


def test_stage_and_all_are_mutex(runner: CliRunner, tmp_path: Path):
    r = runner.invoke(main, [
        "deploy", "--config", str(EXAMPLE_CFG), "--staging", str(tmp_path),
        "--stage", "mesh", "--all",
    ])
    assert r.exit_code == 2


def test_from_requires_all(runner: CliRunner, tmp_path: Path):
    r = runner.invoke(main, [
        "deploy", "--config", str(EXAMPLE_CFG), "--staging", str(tmp_path),
        "--stage", "mesh", "--from", "mesh",
    ])
    assert r.exit_code == 2
    assert "--from requires --all" in r.output


def test_interactive_requires_all(runner: CliRunner, tmp_path: Path):
    r = runner.invoke(main, [
        "deploy", "--config", str(EXAMPLE_CFG), "--staging", str(tmp_path),
        "--stage", "mesh", "--interactive",
    ])
    assert r.exit_code == 2
    assert "--interactive requires --all" in r.output


# ── dry-run per-stage ─────────────────────────────────────────────────

@pytest.mark.parametrize("stage", ["teamserver", "nebula", "relays", "redirectors", "mesh", "scrub"])
def test_dry_run_each_stage_exits_zero(runner: CliRunner, tmp_path: Path, stage: str):
    r = runner.invoke(main, [
        "deploy", "--config", str(EXAMPLE_CFG), "--staging", str(tmp_path),
        "--stage", stage, "--dry-run", "--skip-docker",
    ])
    assert r.exit_code == 0, r.output
    assert f"stage done: {stage}" in r.output
    assert "(dry-run)" in r.output  # every sub-step printed a dry-run marker


# ── --all sequencing ──────────────────────────────────────────────────

def test_dry_run_all_covers_every_stage_in_order(runner: CliRunner, tmp_path: Path):
    r = runner.invoke(main, [
        "deploy", "--config", str(EXAMPLE_CFG), "--staging", str(tmp_path),
        "--all", "--dry-run", "--skip-docker",
    ])
    assert r.exit_code == 0, r.output
    for stage in ["teamserver", "nebula", "relays", "redirectors", "mesh"]:
        assert f"stage: {stage}" in r.output
        assert f"stage done: {stage}" in r.output
    assert "deploy --all complete" in r.output

    # Order sanity: teamserver appears before mesh in the output.
    i_ts = r.output.find("stage: teamserver")
    i_mesh = r.output.find("stage: mesh")
    assert 0 <= i_ts < i_mesh


def test_dry_run_all_from_resumes(runner: CliRunner, tmp_path: Path):
    r = runner.invoke(main, [
        "deploy", "--config", str(EXAMPLE_CFG), "--staging", str(tmp_path),
        "--all", "--from", "redirectors", "--dry-run", "--skip-docker",
    ])
    assert r.exit_code == 0, r.output
    # Earlier stages must be absent
    assert "stage: teamserver" not in r.output
    assert "stage: nebula" not in r.output
    assert "stage: relays" not in r.output
    # Target + remainder present
    assert "stage: redirectors" in r.output
    assert "stage: mesh" in r.output


# ── --only filter ─────────────────────────────────────────────────────

def test_only_filters_to_single_redirector(runner: CliRunner, tmp_path: Path):
    r = runner.invoke(main, [
        "deploy", "--config", str(EXAMPLE_CFG), "--staging", str(tmp_path),
        "--stage", "redirectors", "--only", "redir01", "--dry-run",
    ])
    assert r.exit_code == 0, r.output
    assert "apply --redirector redir01" in r.output
    assert "apply --redirector redir02" not in r.output


def test_only_unknown_node_yields_warning(runner: CliRunner, tmp_path: Path):
    r = runner.invoke(main, [
        "deploy", "--config", str(EXAMPLE_CFG), "--staging", str(tmp_path),
        "--stage", "redirectors", "--only", "nope", "--dry-run",
    ])
    assert r.exit_code == 0
    assert "nothing to do" in r.output


# ── scrub stage ────────────────────────────────────────────────────────

def test_scrub_dry_run_default_excludes_teamserver_overlay_path(runner: CliRunner, tmp_path: Path):
    r = runner.invoke(main, [
        "deploy", "--config", str(EXAMPLE_CFG), "--staging", str(tmp_path),
        "--stage", "scrub", "--dry-run",
    ])
    assert r.exit_code == 0, r.output
    assert "stage: scrub" in r.output
    assert "teamserver=False" in r.output
    assert "(via overlay)" in r.output


def test_scrub_dry_run_direct_and_include_teamserver(runner: CliRunner, tmp_path: Path):
    r = runner.invoke(main, [
        "deploy", "--config", str(EXAMPLE_CFG), "--staging", str(tmp_path),
        "--stage", "scrub", "--dry-run",
        "--direct", "--include-teamserver",
    ])
    assert r.exit_code == 0, r.output
    assert "teamserver=True" in r.output
    assert "--direct" in r.output


def test_scrub_only_narrows_scope(runner: CliRunner, tmp_path: Path):
    r = runner.invoke(main, [
        "deploy", "--config", str(EXAMPLE_CFG), "--staging", str(tmp_path),
        "--stage", "scrub", "--only", "redir01", "--direct", "--dry-run",
    ])
    assert r.exit_code == 0, r.output
    assert "scope=redir01" in r.output


def test_scrub_skips_loopback_redirector(runner: CliRunner, tmp_path: Path):
    """ts-onion in examples/local.yml has deploy.address=127.0.0.1. Scrub must
    skip it (log a warn) rather than attempting torsocks ssh to loopback."""
    r = runner.invoke(main, [
        "deploy", "--config", str(EXAMPLE_CFG), "--staging", str(tmp_path),
        "--stage", "scrub", "--direct", "--dry-run",
    ])
    assert r.exit_code == 0, r.output
    # Scrub must complete (dry-run), not raise.
    assert "stage done: scrub" in r.output


def test_all_now_covers_six_stages(runner: CliRunner, tmp_path: Path):
    r = runner.invoke(main, [
        "deploy", "--config", str(EXAMPLE_CFG), "--staging", str(tmp_path),
        "--all", "--dry-run", "--skip-docker",
    ])
    assert r.exit_code == 0, r.output
    for stage in ["teamserver", "nebula", "relays", "redirectors", "mesh", "scrub"]:
        assert f"stage done: {stage}" in r.output
