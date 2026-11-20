from __future__ import annotations

import time
from pathlib import Path
from typing import Callable, Iterable

from .. import log
from ..core import state as state_mod
from ..core.config import Config, load as load_config
from ..core.renderer import render_all
from . import apply as applymod
from . import clean as cleanmod
from . import nebula as nebulamod
from . import sshca as sshcamod
from .ssh import KitError


STAGES: list[str] = ["teamserver", "nebula", "relays", "redirectors", "mesh", "scrub"]

_NEBULA_LOCAL_CERTS = Path("/opt/conduit/nebula-certs")


class StageError(KitError):
    """A stage failed to complete; upstream orchestrator decides whether to halt."""


def _ts_onion_name(cfg: Config) -> str | None:
    """Return the name of the single enabled tor-hidden-service redirector, if any."""
    for r in cfg.redirectors:
        if r.type.value == "tor-hidden-service" and r.enabled:
            return r.name
    return None


def _run_step(label: str, fn: Callable, *args, dry_run: bool, **kwargs):
    """Timed execution + log banner for one sub-step inside a stage."""
    if dry_run:
        log.info(f"(dry-run) {label}")
        return None
    log.info(label)
    start = time.monotonic()
    try:
        return fn(*args, **kwargs)
    finally:
        elapsed = time.monotonic() - start
        log.detail(f"done: {label} ({elapsed:.1f}s)")


def _reload(config_path: Path) -> Config:
    """Reload the config so freshly-populated state is reflected."""
    return load_config(config_path)


def stage_teamserver(
    cfg: Config,
    config_path: Path,
    staging_dir: Path,
    *,
    dry_run: bool,
    verbose: int,
    skip_docker: bool,
) -> Config:
    """Render → (optional docker build+start) → ts-onion apply → state writeback → re-render."""
    log.ok("stage: teamserver")

    _run_step("1/5 render", render_all, cfg, staging_dir, dry_run=dry_run)

    if not skip_docker:
        if dry_run:
            log.info("(dry-run) 2/5 preflight (docker required)")
        else:
            log.info("2/5 preflight (docker required)")
            problems = applymod.preflight(cfg, need_docker=True)
            if problems:
                for p in problems:
                    log.warn(f"preflight: {p}")
                raise StageError(f"teamserver preflight found {len(problems)} problem(s)")
        _run_step("3a/5 transfer staging", applymod.transfer, cfg, staging_dir, dry_run=dry_run)
        _run_step("3b/5 clone upstream sources", applymod.clone_sources, cfg, dry_run=dry_run)
        _run_step("3c/5 docker compose build", applymod.compose_build, cfg, dry_run=dry_run)
        _run_step("3d/5 docker compose up -d", applymod.compose_up, cfg, dry_run=dry_run)
    else:
        log.info("2/5 preflight + docker build/start (skipped, --skip-docker)")

    ts_name = _ts_onion_name(cfg)
    if ts_name is None:
        log.warn("4/5 ts-onion: no enabled tor-hidden-service redirector found; skipping")
    else:
        _run_step(
            f"4/5 apply --ts-onion ({ts_name})",
            applymod.deploy_redirectors,
            cfg, staging_dir,
            dry_run=dry_run,
            only=ts_name,
            no_torsocks=False,
            playbook_tags=None,
            playbook_skip_tags=None,
        )
        if not dry_run:
            discovered = state_mod.refresh_after_ts_onion(config_path, cfg)
            if discovered:
                # One line per state key discovered (per-service + the legacy
                # `ts_onion` alias). Multi-onion setups want every value in
                # the log for operator reference.
                for key in sorted(discovered):
                    log.ok(f"state: {key} = {discovered[key]}")
            else:
                log.warn("state: no ts_onion discovered (non-loopback deploy or hostname file missing)")

    cfg2 = cfg if dry_run else _reload(config_path)
    _run_step("5/5 re-render (picks up discovered state)", render_all, cfg2, staging_dir, dry_run=dry_run)

    log.ok("stage done: teamserver")
    return cfg2


def stage_nebula(
    cfg: Config,
    config_path: Path,
    staging_dir: Path,
    *,
    dry_run: bool,
    verbose: int,
) -> Config:
    """nebula init → sign every enabled relay + redirector → persist cert dir → re-render."""
    log.ok("stage: nebula")

    total = 1 + sum(1 for rl in cfg.relays if rl.enabled) \
              + sum(1 for r in cfg.redirectors if r.enabled and r.nebula.enabled) \
              + 1  # +1 for the final re-render
    step = 1
    _run_step(f"{step}/{total} nebula CA init (on lighthouse)", nebulamod.ca_init, cfg, dry_run=dry_run)

    for rl in cfg.relays:
        if not rl.enabled:
            continue
        step += 1
        ip = rl.nebula.overlay_ip
        groups = ",".join(rl.nebula.groups) or "relay"
        _run_step(
            f"{step}/{total} sign relay '{rl.name}' ({ip}, groups={groups})",
            nebulamod.sign_cert, cfg, rl.name, ip, groups,
            dry_run=dry_run,
        )

    for r in cfg.redirectors:
        if not r.enabled or not r.nebula.enabled:
            continue
        step += 1
        ip = r.nebula.overlay_ip
        groups = ",".join(r.nebula.groups) or "redirector"
        _run_step(
            f"{step}/{total} sign redirector '{r.name}' ({ip}, groups={groups})",
            nebulamod.sign_cert, cfg, r.name, ip, groups,
            dry_run=dry_run,
        )

    if not dry_run:
        state_mod.refresh_after_nebula_sign(config_path, _NEBULA_LOCAL_CERTS)
        log.ok(f"state: nebula_cert_dir = {_NEBULA_LOCAL_CERTS}")

    cfg2 = cfg if dry_run else _reload(config_path)
    step += 1
    _run_step(f"{step}/{total} re-render (picks up signed cert paths)", render_all, cfg2, staging_dir, dry_run=dry_run)

    log.ok("stage done: nebula")
    return cfg2


def stage_relays(
    cfg: Config,
    config_path: Path,
    staging_dir: Path,
    *,
    dry_run: bool,
    verbose: int,
    only: str | None,
) -> Config:
    """For each enabled relay: apply --no-torsocks → clean logs. Then issue relay-hop cert."""
    log.ok("stage: relays")

    did_any = False
    for rl in cfg.relays:
        if not rl.enabled:
            continue
        if only and rl.name != only:
            continue
        did_any = True

        _run_step(
            f"apply --relay {rl.name} --no-torsocks",
            applymod.deploy_relays, cfg, staging_dir,
            only=rl.name,
            no_torsocks=True,
            playbook_tags=None,
            playbook_skip_tags=None,
            dry_run=dry_run,
        )
        _run_step(
            f"clean logs --relay {rl.name}",
            cleanmod.clean_logs, cfg,
            only=rl.name,
            include_teamserver=False,
            direct=False,
            no_torsocks=False,
            dry_run=dry_run,
        )

    if not did_any:
        log.warn(f"relays: nothing to do (only='{only}' or no enabled relays)")

    _run_step(
        "ca enable-relay-hop (issues ubuntu@relay cert)",
        sshcamod.enable_relay_hop, cfg,
        only=only, validity=None,
        dry_run=dry_run,
    )

    log.ok("stage done: relays")
    return cfg


def stage_redirectors(
    cfg: Config,
    config_path: Path,
    staging_dir: Path,
    *,
    dry_run: bool,
    verbose: int,
    only: str | None,
) -> Config:
    """For each enabled openresty redirector: apply --no-torsocks → clean logs --direct."""
    log.ok("stage: redirectors")

    did_any = False
    for r in cfg.redirectors:
        if not r.enabled:
            continue
        if r.type.value == "tor-hidden-service":
            continue  # owned by teamserver stage
        if only and r.name != only:
            continue
        did_any = True

        _run_step(
            f"apply --redirector {r.name} --no-torsocks",
            applymod.deploy_redirectors, cfg, staging_dir,
            only=r.name,
            no_torsocks=True,
            playbook_tags=None,
            playbook_skip_tags=None,
            dry_run=dry_run,
        )
        _run_step(
            f"clean logs --redirector {r.name} --direct",
            cleanmod.clean_logs, cfg,
            only=r.name,
            include_teamserver=False,
            direct=True,
            no_torsocks=False,
            dry_run=dry_run,
        )

    if not did_any:
        log.warn(f"redirectors: nothing to do (only='{only}' or no enabled openresty redirectors)")

    log.ok("stage done: redirectors")
    return cfg


def stage_scrub(
    cfg: Config,
    config_path: Path,
    staging_dir: Path,
    *,
    dry_run: bool,
    verbose: int,
    only: str | None,
    direct: bool,
    include_teamserver: bool,
) -> Config:
    """Standalone cleanup pass across every node.

    Independent of apply timing. Useful for mid-engagement re-scrub after
    manual activity leaves traces, or for a post-incident wipe. Teamserver
    cleanup is opt-in via `include_teamserver=True` because a scrub on the
    operator host also truncates its own journal and may surprise an operator
    who did not intend it.

    Routes:
      * teamserver: local commands (no SSH)
      * relays:     torsocks SSH to public address
      * redirectors direct=True:  torsocks SSH to public address (mesh-independent)
      * redirectors direct=False: torsocks SSH to relay, then SSH over overlay (needs mesh + relay-hop)
    """
    log.ok("stage: scrub")
    label_direct = " --direct" if direct else " (via overlay)"
    scope = only or "every enabled node"
    log.info(f"scrubbing {scope} ; teamserver={include_teamserver}{label_direct}")

    _run_step(
        f"clean logs scope={scope}",
        cleanmod.clean_logs, cfg,
        only=only,
        include_teamserver=include_teamserver,
        direct=direct,
        no_torsocks=False,
        dry_run=dry_run,
    )

    log.ok("stage done: scrub")
    return cfg


def stage_mesh(
    cfg: Config,
    config_path: Path,
    staging_dir: Path,
    *,
    dry_run: bool,
    verbose: int,
) -> Config:
    """Opportunistic relay-hop refresh → overlay-path scrub per redirector → mesh ping."""
    log.ok("stage: mesh")

    _run_step(
        "1/3 refresh relay-hop cert (idempotent re-sign)",
        sshcamod.enable_relay_hop, cfg,
        only=None, validity=None,
        dry_run=dry_run,
    )

    for r in cfg.redirectors:
        if not r.enabled or not r.nebula.enabled:
            continue
        _run_step(
            f"2/3 clean logs --redirector {r.name} (via overlay)",
            cleanmod.clean_logs, cfg,
            only=r.name,
            include_teamserver=False,
            direct=False,
            no_torsocks=False,
            dry_run=dry_run,
        )

    _run_step("3/3 nebula mesh status (ping overlay peers)", nebulamod.mesh_status, cfg, dry_run=dry_run)

    log.ok("stage done: mesh")
    return cfg


def run_stage(
    cfg: Config,
    config_path: Path,
    staging_dir: Path,
    stage: str,
    *,
    dry_run: bool = False,
    verbose: int = 0,
    only: str | None = None,
    skip_docker: bool = False,
    direct: bool = False,
    include_teamserver: bool = False,
) -> Config:
    """Dispatch one named stage."""
    if stage == "teamserver":
        return stage_teamserver(cfg, config_path, staging_dir, dry_run=dry_run, verbose=verbose, skip_docker=skip_docker)
    if stage == "nebula":
        return stage_nebula(cfg, config_path, staging_dir, dry_run=dry_run, verbose=verbose)
    if stage == "relays":
        return stage_relays(cfg, config_path, staging_dir, dry_run=dry_run, verbose=verbose, only=only)
    if stage == "redirectors":
        return stage_redirectors(cfg, config_path, staging_dir, dry_run=dry_run, verbose=verbose, only=only)
    if stage == "mesh":
        return stage_mesh(cfg, config_path, staging_dir, dry_run=dry_run, verbose=verbose)
    if stage == "scrub":
        return stage_scrub(
            cfg, config_path, staging_dir,
            dry_run=dry_run, verbose=verbose,
            only=only, direct=direct, include_teamserver=include_teamserver,
        )
    raise ValueError(f"unknown stage: {stage!r}; valid: {STAGES}")


def _stages_from(start: str | None) -> list[str]:
    if start is None:
        return list(STAGES)
    if start not in STAGES:
        raise ValueError(f"unknown --from stage: {start!r}; valid: {STAGES}")
    return STAGES[STAGES.index(start):]


def run_all(
    cfg: Config,
    config_path: Path,
    staging_dir: Path,
    *,
    from_stage: str | None = None,
    interactive: bool = False,
    dry_run: bool = False,
    verbose: int = 0,
    only: str | None = None,
    skip_docker: bool = False,
    direct: bool = False,
    include_teamserver: bool = False,
    confirm_fn: Callable[[str], bool] | None = None,
) -> None:
    """Sequence every stage in order (or from --from).

    `confirm_fn(stage) -> bool` lets the CLI layer plug in `click.confirm`
    without making this module import click. When interactive is False the
    function is not called.
    """
    stages = _stages_from(from_stage)
    log.ok(f"deploy --all: {', '.join(stages)}")

    current_cfg = cfg
    for stage in stages:
        if interactive and confirm_fn is not None:
            if not confirm_fn(stage):
                log.warn(f"stage {stage} declined by operator; stopping")
                return
        current_cfg = run_stage(
            current_cfg, config_path, staging_dir, stage,
            dry_run=dry_run, verbose=verbose, only=only,
            skip_docker=skip_docker,
            direct=direct, include_teamserver=include_teamserver,
        )

    log.ok("deploy --all complete")
