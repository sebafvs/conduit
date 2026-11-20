from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, PackageLoader, StrictUndefined

from .config import (
    Config,
    Filter,
    Leaf,
    OpenRestyVpsConfig,
    Operator,
    Redirector,
    RedirectorType,
    Relay,
    TlsProfile,
    TorHiddenServiceConfig,
    CfWorkerConfig,
)
from .pki import write_pki
from .secrets import SecretsResolver

# Local directory where `conduit nebula sign` caches pulled CA + leaf certs so
# ansible `copy src:` tasks on the controller have a readable source path.
_LOCAL_NEBULA_CERTS = Path("/opt/conduit/nebula-certs")


def _nebula_certs_for(name: str) -> dict:
    """Return a cert-path triple. Keys are always present, empty when files are missing.

    When `conduit nebula sign <name>` runs, it pulls ca.crt, <name>.crt, and
    <name>.key into _LOCAL_NEBULA_CERTS. This helper lets the renderer inject
    those paths into per-node ansible-vars so the deploy copy tasks have a
    source. Empty strings keep the ansible tasks skipped (they have
    `when: ... | length > 0` guards). Keys are always present so Jinja2's
    StrictUndefined does not trip when the certs have not been signed yet.
    """
    ca = _LOCAL_NEBULA_CERTS / "ca.crt"
    host_crt = _LOCAL_NEBULA_CERTS / f"{name}.crt"
    host_key = _LOCAL_NEBULA_CERTS / f"{name}.key"
    if ca.exists() and host_crt.exists() and host_key.exists():
        return {
            "ca_cert": str(ca),
            "host_cert": str(host_crt),
            "host_key": str(host_key),
        }
    return {"ca_cert": "", "host_cert": "", "host_key": ""}


def _ssh_ca_pubkey(cfg: Config) -> str:
    """Return the SSH CA public key content, or '' if the CA doesn't exist yet."""
    ca_pub = Path(cfg.management.ssh_ca.ca_dir) / "ca.pub"
    if ca_pub.exists():
        return ca_pub.read_text().strip()
    return ""


# Sane defaults when no tls profile is referenced by teamserver.
_DEFAULT_TLS = TlsProfile(
    min_version="TLS1.2",
    max_version="TLS1.3",
    cipher_suites=[
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    ],
    prefer_server_cipher_suites=False,
)


def _env() -> Environment:
    return Environment(
        loader=PackageLoader("conduit.resources", "templates"),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )


def _resolve_teamserver_tls(cfg: Config) -> TlsProfile:
    """Collapse teamserver.tls (ref or inline) into a concrete TlsProfile."""
    if cfg.teamserver.tls is None:
        return _DEFAULT_TLS
    if cfg.teamserver.tls.ref is not None:
        return cfg.profiles.tls_profiles[cfg.teamserver.tls.ref]
    return TlsProfile(
        min_version=cfg.teamserver.tls.min_version or "TLS1.2",
        max_version=cfg.teamserver.tls.max_version or "TLS1.3",
        cipher_suites=cfg.teamserver.tls.cipher_suites or _DEFAULT_TLS.cipher_suites,
        prefer_server_cipher_suites=(
            cfg.teamserver.tls.prefer_server_cipher_suites
            if cfg.teamserver.tls.prefer_server_cipher_suites is not None
            else False
        ),
    )


def _resolve_filter(
    cfg: Config, filt: Filter | None, resolver: SecretsResolver | None = None
) -> Filter | None:
    """Resolve a Filter.ref against profiles.filter_profiles, then expand any
    `secret://` URIs inside it (require.headers values and require.challenge.secret_ref).

    Returns a shallow copy of the resolved Filter with secrets substituted;
    the original profile model is untouched so re-renders stay stable.
    """
    if filt is None:
        return None
    if filt.ref is None:
        base = filt
    else:
        base = cfg.profiles.filter_profiles[filt.ref]
        # If the inline filter overrides anything, this is where merge logic
        # would live. For now the ref wins outright.

    if resolver is None:
        return base

    updated_require: dict = {}

    if base.require.headers:
        resolved_hdrs = {}
        for hdr_name, hdr_val in base.require.headers.items():
            if resolver.is_secret_uri(hdr_val):
                resolved_hdrs[hdr_name] = resolver.resolve(hdr_val)
            else:
                resolved_hdrs[hdr_name] = hdr_val
        if resolved_hdrs != base.require.headers:
            updated_require["headers"] = resolved_hdrs

    if base.require.challenge is not None and resolver.is_secret_uri(
        base.require.challenge.secret_ref
    ):
        resolved_secret = resolver.resolve(base.require.challenge.secret_ref)
        updated_require["challenge"] = base.require.challenge.model_copy(
            update={"secret_ref": resolved_secret}
        )

    if not updated_require:
        return base

    return base.model_copy(
        update={"require": base.require.model_copy(update=updated_require)}
    )


def _leaf_by_name(cfg: Config, name: str | None) -> Leaf | None:
    if name is None:
        return None
    for leaf in cfg.pki.leaves:
        if leaf.name == name:
            return leaf
    raise ValueError(f"leaf '{name}' not found in pki.leaves")


def render_profile_yaml(cfg: Config, resolver: SecretsResolver | None = None) -> str:
    """Render Adaptix teamserver profile.yaml with secrets resolved."""
    tls = _resolve_teamserver_tls(cfg)
    if resolver is None:
        resolved_ops = cfg.operators
    else:
        resolved_ops = [
            Operator(
                name=o.name,
                password=resolver.resolve(o.password),
                role=o.role,
                only_password=o.only_password,
            )
            for o in cfg.operators
        ]
    tmpl = _env().get_template("profile.yaml.j2")
    return tmpl.render(ts=cfg.teamserver, operators=resolved_ops, tls=tls)


def render_docker_compose(cfg: Config) -> str:
    """Render docker-compose.yml for the C2 stack."""
    tmpl = _env().get_template("docker-compose.yml.j2")
    return tmpl.render(
        meta=cfg.meta,
        ts=cfg.teamserver,
        listeners=cfg.listeners,
        payload=cfg.payload,
        build=cfg.features.build,
    )


def render_payload_nginx(cfg: Config) -> str:
    """Render the payload server nginx.conf."""
    if cfg.payload is None or not cfg.payload.enabled:
        raise ValueError("payload is disabled, cannot render payload nginx conf")
    leaf = _leaf_by_name(cfg, cfg.payload.tls_profile)
    # CRL endpoint location directive serves a directory; strip the filename.
    crl_dir = cfg.payload.crl_endpoint.path.rsplit("/", 1)[0] + "/"
    tmpl = _env().get_template("payload-nginx.conf.j2")
    return tmpl.render(payload=cfg.payload, leaf=leaf, crl_dir=crl_dir)


def render_openresty_vps_vars(
    cfg: Config, r: Redirector, resolver: SecretsResolver | None = None
) -> str:
    """Render ansible group_vars for one openresty-vps redirector."""
    if r.type != RedirectorType.openresty_vps:
        raise ValueError(f"redirector '{r.name}' is not openresty-vps")
    typed: OpenRestyVpsConfig = r.typed_config()  # type: ignore[assignment]
    filt = _resolve_filter(cfg, r.filters, resolver)
    leaf = _leaf_by_name(cfg, r.tls_profile)
    lighthouses = []
    for rl in cfg.relays:
        if rl.enabled and rl.nebula.is_lighthouse:
            lh_ip = rl.nebula.overlay_ip.split("/")[0]
            lighthouses.append({
                "nebula_ip": lh_ip,
                "public_addr": f"{rl.deploy.address}:{rl.nebula.listen_port}",
            })
    tmpl = _env().get_template("openresty-vps-vars.yml.j2")
    return tmpl.render(
        r=r, cfg=typed, filt=filt, leaf=leaf,
        lighthouses=lighthouses,
        nebula_version=cfg.management.nebula.version,
        nebula_certs=_nebula_certs_for(r.name),
        ssh_ca_pubkey=_ssh_ca_pubkey(cfg),
    )


def render_relay_vars(cfg: Config, rl: Relay) -> str:
    """Render ansible vars for one relay node (relay_node role)."""
    nebula_ip_bare = rl.nebula.overlay_ip.split("/")[0]
    lines = [
        "---",
        f"relay_name: {rl.name}",
        f"relay_ssh_port: {rl.deploy.ssh_port}",
        "",
        f"relay_nebula_enabled: true",
        f"relay_nebula_version: \"{cfg.management.nebula.version}\"",
        f"relay_nebula_overlay_ip: \"{rl.nebula.overlay_ip}\"",
        f"relay_nebula_is_lighthouse: {str(rl.nebula.is_lighthouse).lower()}",
        f"relay_nebula_listen_port: {rl.nebula.listen_port}",
        f"relay_nebula_groups:",
    ]
    for g in rl.nebula.groups:
        lines.append(f"  - {g}")

    lines.append("relay_nebula_firewall_allow_ssh_groups:")
    for g in rl.nebula.firewall_allow_ssh_groups:
        lines.append(f"  - {g}")

    if rl.nebula.is_lighthouse:
        lines.append("relay_nebula_static_hosts: []")
        lines.append("relay_nebula_lighthouse_hosts: []")
    else:
        lines.append("relay_nebula_static_hosts:")
        for other_rl in cfg.relays:
            if other_rl.nebula.is_lighthouse and other_rl.enabled:
                lh_ip = other_rl.nebula.overlay_ip.split("/")[0]
                lines.append(f"  - nebula_ip: \"{lh_ip}\"")
                lines.append(f"    public_addr: \"{other_rl.deploy.address}:{other_rl.nebula.listen_port}\"")
        lines.append("relay_nebula_lighthouse_hosts:")
        for other_rl in cfg.relays:
            if other_rl.nebula.is_lighthouse and other_rl.enabled:
                lh_ip = other_rl.nebula.overlay_ip.split("/")[0]
                lines.append(f"  - \"{lh_ip}\"")

    # Nebula cert paths, populated once `conduit nebula sign <relay>` has
    # cached the files locally. Empty strings keep the ansible copy tasks
    # skipped (they are guarded by `when: ... | length > 0`).
    relay_certs = _nebula_certs_for(rl.name)
    lines.append(f"relay_nebula_ca_cert: \"{relay_certs.get('ca_cert', '')}\"")
    lines.append(f"relay_nebula_host_cert: \"{relay_certs.get('host_cert', '')}\"")
    lines.append(f"relay_nebula_host_key: \"{relay_certs.get('host_key', '')}\"")

    lines.append("")
    lines.append(f"relay_ssh_ca_trust: {str(rl.ssh_ca_trust).lower()}")
    ca_pub = _ssh_ca_pubkey(cfg)
    if ca_pub:
        lines.append("relay_ssh_ca_pubkey: |")
        lines.append(f"  {ca_pub}")
    lines.append("")
    lines.append("relay_packages:")
    for pkg in rl.packages:
        lines.append(f"  - {pkg}")

    lines.append("")
    lines.append("relay_firewall_enabled: true")
    lines.append(f"relay_firewall_ssh_port: {rl.deploy.ssh_port}")
    lines.append(f"relay_firewall_nebula_port: {rl.nebula.listen_port}")
    lines.append("")
    return "\n".join(lines) + "\n"


def render_tor_hidden_service_vars(cfg: Config, r: Redirector) -> str:
    """Render ansible vars for one tor-hidden-service redirector."""
    if r.type != RedirectorType.tor_hidden_service:
        raise ValueError(f"redirector '{r.name}' is not tor-hidden-service")
    typed: TorHiddenServiceConfig = r.typed_config()  # type: ignore[assignment]
    if typed.socks_port is not None:
        socks_port = typed.socks_port
    elif str(r.deploy.address) in {"127.0.0.1", "localhost", "::1"} and cfg.management.torsocks_management:
        socks_port = 9050
    else:
        socks_port = 0
    tmpl = _env().get_template("tor-hidden-service-vars.yml.j2")
    return tmpl.render(r=r, cfg=typed, socks_port=socks_port)


def render_openresty_vps_data_files(cfg: Config, r: Redirector) -> dict[str, str]:
    """Return a map of filename → content for the openresty redirector data/ dir."""
    # Data files are allow-list contents only; no secrets land here, so the
    # resolver is not needed on this path.
    filt = _resolve_filter(cfg, r.filters)
    if filt is None:
        return {}
    return {
        "sni-allow.txt": "\n".join(filt.allow.sni) + "\n" if filt.allow.sni else "",
        "uri-allow.txt": "\n".join(filt.allow.uri) + "\n" if filt.allow.uri else "",
        "ua-allow.txt": "\n".join(filt.allow.ua) + "\n" if filt.allow.ua else "",
        "ja3-allow.txt": "\n".join(filt.allow.ja3) + "\n" if filt.allow.ja3 else "",
    }


def render_cf_worker(cfg: Config, resolver: SecretsResolver | None = None) -> str:
    """Render the Cloudflare Worker JS from the referenced filter profile."""
    cw = cfg.cf_worker
    filt = None
    if cw.filter_ref and cw.filter_ref in cfg.profiles.filter_profiles:
        filt = _resolve_filter(cfg, cfg.profiles.filter_profiles[cw.filter_ref], resolver)

    uris = filt.allow.uri if filt else []
    ua = filt.allow.ua[0] if filt and filt.allow.ua else ""
    require_header_name = ""
    if filt and filt.require and filt.require.headers:
        require_header_name = next(iter(filt.require.headers.keys()), "")

    tmpl = _env().get_template("cf-worker.js.j2")
    return tmpl.render(uris=uris, ua=ua, require_header_name=require_header_name)


def render_cf_wrangler(cfg: Config) -> str:
    """Render the wrangler.toml for the Cloudflare Worker."""
    cw = cfg.cf_worker
    route = cw.route
    zone_name = route.split("/")[0].lstrip("*.")  if "/" in route else route.lstrip("*.")
    tmpl = _env().get_template("wrangler.toml.j2")
    return tmpl.render(
        name=cw.name,
        compatibility_date=cw.compatibility_date,
        account_id=cw.account_id,
        route=cw.route,
        zone_name=zone_name,
    )


def render_all(cfg: Config, out_dir: Path) -> list[Path]:
    """Render every target into out_dir. Returns the list of written paths."""
    written: list[Path] = []
    out_dir.mkdir(parents=True, exist_ok=True)

    # Secrets resolver (persists to <out>/.secrets.yml, chmod 600)
    resolver = SecretsResolver(cfg, out_dir / ".secrets.yml")

    # profile.yaml
    profile_path = out_dir / "config" / "profile.yaml"
    profile_path.parent.mkdir(parents=True, exist_ok=True)
    profile_path.write_text(render_profile_yaml(cfg, resolver))
    written.append(profile_path)

    # docker-compose.yml
    compose_path = out_dir / "docker-compose.yml"
    compose_path.write_text(render_docker_compose(cfg))
    written.append(compose_path)

    # payload nginx (if enabled)
    if cfg.payload and cfg.payload.enabled:
        payload_nginx = out_dir / "staging" / "conf" / "nginx.conf"
        payload_nginx.parent.mkdir(parents=True, exist_ok=True)
        payload_nginx.write_text(render_payload_nginx(cfg))
        written.append(payload_nginx)

    # PKI: CA + leaves
    written.extend(write_pki(cfg, out_dir / "certs"))

    # per-relay output
    for rl in cfg.relays:
        if not rl.enabled:
            continue
        rldir = out_dir / "relays" / rl.name
        rldir.mkdir(parents=True, exist_ok=True)
        vars_path = rldir / "ansible-vars.yml"
        vars_path.write_text(render_relay_vars(cfg, rl))
        written.append(vars_path)

    # per-redirector output
    for r in cfg.redirectors:
        if not r.enabled:
            continue
        rdir = out_dir / "redirectors" / r.name
        rdir.mkdir(parents=True, exist_ok=True)

        if r.type == RedirectorType.openresty_vps:
            vars_path = rdir / "ansible-vars.yml"
            vars_path.write_text(render_openresty_vps_vars(cfg, r, resolver))
            written.append(vars_path)

            data_dir = rdir / "data"
            data_dir.mkdir(exist_ok=True)
            for fname, content in render_openresty_vps_data_files(cfg, r).items():
                p = data_dir / fname
                p.write_text(content)
                written.append(p)
        elif r.type == RedirectorType.tor_hidden_service:
            vars_path = rdir / "ansible-vars.yml"
            vars_path.write_text(render_tor_hidden_service_vars(cfg, r))
            written.append(vars_path)
        else:
            placeholder = rdir / ".not-yet-implemented"
            placeholder.write_text(
                f"redirector type '{r.type.value}' render not yet implemented\n"
            )
            written.append(placeholder)

    # cf-worker (if enabled)
    if cfg.cf_worker.enabled:
        cfw_dir = out_dir / "cf-worker"
        cfw_dir.mkdir(parents=True, exist_ok=True)
        worker_path = cfw_dir / "worker.js"
        worker_path.write_text(render_cf_worker(cfg, resolver))
        written.append(worker_path)
        wrangler_path = cfw_dir / "wrangler.toml"
        wrangler_path.write_text(render_cf_wrangler(cfg))
        written.append(wrangler_path)

    return written
