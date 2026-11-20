from __future__ import annotations

from enum import Enum
from ipaddress import IPv4Address
from pathlib import Path
from typing import Annotated, Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator


class _Base(BaseModel):
    """Strict base: extra fields rejected."""
    model_config = ConfigDict(extra="forbid")


class Meta(_Base):
    name: str
    env: str = "lab"
    operator_handle: str
    labels: dict[str, str] = Field(default_factory=dict)


class SSHTarget(_Base):
    address: str
    ssh_user: str
    ssh_key: Path
    ssh_port: int = 22


class SourceRef(_Base):
    url: str
    ref: str = "main"


class InstallTarget(str, Enum):
    local = "local"
    remote = "remote"


class TeamserverOs(str, Enum):
    # Values match `<ID>-<VERSION_ID>` from /etc/os-release on the target.
    # Same shape ansible facts produce via
    #   {{ ansible_distribution | lower }}-{{ ansible_distribution_version }}
    ubuntu_24_04 = "ubuntu-24.04"
    debian_13 = "debian-13"


class Prerequisites(_Base):
    check: bool = True


class Install(_Base):
    target: InstallTarget = InstallTarget.local
    target_host: SSHTarget | None = None
    teamserver_os: TeamserverOs = TeamserverOs.ubuntu_24_04
    root: Path = Path("/opt/adaptix")
    owner_user: str = "attacker"
    owner_group: str | None = None
    adaptix_source: SourceRef
    extension_kit_source: SourceRef | None = None
    go_win7_source: SourceRef | None = None
    rebuild: bool = False
    dry_run: bool = False
    verbose: bool = False
    prerequisites: Prerequisites = Prerequisites()

    @model_validator(mode="after")
    def _require_target_host_when_remote(self) -> Install:
        if self.target == InstallTarget.remote and self.target_host is None:
            raise ValueError("install.target=remote requires install.target_host")
        return self


class ResourceLimits(_Base):
    cpu_limit: float | None = None
    memory_limit: str | None = None


class TlsRef(_Base):
    """Reference to profiles.tls_profiles.<name>, or inline map."""
    ref: str | None = None
    min_version: str | None = None
    max_version: str | None = None
    cipher_suites: list[str] | None = None
    prefer_server_cipher_suites: bool | None = None

    @model_validator(mode="after")
    def _ref_or_inline(self) -> TlsRef:
        has_ref = self.ref is not None
        has_inline = any(
            v is not None
            for v in (self.min_version, self.max_version, self.cipher_suites)
        )
        if has_ref and has_inline:
            raise ValueError("tls: specify either ref: or inline fields, not both")
        return self


class Teamserver(_Base):
    bind_host: IPv4Address = IPv4Address("0.0.0.0")
    bind_port: int = 4321
    publish_host: IPv4Address = IPv4Address("127.0.0.1")
    publish_port: int = 4322
    endpoint: str = "/endpoint"
    server_response_header: str = "nginx"
    remove_version_header: bool = True
    access_token_live_hours: int = 12
    refresh_token_live_hours: int = 168
    db_path: str = "/app/data/adaptix.db"
    enable_http2: bool = True
    tls: TlsRef | None = None
    extenders: list[str] | None = None
    axscripts: list[str] = Field(default_factory=list)
    resources: ResourceLimits | None = None


class OperatorRole(str, Enum):
    admin = "admin"
    operator = "operator"


class Operator(_Base):
    name: str
    password: str  # literal, or secret:// URI, resolved at apply time
    role: OperatorRole = OperatorRole.operator
    only_password: bool = False


class CaSource(str, Enum):
    generate = "generate"
    import_ = "import"
    shared = "shared"


class CaSubject(_Base):
    CN: str = "cdn-sync Update CA"
    O: str = "cdn-sync Networks, Inc"
    OU: str = "Content Delivery Services"
    C: str = "US"
    ST: str | None = None
    L: str | None = None


class Ca(_Base):
    source: CaSource = CaSource.generate
    shared_path: Path | None = None
    import_cert: Path | None = None
    import_key: Path | None = None
    subject: CaSubject = CaSubject()
    validity_days: int = 3650
    key_size: int = 4096

    @model_validator(mode="after")
    def _consistency(self) -> Ca:
        if self.source == CaSource.import_ and not (self.import_cert and self.import_key):
            raise ValueError("pki.ca.source=import requires import_cert and import_key")
        if self.source == CaSource.shared and not self.shared_path:
            raise ValueError("pki.ca.source=shared requires shared_path")
        return self


class LeafSource(str, Enum):
    ca_signed = "ca-signed"
    letsencrypt = "letsencrypt"
    byo = "byo"


class LetsEncrypt(_Base):
    domain: str
    email: str
    challenge: str = "http-01"
    dns_provider: str | None = None
    credentials_ref: str | None = None


class Leaf(_Base):
    name: str
    source: LeafSource = LeafSource.ca_signed
    cn: str
    sans_dns: list[str] = Field(default_factory=list)
    sans_ip: list[IPv4Address] = Field(default_factory=list)
    validity_days: int = 365
    letsencrypt: LetsEncrypt | None = None
    byo_cert: Path | None = None
    byo_key: Path | None = None
    byo_chain: Path | None = None
    renew_days: int = 30

    @model_validator(mode="after")
    def _consistency(self) -> Leaf:
        if self.source == LeafSource.letsencrypt and self.letsencrypt is None:
            raise ValueError(f"leaf '{self.name}' source=letsencrypt requires letsencrypt block")
        if self.source == LeafSource.byo and not (self.byo_cert and self.byo_key):
            raise ValueError(f"leaf '{self.name}' source=byo requires byo_cert and byo_key")
        return self


class Pki(_Base):
    ca: Ca = Ca()
    leaves: list[Leaf] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_leaf_names(self) -> Pki:
        names = [l.name for l in self.leaves]
        if len(names) != len(set(names)):
            raise ValueError("pki.leaves: name must be unique")
        return self


class ListenerType(str, Enum):
    beacon_http = "beacon_http"
    beacon_dns = "beacon_dns"
    beacon_smb = "beacon_smb"
    beacon_tcp = "beacon_tcp"
    gopher_http = "gopher_http"
    gopher_tcp = "gopher_tcp"


class L4Proto(str, Enum):
    tcp = "tcp"
    udp = "udp"


class Listener(_Base):
    name: str
    type: ListenerType
    bind_host: IPv4Address = IPv4Address("0.0.0.0")
    bind_port: int
    publish_host: IPv4Address = IPv4Address("127.0.0.1")
    publish_port: int | None = None
    protocol: L4Proto = L4Proto.tcp
    tls_profile: str | None = None
    preset: str | None = None
    notes: str | None = None


class CrlEndpoint(_Base):
    enabled: bool = True
    path: str = "/crl/root.pem"


class Payload(_Base):
    enabled: bool = True
    bind_host: IPv4Address = IPv4Address("127.0.0.1")
    bind_port_http: int = 80
    bind_port_https: int = 443
    docroot: Path = Path("staging/www")
    server_header_fake: str = "cdn-cache/1.0"
    autoindex: bool = False
    tls_profile: str
    crl_endpoint: CrlEndpoint = CrlEndpoint()
    logging: str | None = None  # ref into observability.log_profiles
    resource_limits: ResourceLimits | None = None


class UriMatch(str, Enum):
    prefix = "prefix"
    regex = "regex"
    exact = "exact"


class FilterAllow(_Base):
    sni: list[str] = Field(default_factory=list)
    host: list[str] = Field(default_factory=list)
    uri: list[str] = Field(default_factory=list)
    uri_match: UriMatch = UriMatch.prefix
    ua: list[str] = Field(default_factory=list)
    ja3: list[str] = Field(default_factory=list)
    ja4: list[str] = Field(default_factory=list)
    ip: list[str] = Field(default_factory=list)
    geo: list[str] = Field(default_factory=list)


class FilterDeny(_Base):
    geo: list[str] = Field(default_factory=list)


class ChallengeHeader(_Base):
    name: str
    secret_ref: str


class FilterRequire(_Base):
    headers: dict[str, str] = Field(default_factory=dict)
    challenge: ChallengeHeader | None = None


class RateLimitScope(str, Enum):
    ip = "ip"
    header = "header"


class RateLimit(_Base):
    rpm: int = 60
    per: RateLimitScope = RateLimitScope.ip


class OnMiss(str, Enum):
    decoy = "decoy"
    drop = "drop"
    tarpit = "tarpit"
    not_found = "404"


class InjectHeaders(_Base):
    request: dict[str, str] = Field(default_factory=dict)
    response: dict[str, str] = Field(default_factory=dict)


class Filter(_Base):
    ref: str | None = None  # points at profiles.filter_profiles.<name>
    allow: FilterAllow = FilterAllow()
    deny: FilterDeny = FilterDeny()
    require: FilterRequire = FilterRequire()
    rate_limit: RateLimit = RateLimit()
    on_miss: OnMiss = OnMiss.decoy
    decoy_url: str = "https://en.wikipedia.org/wiki/Main_Page"
    inject_headers: InjectHeaders = InjectHeaders()


class RedirectorType(str, Enum):
    openresty_vps = "openresty-vps"
    cloudflare_cdn = "cloudflare-cdn"
    wireguard_op_ingress = "wireguard-op-ingress"
    tor_hidden_service = "tor-hidden-service"
    dnsdist = "dnsdist"
    socat_tcp = "socat-tcp"
    nginx_container = "nginx-container"


class RedirectorDeploy(_Base):
    address: str
    ssh_user: str = "attacker"
    ssh_key: Path | None = None
    ssh_port: int = 22
    local: bool = False  # true for host-local sidecars (nginx-container)


class RedirectorUpstream(_Base):
    teamserver_host: str
    teamserver_port: int
    payload_host: str | None = None
    payload_port: int | None = None


# Per-type config models. Redirector.config is validated against the right
# model at load time via Redirector's model_validator.

class OpenRestyOpts(_Base):
    workers: int | None = None  # None = auto
    connections: int = 1024


class LuaOpts(_Base):
    phase_handlers: list[str] = Field(default_factory=list)


class NftablesExtraAllow(_Base):
    cidr: str
    port: int


class NftablesPolicy(str, Enum):
    drop = "drop"
    accept = "accept"


class NftablesOpts(_Base):
    enabled: bool = True
    input_policy: NftablesPolicy = NftablesPolicy.drop
    extra_allow: list[NftablesExtraAllow] = Field(default_factory=list)


class Fail2banOpts(_Base):
    enabled: bool = True
    jails: list[str] = Field(default_factory=lambda: ["redir-decoy", "redir-429"])
    ban_time: str = "1h"
    max_retry: int = 5


class GeoipOpts(_Base):
    enabled: bool = False
    license_ref: str | None = None

    @model_validator(mode="after")
    def _license_when_enabled(self) -> GeoipOpts:
        if self.enabled and not self.license_ref:
            raise ValueError("geoip.enabled requires license_ref")
        return self


class TcpRelay(_Base):
    name: str
    listen_port: int
    target: str  # host:port


class TorClient(_Base):
    """Tor client on the redirector, routing upstream through a hidden service."""
    enabled: bool = False
    onion_address: str = ""
    onion_port: int = 80
    gost_listen_port: int = 8888
    gost_version: str = "3.3.1"
    control_port: int = 9051
    cookie_auth: bool = True
    install_nyx: bool = True
    upstream_tls: bool = True

    @model_validator(mode="after")
    def _require_onion_when_enabled(self) -> TorClient:
        if not self.enabled:
            return self
        # Empty = `!state ts_onion` is unresolved (pre-bootstrap). Downstream
        # (deploy teamserver -> ts-onion play) will populate state and the
        # re-render step will re-validate with the discovered value. Emitting
        # a hard error here breaks the chicken-and-egg on first bootstrap AND
        # on any re-apply after scrub destroyed state. Warn, don't fail.
        if not self.onion_address:
            import sys
            print(
                "[warn] tor_client.enabled with empty tor_client.onion_address. "
                "Expected when `!state ts_onion` is unresolved pre-bootstrap. "
                "Deploy the teamserver stage so state picks up the discovered "
                "onion; subsequent re-renders will fill this in.",
                file=sys.stderr,
            )
            return self
        if self.onion_address.startswith("example") or "placeholder" in self.onion_address.lower():
            raise ValueError(
                f"tor_client.onion_address looks like a placeholder: {self.onion_address!r}. "
                "Replace it with `!state ts_onion` or a real .onion."
            )
        return self


class OpenRestyVpsConfig(_Base):
    openresty: OpenRestyOpts = OpenRestyOpts()
    lua: LuaOpts = LuaOpts()
    nftables: NftablesOpts = NftablesOpts()
    fail2ban: Fail2banOpts = Fail2banOpts()
    geoip: GeoipOpts = GeoipOpts()
    tcp_relays: list[TcpRelay] = Field(default_factory=list)
    tor_client: TorClient = TorClient()


class CloudflareCdnOrigin(_Base):
    address: str
    port: int = 443
    scheme: str = "https"


class CloudflareCdnConfig(_Base):
    zone: str
    hostname: str
    origin: CloudflareCdnOrigin
    account_token_ref: str
    tls_mode: str = "strict"
    always_use_https: bool = True
    min_tls_version: str = "1.2"
    waf_rules: list[dict[str, Any]] = Field(default_factory=list)
    transform_rules: list[dict[str, Any]] = Field(default_factory=list)
    access_rules: list[dict[str, Any]] = Field(default_factory=list)
    rate_limit: dict[str, Any] | None = None


class WireguardPeer(_Base):
    name: str
    public_key: str
    allowed_ips: list[str]
    preshared_key_ref: str | None = None


class WireguardOpIngressConfig(_Base):
    interface: str = "wg0"
    listen_port: int = 51820
    address: str = "10.100.0.1/24"
    private_key_ref: str
    peers: Annotated[list[WireguardPeer], Field(min_length=1)]
    allowed_subnets: list[str] = Field(default_factory=lambda: ["10.40.40.0/24"])
    persist_keepalive: int = 25


class TorHiddenService(_Base):
    name: str
    hs_dir: str
    external_port: int
    backend_host: str
    backend_port: int
    version: int = 3
    client_auth_pubkeys: list[str] = Field(default_factory=list)


class TorHiddenServiceConfig(_Base):
    tor_version: str = "0.4.9"
    services: Annotated[list[TorHiddenService], Field(min_length=1)]
    use_bridges: bool = False
    pluggable_transport: str = "none"
    authority_lines: list[str] = Field(default_factory=list)
    socks_port: int | None = None


class DnsdistBackend(_Base):
    host: str
    port: int = 53
    protocol: L4Proto = L4Proto.udp


class DnsdistConfig(_Base):
    bind_addr: IPv4Address = IPv4Address("0.0.0.0")
    bind_port: int = 53
    backends: Annotated[list[DnsdistBackend], Field(min_length=1)]
    allowed_qname_regex: str | None = None
    allowed_qtypes: list[str] = Field(default_factory=lambda: ["A", "TXT"])
    rate_limit_qps: int | None = None


class SocatRelay(_Base):
    name: str
    listen_port: int
    listen_addr: IPv4Address = IPv4Address("0.0.0.0")
    target_host: str
    target_port: int


class SocatTcpConfig(_Base):
    relays: Annotated[list[SocatRelay], Field(min_length=1)]
    tls_passthrough: bool = True


class NginxContainerConfig(_Base):
    image: str = "nginx:1.27-alpine"
    network: str = "c2_dmz"
    publish: Annotated[list[str], Field(min_length=1)]
    conf_source: Path


class RedirectorNebula(_Base):
    """Nebula mesh config for a redirector node."""
    enabled: bool = False
    overlay_ip: str = ""
    groups: list[str] = Field(default_factory=lambda: ["redirector"])
    firewall_allow_ssh_groups: list[str] = Field(
        default_factory=lambda: ["relay", "teamserver", "operator"]
    )

    @model_validator(mode="after")
    def _require_ip_when_enabled(self) -> RedirectorNebula:
        if self.enabled and not self.overlay_ip:
            raise ValueError("nebula.enabled requires nebula.overlay_ip")
        return self


_REDIRECTOR_CONFIG_MODELS: dict[RedirectorType, type[_Base]] = {
    RedirectorType.openresty_vps: OpenRestyVpsConfig,
    RedirectorType.cloudflare_cdn: CloudflareCdnConfig,
    RedirectorType.wireguard_op_ingress: WireguardOpIngressConfig,
    RedirectorType.tor_hidden_service: TorHiddenServiceConfig,
    RedirectorType.dnsdist: DnsdistConfig,
    RedirectorType.socat_tcp: SocatTcpConfig,
    RedirectorType.nginx_container: NginxContainerConfig,
}


class Redirector(_Base):
    name: str
    type: RedirectorType
    enabled: bool = True
    deploy: RedirectorDeploy
    upstream: RedirectorUpstream
    filters: Filter | None = None
    tls_profile: str | None = None
    logging: str | None = None
    config: dict[str, Any] = Field(default_factory=dict)
    nebula: RedirectorNebula = RedirectorNebula()
    payload_dir: Path | None = None
    health_url: str | None = None

    @model_validator(mode="after")
    def _validate_typed_config(self) -> Redirector:
        model = _REDIRECTOR_CONFIG_MODELS[self.type]
        try:
            # validate but do not replace the dict; renderer calls typed_config()
            model.model_validate(self.config)
        except Exception as e:
            raise ValueError(f"redirector '{self.name}' config invalid for type={self.type.value}: {e}") from e
        return self

    def typed_config(self) -> _Base:
        """Return a validated typed config model for this redirector's type."""
        model = _REDIRECTOR_CONFIG_MODELS[self.type]
        return model.model_validate(self.config)


class RelayDeploy(_Base):
    address: str
    ssh_user: str = "ubuntu"
    ssh_key: Path | None = None
    ssh_port: int = 22


class RelayNebula(_Base):
    """Nebula mesh config for a relay (lighthouse) node."""
    overlay_ip: str
    groups: list[str] = Field(default_factory=lambda: ["relay"])
    is_lighthouse: bool = True
    listen_port: int = 4242
    firewall_allow_ssh_groups: list[str] = Field(
        default_factory=lambda: ["relay", "redirector"]
    )


class Relay(_Base):
    name: str
    enabled: bool = True
    deploy: RelayDeploy
    nebula: RelayNebula
    ssh_ca_trust: bool = True
    packages: list[str] = Field(default_factory=lambda: ["tor", "torsocks"])


class SshCaManagement(_Base):
    """SSH Certificate Authority config. CA lives on the teamserver."""
    ca_dir: Path = Path("/opt/conduit/ssh-ca")
    default_principals: str = "ubuntu"
    default_validity: str = "+8760h"
    short_validity: str = "+24h"
    renewal_interval: str = "12h"


class NebulaManagement(_Base):
    """Global Nebula mesh settings. The CA lives on the lighthouse relay."""
    enabled: bool = False
    version: str = "1.11.2"
    overlay_network: str = "10.99.0.0/24"
    ca_name: str = "c2-relay-mesh"
    ca_validity_hours: int = 8760


class TelegramAlert(_Base):
    enabled: bool = False
    token: str = ""
    chat_id: str = ""

    @model_validator(mode="after")
    def _require_fields_when_enabled(self) -> TelegramAlert:
        if self.enabled and (not self.token or not self.chat_id):
            raise ValueError("telegram.enabled requires token and chat_id")
        return self


class HealthCheck(_Base):
    enabled: bool = True
    interval: str = "5m"
    torsocks: bool = True
    connect_timeout: int = 20
    max_time: int = 30


class LogPull(_Base):
    enabled: bool = True
    interval: str = "30m"
    ssh_key: Path = Path("/opt/conduit/logpull")
    ssh_user: str = "ubuntu"
    torsocks: bool = True
    connect_timeout: int = 30
    log_paths: list[str] = Field(default_factory=lambda: [
        "/var/log/openresty/access.log",
        "/var/log/openresty/error.log",
        "/var/log/fail2ban.log",
    ])
    log_dir: Path = Path("/opt/conduit/logs")


class PayloadDistribution(_Base):
    enabled: bool = False
    staging_dir: Path = Path("/opt/payloads")
    via_relay: bool = True


class Monitoring(_Base):
    health_check: HealthCheck = HealthCheck()
    logpull: LogPull = LogPull()
    telegram: TelegramAlert = TelegramAlert()


class Management(_Base):
    ssh_ca: SshCaManagement = SshCaManagement()
    nebula: NebulaManagement = NebulaManagement()
    monitoring: Monitoring = Monitoring()
    payload_distribution: PayloadDistribution = PayloadDistribution()
    torsocks_management: bool = True


class IngressMode(str, Enum):
    ssh_tunnel = "ssh-tunnel"
    wireguard = "wireguard"
    tailscale = "tailscale"
    teleport = "teleport"
    none = "none"


class SshTunnelIngress(_Base):
    """SSH tunnel from operator workstation to the teamserver through the relay."""
    local_port: int = 40022
    relay_hop: bool = True
    teamserver_port: int = 4322

class Ingress(_Base):
    mode: IngressMode = IngressMode.ssh_tunnel
    document_only: bool = False
    ssh_tunnel: SshTunnelIngress = SshTunnelIngress()
    wireguard_ref: str | None = None


class LogRotate(_Base):
    max_size: str = "10m"
    max_files: int = 3


class LogForward(_Base):
    type: str  # syslog | elastic | loki | fluent
    endpoint: str
    tls: bool = True
    token_ref: str | None = None


class LogProfile(_Base):
    name: str
    local_path: Path
    rotate: LogRotate = LogRotate()
    forward: LogForward | None = None


class Observability(_Base):
    log_profiles: list[LogProfile] = Field(default_factory=list)
    install_log: Path = Path("./install.log")
    verbose_components: list[str] = Field(default_factory=list)


class SecretBackend(str, Enum):
    inline = "inline"
    env = "env"
    sops = "sops"
    vault = "vault"
    file = "file"


class SecretGenerated(_Base):
    password_length: int = 30
    encryption_key_bytes: int = 32


class SecretVault(_Base):
    addr: str
    role: str
    mount: str = "secret"


class SecretFile(_Base):
    base_path: Path


class Secrets(_Base):
    backend: SecretBackend = SecretBackend.inline
    env_prefix: str = "C2_"
    sops_config: Path | None = None
    vault: SecretVault | None = None
    file: SecretFile | None = None
    generated: SecretGenerated = SecretGenerated()


class TlsProfile(_Base):
    min_version: str = "TLS1.2"
    max_version: str = "TLS1.3"
    cipher_suites: list[str] = Field(default_factory=list)
    prefer_server_cipher_suites: bool = False


class BeaconProfile(_Base):
    sleep: str = "4s"
    jitter: int = 0
    uris: list[str] = Field(default_factory=list)
    user_agents: list[str] = Field(default_factory=list)
    host_headers: list[str] = Field(default_factory=list)
    method: str = "POST"
    heartbeat_header: str = "X-Beacon-Id"


class ObservabilityProfile(_Base):
    local_path: Path
    rotate: LogRotate = LogRotate()
    forward: LogForward | None = None


class Profiles(_Base):
    tls_profiles: dict[str, TlsProfile] = Field(default_factory=dict)
    filter_profiles: dict[str, Filter] = Field(default_factory=dict)
    beacon_profiles: dict[str, BeaconProfile] = Field(default_factory=dict)
    observability_profiles: dict[str, ObservabilityProfile] = Field(default_factory=dict)


class CfWorkerConfig(_Base):
    """Cloudflare Worker filter deployed via wrangler."""
    enabled: bool = False
    name: str = "c2-filter"
    route: str = ""
    account_id: str = ""
    filter_ref: str | None = None
    compatibility_date: str = "2024-01-01"

    @model_validator(mode="after")
    def _require_fields_when_enabled(self) -> CfWorkerConfig:
        if self.enabled and (not self.route or not self.account_id):
            raise ValueError("cf_worker.enabled requires route and account_id")
        return self


class BuildToggles(_Base):
    server: bool = True
    client: bool = False
    bofs: bool = True


class HostsEntry(_Base):
    address: str
    name: str


class Features(_Base):
    impacket_patch: bool = False
    proxychains_stanza: bool = False
    shell_aliases: bool = False
    hosts_entries: list[HostsEntry] = Field(default_factory=list)
    trust_ca_targets: list[str] = Field(default_factory=list)
    build: BuildToggles = BuildToggles()


class Config(_Base):
    meta: Meta
    install: Install
    teamserver: Teamserver = Teamserver()
    operators: Annotated[list[Operator], Field(min_length=1)]
    pki: Pki = Pki()
    listeners: list[Listener] = Field(default_factory=list)
    payload: Payload | None = None
    redirectors: list[Redirector] = Field(default_factory=list)
    relays: list[Relay] = Field(default_factory=list)
    management: Management = Management()
    ingress: Ingress = Ingress()
    observability: Observability = Observability()
    secrets: Secrets = Secrets()
    profiles: Profiles = Profiles()
    cf_worker: CfWorkerConfig = CfWorkerConfig()
    features: Features = Features()

    @model_validator(mode="after")
    def _resolve_cross_refs(self) -> Config:
        """Walk every ref: field and check it points at something that exists."""
        leaf_names = {l.name for l in self.pki.leaves}
        tls_profile_names = set(self.profiles.tls_profiles.keys())
        filter_profile_names = set(self.profiles.filter_profiles.keys())
        beacon_profile_names = set(self.profiles.beacon_profiles.keys())
        log_profile_names = {p.name for p in self.observability.log_profiles} | set(
            self.profiles.observability_profiles.keys()
        )

        if self.teamserver.tls and self.teamserver.tls.ref:
            if self.teamserver.tls.ref not in tls_profile_names:
                raise ValueError(
                    f"teamserver.tls.ref '{self.teamserver.tls.ref}' not in profiles.tls_profiles"
                )

        if self.payload:
            if self.payload.tls_profile not in leaf_names:
                raise ValueError(
                    f"payload.tls_profile '{self.payload.tls_profile}' not in pki.leaves"
                )
            if self.payload.logging and self.payload.logging not in log_profile_names:
                raise ValueError(f"payload.logging '{self.payload.logging}' not found")

        for lst in self.listeners:
            if lst.tls_profile and lst.tls_profile not in leaf_names:
                raise ValueError(
                    f"listener '{lst.name}' tls_profile '{lst.tls_profile}' not in pki.leaves"
                )
            if lst.preset and lst.preset not in beacon_profile_names:
                raise ValueError(
                    f"listener '{lst.name}' preset '{lst.preset}' not in profiles.beacon_profiles"
                )

        for r in self.redirectors:
            if r.tls_profile and r.tls_profile not in leaf_names:
                raise ValueError(
                    f"redirector '{r.name}' tls_profile '{r.tls_profile}' not in pki.leaves"
                )
            if r.filters and r.filters.ref and r.filters.ref not in filter_profile_names:
                raise ValueError(
                    f"redirector '{r.name}' filters.ref '{r.filters.ref}' not in profiles.filter_profiles"
                )
            if r.logging and r.logging not in log_profile_names:
                raise ValueError(f"redirector '{r.name}' logging '{r.logging}' not found")

        if self.ingress.mode == IngressMode.wireguard:
            if not self.ingress.wireguard_ref:
                raise ValueError("ingress.mode=wireguard requires ingress.wireguard_ref")
            if self.ingress.wireguard_ref not in {r.name for r in self.redirectors}:
                raise ValueError(
                    f"ingress.wireguard_ref '{self.ingress.wireguard_ref}' not in redirectors"
                )

        # relay name uniqueness
        relay_names = [rl.name for rl in self.relays]
        if len(relay_names) != len(set(relay_names)):
            raise ValueError("relays: name must be unique")

        # nebula overlay IP uniqueness across relays + redirectors
        overlay_ips: list[str] = []
        for rl in self.relays:
            if rl.enabled:
                overlay_ips.append(rl.nebula.overlay_ip.split("/")[0])
        for rd in self.redirectors:
            if rd.enabled and rd.nebula.enabled:
                overlay_ips.append(rd.nebula.overlay_ip.split("/")[0])
        if len(overlay_ips) != len(set(overlay_ips)):
            raise ValueError("nebula overlay IPs must be unique across relays and redirectors")

        # relays require management.nebula.enabled
        enabled_relays = [rl for rl in self.relays if rl.enabled]
        if enabled_relays and not self.management.nebula.enabled:
            raise ValueError("relays defined but management.nebula.enabled is false")

        # nebula-enabled redirectors require at least one lighthouse relay
        nebula_redirectors = [
            rd for rd in self.redirectors if rd.enabled and rd.nebula.enabled
        ]
        lighthouses = [rl for rl in enabled_relays if rl.nebula.is_lighthouse]
        if nebula_redirectors and not lighthouses:
            raise ValueError(
                "redirector(s) have nebula enabled but no relay with "
                "is_lighthouse=true exists"
            )

        return self


class _ConduitLoader(yaml.SafeLoader):
    """SafeLoader subclass that resolves `!state <key>` tags from the managed state file."""


_active_state: dict = {"discovered": {}}


def _state_constructor(loader: yaml.SafeLoader, node: yaml.ScalarNode) -> str:
    """Resolve `!state <key>` to the value under `discovered.<key>` of the active state.

    Missing keys resolve to empty string so `conduit validate` passes before
    the first deploy stage has populated state. Downstream consumers (preflight,
    render, apply) are responsible for refusing to proceed when a critical
    value is empty.
    """
    key = loader.construct_scalar(node)
    val = _active_state.get("discovered", {}).get(key)
    return "" if val is None else str(val)


_ConduitLoader.add_constructor("!state", _state_constructor)


def load(path: Path, state: dict | None = None) -> Config:
    """Load and validate a config file.

    `state` lets callers inject a specific state dict (useful in tests). When
    omitted, the state file at the default path for this config is loaded.
    """
    global _active_state
    if state is None:
        from .state import default_state_path, load_state
        state = load_state(default_state_path(path))
    _active_state = state
    with path.open() as f:
        raw = yaml.load(f, Loader=_ConduitLoader)
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: expected a mapping at the top level")
    return Config.model_validate(raw)
