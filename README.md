# conduit

Deploys and manages one AdaptixC2 teamserver and the infrastructure around it (OpenResty redirectors, Tor hidden services, Nebula mesh, SSH certificate authority, Cloudflare Worker), driven by one YAML file.

**Status**: v1.0.0. Minimal. Tightly coupled to AdaptixC2: the compose template, listener schema, operator password flow, and teamserver prep playbook all assume AdaptixC2 as the C2. Swap in another C2 and most of this stops working.

## What it does

Four stages per config:

1. `validate` loads the YAML through Pydantic (`src/conduit/core/config.py`) and cross-checks hosts, keys, and ports.
2. `render` writes every artifact to a staging directory. Renderer at `src/conduit/core/renderer.py`, Jinja2 templates under `src/conduit/resources/templates/`.
3. `apply` or `deploy` builds the teamserver containers and runs the Ansible roles under `src/conduit/resources/ansible/roles/` against redirectors, relays, and the on-box Tor hidden service.
4. Ongoing commands: `status`, `monitor health`, `monitor logpull`, `nebula status`, `ca renew`, `rotate`, `clean`.

## Install

From source:

```
git clone https://github.com/sebafvs/conduit
cd conduit
pip install -e '.[tui]'
```

Package name on PyPI is `conduit-c2` (see `pyproject.toml`).

## Quickstart

```
# Validate
conduit validate --config examples/full.yml

# Render every artifact under a staging dir, no side effects
conduit render --config examples/full.yml --out /tmp/conduit-staging

# Full stack, orchestrated
conduit deploy --all \
    --config examples/full.yml \
    --staging /tmp/conduit-staging --yes

# Or one node at a time
conduit apply --teamserver         --config examples/full.yml --staging /tmp/conduit-staging --yes
conduit apply --relay relay01      --config examples/full.yml --staging /tmp/conduit-staging --yes
conduit apply --redirector redir01 --config examples/full.yml --staging /tmp/conduit-staging --yes
conduit apply --ts-onion           --config examples/full.yml --staging /tmp/conduit-staging --yes
```

The reference config at `examples/full.yml` uses RFC 5737 test IP ranges (`192.0.2.0/24`, `198.51.100.0/24`) and `example.com` domains throughout.

## Command surface

Verified against `src/conduit/cli/__init__.py`.

Top-level:

| Command | What it does |
|---|---|
| `validate` | Pydantic strict load + cross-reference checks |
| `render` | Writes artifacts to a staging directory |
| `preflight` | Checks SSH, docker, torsocks reachability |
| `apply` | Per-node apply: `--teamserver`, `--ts-onion`, `--relay NAME`, `--redirector NAME` |
| `deploy` | One-shot full-stack orchestrator |
| `diff` | Rendered output vs live install (profile.yaml, docker-compose, nginx) |
| `status` | Unified readout |
| `rotate` | Nebula + SSH host + Let's Encrypt cert rotation |
| `dashboard` | Textual TUI, 7 tabs: Overview, Tor, Health, Certs, Logs, Containers, Config (see `VIEWS` in `src/conduit/tui/__init__.py`) |

Groups:

| Group | Commands |
|---|---|
| `ingress`   | `setup`, `connect` (operator SSH tunnel) |
| `cf-worker` | `render`, `deploy` |
| `relay`     | `deploy` |
| `ca`        | `status`, `sign`, `sign-host`, `deploy`, `check`, `renew`, `renew-hosts`, `enable-relay-hop`, `enable-renewal`, `disable-renewal` |
| `payload`   | `push`, `list` |
| `monitor`   | `enable`, `disable`, `health`, `logpull`, `tor` |
| `nebula`    | `init`, `sign`, `status`, `list`, `rotate` |
| `clean`     | `logs`, `destroy` |

## Scope

Working end-to-end:

- Teamserver provisioning on a fresh Debian 13 or Ubuntu 24.04 host via `ansible/teamserver-prep/teamserver-prep.yml`, then WireGuard lockdown via `ansible/operator-bootstrap/`.
- OpenResty redirector with Lua filter chain (`src/conduit/resources/redirector/lua/filter.lua`) and nftables firewall (`src/conduit/resources/redirector/nftables/redirector.nft`).
- Tor hidden service on the teamserver as upstream for the redirector (`src/conduit/resources/ansible/roles/tor_hidden_service/`).
- Nebula mesh between redirectors and a lighthouse relay (`src/conduit/resources/ansible/roles/relay_node/` + `redirector/tasks/nebula.yml`).
- SSH certificate authority: `src/conduit/ops/sshca.py`.
- Terraform for an AWS redirector VPC under `aws/`.
- Cloudflare Worker edge frontend under `cf-worker/`.

Partial / known gaps, called out so nothing surprises you:

- **Secret backends**: `inline` and `env` are implemented. `sops`, `vault`, `file` are enum values in `SecretBackend` (`src/conduit/core/config.py` line 742) but the resolver raises `NotImplementedError` for them (`src/conduit/core/secrets.py` line 45).
- **fail2ban**: config accepts it and the filter+jail files ship under `src/conduit/resources/redirector/fail2ban/`. The redirector role's `tasks/main.yml` leaves `fail2ban.yml` out of the include chain for OPSEC reasons (see the comment at lines 23-26 of that file). Include it yourself if you want it.
- **`diff`** compares the rendered profile.yaml, docker-compose, and nginx config against the live install. It does not diff Lua lists, nftables, or fail2ban.

## Layout

```
src/conduit/
  core/        config.py, renderer.py, pki.py, secrets.py, state.py
  ops/         apply.py, deploy.py, monitor.py, nebula.py, sshca.py, payload.py, clean.py, rotate.py, status.py, ssh.py
  cli/         Click entrypoint
  tui/         Textual dashboard
  resources/   Jinja2 templates, OpenResty+Lua bundle, Ansible roles
ansible/       Out-of-package playbooks: teamserver-prep, operator-bootstrap, aws-bootstrap
aws/           Terraform for an AWS redirector VPC
cf-worker/     Cloudflare Worker source
examples/      Reference configs
extras/        Operator comms (OnionShare chat installer)
tests/         pytest
```

## License

MIT. See `LICENSE`.

## Credits

Built on [AdaptixC2](https://github.com/Adaptix-Framework/AdaptixC2), [Nebula](https://github.com/slackhq/nebula), [OpenResty](https://openresty.org/), and the [Textual](https://github.com/Textualize/textual) framework.
