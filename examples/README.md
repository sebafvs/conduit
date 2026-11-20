# Conduit example config

One worked example: `local.yml`. The full-stack scenario Conduit was designed around.

- Two openresty redirectors on separate domains (CDN pattern + API pattern).
- One Nebula lighthouse relay. The redirectors and relay form the overlay. The teamserver is NOT on the overlay.
- Each redirector forwards upstream over Tor (gost pointed at a `.onion`), so the redirector VM never learns the teamserver IP.
- A Tor hidden service on the teamserver itself, for direct beacon-to-onion traffic.
- All outbound traffic from the teamserver (git clones, package installs, Let's Encrypt registration, log pull) goes through torsocks.
- Full monitoring: health checks over Tor, log pull on a timer, optional Telegram alerts.

**Operator flow.** You run Conduit from inside the teamserver VPS, not from your workstation. SSH to the VPS once, clone or scp this repo onto it, edit `local.yml` with your real values, then `conduit apply`. `install.target: local` tells Conduit the current host is also the teamserver host, so no bootstrap SSH to a remote target. Your workstation only ever talks to the VPS.

All IPs in the example are RFC-reserved documentation ranges (`198.51.100.0/24`, `203.0.113.0/24`, `192.0.2.0/24`). All domains are `example.com`. The `.onion` placeholder starts with "example" and is not a real hidden service. Swap them with your own values before `conduit apply`.

## Validate before touching anything

```
conduit validate --config examples/full.yml
```

If this passes, your Pydantic schema is happy. Nothing has been deployed.

## The swap table

What to replace before `apply`:

| Placeholder | Where it appears | Replace with |
|---|---|---|
| `198.51.100.10`, `198.51.100.11` | redirector addresses | Your two redirector VM public IPv4s |
| `192.0.2.10` | relay / lighthouse address | Your Nebula lighthouse relay public IPv4 |
| `cdn.example.com`, `api.example.com` | redirector SNI / Host / LE domains | Your DNS A records pointing at the redirectors |
| `exampleabc456...nopqd.onion` | Tor hidden service onion address | The real `.onion` from `/var/lib/tor/<service>/hostname` on the teamserver after tor bootstraps |
| `operator@example.com` | Let's Encrypt registration email | Your email, or a `noreply@yourdomain` |
| `~/.ssh/redir01.pem`, `~/.ssh/redir02.pem`, `~/.ssh/relay.pem` | SSH key paths | Your actual SSH key paths on the teamserver VPS. `~/.ssh/id_ed25519` for the ts-onion loopback entry is fine as long as root's own key is in `~/.ssh/authorized_keys`. |
| `TELEGRAM_CHAT_ID_HERE` | monitoring.telegram.chat_id | Your Telegram chat ID. Also set `enabled: true` and put the bot token in your secrets backend. |
| `secret://ops/operator`, `secret://monitoring/telegram_token`, `secret://edge/challenge` | secret URIs | Keep the URI shape; populate the actual secret in your `secrets.backend` of choice (inline, SOPS, Vault, env, file). |

## Local-only copies

To keep a working config in-tree without checking it in, drop it under `examples/_private/` or name it `*.local.yml`. Both patterns are in `.gitignore`.

```
cp examples/full.yml examples/_private/full.yml
# edit with your real values
conduit deploy --all --config examples/_private/full.yml --staging /tmp/conduit-staging --yes
```

## What a secret URI looks like

Conduit never writes secrets into the YAML directly. Fields that take credentials take a `secret://path/to/key` URI, resolved at apply time against the backend configured in `secrets.backend`:

```yaml
secrets:
  backend: inline       # or: sops | vault | env | file
  generated: {password_length: 30, encryption_key_bytes: 32}

operators:
  - {name: alice, password: "secret://ops/alice", role: admin}
```

For `backend: inline`, write the actual values into a `.secrets.yml` next to your config (gitignored by default). For `sops`, `vault`, `env`, `file`, see the top-level README for the backend-specific layout.
