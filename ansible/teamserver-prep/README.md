# teamserver-prep

Takes a fresh VPS and prepares it for conduit. Runs from S1337 (operator controller) against the teamserver over SSH. First in the chain of three playbooks for a full zero-touch engagement.

```
teamserver-prep.yml    ← you are here (fresh VPS → conduit-ready)
    │
    ▼
operator-bootstrap.yml ← WG overlay + autossh tunnel
    │
    ▼
ssh-lockdown.yml       ← firewall off public SSH
```

## What it does

Per-teamserver, in one run, idempotent:

1. Generates an ed25519 SSH keypair **on S1337** at `~/.ssh/teamserver-<label>` (unique per engagement). Private stays on S1337.
2. Pushes the pubkey to `root/.ssh/authorized_keys` on the teamserver.
3. apt-installs the baseline deps the whole stack needs: python, git, rsync, nftables, tor, torsocks, wireguard, ansible, docker.io, docker-compose-v2.
4. Enables + starts docker.
5. Creates `/opt/conduit/{ssh-ca, nebula-certs, state}` on the teamserver.
6. Generates the SSH CA ed25519 keypair at `/opt/conduit/ssh-ca/ca` if not present.
7. Creates `/var/lib/tor/adaptix` with the correct ownership (needed by the ts-onion ansible role when conduit apply runs later).
8. Validates that conduit source is at `/root/conduit/` and runs `pip install -e .[tui]` into a venv at `/root/conduit-venv/`, symlinking `/usr/local/bin/conduit`.

What it DOES NOT do (by design, left to downstream playbooks or to `conduit apply`):

- WG setup (operator-bootstrap).
- SSH lockdown (ssh-lockdown).
- Adaptix docker stack (`conduit apply --teamserver`).
- Nebula CA initialization (`conduit nebula init`, lives on relay01).
- Letsencrypt on redirectors (`conduit apply --redirector`).

## Prerequisites

- Fresh VPS exists. Operator has the public IP and either root password or an initial key.
- Operator has rsynced the conduit source to `/root/conduit/` on the teamserver:
  ```bash
  rsync -avz --delete \
    --exclude='.git' --exclude='*-venv' --exclude='*.egg-info' \
    ~/conduit/ root@<teamserver-public-ip>:/root/conduit/
  ```
  If you would rather the playbook do the rsync, pass `-e rsync_conduit=true` and set `operator_conduit_src`.
- Ansible on S1337 (already installed by `aws-bootstrap` earlier).

## First run

```bash
cd conduit/ansible/teamserver-prep
cp inventory.yml.example inventory.yml
# edit inventory.yml: set TEAMSERVER_PUBLIC_IP

# rsync conduit source to the teamserver first (one-time, manual)
rsync -avz --delete \
  --exclude='.git' --exclude='*-venv' --exclude='*.egg-info' \
  ~/conduit/ root@<teamserver-public-ip>:/root/conduit/

# run the playbook, prompting for the root ssh password on the first connection
ansible-playbook -i inventory.yml teamserver-prep.yml -vvv \
  -e teamserver_label=contabo2026-11 -k
```

- `-e teamserver_label=<label>` - short unique tag for this engagement. Drives the per-teamserver SSH key name.
- `-k` - prompts for the SSH password. Needed on the first connection because the per-teamserver key is not yet in `authorized_keys`. Drop `-k` on re-runs.

Expected end state:

- `~/.ssh/teamserver-<label>` on S1337 (private key, owner-only).
- `/root/.ssh/authorized_keys` on the teamserver contains the matching pubkey.
- `/usr/local/bin/conduit --version` works on the teamserver.
- `/opt/conduit/ssh-ca/ca.pub` exists on the teamserver.

## Re-run against a configured teamserver

Everything is idempotent. If you re-run against the live contabo (post-lockdown), update inventory:

```yaml
teamserver:
  ansible_host: 10.200.0.1     # use the WG IP, lockdown blocks the public IP
  ansible_ssh_private_key_file: ~/.ssh/teamserver-contabo2026-11
```

Then re-run without `-k`:

```bash
ansible-playbook -i inventory.yml teamserver-prep.yml -vvv \
  -e teamserver_label=contabo2026-11
```

Expected: `ok=X changed=0` on every task. If anything shows `changed`, it means state drifted from the template.

## After teamserver-prep succeeds

```bash
# 1. operator WG + autossh tunnel
cd ../operator-bootstrap
cp inventory.yml.example inventory.yml
# edit inventory.yml: ansible_ssh_private_key_file = ~/.ssh/teamserver-<label>
ansible-playbook -i inventory.yml operator-bootstrap.yml -vvv

# 2. lock down public SSH
# edit inventory.yml: ansible_host = 10.200.0.1
ansible-playbook -i inventory.yml ssh-lockdown.yml -vvv

# 3. deploy the C2 stack (runs ON the teamserver, invoked via WG from S1337)
ssh -i ~/.ssh/teamserver-<label> root@10.200.0.1
# then on the teamserver:
cd /root/conduit
conduit deploy --stage teamserver --config examples/_private/full-tf.yml --staging /tmp/conduit-staging --skip-docker
conduit deploy --stage nebula       ...
conduit deploy --stage relays       ...
conduit deploy --stage redirectors  ...
conduit deploy --stage mesh         ...
```

## Variables

Defaults in `group_vars/all.yml`. Common overrides:

| Variable | Default | When to override |
|---|---|---|
| `teamserver_label` | `contabo` | one short tag per engagement; drives key naming |
| `operator_key_path` | `~/.ssh/teamserver-<label>` | custom key location |
| `rsync_conduit` | `false` | set `true` to make the playbook rsync conduit from `operator_conduit_src` to the teamserver instead of asserting it is already there |
| `operator_conduit_src` | `~/conduit` | source tree to rsync when `rsync_conduit=true` |
| `teamserver_conduit_src` | `/root/conduit` | where conduit ends up on the teamserver |
| `teamserver_conduit_venv` | `/root/conduit-venv` | venv path on the teamserver |

## What is NOT covered (and where that work lives)

| Not here | Lives in |
|---|---|
| WG overlay setup | `operator-bootstrap.yml` |
| SSH lockdown + nftables | `ssh-lockdown.yml` |
| Adaptix docker stack | `conduit apply --teamserver` |
| Cloud provider firewall rules (UDP 49821) | Contabo panel / AWS SG |
| DNS A records for redirectors | out of scope |
