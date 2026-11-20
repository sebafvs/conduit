# operator-bootstrap

Ansible playbooks that automate the operator-side setup. Mirrors the manual steps documented in `Obsidian/Ranges/conduit/Operator SSH Hardening + WireGuard.md`.

Two playbooks on purpose, split by blast radius:

| Playbook | Touches | Blast radius |
|---|---|---|
| `operator-bootstrap.yml` | WG peer + autossh tunnel on both sides | low. Can be re-run safely. If anything fails, your public SSH still works. |
| `ssh-lockdown.yml` | nftables on the teamserver | high. If applied wrong, you lose SSH to the teamserver until the 5-min auto-revert fires (or until you use the cloud-provider console). |

## Prerequisites

- Ansible installed on the operator box. If you ran `aws-bootstrap` earlier it already is.
- SSH to the teamserver as root works from the operator box (either password or key auth). Key auth is required for the autossh tunnel; if you only have password auth, generate a key and push it to `~root/.ssh/authorized_keys` on the teamserver first.
- Python 3 on both sides (Debian/Ubuntu ships this by default).

## First run (fresh teamserver)

```bash
cd conduit/ansible/operator-bootstrap
cp inventory.yml.example inventory.yml

# edit inventory.yml: set TEAMSERVER_PUBLIC_IP and (if needed) ansible_ssh_private_key_file

ansible-playbook -i inventory.yml operator-bootstrap.yml -vvv
```

What it does, in order:

1. Install `wireguard` + `wireguard-tools` on the teamserver (apt).
2. Install `wireguard` + `wireguard-tools` + `autossh` on the operator box (apt).
3. Generate a WireGuard keypair on each side if one does not already exist. Private keys stay where they were generated.
4. Exchange pubkeys through ansible facts (pubkeys only, never private material).
5. Render `/etc/wireguard/conduit.conf` on both sides from Jinja templates.
6. `systemctl enable --now wg-quick@conduit` on both sides.
7. Ping `10.200.0.1` from the operator to confirm the handshake worked. Fails loud if not.
8. Render `/etc/systemd/system/adaptix-tunnel.service` on the operator box.
9. `systemctl enable --now adaptix-tunnel`.
10. Wait for `127.0.0.1:4322` to come up (autossh port forward).

Expected end state:

- `wg show conduit` on both sides shows one peer with a recent handshake.
- `ss -tlnp | grep ':4322'` on the operator shows autossh listening.
- Adaptix GUI client can connect to `127.0.0.1:4322`.
- The teamserver's public SSH is still open (not locked down yet).

## Lockdown (optional, run after you have proof the GUI client connects)

```bash
# EDIT inventory.yml: change ansible_host from the public IP to 10.200.0.1
# so ansible SSH goes over WG. Otherwise the lockdown ejects your session.

ansible-playbook -i inventory.yml ssh-lockdown.yml --check --diff   # dry run
ansible-playbook -i inventory.yml ssh-lockdown.yml -vvv             # real
```

What it does:

1. Prompts you to type `yes` to confirm. Blocks any accidental run.
2. Schedules `systemd-run --on-active=5min 'nft flush ruleset'` as an auto-revert. If the playbook crashes or the apply ejects you, the firewall self-wipes in 5 min.
3. Renders `/etc/nftables.conf` with 6 rules + `destroy table inet filter` so re-applies are idempotent.
4. Syntax-checks with `nft -c -f` before applying.
5. Applies with `nft -f`.
6. `wait_for_connection` to confirm ansible SSH still reaches the host after the apply. If this step hangs for 30 seconds, the auto-revert will catch it.
7. Verifies the chain policy is actually `drop` + prints the final ruleset.
8. Enables `nftables.service` so the rules reload on boot.
9. Cancels the safety net.

Expected end state:

- From the operator box, `ssh root@10.200.0.1` works.
- From the operator box WITH WG DOWN, `ssh root@<teamserver-public-ip>` times out.
- The nftables input chain shows `policy drop` + the 6 allow rules.

## Variables

Defaults live in `group_vars/all.yml`. Common overrides:

| Variable | Default | When to override |
|---|---|---|
| `wg_listen_port` | `49821` | pick a different random high port for stealth |
| `wg_cidr` | `10.200.0.0/24` | collision with another overlay on your network |
| `teamserver_public_ip` | `{{ ansible_host }}` | use when inventory points at the WG IP but LE / DNS still needs the public IP |
| `operator_user` | `$USER` | if you run ansible as root but want the autossh service to run as `seba` |
| `operator_ssh_key` | `$HOME/.ssh/id_rsa` | if your teamserver key has a different name |
| `adaptix_forward_port` | `4322` | another local service is already on 4322 |

Override on the command line:

```bash
ansible-playbook -i inventory.yml operator-bootstrap.yml \
  -e wg_listen_port=59123 \
  -e operator_ssh_key=/home/seba/.ssh/contabo_ed25519
```

## Adding a second operator peer (multiple teammates)

Not implemented as a separate playbook yet. For now, generate a new keypair on the second box, add a `[Peer]` block to the teamserver's `/etc/wireguard/conduit.conf` with the new pubkey + a new overlay IP (`10.200.0.3/32`), restart WG on the teamserver, and copy the appropriate operator config to the new box. Future work: `add-peer.yml` that automates this for a list of peers.

## Re-running

Both playbooks are idempotent. Re-runs produce zero `changed` once state is correct. Safe to run after each conduit update, after a reboot, or when you want to pick up a new default (new listen port, etc.).

## What is NOT covered

- Cloud-provider firewall changes (Contabo panel, AWS security groups). The teamserver's cloud-side firewall must already allow inbound UDP on `wg_listen_port`.
- SSH key provisioning (push your pubkey to `~root/.ssh/authorized_keys` on the teamserver before the first run).
- Rotating WG keys mid-engagement (future: `rotate-wg.yml`).
- Rotating the SSH CA operator cert (that's `conduit ca` territory, not operator bootstrap).
