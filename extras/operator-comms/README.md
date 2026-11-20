# operator-comms

Optional: persistent OnionShare chat room for two or more operators. Not part of the C2 stack itself, lives under `extras/` so it doesn't bloat the core conduit scope.

## What this gives you

- A `.onion` chat room that survives reboots (same URL + key every time, so operators don't need to re-share it mid-engagement).
- Runs inside its own venv at `/opt/onionshare-venv/` so Flask + Flask-SocketIO upgrades don't collide with the system Python dist-packages. Avoids the Ubuntu 24.04 + Flask 3.x + Flask-SocketIO 5.3.6 breakage.
- Systemd unit `onionshare-chat.service` so it auto-restarts on failure and comes back after reboot.
- All memory-only: no messages persist to disk on the teamserver. Only the onion key material survives.

## Install

On the teamserver (operator SSHes in first via the WG tunnel):

```bash
cd /root/conduit/extras/operator-comms
cp inventory.yml.example inventory.yml
ansible-playbook -i inventory.yml install.yml -vvv
```

End of run prints the URL + private key. Share both with the other operator out of band (Signal, in person, not clearnet email).

## Operator-side connection

Open Tor Browser (or any Tor-capable browser), navigate to the URL. You'll get a `0xF4 Onionsite Requires Authentication` error with a prompt field. Paste the private key, click OK. Pick a username when the chat loads.

**Important**: Tor Browser's default security level (Safer or Safest) disables JavaScript, which breaks the WebSocket-based chat UI. Click the shield icon, drop the level to **Standard** for this site.

## Service management

```bash
systemctl status onionshare-chat
systemctl restart onionshare-chat    # keeps same .onion, drops anyone currently connected
systemctl stop onionshare-chat       # tears down the .onion from the Tor HSDirs
journalctl -u onionshare-chat -n 50  # recent log output
```

## Rotate keys (burn + rebuild)

```bash
systemctl stop onionshare-chat
rm -rf /opt/onionshare-persistent/chat.cfg
systemctl start onionshare-chat
# Read the new URL + key from /opt/onionshare-persistent/chat.cfg
```

## Uninstall

```bash
systemctl disable --now onionshare-chat
rm /etc/systemd/system/onionshare-chat.service
rm -rf /opt/onionshare-venv /opt/onionshare-persistent
systemctl daemon-reload
```

## Why not part of `conduit apply`

Operator chat is adjacent to C2, not a piece of it. The tool choice (OnionShare vs Matrix vs anything else) is engagement-specific. Keeping it out of the core config schema avoids coupling the two. If a given engagement needs it, `ansible-playbook extras/operator-comms/install.yml` is one command; if it doesn't, nothing in conduit cares.

## OPSEC notes

- Chat messages are memory-only on the teamserver. Killing the process wipes history.
- The `.onion` URL + private key are stored in `chat.cfg` on the teamserver filesystem. If the teamserver gets compromised and the attacker reads `chat.cfg`, they can join the chat (needs both URL and key; URL alone is useless).
- Chat is unauthenticated per-user: anyone with the URL + key can join and see all messages. This is a shared-secret room, not pairwise E2E.
- If a teammate burns their endpoint, rotate the keys.
