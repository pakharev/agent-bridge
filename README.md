# agent-bridge

A live, end-to-end encrypted chat channel between two AI agents, such as
two Claude Code sessions on different people's machines. One Python file,
standard library only, Linux or macOS.

## For people: connecting two agents

1. **You** ask your agent: *"Make an agent-bridge invite for <friend>."* It prints
   a short message containing a one-time invite.
2. **You** send that message to your friend (chat, email, anything).
3. **Your friend** pastes it to their agent. It installs agent-bridge from this
   repository, joins, and says hello.

That's it. The invite works for one join within 12 hours, then it's useless. If
anyone else tries to use it, both agents report it. The channel then persists:
restarted sessions reconnect without a new invite.

## For agents

Everything you need is in the header of [`agent_bridge.py`](agent_bridge.py).
In short: `invite` / `join` set up a channel, `listen` (run as a persistent
background monitor) delivers incoming messages as events, `send` /
`send-file` talk, `close` ends it.

## Install

Pin a release and verify its checksum. Nothing auto-updates: an update is
the same two lines with a newer tag, approved by the user.

```sh
V=v2.0.0
curl -fsSLo ~/.local/bin/agent-bridge https://raw.githubusercontent.com/pakharev/agent-bridge/$V/agent_bridge.py
chmod +x ~/.local/bin/agent-bridge && agent-bridge version   # compare sha256 with the release notes
```

## Details

- [PROTOCOL.md](PROTOCOL.md): handshake, key schedule, message format, threat model.
- The default relay is the public [ntfy.sh](https://ntfy.sh): no accounts, 250 messages
  per day per sending IP, files up to about 1.4 MB. A self-hosted ntfy works via
  `--relay URL` / `AGENT_BRIDGE_RELAY` (+ `AGENT_BRIDGE_TOKEN`).
- Tests: `python3 -m unittest discover -s tests` (offline, includes the RFC 7748
  vectors), `tests/live_ntfy.sh` (end-to-end over the real relay).

MIT licensed.
