# agent-bridge protocol, version 2 ("ab2")

Two agents, each run by a different person, get a private, authenticated,
persistent channel through an untrusted relay. The relay sees only
ciphertext and metadata. The people never handle keys, only a one-time
invite.

## Roles and flow

1. **Inviter** runs `invite`. It creates a random rendezvous topic `R`
   (128 bits) and a secret `S` (256 bits). The invite string is
   `ab2.` + base64url(JSON `{r: relay URL, t: R, s: S, n: inviter name, x: expiry}`).
   The inviter keeps `(R, S)` as a pending invite.
2. The people carry the invite from the inviter's side to the joiner's side
   by any channel (chat, call). It is valid for 12 hours and for one join.
3. **Joiner** runs `join`. It makes an ephemeral X25519 key pair `(x, X)` and a
   16-byte nonce `nj`, then publishes `JOIN = Seal(kR, aad=R, {X, nj, name, ts})`
   to topic `R`, where `kR = HKDF(S, info="ab2 rendezvous")`.
4. The inviter's `listen` opens `JOIN` with `kR`. That proves the sender holds `S`.
   It makes an ephemeral `(y, Y)` and a nonce `ni` and computes
   `Z = X25519(y, X)`, rejecting all-zero `Z`. Then it derives:
   - `T = SHA256("ab2" | R | X | Y | nj | ni | joiner name | inviter name)`
   - `OKM = HKDF(ikm=Z, salt=S, info="ab2 channel" || T)`, 112 bytes, split into
     `k_i2j`, `k_j2i`, `k_conf` (32 bytes each) and a 16-byte channel topic id.
   - `conf = HMAC(k_conf, "accept" || T)`

   It publishes `ACCEPT = Seal(kR, aad=R, {nj, Y, ni, name, conf})`, stores
   the channel, and **deletes `S`**. From then on the invite is spent.
5. The joiner opens `ACCEPT`, ignores it unless `nj` is its own, computes
   `Z = X25519(x, Y)` and the same keys, and checks `conf`. Only a holder of
   `y` can produce a valid `conf`, so a forged accept from someone who merely
   knows `S` fails. The joiner then stores the channel.

## Spent invites

After step 4 the inviter keeps only `kR` until the invite's expiry, no
longer `S`. Any later `JOIN` that opens under `kR` is refused: no channel is
created. The inviter's agent reports it as a warning, since the invite
string has leaked or been reused, and answers that join with
`REFUSED = Seal(kR, {nj})` so the late joiner stops waiting. Possession of
`kR` cannot recover the channel keys, which depend on `Z`.

## Channel messages

Each direction has its own key: inviter to joiner uses `k_i2j`, joiner to
inviter uses `k_j2i`. A party never accepts its own messages, and
reflection is impossible. A message is
`Seal(k_dir, aad=channel topic, zlib(JSON {v, id, from, ts, seq, kind, ...}))`,
where `kind` is `text`, `file` (base64 data plus a note) or `close`. The
receiver drops anything that fails authentication, is older than 12 h, or
has `seq` ≤ the last accepted `seq`, which defeats replay. Sequence counters
persist across restarts and are file-locked across processes.

`Seal` is encrypt-then-MAC: a keystream of HMAC-SHA256(ke, nonce‖counter),
XORed with the plaintext, then a tag HMAC-SHA256(km, len(aad)‖aad‖nonce‖ct).
`ke` and `km` come from HKDF of the key, and the nonce is 16 random bytes.
It uses only the standard library. A stdlib-only Python has no AES-GCM or
ChaCha20, while HMAC-SHA256 is a PRF in counter mode, a standard
construction.

## Relay interface

A relay needs `publish(topic, bytes)` and
`subscribe(topics, since) -> (id, topic, time, bytes)*`, with messages kept
for at least the invite lifetime. The default is ntfy (`https://ntfy.sh`,
or self-hosted with `AGENT_BRIDGE_RELAY` / `--relay` and a bearer token in
`AGENT_BRIDGE_TOKEN`). Small payloads travel as `ab2.<base64url>` message
bodies, larger ones as attachments. Each channel records its relay, so
channels on different relays coexist.

## Threat model

| Adversary | Outcome |
|---|---|
| Relay operator or network observer | Sees topics, timing, sizes and IPs. Cannot read, forge or replay messages. |
| Learns the invite **after** it was used | Learns nothing about past or future traffic: keys come from the ephemeral DH. Cannot join; the inviter is warned. |
| Learns the invite **before** it is used and joins first | Gets the channel instead of the intended peer. The inviter's agent reports who joined, by name, and the real joiner is refused and told the invite was used. Mitigation: the people confirm the "established" event names the right peer; the invite expires in 12 h. |
| Active MITM on the relay without the invite | Cannot complete either half of the handshake: JOIN and ACCEPT are authenticated under `kR`, ACCEPT also under `k_conf`. |
| Reads a party's `~/.config/agent-bridge` | Gets that party's channel keys and can read any traffic it recorded from the relay. Files are mode 0600. There is no ratchet; `close` deletes keys on both sides. |
| Local timing side channels | Python big-int X25519 is not constant-time. Only a co-resident process measuring timings could exploit that, and such a process could read the key files anyway. |

There are no long-term identity keys. Authentication means possession of the
invite plus the people confirming the peer's name, which is deliberate:
pairwise channels between people who already talk to each other.
