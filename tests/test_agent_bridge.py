"""Unit tests: RFC 7748 vectors, AEAD, and the full invite/join/message flow
against an in-memory relay. Run: python3 -m unittest discover -s tests"""
import contextlib
import io
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import agent_bridge as ab  # noqa: E402

H = bytes.fromhex


class FakeRelay:
    store = {}  # topic -> [(id, topic, time, blob)]

    def __init__(self, url):
        self.url = url

    def publish(self, topic, blob):
        msgs = FakeRelay.store.setdefault(topic, [])
        msgs.append((f"m{sum(map(len, FakeRelay.store.values()))}", topic, int(time.time()), blob))

    def subscribe(self, topics, since, timeout=90):
        for t in topics:
            yield from FakeRelay.store.get(t, [])

    def last(self, topic):
        return FakeRelay.store[topic][-1][3]


@contextlib.contextmanager
def identity(root):
    """Point the module's state at one party's directories."""
    old = ab.CONFIG, ab.CACHE
    ab.CONFIG, ab.CACHE = root / "config", root / "cache"
    try:
        yield
    finally:
        ab.CONFIG, ab.CACHE = old


class X25519(unittest.TestCase):
    def test_rfc7748_5_2(self):
        out = ab.x25519(H("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
                        H("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"))
        self.assertEqual(out.hex(), "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")

    def test_rfc7748_iterated(self):
        k = u = (9).to_bytes(32, "little")
        for i in range(1, 1001):
            k, u = ab.x25519(k, u), k
            if i == 1:
                self.assertEqual(k.hex(), "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
        self.assertEqual(k.hex(), "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")

    def test_rfc7748_6_1(self):
        base = (9).to_bytes(32, "little")
        a = H("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        b = H("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        A, B = ab.x25519(a, base), ab.x25519(b, base)
        self.assertEqual(A.hex(), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        self.assertEqual(B.hex(), "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        k = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        self.assertEqual(ab.x25519(a, B).hex(), k)
        self.assertEqual(ab.x25519(b, A).hex(), k)


class Seal(unittest.TestCase):
    def test_roundtrip_and_tamper(self):
        k = b"k" * 32
        blob = ab.seal(k, b"aad", b"hello")
        self.assertEqual(ab.unseal(k, b"aad", blob), b"hello")
        bad = bytearray(blob)
        bad[20] ^= 1
        for key, aad, b in [(k, b"aad", bytes(bad)), (k, b"other", blob), (b"x" * 32, b"aad", blob)]:
            with self.assertRaises(ValueError):
                ab.unseal(key, aad, b)


class Flow(unittest.TestCase):
    def setUp(self):
        FakeRelay.store = {}
        self._relay = ab.relay_for
        ab.relay_for = FakeRelay
        self.tmp = Path(tempfile.mkdtemp())
        self.A, self.B, self.C = (self.tmp / n for n in "ABC")
        self.events = []

    def tearDown(self):
        ab.relay_for = self._relay
        shutil.rmtree(self.tmp)

    def say(self, s):
        self.events.append(s)

    def handshake(self):
        with identity(self.A):
            inv = ab.make_invite("alice", relay="fake")
            rv = ab.parse_invite(inv)["t"]
        with identity(self.B):
            ab.start_join(inv, "bob")
        with identity(self.A):
            ab.on_rendezvous(rv, FakeRelay("fake").last(rv), self.say)
        with identity(self.B):
            ab.on_rendezvous(rv, FakeRelay("fake").last(rv), self.say)
        return inv, rv

    def test_handshake_keys_and_spent_invite(self):
        inv, rv = self.handshake()
        with identity(self.A):
            ca = ab.channels()["bob"]
            self.assertFalse(ab.pending_invites())
        with identity(self.B):
            cb = ab.channels()["alice"]
            self.assertFalse(ab.pending_joins())
        self.assertEqual(ca["topic"], cb["topic"])
        self.assertEqual(ca["k_send"], cb["k_recv"])
        self.assertEqual(ca["k_recv"], cb["k_send"])
        self.assertNotEqual(ca["k_send"], ca["k_recv"])
        self.assertIn("established", self.events[0])
        # a second join with the same invite is refused and reported
        with identity(self.C):
            ab.start_join(inv, "mallory")
        with identity(self.A):
            ab.on_rendezvous(rv, FakeRelay("fake").last(rv), self.say)
            self.assertEqual(list(ab.channels()), ["bob"])
        self.assertIn("WARNING", self.events[-1])
        self.assertIn("mallory", self.events[-1])
        with identity(self.C):  # mallory learns the invite is spent; bob's accept is ignored silently
            n = len(self.events)
            for _, _, _, blob in FakeRelay("fake").subscribe([rv], 0):
                ab.on_rendezvous(rv, blob, self.say)
            self.assertFalse(ab.pending_joins())
            self.assertFalse(ab.channels())
        self.assertEqual(len(self.events), n + 1)
        self.assertIn("join refused", self.events[-1])

    def test_messages_replay_and_own(self):
        self.handshake()
        with identity(self.A):
            ab.send("bob", "text", text="ping " + "x" * 3000)
            topic = ab.channels()["bob"]["topic"]
        blob = FakeRelay("fake").last(topic)
        with identity(self.A):  # our own message on the shared topic is not delivered back
            n = len(self.events)
            ab.deliver("bob", topic, blob, self.say)
            self.assertEqual(len(self.events), n)
        with identity(self.B):
            ab.deliver("alice", topic, blob, self.say)
            ev = self.events[-1]
            self.assertIn("message from alice", ev)
            self.assertIn("full text:", ev)
            self.assertTrue(all(len(l) <= ab.WRAP + 80 for l in ev.splitlines()))
            n = len(self.events)
            ab.deliver("alice", topic, blob, self.say)  # replay
            self.assertEqual(len(self.events), n)
            full = Path(ev.rsplit("full text: ", 1)[1].rstrip("]")).read_text()
            self.assertIn("x" * 3000, full)

    def test_close(self):
        self.handshake()
        with identity(self.B):
            ab.send("alice", "close")
            topic = ab.channels()["alice"]["topic"]
        with identity(self.A):
            ab.deliver("bob", topic, FakeRelay("fake").last(topic), self.say)
            self.assertFalse(ab.channels())
        self.assertIn("closed", self.events[-1])

    def test_forged_accept_rejected(self):
        with identity(self.A):
            inv = ab.make_invite("alice", relay="fake")
            rv = ab.parse_invite(inv)["t"]
        with identity(self.B):
            ab.start_join(inv, "bob")
            secret = ab.b64d(ab.parse_invite(inv)["s"])
            # attacker knows the invite but not the inviter's DH secret
            _, Y = ab.x25519_keypair()
            nj = ab.unpack(ab._rendezvous_key(secret), rv.encode(), FakeRelay("fake").last(rv))["nj"]
            fake = {"k": "accept", "nj": nj, "Y": ab.b64e(Y), "ni": ab.b64e(b"n" * 16), "name": "alice",
                    "conf": ab.b64e(b"c" * 32)}
            ab.on_rendezvous(rv, ab.pack(ab._rendezvous_key(secret), rv.encode(), fake), self.say)
            self.assertFalse(ab.channels())
            self.assertTrue(ab.pending_joins())
        self.assertIn("WARNING", self.events[-1])

    def test_expired_invite(self):
        with identity(self.A):
            inv = ab.make_invite("alice", relay="fake")
            rv = ab.parse_invite(inv)["t"]
            p = ab._dir("invites") / f"{rv}.json"
            d = ab._read(p)
            d["expires"] = 0
            ab._write_secret(p, d)
        with identity(self.B):
            ab.start_join(inv, "bob")
        with identity(self.A):
            ab.on_rendezvous(rv, FakeRelay("fake").last(rv), self.say)
            self.assertFalse(ab.channels())
        self.assertIn("expired", self.events[-1])


if __name__ == "__main__":
    unittest.main()
