"""Independent check of the StegPony format v1 test vectors.

Written from FORMAT.md, not from the Rust code, so that the vectors test the
specification and not only the reference implementation's agreement with itself.

Run from the repo root:  python3 tools/check_vectors.py
Needs: argon2-cffi, cryptography, Pillow, NumPy, jpeglib.

What it checks:
  envelope_vectors.json  every passphrase envelope is rebuilt from its random bytes
                         (FORMAT.md 2, 3.1, 4.1); every public-key envelope is checked
                         from both ends: the sender's shared secret from the ephemeral
                         key, and the reader's from the representative through Elligator 2
                         (3.2, 4.1).
  png_vectors/           every image is revealed from scratch with the listed keys
                         (4, 5) and must give exactly the expected payload, or nothing.
  text_vectors.json      the word list's hash, then every text is read back to its
                         stream (7.2, 7.3) and revealed (7.1).
"""
import hashlib
import hmac
import json
import os
import struct
import sys
import unicodedata

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from PIL import Image

# FORMAT.md section 1
ARGON2_M_KIB, ARGON2_T, ARGON2_P = 131072, 3, 4
LOCATE_SALT = b"StegPony/v1/locate"
PK_LOCATE_SALT = b"StegPony/v1/pk-locate"
INFO_LOCATE = b"StegPony/v1/locate"
INFO_BODY = b"StegPony/v1/body"
INFO_PRP = b"StegPony/v1/prp"
NUM_BUCKETS = 37
MAX_ELEMENTS_PER_SLOT = 2_000_000
M64 = (1 << 64) - 1


# ---- primitives --------------------------------------------------------------------

def argon2id(password: bytes, salt: bytes) -> bytes:
    return hash_secret_raw(password, salt, time_cost=ARGON2_T, memory_cost=ARGON2_M_KIB,
                           parallelism=ARGON2_P, hash_len=32, type=Type.ID, version=19)


def hkdf_extract(salt, ikm):
    return hmac.new(salt if salt is not None else b"\x00" * 32, ikm, hashlib.sha256).digest()


def hkdf_expand(prk, info, length):
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def hkdf(salt, ikm, info, length):
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


def bucket_size(k):  # FORMAT.md 2
    base = 64 << (k // 2)
    return base + base // 2 if k % 2 else base


def nfc(p: str) -> bytes:
    return unicodedata.normalize("NFC", p).encode("utf-8")


def x25519(scalar: bytes, u: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(scalar).exchange(X25519PublicKey.from_public_bytes(u))


def x25519_base(scalar: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(scalar).public_key().public_bytes_raw()


# Bech32 (BIP 173, not Bech32m), for age keys. FORMAT.md 3.2
B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (b >> i) & 1 else 0
    return chk


def bech32_decode(s: str, hrp: str) -> bytes:
    s = s.strip().lower()
    pos = s.rfind("1")
    if s[:pos] != hrp:
        raise ValueError("wrong hrp")
    data = [B32.index(c) for c in s[pos + 1:]]
    hrp_exp = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    if _polymod(hrp_exp + data) != 1:
        raise ValueError("bad checksum")
    acc, bits, out = 0, 0, []
    for v in data[:-6]:
        acc = (acc << 5) | v
        bits += 5
        while bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    if bits >= 5 or (acc & ((1 << bits) - 1)):
        raise ValueError("bad padding")
    return bytes(out)


# Elligator 2 forward map on Curve25519 (the reader's side of FORMAT.md 3.2).
P = 2 ** 255 - 19
A = 486662


def elligator2_u(repr_bytes: bytes) -> bytes:
    r = int.from_bytes(repr_bytes[:31] + bytes([repr_bytes[31] & 0x3F]), "little")
    w = (-A * pow(1 + 2 * r * r, P - 2, P)) % P
    gw = (w * w * w + A * w * w + w) % P
    square = gw == 0 or pow(gw, (P - 1) // 2, P) == 1
    u = w if square else (-w - A) % P
    return u.to_bytes(32, "little")


# SipHash-2-4 and the keyed permutation. FORMAT.md 4.1
def _rotl(x, b):
    return ((x << b) | (x >> (64 - b))) & M64


def siphash24(key: bytes, msg: bytes) -> int:
    k0, k1 = struct.unpack("<QQ", key)
    v = [k0 ^ 0x736F6D6570736575, k1 ^ 0x646F72616E646F6D, k0 ^ 0x6C7967656E657261, k1 ^ 0x7465646279746573]

    def rnd():
        v[0] = (v[0] + v[1]) & M64; v[1] = _rotl(v[1], 13) ^ v[0]; v[0] = _rotl(v[0], 32)
        v[2] = (v[2] + v[3]) & M64; v[3] = _rotl(v[3], 16) ^ v[2]
        v[0] = (v[0] + v[3]) & M64; v[3] = _rotl(v[3], 21) ^ v[0]
        v[2] = (v[2] + v[1]) & M64; v[1] = _rotl(v[1], 17) ^ v[2]; v[2] = _rotl(v[2], 32)

    n = len(msg)
    full = n - n % 8
    for i in range(0, full, 8):
        m = struct.unpack("<Q", msg[i:i + 8])[0]
        v[3] ^= m; rnd(); rnd(); v[0] ^= m
    m = struct.unpack("<Q", msg[full:] + b"\x00" * (7 - n % 8) + bytes([n & 0xFF]))[0]
    v[3] ^= m; rnd(); rnd(); v[0] ^= m
    v[2] ^= 0xFF
    for _ in range(4):
        rnd()
    return v[0] ^ v[1] ^ v[2] ^ v[3]


assert siphash24(bytes(range(16)), bytes(range(15))) == 0xA129CA6149BE45E5


class Prp:
    def __init__(self, key: bytes, t: int):
        bits = max((t - 1).bit_length(), 2)
        bits += bits & 1
        self.half, self.mask, self.key, self.t = bits // 2, (1 << (bits // 2)) - 1, key, t

    def _net(self, x):
        l, r = x >> self.half, x & self.mask
        for i in range(4):
            l, r = r, l ^ (siphash24(self.key, bytes([i]) + struct.pack("<Q", r)) & self.mask)
        return (l << self.half) | r

    def permute(self, x):
        y = self._net(x)
        while y >= self.t:
            y = self._net(y)
        return y


assert [Prp(bytes(16), 1_000_000).permute(i) for i in range(4)] == [354941, 379842, 364614, 325392]


def prp_key(locate: bytes, slot: int) -> bytes:
    return hkdf_expand(locate, INFO_PRP + bytes([slot]), 16)


# Ternary syndrome-trellis extraction. FORMAT.md 4.3
STC_H = 4


def stc_columns(wmax):
    """Each column as a list of STC_H trits, row 0 first."""
    st = 0x5374_6567_5465_726E ^ wmax
    cols = []
    for _ in range(wmax):
        st = (st + 0x9E3779B97F4A7C15) & M64
        z = st
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & M64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & M64
        v = z ^ (z >> 31)
        col = [(v // 3 ** k) % 3 for k in range(STC_H)]
        if col[0] == 0:
            col[0] = 1
        if col[-1] == 0:
            col[-1] = 1
        cols.append(col)
    return cols


def stc_extract(y, m):
    n = len(y)
    cols = stc_columns(-(-n // m))
    s, out = [0] * STC_H, []
    for i in range(m):
        start, end = i * n // m, (i + 1) * n // m
        rows = min(STC_H, m - i)
        for j in range(start, end):
            col = cols[j - start]
            for k in range(rows):
                s[k] = (s[k] + y[j] * col[k]) % 3
        out.append(s[0])
        s = s[1:] + [0]
    return out


def trits_for_bits(bits):
    return 7 * -(-bits // 11)


def trits_to_bytes(trits, length):
    bits = []
    for g in range(0, len(trits), 7):
        v = sum(t * 3 ** k for k, t in enumerate(trits[g:g + 7]))
        bits.extend((v >> k) & 1 for k in range(11))
    return bits_to_bytes(bits[:8 * length])


def bits_to_bytes(bits):
    return bytes(sum((bits[8 * i + k] & 1) << k for k in range(8)) for i in range(len(bits) // 8))


# Payload framing. FORMAT.md 2
def frame(p):
    if p["kind"] == "text":
        t = p["text"].encode("utf-8")
        return b"\x01" + struct.pack("<I", len(t)) + t
    name, mime, data = p["name"].encode(), p["mime"].encode(), bytes.fromhex(p["data_hex"])
    return (b"\x02" + struct.pack("<I", len(data)) + struct.pack("<H", len(name)) + name
            + struct.pack("<H", len(mime)) + mime + data)


def parse(plain):
    kind, n = plain[0], struct.unpack("<I", plain[1:5])[0]
    if kind == 1:
        return {"kind": "text", "text": plain[5:5 + n].decode("utf-8")}
    if kind == 2:
        pos = 5
        nl = struct.unpack("<H", plain[pos:pos + 2])[0]; pos += 2
        name = plain[pos:pos + nl].decode(); pos += nl
        ml = struct.unpack("<H", plain[pos:pos + 2])[0]; pos += 2
        mime = plain[pos:pos + ml].decode(); pos += ml
        return {"kind": "file", "name": name, "mime": mime, "data_hex": plain[pos:pos + n].hex()}
    return None


NONCE = b"\x00" * 12


# ---- envelope vectors --------------------------------------------------------------

def check_envelope(case, report):
    name, exp = case["name"], case["expected"]
    k, size = case["bucket"], bucket_size(case["bucket"])
    report(f"{name}: bucket size", size == case["bucket_size"])
    plain = frame(case["payload"])
    plain += b"\x00" * (size - 16 - len(plain))
    report(f"{name}: padded plaintext", plain.hex() == exp["plaintext_hex"])
    rnd = bytes.fromhex(case["random_hex"])

    if case["mode"] == "passphrase":
        p = nfc(case["passphrase"])
        locate = argon2id(p, LOCATE_SALT)
        salt = rnd[:16]
        report(f"{name}: random bytes are the salt", len(rnd) == 16)
        content = argon2id(p, salt)
        okm = hkdf(None, content, INFO_BODY, 36)
        head = salt + bytes(a ^ b for a, b in zip(struct.pack("<I", k), okm[32:]))
        report(f"{name}: content key", content.hex() == exp["content_key_hex"])
        reveal_locate = argon2id(nfc(case["reveal"]["passphrase"]), LOCATE_SALT)
    else:
        identity = bech32_decode(case["reveal"]["identity"], "age-secret-key-")
        recipient = bech32_decode(case["recipient"], "age")
        report(f"{name}: recipient matches identity", x25519_base(identity) == recipient)
        locate = hkdf(PK_LOCATE_SALT, recipient, INFO_LOCATE, 32)
        eph, tweak = bytes.fromhex(exp["eph_hex"]), exp["tweak"]
        report(f"{name}: random bytes end with eph || tweak", rnd[-33:] == eph + bytes([tweak]))
        repr_ = bytes.fromhex(exp["repr_hex"])
        shared = x25519(eph, recipient)
        reader = x25519(identity, elligator2_u(repr_))
        report(f"{name}: sender's shared secret", shared.hex() == exp["shared_hex"])
        report(f"{name}: reader's shared secret via Elligator 2", reader == shared)
        okm = hkdf(repr_ + recipient, shared, INFO_BODY, 36)
        head = repr_ + bytes(a ^ b for a, b in zip(struct.pack("<I", k), okm[32:]))
        reveal_locate = hkdf(PK_LOCATE_SALT, x25519_base(identity), INFO_LOCATE, 32)

    body = ChaCha20Poly1305(okm[:32]).encrypt(NONCE, plain, None)
    report(f"{name}: locate key", locate.hex() == exp["locate_hex"])
    report(f"{name}: reveal key finds the same positions", reveal_locate == locate)
    report(f"{name}: prp keys", prp_key(locate, 0).hex() == exp["prp_key_slot0_hex"]
           and prp_key(locate, 1).hex() == exp["prp_key_slot1_hex"])
    report(f"{name}: okm", okm.hex() == exp["okm_hex"])
    report(f"{name}: head", head.hex() == exp["head_hex"])
    report(f"{name}: body", body.hex() == exp["body_hex"])


# ---- Lossless reveal ---------------------------------------------------------------

class LosslessImage:
    """FORMAT.md 5: elements are color samples of opaque pixels; slots are 8x8 checkers."""

    def __init__(self, path):
        im = Image.open(path)
        if im.mode not in ("L", "LA", "RGB", "RGBA"):
            raise ValueError(f"unsupported mode {im.mode}")
        self.w, self.h = im.size
        self.ch = len(im.mode)
        self.cc = self.ch - 1 if im.mode in ("LA", "RGBA") else self.ch
        self.alpha = im.mode in ("LA", "RGBA")
        self.data = im.tobytes()
        self.t = self.w * self.h * self.cc
        self.counts = [0, 0]
        for p in range(self.w * self.h):
            if self._opaque(p):
                self.counts[self._slot_px(p)] += self.cc
        self._positions = {}

    def _opaque(self, p):
        return not self.alpha or self.data[p * self.ch + self.cc] == 255

    def _slot_px(self, p):
        return (((p % self.w) >> 3) + ((p // self.w) >> 3)) & 1

    def slot_of(self, t):
        p = t // self.cc
        return self._slot_px(p) if self._opaque(p) else None

    def symbol(self, t):
        return self.data[(t // self.cc) * self.ch + t % self.cc] % 3

    def positions(self, key, slot, n):
        cache = (key, slot, n)
        if cache not in self._positions:
            prp, out, i = Prp(key, self.t), [], 0
            while len(out) < n and i < self.t:
                t = prp.permute(i)
                if self.slot_of(t) == slot:
                    out.append(t)
                i += 1
            self._positions[cache] = out
        return self._positions[cache]


class JpegImage(LosslessImage):
    """FORMAT.md 6, read through libjpeg, independently of Rust coefficient I/O."""
    def __init__(self, path):
        import jpeglib
        import numpy as np
        image = jpeglib.read_dct(path)
        self.data, self.slots, self.counts, self.dc = [], [], [0, 0], []
        for name in ("Y", "Cb", "Cr", "K"):
            plane = getattr(image, name, None)
            if plane is None or not np.asarray(plane).size:
                continue
            plane = np.asarray(plane)
            rows, cols = plane.shape[:2]
            for by in range(rows):
                for bx in range(cols):
                    slot = (bx + by) & 1
                    self.dc.append(int(plane[by, bx].reshape(64)[0]))
                    self.data.extend(int(v) for v in plane[by, bx].reshape(64)[1:])
                    self.slots.extend([slot] * 63)
                    self.counts[slot] += 63
        self.t = len(self.data)
        self._positions = {}

    def slot_of(self, t):
        return self.slots[t]

    def symbol(self, t):
        return self.data[t] % 3  # Python's % is already non-negative for negatives


def reveal(img, keys):
    locs = []
    for key in keys:
        if "passphrase" in key:
            p = nfc(key["passphrase"])
            locs.append(("passphrase", argon2id(p, LOCATE_SALT), p))
        else:
            identity = bech32_decode(key["identity"], "age-secret-key-")
            recipient = x25519_base(identity)
            locs.append(("public_key", hkdf(PK_LOCATE_SALT, recipient, INFO_LOCATE, 32), (identity, recipient)))
    for slot in (0, 1):
        n = min(img.counts[slot], MAX_ELEMENTS_PER_SLOT)
        for mode, locate, secret in locs:
            head_len = 20 if mode == "passphrase" else 36
            head_trits = trits_for_bits(8 * head_len)
            head_region = max(n // 16, 8 * head_trits)
            if n < 2 * head_region:
                continue
            pos = img.positions(prp_key(locate, slot), slot, n)
            if len(pos) != n:
                continue
            y = [img.symbol(t) for t in pos]
            head = trits_to_bytes(stc_extract(y[:head_region], head_trits), head_len)
            if mode == "passphrase":
                okm = hkdf(None, argon2id(secret, head[:16]), INFO_BODY, 36)
            else:
                identity, recipient = secret
                try:
                    shared = x25519(identity, elligator2_u(head[:32]))
                except ValueError:
                    continue
                okm = hkdf(head[:32] + recipient, shared, INFO_BODY, 36)
            k = struct.unpack("<I", bytes(a ^ b for a, b in zip(head[-4:], okm[32:])))[0]
            if k >= NUM_BUCKETS:
                continue
            body_trits = trits_for_bits(8 * bucket_size(k))
            if 3 * body_trits > n - head_region:
                continue
            body = trits_to_bytes(stc_extract(y[head_region:], body_trits), bucket_size(k))
            try:
                plain = ChaCha20Poly1305(okm[:32]).decrypt(NONCE, body, None)
            except InvalidTag:
                continue
            return parse(plain)
    return None


# ---- text carriers (FORMAT.md 7) ----------------------------------------------------

HEAD_AREA = 36
ZW = {"\u200b": 0, "\u200c": 1, "\u200d": 2, "\u2060": 3}


def stream_len(k):
    return 2 * (HEAD_AREA + bucket_size(k))


# Unicode White_Space (FORMAT.md 7.2); str.isspace() is not the same set.
WHITE_SPACE = set(chr(c) for c in [*range(0x09, 0x0E), 0x20, 0x85, 0xA0, 0x1680, *range(0x2000, 0x200B),
                                    0x2028, 0x2029, 0x202F, 0x205F, 0x3000])


def zero_width_stream(text):
    syms, at = [], True
    for c in text:
        if at and c in ZW:
            syms.append(ZW[c])
            continue
        at = c in WHITE_SPACE
    if not syms:
        return None
    if len(syms) % 4:
        return b""
    return bytes(q[0] | q[1] << 2 | q[2] << 4 | q[3] << 6 for q in zip(*[iter(syms)] * 4))


def words_stream(text, index):
    words, cur = [], []
    for c in text + " ":
        if ("a" <= c <= "z") or ("A" <= c <= "Z"):
            cur.append(c)
        elif cur:
            words.append("".join(cur).lower())
            cur = []
    idx = [index[w] for w in words]  # KeyError: not StegPony words
    lens = [stream_len(k) for k in range(NUM_BUCKETS) if -(-8 * stream_len(k) // 12) == len(idx)]
    if not lens:
        return b""
    v = sum(i << (12 * n) for n, i in enumerate(idx))
    return v.to_bytes((12 * len(idx) + 7) // 8, "little")[: lens[0]]


def reveal_stream(stream, keys):
    ks = [k for k in range(NUM_BUCKETS) if stream_len(k) == len(stream)]
    if not ks:
        return None
    k = ks[0]
    size = HEAD_AREA + bucket_size(k)
    for slot in (stream[:size], stream[size:]):
        area, body = slot[:HEAD_AREA], slot[HEAD_AREA:]
        for key in keys:
            if "passphrase" in key:
                head = area[:20]
                okm = hkdf(None, argon2id(nfc(key["passphrase"]), head[:16]), INFO_BODY, 36)
            else:
                head = area
                identity = bech32_decode(key["identity"], "age-secret-key-")
                recipient = x25519_base(identity)
                try:
                    shared = x25519(identity, elligator2_u(head[:32]))
                except ValueError:
                    continue
                okm = hkdf(head[:32] + recipient, shared, INFO_BODY, 36)
            if struct.unpack("<I", bytes(a ^ b for a, b in zip(head[-4:], okm[32:])))[0] != k:
                continue
            try:
                return parse(ChaCha20Poly1305(okm[:32]).decrypt(NONCE, body, None))
            except InvalidTag:
                continue
    return None


def check_text(root, report):
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "..", "crates", "stegpony-core", "src", "text", "en.txt"), "rb") as f:
        raw = f.read()
    with open(os.path.join(root, "text_vectors.json"), encoding="utf-8") as f:
        doc = json.load(f)
    words = raw.decode("ascii").split("\n")[:-1]
    report("word list: 4096 words, SHA-256 matches",
           len(words) == 4096 and hashlib.sha256(raw).hexdigest() == doc["wordlist_sha256"])
    index = {w: i for i, w in enumerate(words)}
    for case in doc["cases"]:
        text = case["text"]
        # FORMAT.md 7.2: hidden characters that make a whole stream win; otherwise
        # the text is read as words.
        zw = zero_width_stream(text)
        if zw and any(stream_len(k) == len(zw) for k in range(NUM_BUCKETS)):
            mode, stream = "zero-width", zw
        else:
            mode, stream = "words", words_stream(text, index)
        report(f"{case['name']}: read as {case['mode']}", mode == case["mode"])
        if mode == "zero-width":
            visible = "".join(c for c in text if c not in ZW)
            report(f"{case['name']}: visible text unchanged",
                   visible == "".join(c for c in case["visible"] if c not in ZW))
        for chk in case["checks"]:
            report(f"{case['name']}: -> {'nothing' if chk['expect'] is None else chk['expect']['kind']}",
                   reveal_stream(stream, chk["keys"]) == chk["expect"])


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "crates/stegpony-core/tests/vectors"
    failures, passes = [], 0

    def report(what, ok):
        nonlocal passes
        if ok:
            passes += 1
        else:
            failures.append(what)
        print(("ok    " if ok else "FAIL  ") + what, flush=True)

    with open(os.path.join(root, "envelope_vectors.json"), encoding="utf-8") as f:
        for case in json.load(f)["cases"]:
            check_envelope(case, report)

    check_text(root, report)

    png_dir = os.path.join(root, "png_vectors")
    with open(os.path.join(png_dir, "index.json"), encoding="utf-8") as f:
        index = json.load(f)
    for case in index["cases"]:
        img = LosslessImage(os.path.join(png_dir, case["file"]))
        for chk in case["checks"]:
            got = reveal(img, chk["keys"])
            what = [("passphrase " + repr(k["passphrase"])) if "passphrase" in k else "identity" for k in chk["keys"]]
            report(f"{case['file']} with {', '.join(what)} -> {'nothing' if chk['expect'] is None else chk['expect']['kind']}",
                   got == chk["expect"])

    jpeg_dir = os.path.join(root, "jpeg_vectors")
    with open(os.path.join(jpeg_dir, "index.json"), encoding="utf-8") as f:
        jpeg_index = json.load(f)
    for case in jpeg_index["cases"]:
        img = JpegImage(os.path.join(jpeg_dir, case["file"]))
        cover = JpegImage(os.path.join(jpeg_dir, case["cover"]))
        report(f"{case['file']}: unchanged enumeration and DC, ±1 AC changes",
               img.slots == cover.slots and img.dc == cover.dc
               and all(abs(a-b) <= 1 for a,b in zip(img.data, cover.data)))
        # libjpeg must also decode the complete stego JPEG to pixels.
        import jpeglib
        jpeglib.read_spatial(os.path.join(jpeg_dir, case["file"])).spatial
        for chk in case["checks"]:
            report(f"{case['file']}: independent reveal -> {chk['expect']}",
                   reveal(img, chk["keys"]) == chk["expect"])

    print(f"\n{passes} passed, {len(failures)} failed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
