"""UR — the animated-QR format the rest of the airgap ecosystem speaks.

`qr.py` carries the `pNofM` framing this device shipped with: a text prefix and
base64, deliberately boring, and understood by Specter and Sparrow. This module
carries the other one, and it is the one most coordinators now reach for first.

WHY A SECOND FRAMING AT ALL. `pNofM` is a fixed-rate code. The receiver needs
every index, so a transfer of nine frames where the camera keeps missing frame
four is a transfer that never finishes, and the owner learns that by watching a
counter sit at eight of nine. UR is rateless: past the first `seqLen` parts the
sender keeps emitting XOR mixtures of fragments chosen by a seeded PRNG, and
any sufficient subset reconstructs the message. A missed frame stops costing a
whole loop of the animation.

That matters more here than on a device with a fast camera. This one has a $8
webcam and a Pi Zero, and `camera.USBCamera` already drops to 640x480 because
a Pi decoding 1080p spends its time on pixels rather than on frames.

WHAT THIS IS NOT. It is not a replacement. `qr.py` stays, both encoders are
offered, and `camera.scan` accepts either without being told which — a device
that could only speak the newer dialect would be a device that stopped working
with the coordinator its owner already has. Neither framing is trusted: both
hand bytes to `app.classify`, and what the device signs is what it rendered.

THE SPECIFICATION, AND WHY THE VECTORS ARE NOT OPTIONAL. This is BCR-2020-005
(UR), BCR-2020-012 (Bytewords) and BCR-2024-001 (multipart UR). Every piece of
it is load-bearing for interoperability and none of it is guessable: the
fountain mixture in part 13 of a transfer depends on Xoshiro256**, seeded from
a CRC-32, sampled through a Walker-Vose alias table, permuted by a particular
Fisher-Yates. Get any one of those subtly wrong and the encoder still produces
plausible-looking URs that no other implementation can decode — the exact
failure `qr.py` warns about, discovered while holding a device that has already
been bled into.

So `vectors/ur.json` holds the reference implementation's own published test
vectors, and `_selftest` runs all of them: the PRNG streams, the alias sampler,
the shuffle, the degree chooser, the fragment selection, the partition, and two
complete end-to-end UR encodings checked string for string. A change that
breaks interoperability fails here rather than on a bench.
"""

from __future__ import annotations

import hashlib
import json
import zlib
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------
# Bytewords — BCR-2020-012
# --------------------------------------------------------------------------

# 256 four-letter words, indexed by byte value. UR uses the `minimal` style,
# which keeps only each word's first and last letter, so a byte costs two
# characters exactly as hex does. The full words exist for the styles a human
# reads aloud, which this device never does.
#
# Committed as a literal rather than fetched, and then checked below, on the
# same reasoning as `bip39.py`'s wordlist digest: a transport table that is
# wrong is a transport that fails against every other implementation, and the
# cheapest place to notice is import time.
BYTEWORDS = (
    "able acid also apex aqua arch atom aunt away axis back bald barn belt "
    "beta bias blue body brag brew bulb buzz calm cash cats chef city claw "
    "code cola cook cost crux curl cusp cyan dark data days deli dice diet "
    "door down draw drop drum dull duty each easy echo edge epic even exam "
    "exit eyes fact fair fern figs film fish fizz flap flew flux foxy free "
    "frog fuel fund gala game gear gems gift girl glow good gray grim guru "
    "gush gyro half hang hard hawk heat help high hill holy hope horn huts "
    "iced idea idle inch inky into iris iron item jade jazz join jolt jowl "
    "judo jugs jump junk jury keep keno kept keys kick kiln king kite kiwi "
    "knob lamb lava lazy leaf legs liar limp lion list logo loud love luau "
    "luck lung main many math maze memo menu meow mild mint miss monk nail "
    "navy need news next noon note numb obey oboe omit onyx open oval owls "
    "paid part peck play plus poem pool pose puff puma purr quad quiz race "
    "ramp real redo rich road rock roof ruby ruin runs rust safe saga scar "
    "sets silk skew slot soap solo song stub surf swan taco task taxi tent "
    "tied time tiny toil tomb toys trip tuna twin ugly undo unit urge user "
    "vast very veto vial vibe view visa void vows wall wand warm wasp wave "
    "waxy webs what when whiz wolf work yank yawn yell yoga yurt zaps zero "
    "zest zinc zone zoom"
).split()


class BadUR(ValueError):
    """A UR frame that does not belong to the transfer being collected."""


def _check_bytewords() -> None:
    """Three structural properties, checked once at import.

    None of them proves the table is the published one on its own. Together
    they catch every transcription error that is survivable enough to be
    dangerous: a dropped word shortens it, a mistyped letter breaks the
    minimal-encoding uniqueness the format depends on, and a transposition
    breaks the sort. A table that passes all three and is still wrong would
    have to be wrong in a way that preserved 256 entries, 256 distinct
    two-letter codes and lexicographic order, which is not a typo.
    """
    if len(BYTEWORDS) != 256:
        raise BadUR(f"the byteword table has {len(BYTEWORDS)} entries, not 256")
    if any(len(w) != 4 or not w.isalpha() or not w.islower() for w in BYTEWORDS):
        raise BadUR("every byteword is four lowercase letters")
    minimal = [w[0] + w[-1] for w in BYTEWORDS]
    if len(set(minimal)) != 256:
        raise BadUR(
            "two bytewords share a first-and-last letter pair, so the minimal "
            "encoding this format uses would be ambiguous")
    if BYTEWORDS != sorted(BYTEWORDS):
        raise BadUR("the byteword table is not in its published order")


_check_bytewords()

_MINIMAL = {w[0] + w[-1]: i for i, w in enumerate(BYTEWORDS)}


def crc32(data: bytes) -> int:
    """The checksum the whole format is keyed on. Standard CRC-32, as zlib."""
    return zlib.crc32(data) & 0xFFFFFFFF


def _be4(n: int) -> bytes:
    return n.to_bytes(4, "big")


def bytewords_encode(payload: bytes) -> str:
    """Minimal-style bytewords, with the CRC-32 appended as the format requires."""
    body = payload + _be4(crc32(payload))
    return "".join(BYTEWORDS[b][0] + BYTEWORDS[b][-1] for b in body)


def bytewords_decode(text: str) -> bytes:
    """The inverse, refusing anything whose checksum does not hold.

    The checksum is not a security property — an attacker holding up a screen
    computes it as easily as anyone else. It is a transcription property: it
    catches a frame the camera half-read, which is the common case, and it
    means a corrupted fragment is refused here rather than XORed into a
    reconstruction that then fails as a whole with nothing to point at.
    """
    if len(text) % 2:
        raise BadUR("a minimal bytewords string has two characters per byte")
    if len(text) < 10:
        # 4 bytes of checksum plus at least one byte of payload.
        raise BadUR("bytewords payload is too short to carry a checksum")
    out = bytearray()
    for i in range(0, len(text), 2):
        pair = text[i:i + 2]
        idx = _MINIMAL.get(pair)
        if idx is None:
            raise BadUR(f"{pair!r} is not a byteword")
        out.append(idx)
    body, want = bytes(out[:-4]), int.from_bytes(out[-4:], "big")
    if crc32(body) != want:
        raise BadUR("bytewords checksum does not match; the frame was misread")
    return body


# --------------------------------------------------------------------------
# CBOR — only the four things UR needs
# --------------------------------------------------------------------------

# UR payloads are CBOR, but the subset in play is tiny: an unsigned integer, a
# byte string, a definite-length array, and a tag. A general CBOR library would
# bring indefinite lengths, floats, maps with arbitrary keys and recursion --
# all of it reachable from the camera, and none of it needed. So this is a
# deliberate four-case encoder and a decoder that refuses everything else.
#
# Maps and text strings decode too, because `eth-sign-request` is a map, but
# nothing here recurses without a depth bound.

# Deep enough for the deepest structure this module writes, and no deeper. A
# crypto-account nests about twelve levels -- account, map, array, output,
# sh, wpkh, hdkey, map, keypath, map, array, component -- so a bound of 8 was
# one this module's own encoder could produce output past. The bound is here to
# stop `[` repeated a few hundred thousand times off the camera from recursing
# the decoder into the ground; 16 does that as well as 8 does.
CBOR_MAX_DEPTH = 16


def cbor_uint(n: int) -> bytes:
    return _cbor_head(0, n)


def cbor_bytes(b: bytes) -> bytes:
    return _cbor_head(2, len(b)) + b


def cbor_text(s: str) -> bytes:
    raw = s.encode("utf-8")
    return _cbor_head(3, len(raw)) + raw


def cbor_array(items: list[bytes]) -> bytes:
    return _cbor_head(4, len(items)) + b"".join(items)


def cbor_map(pairs: list[tuple[bytes, bytes]]) -> bytes:
    return _cbor_head(5, len(pairs)) + b"".join(k + v for k, v in pairs)


def cbor_tag(tag: int, item: bytes) -> bytes:
    return _cbor_head(6, tag) + item


def cbor_bool(v: bool) -> bytes:
    return b"\xf5" if v else b"\xf4"


def _cbor_head(major: int, n: int) -> bytes:
    if n < 0:
        raise BadUR("CBOR lengths and unsigned integers are not negative")
    m = major << 5
    if n < 24:
        return bytes([m | n])
    for bits, marker in ((8, 24), (16, 25), (32, 26), (64, 27)):
        if n < (1 << bits):
            return bytes([m | marker]) + n.to_bytes(bits // 8, "big")
    raise BadUR("value too large for CBOR")


def cbor_decode(data: bytes, depth: int = 0):
    """Decode one CBOR item. Returns (value, rest).

    Byte and text strings come back as `bytes` and `str`, arrays as lists,
    maps as dicts, tags as `(Tag, value)`. Anything else -- floats, indefinite
    lengths, negative integers, simple values -- is a refusal, because nothing
    this device reads uses them and a decoder that accepts them is a decoder
    with more behaviour than the format needs.
    """
    if depth > CBOR_MAX_DEPTH:
        raise BadUR(f"CBOR nested deeper than {CBOR_MAX_DEPTH}")
    if not data:
        raise BadUR("CBOR ended early")
    ib = data[0]
    major, minor = ib >> 5, ib & 0x1F
    rest = data[1:]
    if minor < 24:
        n = minor
    elif minor in (24, 25, 26, 27):
        width = 1 << (minor - 24)
        if len(rest) < width:
            raise BadUR("CBOR length ended early")
        n, rest = int.from_bytes(rest[:width], "big"), rest[width:]
    else:
        raise BadUR(f"CBOR additional-information {minor} is not supported")

    if major == 0:
        return n, rest
    if major in (2, 3):
        if len(rest) < n:
            raise BadUR("CBOR string ended early")
        raw, rest = rest[:n], rest[n:]
        if major == 2:
            return raw, rest
        try:
            return raw.decode("utf-8"), rest
        except UnicodeDecodeError:
            raise BadUR("CBOR text is not valid UTF-8") from None
    if major == 4:
        items = []
        for _ in range(n):
            item, rest = cbor_decode(rest, depth + 1)
            items.append(item)
        return items, rest
    if major == 5:
        out = {}
        for _ in range(n):
            k, rest = cbor_decode(rest, depth + 1)
            v, rest = cbor_decode(rest, depth + 1)
            if isinstance(k, (bytes, str, int)):
                out[k] = v
            else:
                raise BadUR("CBOR map keys must be integers, text or bytes")
        return out, rest
    if major == 6:
        item, rest = cbor_decode(rest, depth + 1)
        return Tag(n, item), rest
    if major == 7:
        # Booleans only, and only because a crypto-keypath spells its hardened
        # flags with them. `null` stays refused along with the floats: a null
        # in a map is a field with no value to display, and this device does
        # not sign fields it cannot show.
        if ib == 0xF4:
            return False, rest
        if ib == 0xF5:
            return True, rest
        raise BadUR(
            "CBOR floats, null and undefined are not read by this device")
    raise BadUR(f"CBOR major type {major} is not supported")


@dataclass(frozen=True)
class Tag:
    """A CBOR tag and what it wraps."""
    tag: int
    value: object


# --------------------------------------------------------------------------
# Xoshiro256** — BCR-2020-005
# --------------------------------------------------------------------------

_M64 = (1 << 64) - 1
_TWO64 = 1 << 64


def _rotl(x: int, k: int) -> int:
    return ((x << k) | (x >> (64 - k))) & _M64


class Xoshiro256:
    """The PRNG the fountain code is defined in terms of.

    Seeded from bytes by SHA-256, then read as four big-endian 64-bit words.
    Reproduced exactly, including `next_int`'s INCLUSIVE upper bound and
    `next_double`'s division by 2^64 rather than by 2^64 - 1: both are
    observable in the fragment mixtures, so a "more correct" variant is an
    incompatible one.
    """

    __slots__ = ("s",)

    def __init__(self, seed):
        if isinstance(seed, str):
            seed = seed.encode("utf-8")
        if isinstance(seed, int):
            seed = _be4(seed)
        digest = hashlib.sha256(bytes(seed)).digest()
        self.s = [int.from_bytes(digest[i * 8:(i + 1) * 8], "big")
                  for i in range(4)]

    def next(self) -> int:
        s = self.s
        result = (_rotl((s[1] * 5) & _M64, 7) * 9) & _M64
        t = (s[1] << 17) & _M64
        s[2] ^= s[0]
        s[3] ^= s[1]
        s[1] ^= s[2]
        s[0] ^= s[3]
        s[2] ^= t
        s[3] = _rotl(s[3], 45)
        return result

    def next_double(self) -> float:
        return self.next() / _TWO64

    def next_int(self, low: int, high: int) -> int:
        """Inclusive on both ends, as the reference implementation is."""
        return int(self.next_double() * (high - low + 1)) + low

    def next_byte(self) -> int:
        return self.next_int(0, 255)

    def next_data(self, count: int) -> bytes:
        return bytes(self.next_byte() for _ in range(count))


class RandomSampler:
    """Walker-Vose alias sampling, as the degree chooser is specified to use.

    The construction order is part of the specification, not an implementation
    detail: the small and large index lists are filled by walking the
    probabilities BACKWARDS, and both are used as stacks. Fill them forwards
    and the alias table differs, the sampled degrees differ, and the mixtures
    in every part past `seqLen` differ. `next` draws TWO doubles from the
    generator, which is also observable.
    """

    __slots__ = ("probs", "aliases")

    def __init__(self, probs: list[float]):
        if not probs or any(p < 0 for p in probs):
            raise BadUR("probabilities must be non-empty and non-negative")
        total = sum(probs)
        if total <= 0:
            raise BadUR("probabilities sum to zero")
        n = len(probs)
        P = [p * n / total for p in probs]
        small: list[int] = []
        large: list[int] = []
        for i in range(n - 1, -1, -1):
            (small if P[i] < 1 else large).append(i)
        out_probs = [0.0] * n
        aliases = [0] * n
        while small and large:
            a = small.pop()
            g = large.pop()
            out_probs[a] = P[a]
            aliases[a] = g
            P[g] += P[a] - 1
            (small if P[g] < 1 else large).append(g)
        while large:
            out_probs[large.pop()] = 1.0
        while small:
            # Only reachable through floating-point drift.
            out_probs[small.pop()] = 1.0
        self.probs = out_probs
        self.aliases = aliases

    def next(self, rng: Xoshiro256) -> int:
        r1 = rng.next_double()
        r2 = rng.next_double()
        i = int(len(self.probs) * r1)
        return i if r2 < self.probs[i] else self.aliases[i]


def shuffled(items: list, rng: Xoshiro256) -> list:
    """Fisher-Yates, in the reference implementation's exact draw order."""
    remaining = list(items)
    result = []
    while remaining:
        index = rng.next_int(0, len(remaining) - 1)
        result.append(remaining.pop(index))
    return result


def choose_degree(seq_len: int, rng: Xoshiro256) -> int:
    """How many fragments this part mixes. Harmonic weights, so 1 is commonest."""
    return RandomSampler([1.0 / i for i in range(1, seq_len + 1)]).next(rng) + 1


def choose_fragments(seq_num: int, seq_len: int, checksum: int) -> set:
    """Which fragment indexes part `seq_num` carries.

    The first `seq_len` parts are the pure fragments, each carrying exactly
    one, which is what makes a UR transfer that is never interrupted no slower
    than a fixed-rate one. Past that the mixtures begin, and both ends derive
    them from the same seed rather than from anything on the wire.
    """
    if seq_num <= seq_len:
        return {seq_num - 1}
    rng = Xoshiro256(_be4(seq_num) + _be4(checksum))
    degree = choose_degree(seq_len, rng)
    return set(shuffled(list(range(seq_len)), rng)[:degree])


# --------------------------------------------------------------------------
# Fountain encoding
# --------------------------------------------------------------------------

# A conservative default, for the same reason `qr.DEFAULT_CHUNK` is 300: the
# real constraint is a 240x240 panel and a cheap webcam, not the QR standard.
DEFAULT_MAX_FRAGMENT = 200
MIN_FRAGMENT = 10

# Ceilings on what a frame off the camera may claim, on `qr.MAX_FRAMES`'
# reasoning: `seq_len` and `message_len` are attacker-chosen, and without a
# bound one held-up code sizes an allocation or a loop on this device. A
# megabyte is far past any PSBT this device will render, and 4096 fragments is
# past any transfer it will ever be shown.
MAX_SEQ_LEN = 4096
MAX_MESSAGE_LEN = 1 << 20


def find_nominal_fragment_length(message_len: int, min_fragment_len: int,
                                 max_fragment_len: int) -> int:
    """The fragment size both ends must agree on, derived not transmitted."""
    if message_len <= 0 or min_fragment_len <= 0:
        raise BadUR("message and fragment lengths must be positive")
    if max_fragment_len < min_fragment_len:
        raise BadUR("max fragment length is below the minimum")
    max_count = message_len // min_fragment_len
    fragment_len = message_len
    for count in range(1, max_count + 1):
        fragment_len = -(-message_len // count)          # ceil
        if fragment_len <= max_fragment_len:
            break
    return fragment_len


def partition(message: bytes, fragment_len: int) -> list[bytes]:
    """Split into equal fragments, zero-padding the last one.

    The padding is why `messageLen` travels in every part: the receiver has to
    know where the message stopped and the zeroes began.
    """
    out = []
    for i in range(0, len(message), fragment_len):
        piece = message[i:i + fragment_len]
        out.append(piece + bytes(fragment_len - len(piece)))
    return out


@dataclass(frozen=True)
class Part:
    """One part of a multipart transfer, as it travels."""

    seq_num: int
    seq_len: int
    message_len: int
    checksum: int
    data: bytes

    def cbor(self) -> bytes:
        return cbor_array([cbor_uint(self.seq_num), cbor_uint(self.seq_len),
                           cbor_uint(self.message_len), cbor_uint(self.checksum),
                           cbor_bytes(self.data)])

    @staticmethod
    def from_cbor(raw: bytes) -> "Part":
        item, rest = cbor_decode(raw)
        if rest:
            raise BadUR("trailing bytes after a UR part")
        if not isinstance(item, list) or len(item) != 5:
            raise BadUR("a UR part is a five-element array")
        seq_num, seq_len, message_len, checksum, data = item
        for name, v in (("seqNum", seq_num), ("seqLen", seq_len),
                        ("messageLen", message_len), ("checksum", checksum)):
            if not isinstance(v, int) or isinstance(v, bool):
                raise BadUR(f"{name} is not an unsigned integer")
        if not isinstance(data, bytes):
            raise BadUR("a UR part's payload is a byte string")
        return Part(seq_num, seq_len, message_len, checksum, data)


class FountainEncoder:
    """Emits parts forever. Past `seq_len` they are mixtures."""

    def __init__(self, message: bytes, max_fragment_len: int = DEFAULT_MAX_FRAGMENT,
                 first_seq_num: int = 0, min_fragment_len: int = MIN_FRAGMENT):
        if not message:
            raise BadUR("nothing to encode")
        self.message_len = len(message)
        self.checksum = crc32(message)
        self.fragment_len = find_nominal_fragment_length(
            self.message_len, min_fragment_len, max_fragment_len)
        self.fragments = partition(message, self.fragment_len)
        self.seq_num = first_seq_num

    @property
    def seq_len(self) -> int:
        return len(self.fragments)

    @property
    def is_single_part(self) -> bool:
        return self.seq_len == 1

    def next_part(self) -> Part:
        self.seq_num = (self.seq_num + 1) % (1 << 32)
        indexes = choose_fragments(self.seq_num, self.seq_len, self.checksum)
        mixed = bytearray(self.fragment_len)
        for i in sorted(indexes):
            frag = self.fragments[i]
            for j in range(self.fragment_len):
                mixed[j] ^= frag[j]
        return Part(self.seq_num, self.seq_len, self.message_len,
                    self.checksum, bytes(mixed))


# --------------------------------------------------------------------------
# Fountain decoding
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class _Piece:
    """A set of fragment indexes and the XOR of those fragments."""
    indexes: frozenset
    data: bytes

    @property
    def is_simple(self) -> bool:
        return len(self.indexes) == 1

    @property
    def index(self) -> int:
        return next(iter(self.indexes))


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _reduce_by(piece: _Piece, other: _Piece) -> _Piece:
    """Subtract `other` from `piece`, if it is a strict subset of it."""
    if other.indexes < piece.indexes:
        return _Piece(piece.indexes - other.indexes,
                      _xor(piece.data, other.data))
    return piece


class FountainDecoder:
    """Accumulates parts, reducing mixtures against what is already known.

    The algorithm is the reference one: a pure fragment retires itself and is
    then subtracted from every mixture held; a mixture is first reduced by
    everything known, and either collapses to a pure fragment or is kept to be
    reduced later. What is added here is refusal rather than tolerance, on
    `qr.Collector`'s reasoning.

    THE SUBSTITUTION RULE. A part's contents are a deterministic function of
    its `seqNum` and the message, so the same `seqNum` arriving twice with
    DIFFERENT bytes cannot happen to an honest sender. The reference decoder
    ignores the second copy; this one refuses the whole transfer, because the
    situation it describes is two screens in the camera's field of view, one of
    which is not the owner's.
    """

    def __init__(self):
        self.seq_len: int | None = None
        self.message_len: int | None = None
        self.checksum: int | None = None
        self.fragment_len: int | None = None
        self._simple: dict[int, _Piece] = {}
        self._mixed: dict[frozenset, _Piece] = {}
        self._seen: dict[int, bytes] = {}
        self.result: bytes | None = None

    # ---- shape checks, all before anything is kept ----

    def _pin(self, part: Part) -> None:
        if not 1 <= part.seq_len <= MAX_SEQ_LEN:
            raise BadUR(
                f"a part claims {part.seq_len} fragments; this device collects "
                f"between 1 and {MAX_SEQ_LEN}")
        if not 1 <= part.message_len <= MAX_MESSAGE_LEN:
            raise BadUR(
                f"a part claims a {part.message_len}-byte message; this device "
                f"collects up to {MAX_MESSAGE_LEN}")
        if part.seq_num < 1:
            raise BadUR("sequence numbers are one-based")
        if part.checksum >> 32:
            raise BadUR("the checksum is not a 32-bit value")
        want = -(-part.message_len // part.seq_len)
        if len(part.data) != want:
            raise BadUR(
                f"a part carries {len(part.data)} bytes where {part.seq_len} "
                f"fragments of a {part.message_len}-byte message need {want}")
        if self.seq_len is None:
            self.seq_len, self.message_len = part.seq_len, part.message_len
            self.checksum, self.fragment_len = part.checksum, want
            return
        if (part.seq_len, part.message_len, part.checksum) != \
                (self.seq_len, self.message_len, self.checksum):
            raise BadUR(
                "this part belongs to a different transfer than the one being "
                "collected. Two different transfers are on screen; restart "
                "the scan.")

    def receive(self, part: Part) -> bytes | None:
        """Add a part. Returns the message once it is complete, else None."""
        if self.result is not None:
            return self.result
        self._pin(part)
        prior = self._seen.get(part.seq_num)
        if prior is not None:
            if prior != part.data:
                raise BadUR(
                    f"part {part.seq_num} arrived twice with different "
                    f"contents. Something is changing the payload mid-scan; "
                    f"restart the scan.")
            return None
        self._seen[part.seq_num] = part.data
        indexes = choose_fragments(part.seq_num, part.seq_len, part.checksum)
        if any(not 0 <= i < part.seq_len for i in indexes):
            raise BadUR("a part names a fragment outside the transfer")
        self._absorb(_Piece(frozenset(indexes), part.data))
        return self.result

    # ---- the reduction ----

    def _absorb(self, piece: _Piece) -> None:
        if piece.is_simple:
            self._absorb_simple(piece)
        else:
            self._absorb_mixed(piece)

    def _absorb_simple(self, piece: _Piece) -> None:
        if piece.index in self._simple:
            return
        self._simple[piece.index] = piece
        if len(self._simple) == self.seq_len:
            self._finish()
            return
        self._reduce_mixed_by(piece)

    def _absorb_mixed(self, piece: _Piece) -> None:
        if piece.indexes in self._mixed:
            return
        for known in list(self._simple.values()) + list(self._mixed.values()):
            piece = _reduce_by(piece, known)
            if piece.is_simple:
                self._absorb_simple(piece)
                return
        self._reduce_mixed_by(piece)
        if self.result is None:
            self._mixed[piece.indexes] = piece

    def _reduce_mixed_by(self, piece: _Piece) -> None:
        still_mixed: dict[frozenset, _Piece] = {}
        collapsed: list[_Piece] = []
        for held in self._mixed.values():
            reduced = _reduce_by(held, piece)
            if reduced.is_simple:
                collapsed.append(reduced)
            else:
                still_mixed[reduced.indexes] = reduced
        self._mixed = still_mixed
        for c in collapsed:
            self._absorb_simple(c)
            if self.result is not None:
                return

    def _finish(self) -> None:
        assert self.seq_len is not None and self.message_len is not None
        joined = b"".join(self._simple[i].data for i in range(self.seq_len))
        message = joined[:self.message_len]
        if crc32(message) != self.checksum:
            # Every fragment passed its own bytewords checksum and the message
            # still does not match, which means the mixtures were mutually
            # consistent and wrong -- so the transfer is discarded whole
            # rather than handed up as bytes that came from somewhere.
            raise BadUR(
                "the reassembled message does not match the checksum every "
                "part carried; discarding the transfer")
        self.result = message

    # ---- what the screen reports ----

    @property
    def missing(self) -> list[int]:
        if self.seq_len is None:
            return []
        return [i for i in range(self.seq_len) if i not in self._simple]

    def progress(self) -> str:
        if self.seq_len is None:
            return "waiting for the first part"
        return f"{len(self._simple)} of {self.seq_len} fragments"


# --------------------------------------------------------------------------
# The UR text format
# --------------------------------------------------------------------------

# UR types this device speaks, and what each one means to the layer above.
#
#   crypto-psbt   a PSBT, CBOR byte string. The Bitcoin airgap standard.
#   bytes         an opaque payload, CBOR byte string. What CELL's own JSON
#                 requests travel in, and what BBQr-era tooling falls back to.
#
# A type this device does not know is a refusal rather than an unwrap: a
# `crypto-hdkey` handed to `app.classify` would be bytes with no meaning, and
# the owner would be shown a parse failure instead of "this device does not
# read that".
#   eth-sign-request  an EVM signing request, EIP-4527. What MetaMask's and
#                     Rabby's QR-account flows emit, and the reason the EVM
#                     half of this device is reachable from a browser at all.
#                     A tagged CBOR map, not a byte string.
BYTE_STRING_TYPES = frozenset({"crypto-psbt", "bytes"})

# What a transfer may ARRIVE as. Deliberately not the same set as what the
# device emits: `eth-signature` and `crypto-account` are answers, and a device
# that collected them would spend a scan reassembling something it has no
# flow for and then refuse it with a parse failure. Naming the direction turns
# that into a sentence the owner can act on.
INBOUND_TYPES = BYTE_STRING_TYPES | frozenset({"eth-sign-request"})
OUTBOUND_TYPES = frozenset({"crypto-psbt", "bytes", "eth-signature",
                            "crypto-account"})
KNOWN_TYPES = INBOUND_TYPES | OUTBOUND_TYPES

# --------------------------------------------------------------------------
# EIP-4527 — eth-sign-request and eth-signature
# --------------------------------------------------------------------------

TAG_UUID = 37
TAG_KEYPATH = 304
TAG_ETH_SIGN_REQUEST = 401
TAG_ETH_SIGNATURE = 402

# `dataType`, from the EIP. Only one of them is renderable on this device, and
# the names are kept for the refusal messages: an owner told "data type 4 is
# refused" learns nothing, and one told "EIP-712 typed data" can act on it.
DATA_TYPES = {
    1: "a legacy transaction",
    2: "a typed transaction",
    3: "a personal message",
    4: "EIP-712 typed data",
}
DATA_TYPE_TRANSACTION = 2

MAX_SIGN_DATA = 1 << 16
MAX_PATH_DEPTH = 16


def _uuid_bytes(v) -> bytes:
    """A request id, which travels either bare or under CBOR tag 37."""
    if isinstance(v, Tag):
        if v.tag != TAG_UUID:
            raise BadUR(f"a request id is not CBOR tag {v.tag}")
        v = v.value
    if not isinstance(v, bytes) or not 1 <= len(v) <= 64:
        raise BadUR("a request id is a short byte string")
    return v


def _keypath(v) -> str:
    """A crypto-keypath, spelled the way a wallet writes one.

    Decoded, not skipped. The path says WHICH KEY the requester expects to
    sign, so a device that ignores it cannot tell its owner the request was
    aimed somewhere else. `ops.parse` makes the same argument about unknown
    fields: what cannot be displayed cannot be consented to.
    """
    if isinstance(v, Tag):
        if v.tag != TAG_KEYPATH:
            raise BadUR(f"a derivation path is not CBOR tag {v.tag}")
        v = v.value
    if not isinstance(v, dict) or 1 not in v:
        raise BadUR("a crypto-keypath carries its components under key 1")
    comps = v[1]
    if not isinstance(comps, list) or not comps or len(comps) % 2:
        raise BadUR("keypath components are index and hardened-flag pairs")
    if len(comps) // 2 > MAX_PATH_DEPTH:
        raise BadUR(f"a derivation path deeper than {MAX_PATH_DEPTH} levels")
    out = ["m"]
    for i in range(0, len(comps), 2):
        index, hardened = comps[i], comps[i + 1]
        if not isinstance(index, int) or isinstance(index, bool) \
                or not 0 <= index < (1 << 31):
            raise BadUR("a keypath index is a non-negative 31-bit integer")
        if not isinstance(hardened, bool):
            raise BadUR("a keypath hardened flag is a boolean")
        out.append(f"{index}h" if hardened else str(index))
    return "/".join(out)


def decode_eth_sign_request(message: bytes) -> dict:
    """Decode an EIP-4527 request into plain fields, or refuse.

    Returns what the map carried, converted and bounds-checked, and nothing
    interpreted. `sign_data` comes back as bytes: this function does not know
    what a transaction is. The caller rebuilds one from those bytes and checks
    its own re-encoding against them, which is what keeps `eth.py`'s rule
    intact -- the device displays fields it derived, and refuses if what it
    would encode differs by a byte from what it was handed. See
    `app.parse_eth_sign_request`.

    Unknown map keys are refused instead of ignored, on `ops.parse`'s
    reasoning. That is stricter than the EIP, which reserves room to grow, and
    it is the correct side to err on for a device whose claim is that it
    displays everything it signs: a requester using a key this device has
    never heard of gets a refusal naming the key, which is a bug report.
    """
    item, rest = cbor_decode(message)
    if rest:
        raise BadUR("trailing bytes after an eth-sign-request")
    if isinstance(item, Tag):
        if item.tag != TAG_ETH_SIGN_REQUEST:
            raise BadUR(
                f"an eth-sign-request is CBOR tag {TAG_ETH_SIGN_REQUEST}, "
                f"not {item.tag}")
        item = item.value
    if not isinstance(item, dict):
        raise BadUR("an eth-sign-request is a CBOR map")
    unknown = set(item) - {1, 2, 3, 4, 5, 6, 7}
    if unknown:
        raise BadUR(
            f"refusing an eth-sign-request with unknown map key(s) "
            f"{sorted(unknown)}; this device cannot display what it does not "
            f"understand")
    for required in (1, 2, 3, 5):
        if required not in item:
            raise BadUR(
                f"an eth-sign-request needs map key {required}. This device "
                f"reads a request id, sign data, a data type and a "
                f"derivation path.")
    sign_data = item[2]
    if not isinstance(sign_data, bytes) or not sign_data:
        raise BadUR("sign data is a non-empty byte string")
    if len(sign_data) > MAX_SIGN_DATA:
        raise BadUR(
            f"sign data is {len(sign_data)} bytes; this device reads up to "
            f"{MAX_SIGN_DATA}")
    data_type = item[3]
    if not isinstance(data_type, int) or isinstance(data_type, bool):
        raise BadUR("a data type is an unsigned integer")
    chain_id = item.get(4)
    if chain_id is not None and (not isinstance(chain_id, int)
                                 or isinstance(chain_id, bool)
                                 or chain_id < 1):
        raise BadUR("a chain id is a positive integer")
    address = item.get(6)
    if address is not None and (not isinstance(address, bytes)
                                or len(address) != 20):
        raise BadUR("an address is twenty bytes")
    origin = item.get(7)
    if origin is not None and not isinstance(origin, str):
        raise BadUR("an origin is text")
    return {
        "request_id": _uuid_bytes(item[1]),
        "sign_data": sign_data,
        "data_type": data_type,
        "chain_id": chain_id,
        "path": _keypath(item[5]),
        "address": address,
        "origin": origin,
    }


def encode_eth_sign_request(request_id: bytes, sign_data: bytes,
                            data_type: int, path: str,
                            chain_id: int | None = None,
                            address: bytes | None = None,
                            origin: str | None = None) -> bytes:
    """The inverse. Here so the tests can build what a companion would send.

    Nothing on the device calls this -- the device answers requests, it does
    not make them -- but a decoder tested only against its own idea of the
    format is a decoder tested against nothing.
    """
    comps: list[bytes] = []
    for element in path.split("/")[1:]:
        hardened = element.endswith(("h", "'"))
        comps.append(cbor_uint(int(element.rstrip("h'"))))
        comps.append(cbor_bool(hardened))
    pairs = [
        (cbor_uint(1), cbor_tag(TAG_UUID, cbor_bytes(request_id))),
        (cbor_uint(2), cbor_bytes(sign_data)),
        (cbor_uint(3), cbor_uint(data_type)),
    ]
    if chain_id is not None:
        pairs.append((cbor_uint(4), cbor_uint(chain_id)))
    pairs.append((cbor_uint(5), cbor_tag(TAG_KEYPATH, cbor_map(
        [(cbor_uint(1), cbor_array(comps))]))))
    if address is not None:
        pairs.append((cbor_uint(6), cbor_bytes(address)))
    if origin is not None:
        pairs.append((cbor_uint(7), cbor_text(origin)))
    # Map keys in ascending order, which is what every encoder of this format
    # emits and what a decoder refusing duplicates depends on.
    pairs.sort(key=lambda kv: kv[0])
    return cbor_tag(TAG_ETH_SIGN_REQUEST, cbor_map(pairs))


# --------------------------------------------------------------------------
# crypto-account — exporting the watch-only half
# --------------------------------------------------------------------------

# BCR-2020-007, -010 and -015, on the LEGACY tag numbers. The hdkey paper has
# since been renumbered into the 40000 range as `ur:hdkey`, and this uses 303
# rather than 40303 on purpose: the point of exporting an account is that a
# coordinator somebody already has can read it, and Sparrow, Nunchuk and the
# Keystone-compatible tooling read `ur:crypto-account` with these numbers.
# BCR-2020-015's own published vector uses them too.
TAG_HDKEY = 303
TAG_CRYPTO_KEYPATH = 304
TAG_COIN_INFO = 305
TAG_OUTPUT = 308
TAG_ACCOUNT = 311

# The script expressions, from BCR-2020-010. Nested outside in, so
# `sh(wpkh(k))` is tag 400 wrapping tag 404 wrapping the key.
TAG_SH = 400
TAG_WSH = 401
TAG_PKH = 403
TAG_WPKH = 404
TAG_SORTEDMULTI = 407
TAG_TR = 409

# CELL's own script-type names to the expression that describes them. Held here
# rather than in wallet.py because it is a fact about this WIRE FORMAT, not
# about the wallet: the same account is `p2sh-p2wpkh` on the device's screen
# and `sh(wpkh(...))` to a coordinator.
SCRIPT_EXPRESSIONS = {
    "p2pkh": (TAG_PKH,),
    "p2wpkh": (TAG_WPKH,),
    "p2sh-p2wpkh": (TAG_SH, TAG_WPKH),
    "p2tr": (TAG_TR,),
}

# `coin-info`'s network field. 0 is mainnet and is the default, so it is left
# out entirely there; 1 covers testnet and regtest, which share a coin type.
NETWORK_TESTNET = 1


def encode_keypath(path: str, source_fingerprint: bytes | None = None,
                   depth: int | None = None) -> bytes:
    """A crypto-keypath. `path` is written the way this repository writes one.

    Accepts `44h` and `44'` for a hardened level, because both spellings are in
    use and a format that accepted only one would refuse half the descriptors
    people paste at it.
    """
    if not path.startswith("m"):
        raise BadUR(f"a derivation path starts at m, not {path[:4]!r}")
    comps: list[bytes] = []
    for element in path.split("/")[1:]:
        if not element:
            raise BadUR(f"empty level in {path!r}")
        hardened = element.endswith(("h", "H", "'"))
        digits = element.rstrip("hH'")
        if not digits.isdigit():
            raise BadUR(f"{element!r} is not a derivation index")
        index = int(digits)
        if index >= (1 << 31):
            raise BadUR(f"derivation index {index} does not fit 31 bits")
        comps.append(cbor_uint(index))
        comps.append(cbor_bool(hardened))
    pairs = [(cbor_uint(1), cbor_array(comps))]
    if source_fingerprint is not None:
        if len(source_fingerprint) != 4:
            raise BadUR("a source fingerprint is four bytes")
        pairs.append((cbor_uint(2),
                      cbor_uint(int.from_bytes(source_fingerprint, "big"))))
    if depth is not None:
        pairs.append((cbor_uint(3), cbor_uint(depth)))
    return cbor_tag(TAG_CRYPTO_KEYPATH, cbor_map(pairs))


def encode_hdkey(pubkey: bytes, chain_code: bytes, origin_path: str,
                 master_fingerprint: bytes, parent_fingerprint: bytes,
                 testnet: bool = False) -> bytes:
    """A crypto-hdkey for a derived PUBLIC key. Never a private one.

    There is deliberately no way to spell a private key here. `is-private` is
    map key 2 in the specification and this function does not offer it, so the
    export path cannot be talked into carrying key material by a caller that
    passes the wrong node: a private key would have to be constructed by
    hand, somewhere else, on purpose.

    `origin` carries the path AND the master fingerprint, which is what lets a
    coordinator file the key under the right wallet and build a descriptor
    with a correct `[fingerprint/path]` prefix. Without it the xpub is an
    orphan and the coordinator cannot tell whose it is.
    """
    if len(pubkey) != 33 or pubkey[0] not in (2, 3):
        raise BadUR("an hdkey carries a 33-byte compressed public key")
    if len(chain_code) != 32:
        raise BadUR("a chain code is 32 bytes")
    if len(parent_fingerprint) != 4:
        raise BadUR("a parent fingerprint is four bytes")
    pairs = [
        (cbor_uint(3), cbor_bytes(pubkey)),
        (cbor_uint(4), cbor_bytes(chain_code)),
    ]
    if testnet:
        # Omitted on mainnet, where 0 is the default. A coordinator that read
        # a mainnet key as testnet would offer to watch addresses that do not
        # exist, so this is the one field worth being explicit about.
        pairs.append((cbor_uint(5), cbor_tag(TAG_COIN_INFO, cbor_map(
            [(cbor_uint(2), cbor_uint(NETWORK_TESTNET))]))))
    pairs.append((cbor_uint(6),
                  encode_keypath(origin_path, master_fingerprint)))
    pairs.append((cbor_uint(8),
                  cbor_uint(int.from_bytes(parent_fingerprint, "big"))))
    return cbor_tag(TAG_HDKEY, cbor_map(pairs))


def encode_output(script_type: str, key: bytes) -> bytes:
    """One output descriptor: a script expression wrapped around a key."""
    tags = SCRIPT_EXPRESSIONS.get(script_type)
    if tags is None:
        raise BadUR(
            f"no output descriptor is defined for {script_type!r}. This "
            f"device exports {', '.join(sorted(SCRIPT_EXPRESSIONS))}.")
    out = key
    for tag in reversed(tags):
        out = cbor_tag(tag, out)
    return out


def encode_account(master_fingerprint: bytes,
                   descriptors: list[bytes]) -> bytes:
    """A crypto-account: whose keys these are, and one descriptor per script type.

    This is the whole reason the type exists. A coordinator scanning it learns
    every script type at once and can set up a watch-only wallet without
    anybody transcribing an xpub, which is the step where a character gets
    dropped and the money goes to an address nobody can spend from.

    IT AUTHORISES NOTHING. Everything in here is public and already printed on
    the THIS DEVICE screen. It is a convenience for the coordinator and a
    privacy decision for the owner -- an account xpub reveals every address
    the wallet will ever use -- and it is emitted only when somebody presses
    the button.
    """
    if len(master_fingerprint) != 4:
        raise BadUR("a master fingerprint is four bytes")
    if not descriptors:
        raise BadUR("an account with no descriptors describes nothing")
    return cbor_tag(TAG_ACCOUNT, cbor_map([
        (cbor_uint(1), cbor_uint(int.from_bytes(master_fingerprint, "big"))),
        (cbor_uint(2), cbor_array([cbor_tag(TAG_OUTPUT, d)
                                   for d in descriptors])),
    ]))


def encode_eth_signature(request_id: bytes, signature: bytes) -> bytes:
    """The CBOR body of an eth-signature, which is the reply EIP-4527 expects.

    65 bytes, r || s || v. `v` is the y-parity, 0 or 1, and NOT the 27-based
    form -- which is the one field in this format worth checking against a real
    browser wallet before trusting it, because implementations differ on it and
    the EIP does not settle it. `VALIDATION.md` carries that open. A companion
    that recovers the wrong address from an otherwise correct signature is
    looking at this byte.

    The request id goes back untouched so a companion can match the reply to
    the request it made. Nothing signs it, which is why it is echoed and never
    checked.
    """
    if len(signature) != 65:
        raise BadUR(f"an eth-signature is 65 bytes, not {len(signature)}")
    return cbor_tag(TAG_ETH_SIGNATURE, cbor_map([
        (cbor_uint(1), cbor_tag(TAG_UUID, cbor_bytes(request_id))),
        (cbor_uint(2), cbor_bytes(signature)),
    ]))

MAX_UR_TYPE_LEN = 32

# Spelled out rather than derived from `str.islower`, which is true of "é" and
# would admit a type name that is not ASCII at all.
_TYPE_ALPHABET = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")


def _check_type(ur_type: str) -> str:
    if not ur_type or len(ur_type) > MAX_UR_TYPE_LEN:
        raise BadUR(f"{ur_type!r} is not a plausible UR type")
    if any(c not in _TYPE_ALPHABET for c in ur_type):
        raise BadUR(
            f"{ur_type!r} has characters outside a UR type's alphabet "
            f"(lowercase letters, digits and hyphen)")
    return ur_type


def encode(payload: bytes, ur_type: str = "bytes",
           max_fragment_len: int = DEFAULT_MAX_FRAGMENT,
           parts: int | None = None) -> list[str]:
    """Frame a payload as UR. One frame if it fits, a fountain loop if not.

    `parts` is how many frames to produce. The default is one full pass of the
    pure fragments, which is the minimum a receiver needs; asking for more
    yields the mixtures, which is what makes a loop that survives a missed
    frame. `camera.emit_ur` asks for more.
    """
    _check_type(ur_type)
    body = cbor_bytes(payload) if ur_type in BYTE_STRING_TYPES else payload
    enc = FountainEncoder(body, max_fragment_len=max_fragment_len)
    if enc.is_single_part and parts in (None, 1):
        return [f"ur:{ur_type}/{bytewords_encode(body)}"]
    n = parts if parts is not None else enc.seq_len
    out = []
    for _ in range(max(n, enc.seq_len)):
        p = enc.next_part()
        out.append(f"ur:{ur_type}/{p.seq_num}-{p.seq_len}/"
                   f"{bytewords_encode(p.cbor())}")
    return out


def is_ur(frame: str) -> bool:
    """Cheap enough to call on every string the camera decodes."""
    return frame.strip().lower().startswith("ur:")


def parse(frame: str) -> tuple[str, Part | None, bytes | None]:
    """Split one UR frame into (type, part, single-part body).

    Exactly one of `part` and `body` is set: a single-part UR carries its whole
    message, and a multipart one carries a fragment.
    """
    text = frame.strip().lower()
    if not text.startswith("ur:"):
        raise BadUR(f"not a UR frame: {frame[:24]!r}")
    fields = text[3:].split("/")
    if len(fields) == 2:
        ur_type, seq, body = fields[0], None, fields[1]
    elif len(fields) == 3:
        ur_type, seq, body = fields
    else:
        raise BadUR(f"a UR has two or three slash-separated fields, not "
                    f"{len(fields)}")
    _check_type(ur_type)
    raw = bytewords_decode(body)
    if seq is None:
        return ur_type, None, raw
    if "-" not in seq:
        raise BadUR(f"{seq!r} is not a seqNum-seqLen pair")
    num, _, length = seq.partition("-")
    if not (num.isdigit() and length.isdigit()):
        raise BadUR(f"{seq!r} is not a seqNum-seqLen pair")
    part = Part.from_cbor(raw)
    if (part.seq_num, part.seq_len) != (int(num), int(length)):
        # The header outside the bytewords and the header inside them disagree.
        # Only the inner one is covered by the CRC, so the outer one is a hint
        # and never a fact -- but a mismatch means somebody built the frame by
        # hand, and this device is not the place to work out which half to
        # believe.
        raise BadUR(
            f"a part is labelled {num}-{length} on the outside and "
            f"{part.seq_num}-{part.seq_len} inside")
    return ur_type, part, None


@dataclass
class Collector:
    """Accumulates UR frames until the payload is complete.

    Deliberately the same shape as `qr.Collector`: `feed` returns the payload
    or None, `missing` and `progress` say where the transfer is, and `reset`
    starts again. `camera.scan` drives whichever one the first frame selects
    and never has to know which it got.

    `payload` is what the layer above wants -- the PSBT, or CELL's JSON -- with
    the CBOR wrapper already off. `ur_type` records what the sender called it,
    for the one screen that needs to say so.
    """

    ur_type: str | None = None
    decoder: FountainDecoder = field(default_factory=FountainDecoder)

    def feed(self, frame: str) -> bytes | None:
        ur_type, part, body = parse(frame)
        if self.ur_type is None:
            if ur_type not in INBOUND_TYPES:
                if ur_type in OUTBOUND_TYPES:
                    raise BadUR(
                        f"ur:{ur_type} is what this device EMITS, not "
                        f"something it reads. Whatever is on the screen in "
                        f"front of the camera came from a signer, not from a "
                        f"coordinator.")
                raise BadUR(
                    f"this device does not read ur:{ur_type}. It reads "
                    f"{', '.join(sorted(INBOUND_TYPES))}.")
            self.ur_type = ur_type
        elif ur_type != self.ur_type:
            raise BadUR(
                f"a ur:{ur_type} part arrived during a ur:{self.ur_type} "
                f"transfer. Two different transfers are on screen; restart "
                f"the scan.")
        message = body if part is None else self.decoder.receive(part)
        if message is None:
            return None
        return self._unwrap(message)

    def _unwrap(self, message: bytes) -> bytes:
        return unwrap_payload(self.ur_type, message)

    @property
    def missing(self) -> list[int]:
        return self.decoder.missing

    def progress(self) -> str:
        return self.decoder.progress()

    def reset(self) -> None:
        self.ur_type = None
        self.decoder = FountainDecoder()


def unwrap_payload(ur_type: str | None, message: bytes) -> bytes:
    """Take the CBOR wrapper off, for the types that have one.

    `crypto-psbt` and `bytes` are a single CBOR byte string around a payload,
    so what the layer above wants is inside it. Everything else -- an
    `eth-sign-request`, a `crypto-account` -- IS the CBOR, and is handed up
    whole for a decoder that knows the shape.
    """
    if ur_type not in BYTE_STRING_TYPES:
        return message
    payload, rest = cbor_decode(message)
    if rest or not isinstance(payload, bytes):
        raise BadUR(f"a ur:{ur_type} carries a single CBOR byte string")
    return payload


def reassemble(frames: list[str]) -> bytes:
    """Rebuild a transfer's message from its frames, framing only.

    NOT AN INPUT PATH, and never used by `camera.scan`. `Collector` is, and it
    adds what an input path needs: a locked UR type, the inbound/outbound
    direction rule, and the refusal of a fragment replaced mid-scan. This
    function has none of that.

    It exists to read back what this device EMITTED -- an `eth-signature`, a
    `crypto-account` -- which `Collector` correctly refuses to collect. The
    tests use it, and so would a companion. Nothing on the signing path may.
    """
    dec = FountainDecoder()
    for frame in frames:
        ur_type, part, body = parse(frame)
        if part is None:
            return unwrap_payload(ur_type, body)
        got = dec.receive(part)
        if got is not None:
            return unwrap_payload(ur_type, got)
    raise BadUR(f"transfer incomplete; missing fragments {dec.missing}")


def decode(frames: list[str]) -> bytes:
    """Collect a whole transfer at once. Raises unless it completes."""
    c = Collector()
    out = None
    for f in frames:
        got = c.feed(f)
        if got is not None:
            out = got
    if out is None:
        raise BadUR(f"transfer incomplete; missing fragments {c.missing}")
    return out


# --------------------------------------------------------------------------


def _vectors() -> dict:
    path = Path(__file__).resolve().parent / "vectors" / "ur.json"
    return json.loads(path.read_text())


def _selftest() -> int:
    print("UR transport — the published vectors, then hostile frames\n")
    checks: list[tuple[str, bool]] = []
    v = _vectors()

    # ---- the pieces, against the reference implementation's own vectors ----

    checks.append(("CRC-32 matches the published values",
                   all(f"{crc32(k.encode()):08x}" == want
                       for k, want in v["crc32"].items())))

    bw = v["bytewords"]
    raw = bytes.fromhex(bw["input_hex"])
    checks.append(("bytewords encode, minimal style",
                   bytewords_encode(raw) == bw["minimal"]))
    checks.append(("bytewords decode round trips",
                   bytewords_decode(bw["minimal"]) == raw))

    def bad(label, fn, exc=BadUR):
        try:
            fn()
            checks.append((label, False))
        except exc:
            checks.append((label, True))

    bad("refuses a bytewords checksum that does not hold",
        lambda: bytewords_decode(bw["bad_checksum_minimal"]))

    r = Xoshiro256("Wolf")
    checks.append(("Xoshiro256** stream, seeded from a string",
                   [r.next() % 100 for _ in range(100)] == v["rng_wolf_mod100"]))
    r = Xoshiro256(crc32(b"Wolf"))
    checks.append(("...seeded from a CRC-32",
                   [r.next() % 100 for _ in range(100)]
                   == v["rng_crc32_wolf_mod100"]))
    r = Xoshiro256("Wolf")
    checks.append(("next_int is inclusive on both ends",
                   [r.next_int(1, 10) for _ in range(100)]
                   == v["rng_wolf_next_int_1_10"]))

    for case in v["find_nominal_fragment_length"]:
        got = find_nominal_fragment_length(case["message_len"], case["min"],
                                           case["max"])
        checks.append((f"nominal fragment length for {case['message_len']}/"
                       f"{case['max']} is {case['expect']}",
                       got == case["expect"]))

    s = v["random_sampler"]
    sampler = RandomSampler([float(p) for p in s["probs"]])
    r = Xoshiro256(s["seed"])
    checks.append(("the alias sampler draws the published sequence",
                   [sampler.next(r) for _ in range(len(s["expect"]))]
                   == s["expect"]))

    sh = v["shuffle"]
    r = Xoshiro256(sh["seed"])
    checks.append(("Fisher-Yates draws in the published order",
                   [shuffled(sh["items"], r) for _ in range(len(sh["expect"]))]
                   == sh["expect"]))

    cd = v["choose_degree"]
    checks.append(("the degree chooser matches, 200 nonces",
                   [choose_degree(cd["seq_len"],
                                  Xoshiro256(f"{cd['seed_prefix']}{n}"))
                    for n in range(1, len(cd["expect"]) + 1)] == cd["expect"]))

    # The message every vector below is built from: 1024 bytes of the
    # "Wolf"-seeded generator, which is how the reference tests make one.
    message = Xoshiro256("Wolf").next_data(1024)
    frag_len = find_nominal_fragment_length(len(message), 10, 100)
    frags = partition(message, frag_len)
    checks.append(("the partition matches, padding included",
                   [f.hex() for f in frags] == v["partition_1024_min10_max100"]))
    checks.append(("...and rejoins to the message",
                   b"".join(frags)[:len(message)] == message))

    got = [sorted(choose_fragments(n, len(frags), crc32(message)))
           for n in range(1, len(v["choose_fragments_1024"]) + 1)]
    checks.append(("fragment selection matches, 30 parts",
                   got == v["choose_fragments_1024"]))

    # ---- and end to end, string for string ----

    fifty = Xoshiro256("Wolf").next_data(50)
    checks.append(("a single-part UR encodes to the published string",
                   encode(fifty, "bytes") == [v["single_part_ur_50"]]))
    checks.append(("...and decodes back",
                   decode([v["single_part_ur_50"]]) == fifty))

    two_five_six = Xoshiro256("Wolf").next_data(256)
    want = v["ur_encoder_256_max30"]
    produced = encode(two_five_six, "bytes", max_fragment_len=30,
                      parts=len(want))
    checks.append((f"a {len(want)}-part UR encodes to the published strings",
                   produced == want))
    checks.append(("...and the first pass alone decodes",
                   decode(want[:9]) == two_five_six))

    # ---- the fountain property, which is the reason this module exists ----

    checks.append(("a transfer completes from the mixtures alone",
                   decode(want[1:]) == two_five_six))
    checks.append(("...and out of order",
                   decode(list(reversed(want))) == two_five_six))
    checks.append(("...and with every duplicate an animated loop produces",
                   decode(want + want) == two_five_six))

    # Nine pure fragments; drop one and feed mixtures until it reconstructs.
    partial = [f for f in want[:9] if not f.startswith("ur:bytes/4-9/")]
    checks.append(("a permanently missed frame is recovered by a mixture",
                   decode(partial + want[9:]) == two_five_six))

    # A large payload, the size a real multi-input PSBT reaches.
    big = Xoshiro256("cell").next_data(6000)
    frames = encode(big, "crypto-psbt", max_fragment_len=200)
    checks.append(("a 6 kB crypto-psbt round trips", decode(frames) == big))
    checks.append(("...and reports its type",
                   parse(frames[0])[0] == "crypto-psbt"))

    # ---- hostile frames ----

    bad("refuses a frame that is not a UR", lambda: Collector().feed("hello"))
    bad("refuses a UR type this device does not read",
        lambda: Collector().feed(encode(b"x" * 40, "bytes")[0]
                                 .replace("ur:bytes/", "ur:crypto-hdkey/")))
    bad("refuses a UR type outside the alphabet",
        lambda: Collector().feed("ur:CRYPTO_PSBT/aeadaolazmjendeoti"))
    bad("refuses a part with a seqLen of zero",
        lambda: Collector().feed("ur:bytes/0-0/aeadaolazmjendeoti"))

    def mixed_transfers():
        c = Collector()
        c.feed(want[0])
        other = encode(Xoshiro256("other").next_data(256), "bytes",
                       max_fragment_len=30, parts=2)
        c.feed(other[1])
    bad("refuses two different transfers mixed on screen", mixed_transfers)

    def mixed_types():
        c = Collector()
        c.feed(want[0])
        c.feed(want[1].replace("ur:bytes/", "ur:crypto-psbt/"))
    bad("refuses two UR types mixed on screen", mixed_types)

    def substituted():
        c = Collector()
        c.feed(want[0])
        # Same seqNum, different fragment: rebuild part 1 carrying part 2's
        # bytes. Every checksum in the frame is recomputed, so this is what an
        # attacker with a second screen actually produces.
        _t, p2, _b = parse(want[1])
        forged = Part(1, p2.seq_len, p2.message_len, p2.checksum, p2.data)
        c.feed(f"ur:bytes/1-{forged.seq_len}/{bytewords_encode(forged.cbor())}")
    bad("refuses a fragment replaced mid-scan", substituted)

    def outer_disagrees():
        _t, p, _b = parse(want[2])
        Collector().feed(f"ur:bytes/9-9/{bytewords_encode(p.cbor())}")
    bad("refuses a part whose outer and inner headers disagree", outer_disagrees)

    def oversized_seq_len():
        p = Part(1, MAX_SEQ_LEN + 1, 10, 0, b"\x00")
        Collector().feed(f"ur:bytes/1-{p.seq_len}/{bytewords_encode(p.cbor())}")
    bad("refuses a part claiming more fragments than it will collect",
        oversized_seq_len)

    def oversized_message():
        p = Part(1, 1, MAX_MESSAGE_LEN + 1, 0, b"\x00")
        Collector().feed(f"ur:bytes/1-1/{bytewords_encode(p.cbor())}")
    bad("refuses a part claiming a message larger than it will collect",
        oversized_message)

    def wrong_fragment_size():
        # seqLen and messageLen imply 100 bytes; the part carries one.
        p = Part(1, 10, 1000, 0, b"\x00")
        Collector().feed(f"ur:bytes/1-10/{bytewords_encode(p.cbor())}")
    bad("refuses a part whose payload is the wrong size for its claims",
        wrong_fragment_size)

    def bad_message_checksum():
        # Nine consistent parts whose checksum field is a lie. Each frame's own
        # bytewords checksum is valid, so nothing catches this until the whole
        # message is reassembled and hashed.
        enc = FountainEncoder(cbor_bytes(two_five_six), max_fragment_len=30)
        c = Collector()
        for i in range(enc.seq_len):
            p = enc.next_part()
            lied = Part(p.seq_num, p.seq_len, p.message_len,
                        p.checksum ^ 1, p.data)
            c.feed(f"ur:bytes/{lied.seq_num}-{lied.seq_len}/"
                   f"{bytewords_encode(lied.cbor())}")
    bad("refuses a reassembled message that fails its own checksum",
        bad_message_checksum)

    bad("refuses CBOR nested past its depth bound",
        lambda: cbor_decode(b"\x81" * 40))
    bad("refuses a CBOR float", lambda: cbor_decode(b"\xfa\x00\x00\x00\x00"))
    bad("refuses an indefinite-length CBOR string",
        lambda: cbor_decode(b"\x5f\x41\x00\xff"))

    # ---- crypto-account, against BCR-2020-015's published vector ----
    #
    # The strongest check available for an emit-only format: the device's own
    # output has to appear inside the specification's own bytes. Only the four
    # script types this device exports are checked, as substrings, so the
    # cosigner descriptors the vector also carries need not be implemented for
    # the comparison to mean something.
    import bip32                                             # noqa: E402
    ca = v["crypto_account"]
    _root = bip32.from_mnemonic(ca["mnemonic"])
    _mfp = _root.fingerprint()
    checks.append(("the vector's seed derives the fingerprint it claims",
                   _mfp.hex() == ca["master_fingerprint"]))
    _mine = []
    for spec in ca["descriptors"]:
        node = _root.derive(bip32.parse_path(spec["path"])).neutered()
        hd = encode_hdkey(node.pubkey, node.chain_code, spec["path"],
                          _mfp, node.parent_fp)
        d = encode_output(spec["script_type"], hd)
        _mine.append(d)
        checks.append((f"{spec['script_type']} at {spec['path']} matches the "
                       f"published descriptor",
                       cbor_tag(TAG_OUTPUT, d).hex() in ca["account_cbor"]))
    _acct = encode_account(_mfp, _mine)
    _item, _rest = cbor_decode(_acct)
    checks.append(("an account is tag 311 carrying a fingerprint and outputs",
                   not _rest and isinstance(_item, Tag)
                   and _item.tag == TAG_ACCOUNT
                   and _item.value[1] == int.from_bytes(_mfp, "big")
                   and len(_item.value[2]) == len(_mine)))
    # Reassembled through `reassemble` rather than through Collector, which
    # refuses this type by direction -- correctly, and it is the framing being
    # checked here, not the policy.
    _frames = encode(_acct, "crypto-account", max_fragment_len=60)
    checks.append(("...and it survives a whole UR transfer",
                   reassemble(_frames) == _acct))
    checks.append(("...under a UR type a coordinator recognises",
                   _frames[0].startswith("ur:crypto-account/")))

    # A testnet key carries coin-info; a mainnet one leaves it out, because 0
    # is the default and a mainnet key read as testnet watches addresses that
    # do not exist.
    _n = _root.derive(bip32.parse_path("m/84h/1h/0h")).neutered()
    _tnet = encode_hdkey(_n.pubkey, _n.chain_code, "m/84h/1h/0h", _mfp,
                         _n.parent_fp, testnet=True)
    _mnet = encode_hdkey(_n.pubkey, _n.chain_code, "m/84h/1h/0h", _mfp,
                         _n.parent_fp)
    checks.append(("a testnet hdkey declares its network",
                   cbor_decode(_tnet)[0].value[5].value[2] == NETWORK_TESTNET))
    checks.append(("...and a mainnet one says nothing, which is the default",
                   5 not in cbor_decode(_mnet)[0].value))

    checks.append(("both hardened spellings are accepted",
                   encode_keypath("m/84h/0h/0h")
                   == encode_keypath("m/84'/0'/0'")))
    bad("refuses a path that does not start at m",
        lambda: encode_keypath("84h/0h/0h"))
    bad("refuses a non-numeric level", lambda: encode_keypath("m/eight"))
    bad("refuses an index past 31 bits",
        lambda: encode_keypath(f"m/{1 << 31}"))
    bad("refuses an empty level", lambda: encode_keypath("m/84h//0h"))
    bad("refuses an uncompressed key in an hdkey",
        lambda: encode_hdkey(b"\x04" + bytes(32), bytes(32), "m/0",
                            bytes(4), bytes(4)))
    bad("refuses a chain code of the wrong length",
        lambda: encode_hdkey(b"\x02" + bytes(32), bytes(31), "m/0",
                            bytes(4), bytes(4)))
    bad("refuses a script type it has no descriptor for",
        lambda: encode_output("p2wsh-multisig", b"\x00"))
    bad("refuses an account with no descriptors",
        lambda: encode_account(bytes(4), []))
    # The private-key form is not reachable: `is-private` is map key 2 and
    # nothing here writes it, so an export cannot be talked into carrying
    # key material by a caller passing the wrong node.
    checks.append(("an exported hdkey never claims to be private",
                   2 not in cbor_decode(_mnet)[0].value))

    def collect_outbound(t):
        return Collector().feed(f"ur:{t}/aeadaolazmjendeoti")

    for t in ("crypto-account", "eth-signature"):
        bad(f"refuses to collect ur:{t}, which it emits",
            lambda t=t: collect_outbound(t))

    # ---- EIP-4527, the shape a browser wallet sends ----

    rid = bytes(range(16))
    sd = bytes.fromhex("02f0010984773594008506fc23ac008252089435" * 1)[:20]
    req = encode_eth_sign_request(rid, sd, 2, "m/44h/60h/0h/0/0",
                                  chain_id=1, address=bytes(range(20)),
                                  origin="metamask")
    got = decode_eth_sign_request(req)
    checks.append(("an eth-sign-request round trips",
                   got["request_id"] == rid and got["sign_data"] == sd
                   and got["data_type"] == 2 and got["chain_id"] == 1))
    checks.append(("...with the derivation path spelled out",
                   got["path"] == "m/44h/60h/0h/0/0"))
    checks.append(("...and the optional fields carried",
                   got["address"] == bytes(range(20))
                   and got["origin"] == "metamask"))
    checks.append(("a request with only its required fields decodes",
                   decode_eth_sign_request(
                       encode_eth_sign_request(rid, sd, 2, "m/44h/60h/0h/0/0")
                   )["chain_id"] is None))
    checks.append(("it survives a whole UR transfer",
                   decode(encode(req, "eth-sign-request",
                                 max_fragment_len=20)) == req))

    sig = encode_eth_signature(rid, bytes(65))
    item, rest = cbor_decode(sig)
    checks.append(("an eth-signature is tagged 402 with the id echoed",
                   not rest and isinstance(item, Tag)
                   and item.tag == TAG_ETH_SIGNATURE
                   and item.value[1].value == rid
                   and item.value[2] == bytes(65)))
    bad("refuses a signature that is not 65 bytes",
        lambda: encode_eth_signature(rid, bytes(64)))

    bad("refuses an eth-sign-request under the wrong tag",
        lambda: decode_eth_sign_request(cbor_tag(999, cbor_map([]))))
    bad("refuses one that is not a map",
        lambda: decode_eth_sign_request(cbor_tag(TAG_ETH_SIGN_REQUEST,
                                                 cbor_uint(1))))
    bad("refuses a map key this device has never heard of",
        lambda: decode_eth_sign_request(cbor_tag(TAG_ETH_SIGN_REQUEST, cbor_map(
            [(cbor_uint(9), cbor_uint(1))]))))
    bad("refuses one missing its sign data",
        lambda: decode_eth_sign_request(cbor_tag(TAG_ETH_SIGN_REQUEST, cbor_map(
            [(cbor_uint(1), cbor_bytes(rid)), (cbor_uint(3), cbor_uint(2))]))))
    bad("refuses sign data past the ceiling",
        lambda: decode_eth_sign_request(
            encode_eth_sign_request(rid, b"x" * (MAX_SIGN_DATA + 1), 2,
                                    "m/44h/60h/0h/0/0")))
    bad("refuses a path deeper than it will render",
        lambda: decode_eth_sign_request(
            encode_eth_sign_request(rid, sd, 2,
                                    "m/" + "/".join(["0"] * 20))))
    bad("refuses an address that is not twenty bytes",
        lambda: decode_eth_sign_request(
            encode_eth_sign_request(rid, sd, 2, "m/44h/60h/0h/0/0",
                                    address=bytes(19))))
    bad("refuses a keypath under the wrong tag",
        lambda: decode_eth_sign_request(cbor_tag(TAG_ETH_SIGN_REQUEST, cbor_map([
            (cbor_uint(1), cbor_bytes(rid)), (cbor_uint(2), cbor_bytes(sd)),
            (cbor_uint(3), cbor_uint(2)),
            (cbor_uint(5), cbor_tag(999, cbor_map(
                [(cbor_uint(1), cbor_array([cbor_uint(0), cbor_bool(False)]))]))),
        ]))))
    bad("refuses a keypath whose hardened flag is not a boolean",
        lambda: decode_eth_sign_request(cbor_tag(TAG_ETH_SIGN_REQUEST, cbor_map([
            (cbor_uint(1), cbor_bytes(rid)), (cbor_uint(2), cbor_bytes(sd)),
            (cbor_uint(3), cbor_uint(2)),
            (cbor_uint(5), cbor_tag(TAG_KEYPATH, cbor_map(
                [(cbor_uint(1), cbor_array([cbor_uint(0), cbor_uint(1)]))]))),
        ]))))
    checks.append(("booleans decode, and null still does not",
                   cbor_decode(cbor_bool(True))[0] is True
                   and cbor_decode(cbor_bool(False))[0] is False))
    bad("refuses CBOR null", lambda: cbor_decode(b"\xf6"))

    # Progress, which is what the owner reads while the loop runs.
    c = Collector()
    for f in want[:5]:
        c.feed(f)
    checks.append(("reports progress mid-transfer", c.progress() == "5 of 9 fragments"))
    checks.append(("...and says what is missing", c.missing == [5, 6, 7, 8]))
    checks.append(("an incomplete transfer yields nothing at all",
                   c.decoder.result is None))
    c.reset()
    checks.append(("reset clears the transfer",
                   c.ur_type is None and c.progress().startswith("waiting")))

    ok = True
    for label, good in checks:
        ok &= good
        print(f"  {label:<62}{'PASS' if good else 'FAIL'}")
    print(f"\n{len(checks)} checks. " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_selftest())
