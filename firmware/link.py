"""The wire, for builds that have one. A USB-C data path instead of a camera.

READ THIS BEFORE ENABLING IT. The shipped device has no USB data path, and
that sentence is in README.md, BUILD.md §1 and BUILD.md §11. This module is
the documented way to give one up, and a build that uses it is a different
device from the one those documents describe. `BUILD.md` §11 carries the
wiring and §16 carries what it costs.

WHY IT EXISTS. QR is the right default and a poor fit for two things people
actually do: driving a signer from Bitcoin Core, Sparrow or Specter over HWI,
and signing more than one transaction in a sitting. A cheap webcam and a
240x240 panel move a few hundred bytes a frame; a wire moves a PSBT instantly
and does not have to be aimed.

WHAT IT COSTS, STATED PLAINLY. Three things, and only the first is answered by
anything else in this repository:

  SUBSTITUTION -- answered. What the device signs is what it rendered, and the
      confirmation screen, the PIN and the gate are untouched by this file.
      Bytes arriving on a wire reach `app.classify` exactly as bytes arriving
      through a lens do, and neither is believed. `qr.py` makes the same
      argument for the same reason.

  EXFILTRATION -- NOT answered. QR out is a screen the owner is looking at,
      moving 300 bytes a frame. This is a bidirectional link to a device
      holding a seed, at megabits, unobserved. Nothing here bounds what
      compromised firmware could send up it, because nothing can: the bound on
      the camera build is physical, and this removes it.

  THE STACK UNDER THE PARSER -- NOT answered. On the camera build the whole
      input surface is a lens and a regex, and `cell.service` confines it to an
      unprivileged user with four device nodes. This puts the Linux USB gadget
      stack in front of that parser, and that is kernel code running as root.

So: a variant, chosen deliberately, recorded like `--delegated-eoa` is. Not a
default, and not something a build acquires by installing a newer firmware.

WHY IT REPLACES THE CAMERA RATHER THAN JOINING IT. Not policy — wiring. The Pi
Zero 2 W has one USB port capable of data, the QR webcam is plugged into it
through an OTG adapter, and a dwc2 controller cannot be a host and a peripheral
at the same time. A build with this link has no QR camera, which is why the
variant is $10 CHEAPER than the build in `BOM.csv`: the webcam and its adapter
come off, and the USB-C breakout already in the bill carries D+/D- through the
opening that is already in the shell. No printed part changes.

THE FRAMING IS DELIBERATELY BORING, on `qr.py`'s reasoning. One message per
line, an ASCII tag and base64:

    cell1 cHNidP8BAHECAAAAAf...

A stream can be joined halfway through, so the receiver resynchronises on the
newline and drops anything it cannot read rather than trying to interpret it.
There is no handshake, no version negotiation and no session: every message
stands alone, because a protocol with state is a protocol with states nobody
tested.
"""

from __future__ import annotations

import base64
import re
import time
from dataclasses import dataclass, field
from typing import Callable, Protocol, runtime_checkable

import camera as cam
import qr

# The gadget's character device. `dtoverlay=dwc2` plus libcomposite's
# CDC-ACM function; BUILD.md §11 has the unit file and the config.
DEFAULT_PORT = "/dev/ttyGS0"

# One message per line, and a cap on the line. `total` in qr.py is
# attacker-chosen and bounded for the same reason: a host that can open this
# port can send an unterminated stream, and a reader without a ceiling
# accumulates it until the Pi is killed. Base64 of a megabyte is ~1.37 MB, so
# this admits any PSBT this device will render and nothing beyond it.
MAX_LINE = 1_400_000

TAG = b"cell1"
_LINE = re.compile(rb"^cell1 ([A-Za-z0-9+/=]*)$")

# How long to wait for a companion before giving up and going back to idle.
# Matches camera.SCAN_TIMEOUT_S: the owner is standing there either way.
RECEIVE_TIMEOUT_S = 180.0


class LinkError(Exception):
    """The port is missing, or stopped behaving like one."""


class BadMessage(ValueError):
    """A line that is not a CELL message. Dropped, never interpreted."""


def encode_message(payload: bytes) -> bytes:
    """One framed message, newline-terminated."""
    line = TAG + b" " + base64.b64encode(payload)
    if len(line) + 1 > MAX_LINE:
        raise LinkError(
            f"a {len(payload)}-byte message does not fit this link's "
            f"{MAX_LINE}-byte line")
    return line + b"\n"


def decode_message(line: bytes) -> bytes:
    """The inverse, refusing anything that is not exactly one message."""
    # Only the line ending is stripped, never spaces. `strip()` would eat the
    # separator after the tag, so an empty payload -- a legitimate message --
    # arrived as `b"cell1"` and failed to match at all.
    m = _LINE.match(line.strip(b"\r\n"))
    if not m:
        raise BadMessage(f"not a cell1 message: {line[:24]!r}")
    try:
        return base64.b64decode(m.group(1), validate=True)
    except Exception:                                           # noqa: BLE001
        raise BadMessage("message body is not valid base64") from None


@runtime_checkable
class Port(Protocol):
    """A byte stream. A serial device on the build, a fake in the tests."""

    def read(self, n: int) -> bytes:
        ...

    def write(self, data: bytes) -> int:
        ...

    def close(self) -> None:
        ...


@dataclass
class FakePort:
    """Plays back scripted bytes and records what was written."""

    script: bytes = b""
    written: bytearray = field(default_factory=bytearray)
    _pos: int = 0

    def read(self, n: int) -> bytes:
        chunk = self.script[self._pos:self._pos + n]
        self._pos += len(chunk)
        return chunk

    def write(self, data: bytes) -> int:
        self.written += data
        return len(data)

    def close(self) -> None:
        pass


class SerialPort:                                           # pragma: no cover
    """The real one. Untested until it is on a bench, like camera.USBCamera.

    Opened unbuffered and in binary. No `pyserial`: the gadget presents a plain
    character device, `termios` settings are meaningless on it, and a
    dependency that exists to configure a baud rate nothing has is a dependency
    this project does not need.
    """

    def __init__(self, path: str = DEFAULT_PORT):
        try:
            self._fh = open(path, "r+b", buffering=0)
        except OSError as e:
            raise LinkError(
                f"cannot open {path}: {e}. This build needs the USB gadget "
                f"configured -- see BUILD.md section 11. A camera build does "
                f"not have this port and should not be running with a link.") from None

    def read(self, n: int) -> bytes:
        import select
        # Never block forever. `receive` owns the deadline and cannot enforce
        # one if a read below it can hang: an unplugged host leaves the port
        # open and silent, and the loop would sit in read() past any timeout
        # the caller thought it had set.
        r, _, _ = select.select([self._fh], [], [], 0.2)
        if not r:
            return b""
        try:
            return self._fh.read(n) or b""
        except OSError as e:
            raise LinkError(f"the link stopped returning data: {e}") from None

    def write(self, data: bytes) -> int:
        try:
            n = self._fh.write(data)
            self._fh.flush()
            return n or 0
        except OSError as e:
            raise LinkError(f"the link stopped accepting data: {e}") from None

    def close(self) -> None:
        self._fh.close()


@dataclass
class Link:
    """One framed message in, one framed message out.

    The same shape as the camera path deliberately: `receive` returns a
    `camera.Transfer` so `app.sign_flow` dispatches on the payload without
    caring how it arrived, and every judgement about those bytes still happens
    above, against the device's own keys.
    """

    port: Port
    on_progress: Callable[[str], None] | None = None
    _buf: bytearray = field(default_factory=bytearray)

    def receive(self, timeout_s: float = RECEIVE_TIMEOUT_S,
                clock: Callable[[], float] = time.monotonic,
                buttons=None) -> cam.Transfer:
        """Wait for one complete message, or raise.

        BACK is polled here exactly as it is during a scan. A companion that
        never sends anything is the ordinary failure on this path -- the cable
        is in the charger, the host has no driver -- and an owner who cannot
        get out of the waiting screen power-cycles a device holding a seed.
        """
        deadline = clock() + timeout_s
        while True:
            if clock() > deadline:
                raise LinkError(
                    f"no message from the companion in {timeout_s:.0f}s")
            if buttons is not None and buttons.peek() == "BACK":
                buttons.poll()
                raise cam.ScanCancelled()
            chunk = self.port.read(4096)
            if chunk:
                self._buf += chunk
                if len(self._buf) > MAX_LINE:
                    # An unterminated stream. Drop what is held rather than
                    # growing without bound; a real message re-sent after this
                    # still arrives, because nothing about a message depends
                    # on what preceded it.
                    self._buf.clear()
                    raise LinkError(
                        f"the companion sent more than {MAX_LINE} bytes with "
                        f"no end of message; the buffer was discarded")
            while b"\n" in self._buf:
                line, _, rest = bytes(self._buf).partition(b"\n")
                self._buf = bytearray(rest)
                if not line.strip():
                    continue
                try:
                    payload = decode_message(line)
                except BadMessage as e:
                    # Junk on the wire is the normal condition of a serial
                    # port somebody just plugged in: getty banners, terminal
                    # escapes, a host probing for a modem. Report and keep
                    # reading, exactly as camera.scan steps over a QR code
                    # that is not ours.
                    if self.on_progress:
                        self.on_progress(str(e))
                    continue
                return cam.Transfer(payload, cam.LINK)

    def send(self, payload: bytes) -> int:
        """Write one framed message. Returns the bytes written."""
        return self.port.write(encode_message(payload))

    def close(self) -> None:
        self.port.close()


def open_link(path: str = DEFAULT_PORT) -> Link:             # pragma: no cover
    return Link(SerialPort(path))


# --------------------------------------------------------------------------


def _selftest() -> int:
    print("USB link — framing, resynchronisation, hostile streams\n")
    checks = []

    payload = bytes(range(256)) * 5
    framed = encode_message(payload)
    checks.append(("a message is one newline-terminated line",
                   framed.endswith(b"\n") and framed.count(b"\n") == 1))
    checks.append(("it is tagged", framed.startswith(TAG + b" ")))
    checks.append(("it round trips", decode_message(framed) == payload))
    checks.append(("an empty payload survives",
                   decode_message(encode_message(b"")) == b""))

    link = Link(FakePort(framed))
    got = link.receive()
    checks.append(("receives a whole message", got.payload == payload))
    checks.append(("...and reports how it arrived", got.framing == cam.LINK))

    # A stream joined halfway through, which is what opening a port that was
    # already being written to actually looks like.
    partial = framed[40:] + framed
    checks.append(("resynchronises after a truncated first message",
                   Link(FakePort(partial)).receive().payload == payload))

    # Junk a host emits before anyone is listening.
    noise = (b"\x1b[0m login: \n" + b"AT\r\n" + b"cell1 not base64!!!\n"
             + b"\n\n" + framed)
    notes: list[str] = []
    checks.append(("steps over junk on the wire",
                   Link(FakePort(noise),
                        on_progress=notes.append).receive().payload == payload))
    checks.append(("...and says so rather than failing silently",
                   any("cell1" in n or "base64" in n for n in notes)))

    # Two messages back to back: the second must survive the first being read.
    two = Link(FakePort(framed + encode_message(b"second")))
    checks.append(("reads the first of two", two.receive().payload == payload))
    checks.append(("...and then the second",
                   two.receive().payload == b"second"))

    # Delivered a byte at a time, which is what a slow host does.
    class Trickle:
        def __init__(self, data): self.data, self.i = data, 0
        def read(self, n):
            b = self.data[self.i:self.i + 1]
            self.i += len(b)
            return b
        def write(self, d): return len(d)
        def close(self): pass

    checks.append(("reassembles a message delivered a byte at a time",
                   Link(Trickle(framed)).receive().payload == payload))

    # Sending.
    port = FakePort()
    n = Link(port).send(payload)
    checks.append(("send writes one framed message",
                   n == len(framed) and bytes(port.written) == framed))
    checks.append(("what is sent is what a receiver reads",
                   Link(FakePort(bytes(port.written))).receive().payload
                   == payload))

    def bad(label, fn, exc):
        try:
            fn()
            checks.append((label, False))
        except exc:
            checks.append((label, True))

    bad("refuses an untagged line", lambda: decode_message(b"hello"),
        BadMessage)
    bad("refuses another tag", lambda: decode_message(b"cell2 aGk="),
        BadMessage)
    bad("refuses a body that is not base64",
        lambda: decode_message(b"cell1 ~~~~"), BadMessage)
    bad("refuses a message past the line cap",
        lambda: encode_message(b"x" * MAX_LINE), LinkError)

    # An unterminated stream must be dropped, not accumulated.
    bad("drops an unterminated stream rather than growing",
        lambda: Link(FakePort(b"cell1 " + b"A" * (MAX_LINE + 8))).receive(),
        LinkError)

    # And silence must time out rather than hang.
    ticks = iter([0.0] + [1000.0] * 50)
    bad("times out on silence",
        lambda: Link(FakePort(b"")).receive(clock=lambda: next(ticks)),
        LinkError)

    # BACK, which is the only way out of a waiting screen.
    class BackButton:
        def peek(self): return "BACK"
        def poll(self): return "BACK"

    bad("BACK leaves the waiting screen",
        lambda: Link(FakePort(b"")).receive(buttons=BackButton()),
        cam.ScanCancelled)

    # The payload is bytes and nothing else. A PSBT arriving on the wire must
    # reach classify() as the same bytes it would have off the camera.
    import psbt as psbtmod
    fake_psbt = psbtmod.PSBT_MAGIC + b"\x00" * 32
    over_wire = Link(FakePort(encode_message(fake_psbt))).receive().payload
    over_lens = qr.decode(qr.encode(fake_psbt))
    checks.append(("a payload is identical over wire and over lens",
                   over_wire == over_lens == fake_psbt))

    checks.append(("FakePort satisfies the protocol", isinstance(FakePort(), Port)))
    checks.append(("SerialPort satisfies the protocol",
                   all(hasattr(SerialPort, m) for m in ("read", "write", "close"))))

    ok = True
    for label, good in checks:
        ok &= good
        print(f"  {label:<58}{'PASS' if good else 'FAIL'}")
    print("\n" + ("PASS" if ok else "FAIL"))
    print("\nThe gadget port itself is unverified until it is on a bench.")
    print("This is an opt-in build variant. See BUILD.md sections 11 and 16.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_selftest())
