#!/usr/bin/env python3
"""The other end of the USB-C data variant's wire.

`firmware/link.py` is the device side. This is the host side, and it exists
because a protocol with one end is a protocol nobody can use: a builder who
wires the variant in BUILD.md §11 has a device presenting `/dev/ttyGS0` and
nothing to talk to it with.

    # sign a PSBT a coordinator produced
    python3 tools/companion.py send --port /dev/ttyACM0 \\
        --in unsigned.psbt --out signed.psbt

    # or an Ethereum request this repository's own JSON shape
    python3 tools/companion.py send --port /dev/ttyACM0 \\
        --in request.json --out signed.hex

ONE DEFINITION OF THE FRAMING, and it lives in `firmware/link.py`. This file
imports it rather than restating it. Two implementations of a wire format is
how they drift, and the drift shows up as a device that works with the tool it
shipped with and nothing else -- the failure `firmware/qr.py` warns about, one
layer down.

WHAT THIS IS NOT. It is not HWI. Bitcoin Core, Sparrow and Specter drive a
hardware wallet through a driver inside the `hwi` package, and adding one means
a change to that package rather than a file here. What this gives you is the
workflow underneath it: a coordinator writes a PSBT, this sends it, the device
displays it and asks for a pulse, and the signed PSBT comes back as a file the
coordinator can finalise. That is the whole airgap loop without a camera, and
it is the honest description of what the variant buys today.

IT VERIFIES NOTHING, DELIBERATELY. This runs on the machine the device is
airgapped FROM. It is a pipe. Every judgement about what was signed belongs on
the device, in front of the owner, which is where the confirmation screen is.
A companion that checked the reply and reported "looks right" would be telling
the owner something only the device is in a position to know.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "firmware"))

import link                                                    # noqa: E402
import psbt as psbtmod                                         # noqa: E402

# Long enough for the owner to read the screen, type eight digits, and pass a
# gate. The blood tier runs for 600 s on its own, so a timeout that assumed
# the touch tier would abandon a transfer somebody was bleeding for.
DEFAULT_TIMEOUT_S = 900.0


def describe(payload: bytes) -> str:
    """A one-line note on what came back, for the operator's benefit only.

    Structure, never a claim. It says "this is shaped like a PSBT", not "this
    is your transaction" -- see the note at the top of this file about where
    that judgement belongs.
    """
    if payload.startswith(psbtmod.PSBT_MAGIC):
        return f"{len(payload)} bytes, shaped like a PSBT"
    if payload[:1] == b"\x02":
        return f"{len(payload)} bytes, shaped like a type-2 transaction"
    if payload[:1] in (b"{", b"["):
        return f"{len(payload)} bytes, shaped like JSON"
    return f"{len(payload)} bytes"


def cmd_send(args, open_link=None) -> int:
    """Send one payload, wait for one reply, write it out.

    `open_link` is injected so the self-test can drive the whole path against
    a fake port. Without it the port would be the one thing this file has that
    nothing checks, and it is the thing most likely to be wrong.
    """
    payload = Path(args.infile).read_bytes()
    if not payload:
        print("Refusing to send an empty file.")
        return 1
    try:
        lk = (open_link or link.open_link)(args.port)
    except link.LinkError as e:
        print(f"Cannot open {args.port}: {e}")
        return 1
    try:
        lk.send(payload)
        print(f"Sent {describe(payload)} to {args.port}.")
        print("\nNow look at the device. It will show you the transaction,")
        print("ask for your PIN, and run the gate. Nothing is signed until")
        print("you confirm it there.\n")
        try:
            reply = lk.receive(timeout_s=args.timeout).payload
        except link.LinkError as e:
            print(f"No reply: {e}")
            print("\nIf the device showed a refusal, the reason is on its")
            print("screen. Nothing was signed.")
            return 1
    finally:
        lk.close()
    Path(args.out).write_bytes(reply)
    print(f"Wrote {describe(reply)} to {args.out}.")
    return 0


# --------------------------------------------------------------------------


def _selftest() -> int:
    """The framing, both ways, against a fake port.

    The port itself needs the hardware. What does not need hardware is that
    the two ends agree -- so this drives `cmd_send`'s round trip through
    `link.FakePort`, which is the same framing code the device runs.
    """
    print("Companion — the host side of the USB link\n")
    checks: list[tuple[str, bool]] = []

    payload = psbtmod.PSBT_MAGIC + bytes(range(200))
    reply = psbtmod.PSBT_MAGIC + bytes(range(100))

    # Host sends, device reads: exactly the bytes that went in.
    port = link.FakePort()
    link.Link(port).send(payload)
    got = link.Link(link.FakePort(bytes(port.written))).receive()
    checks.append(("what the host writes, the device reads",
                   got.payload == payload))

    # Device replies, host reads.
    back = link.FakePort()
    link.Link(back).send(reply)
    checks.append(("what the device writes, the host reads",
                   link.Link(link.FakePort(bytes(back.written)))
                   .receive().payload == reply))

    # Both directions on one port, which is what a real session is.
    both = link.FakePort(link.encode_message(reply))
    lk = link.Link(both)
    lk.send(payload)
    checks.append(("a whole session round trips",
                   bytes(both.written) == link.encode_message(payload)
                   and lk.receive().payload == reply))

    checks.append(("the framing comes from firmware/link.py, not from here",
                   link.encode_message(payload).startswith(link.TAG)))

    for label, blob, needle in (
        ("a PSBT", psbtmod.PSBT_MAGIC + b"\x00", "PSBT"),
        ("a type-2 transaction", b"\x02\xf0", "type-2"),
        ("JSON", b'{"type":"cell-eth-tx"}', "JSON"),
        ("anything else", b"\xff\xff", "bytes"),
    ):
        checks.append((f"describes {label} by structure alone",
                       needle in describe(blob)))

    # The whole `send` path, against a fake port. This is the one part of this
    # file that talks to hardware, so it is the part most worth driving.
    import contextlib
    import io as _io
    import tempfile

    def quietly(fn):
        buf = _io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = fn()
        return rc, buf.getvalue()

    with tempfile.TemporaryDirectory() as tmp:
        tdir = Path(tmp)
        (tdir / "in.psbt").write_bytes(payload)
        (tdir / "empty").write_bytes(b"")

        class Args:
            infile = str(tdir / "in.psbt")
            port = "/dev/ttyACM0"
            out = str(tdir / "out.psbt")
            timeout = 5.0

        session = link.FakePort(link.encode_message(reply))
        rc, said = quietly(
            lambda: cmd_send(Args(), open_link=lambda _p: link.Link(session)))
        checks.append(("send writes the payload and keeps the reply", rc == 0))
        checks.append(("...sending exactly what was in the file",
                       bytes(session.written) == link.encode_message(payload)))
        checks.append(("...and writing exactly what came back",
                       (tdir / "out.psbt").read_bytes() == reply))
        checks.append(("...telling the operator to look at the device",
                       "look at the device" in said))

        # A device that refuses shows the reason on ITS screen, so the host
        # must say that rather than inventing an explanation.
        class Silent(Args):
            out = str(tdir / "none.psbt")
            timeout = 0.0

        rc, said = quietly(
            lambda: cmd_send(Silent(),
                             open_link=lambda _p: link.Link(link.FakePort(b""))))
        checks.append(("no reply is an exit code and a pointer to the screen",
                       rc == 1 and "on its" in said and "screen" in said))
        checks.append(("...and writes no output file",
                       not (tdir / "none.psbt").exists()))

        # An empty file is refused before the port is opened, so a mistyped
        # path cannot leave the device waiting on a transfer never coming.
        class Empty(Args):
            infile = str(tdir / "empty")

        rc, _ = quietly(lambda: cmd_send(Empty()))
        checks.append(("refuses to send an empty file", rc == 1))

        # And a port that is not there is a message, not a traceback.
        class NoPort(Args):
            port = "/nonexistent"

        rc, said = quietly(lambda: cmd_send(NoPort()))
        checks.append(("a missing port is a readable error",
                       rc == 1 and "Cannot open" in said))

    ok = True
    for label, good in checks:
        ok &= good
        print(f"  {label:<58}{'PASS' if good else 'FAIL'}")
    print("\n" + ("PASS" if ok else "FAIL"))
    print("\nThe gadget port itself is unverified until it is on a bench.")
    print("This tool is for the USB-C data variant only. See BUILD.md §11.")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description="The host side of CELL's USB-C data variant.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("send", help="send a payload and write the reply")
    p.add_argument("--port", default=link.DEFAULT_PORT,
                   help="the device's serial port as the HOST sees it, "
                        "usually /dev/ttyACM0 on Linux")
    p.add_argument("--in", dest="infile", required=True,
                   help="the PSBT or JSON request to sign")
    p.add_argument("--out", required=True, help="where to write the reply")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S,
                   help="seconds to wait for the reply. The default allows "
                        "for the blood tier's 600 s capture")
    p.set_defaults(fn=cmd_send)

    p = sub.add_parser("selftest", help="check both ends agree on the framing")
    p.set_defaults(fn=lambda _a: _selftest())

    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
