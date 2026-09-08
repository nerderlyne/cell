"""The camera, and the only way data gets into this device.

There is no wifi and no bluetooth, and on the shipped build no USB data path
either, so everything the device learns about the outside world arrives as
pixels through a lens. That makes this file the whole input attack surface, and
it is written accordingly: it decodes QR codes and hands the bytes to
`qr.Collector`, where the paranoia about substituted frames lives. (`link.py`
is the other input surface, on the one build that has it.)

TWO CAMERAS, ONE CSI PORT. The Pi Zero has a single CSI connector and the
speckle path owns it — that camera has its lens removed and its exposure,
gain and white balance pinned, because auto-adjustment destroys the
correlation measurement the blood gate depends on. So QR capture uses a USB
webcam, where auto-exposure is not merely tolerable but wanted. BOM.csv says
the same thing in the sourcing notes; getting this backwards means a device
that either cannot read a QR code or cannot run its own gate.

WHAT THIS FILE DOES NOT DO. It does not decide anything. It returns bytes.
Every judgement about those bytes — is it a PSBT, is it ours, does it pay who
it says — happens above, against the device's own keys. A camera that could
be made to lie is assumed; the design's answer is that nothing downstream
believes it.

TWO FRAMINGS, AND WHY THE DEVICE DOES NOT CHOOSE. A transfer arrives either as
`qr.py`'s `pNofM` frames or as `ur.py`'s UR parts, and which one it is depends
entirely on the coordinator the owner already uses: Specter speaks pNofM,
Keystone-compatible tooling speaks UR, Sparrow speaks both. So `scan` accepts
either, decided by the first frame it can parse and then locked for the rest of
the transfer, and `emit` REPLIES IN THE FRAMING IT WAS ASKED IN. A coordinator
that could talk to this device cannot then fail to read its answer.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Protocol, runtime_checkable

import qr
import ur

# What either collector raises for a frame that does not belong to the
# transfer. `scan` steps over these and keeps going: the owner may simply have
# panned across another screen, and taking the loop down for that would make a
# busy desk unusable.
FramingError = (qr.BadFrame, ur.BadUR)

PNOFM, UR = "pNofM", "ur"
# A third value that never comes off a camera: the USB build's wire. It lives
# beside the other two because `Transfer` is what the loop dispatches on, and a
# reply has to know which route to go back out by. See link.py.
LINK = "link"

# How long to keep the camera running before giving up on a transfer. Long
# enough for an animated loop of a few dozen frames to come round twice.
SCAN_TIMEOUT_S = 180.0


class CameraError(Exception):
    """The camera is missing, or cannot be configured the way we need it."""


@runtime_checkable
class Camera(Protocol):
    def frames(self):
        """Yield decoded QR strings as they are seen. May yield duplicates."""

    def close(self) -> None:
        ...


@dataclass
class FakeCamera:
    """Plays back a scripted list of decoded strings, for the tests."""

    script: list[str] = field(default_factory=list)
    repeats: int = 1

    def frames(self):
        for _ in range(self.repeats):
            for s in self.script:
                yield s

    def close(self) -> None:
        pass


class USBCamera:
    """A cheap USB webcam plus a QR decoder. Untested until it is on a bench."""

    def __init__(self, index: int = 0):
        try:
            import cv2
        except ImportError:                                     # pragma: no cover
            raise CameraError(
                "QR capture needs OpenCV. On Raspberry Pi OS:\n"
                "    apt install python3-opencv") from None
        self._cv2 = cv2
        self._cap = cv2.VideoCapture(index)
        if not self._cap.isOpened():
            raise CameraError(
                f"no camera at index {index}. The QR camera is the USB webcam; "
                f"the CSI port belongs to the speckle path.")
        # Modest resolution on purpose: a Pi Zero decoding 1080p spends its
        # time on pixels rather than on frames, and QR wants frames.
        self._cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
        self._cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
        self._detector = cv2.QRCodeDetector()

    def frames(self):
        while True:
            ok, frame = self._cap.read()
            if not ok:
                raise CameraError("the camera stopped returning frames")
            try:
                data, points, _ = self._detector.detectAndDecode(frame)
            except Exception:                                   # noqa: BLE001
                # A decoder that throws on a garbage frame must not take the
                # device down mid-transfer. Drop the frame and keep looking.
                continue
            # A read that decoded nothing is still a tick. Yielding None
            # rather than looping is what lets scan() reach its deadline and
            # its BACK check: a camera pointed at a blank wall never decodes,
            # and a loop that only yields on success never comes back.
            yield data if data else None

    def close(self) -> None:
        self._cap.release()


class ScanCancelled(Exception):
    """The owner pressed BACK during a scan. Not a failure, a decision."""


@dataclass(frozen=True)
class Transfer:
    """One complete transfer, and how it was framed.

    The framing travels with the payload for one reason: the reply has to use
    it. Everything else about this object is deliberately inert — nothing
    downstream may treat `ur_type` as a claim about what the bytes are. A
    `crypto-psbt` label on a payload that is not a PSBT is caught by
    `app.classify` reading the bytes, exactly as it would be without a label.
    """

    payload: bytes
    framing: str = PNOFM
    ur_type: str | None = None


@dataclass
class EitherCollector:
    """Collects a transfer in whichever framing turns up first.

    The first frame that parses picks the framing, and it is then locked: a UR
    part arriving mid-`pNofM` transfer is refused rather than starting a second
    collection alongside the first. Both underlying collectors already refuse a
    chunk replaced mid-scan, and locking the framing closes the same hole one
    level up — otherwise a second screen could restart the transfer in the
    other dialect and be reassembled independently.
    """

    framing: str | None = None
    _qr: qr.Collector = field(default_factory=qr.Collector)
    _ur: ur.Collector = field(default_factory=ur.Collector)

    def feed(self, frame: str) -> Transfer | None:
        wants = UR if ur.is_ur(frame) else PNOFM
        if self.framing is None:
            self.framing = wants
        elif wants != self.framing:
            raise qr.BadFrame(
                f"a {wants} frame arrived during a {self.framing} transfer. "
                f"Two different transfers are on screen; restart the scan.")
        if self.framing == UR:
            payload = self._ur.feed(frame)
            if payload is None:
                return None
            return Transfer(payload, UR, self._ur.ur_type)
        payload = self._qr.feed(frame)
        if payload is None:
            return None
        return Transfer(payload, PNOFM)

    @property
    def missing(self) -> list[int]:
        return self._ur.missing if self.framing == UR else self._qr.missing

    def progress(self) -> str:
        if self.framing is None:
            return "waiting for the first frame"
        return (self._ur.progress() if self.framing == UR
                else self._qr.progress())


def scan(camera: Camera, display=None, timeout_s: float = SCAN_TIMEOUT_S,
         clock: Callable[[], float] = time.monotonic,
         on_progress: Callable[[str], None] | None = None,
         buttons=None) -> bytes:
    """Collect one complete transfer and return its bytes.

    Kept for the callers that only want the payload. `scan_transfer` is the
    same scan with the framing attached, which is what the signing flows use
    so the reply goes back in the dialect it arrived in.
    """
    return scan_transfer(camera, display, timeout_s, clock, on_progress,
                         buttons).payload


def scan_transfer(camera: Camera, display=None, timeout_s: float = SCAN_TIMEOUT_S,
                  clock: Callable[[], float] = time.monotonic,
                  on_progress: Callable[[str], None] | None = None,
                  buttons=None) -> Transfer:
    """Collect one complete transfer, or raise.

    Progress is reported because an animated transfer that is missing one
    frame looks identical to one that is not working at all, and the owner
    needs to know which — the fix for the first is to keep the camera still,
    and for the second it is to start again.

    BACK IS A REAL BUTTON HERE. Both screens say "BACK to stop", and until
    `buttons` was passed nothing polled one: the only way out of a scan that
    was not going to complete was the power switch.
    """
    collector = EitherCollector()
    deadline = clock() + timeout_s
    for frame in camera.frames():
        if clock() > deadline:
            raise CameraError(
                f"gave up after {timeout_s:.0f}s with {collector.progress()}; "
                f"missing {collector.missing}")
        # peek, not poll: this screen is watching for BACK, and consuming a
        # CONFIRM pressed a moment early would make it disappear.
        if buttons is not None and buttons.peek() == "BACK":
            buttons.poll()
            raise ScanCancelled()
        if frame is None:
            continue                    # a read that carried no code
        try:
            transfer = collector.feed(frame)
        except FramingError as e:
            # A frame from a different transfer, or one that changed under us.
            # Report it and keep scanning — the owner may simply have panned
            # across another screen.
            if on_progress:
                on_progress(str(e))
            continue
        if on_progress:
            on_progress(collector.progress())
        if display is not None:
            display.show(["SCANNING", "", f"  {collector.progress()}", "",
                          "  BACK to stop"])
        if transfer is not None:
            return transfer
    raise CameraError(f"the camera ran out of frames with {collector.progress()}")


def emit(display, payload: bytes, caption: str = "", loops: int = 3,
         chunk: int = qr.DEFAULT_CHUNK,
         sleep: Callable[[float], None] = time.sleep,
         frame_s: float = 0.4, framing: str = PNOFM,
         ur_type: str | None = None) -> int:
    """Show a payload as an animated QR loop. Returns the frame count.

    It loops rather than showing each frame once, because the reader on the
    other side will miss frames and there is no back channel to ask again.

    THE TWO FRAMINGS LOOP DIFFERENTLY, and that is the point of offering UR at
    all. A `pNofM` loop repeats the same fixed frames, so a reader that keeps
    missing frame four never finishes. A UR loop's second pass is not a repeat:
    past the pure fragments the encoder emits XOR mixtures, and a reader
    missing one fragment recovers it from a mixture of others. Same wall-clock,
    same screen, and a transfer that converges instead of stalling.
    """
    if framing not in (PNOFM, UR):
        raise CameraError(f"unknown framing {framing!r}")
    if framing == PNOFM:
        frames = qr.encode(payload, chunk=chunk)
        shown = [f for _ in range(loops) for f in frames]
    else:
        pure = ur.encode(payload, ur_type or "bytes", max_fragment_len=chunk)
        # A payload small enough for one part is a still image, and a still
        # image is the easiest thing a cheap webcam ever has to read. Repeat
        # it rather than turning it into a fountain of one.
        shown = pure * loops if len(pure) == 1 else ur.encode(
            payload, ur_type or "bytes", max_fragment_len=chunk,
            parts=len(pure) * loops)
        frames = pure
    for i, f in enumerate(shown, 1):
        display.show_qr(f, caption or f"{i} of {len(shown)}  ·  "
                                      f"{qr.digest(payload)}")
        sleep(frame_s)
    return len(frames)


def open_camera(console: bool = False, script: list[str] | None = None) -> Camera:
    if console:
        return FakeCamera(script or [])
    try:
        return USBCamera()
    except CameraError as e:
        print(f"No camera: {e}\nFalling back to a scripted stub.")
        return FakeCamera(script or [])


# --------------------------------------------------------------------------


def _selftest() -> int:
    print("Camera — transfer collection, hostile frames, emission\n")
    checks = []
    from display import ConsoleDisplay

    payload = bytes(range(256)) * 3
    frames = qr.encode(payload, chunk=100)

    checks.append(("FakeCamera satisfies the protocol",
                   isinstance(FakeCamera(), Camera)))
    checks.append(("USBCamera satisfies the protocol",
                   all(hasattr(USBCamera, m) for m in ("frames", "close"))))

    checks.append(("collects a transfer in order",
                   scan(FakeCamera(frames)) == payload))
    checks.append(("collects it out of order",
                   scan(FakeCamera(list(reversed(frames)))) == payload))
    checks.append(("tolerates the duplicates an animated loop produces",
                   scan(FakeCamera(frames, repeats=3)) == payload))

    # Junk in the field of view must be stepped over, not fatal.
    noisy = ["https://example.com", "hello"] + frames + ["not a frame"]
    checks.append(("ignores non-CELL QR codes in view",
                   scan(FakeCamera(noisy)) == payload))

    notes: list[str] = []
    scan(FakeCamera(noisy), on_progress=notes.append)
    checks.append(("...and says so rather than failing silently",
                   any("pNofM" in n for n in notes)))

    # A frame swapped mid-scan is the attack this path exists to survive. The
    # collector refuses it, and scan() keeps going rather than accepting it.
    swapped = [frames[0], "p1of%d %s" % (len(frames), "AAAA")] + frames[1:]
    checks.append(("a substituted frame does not corrupt the payload",
                   scan(FakeCamera(swapped)) == payload))

    # Incomplete transfers must raise, never return a partial payload.
    for label, script in [("an incomplete transfer", frames[:-1]),
                          ("an empty field of view", [])]:
        try:
            scan(FakeCamera(script))
            checks.append((f"refuses {label}", False))
        except CameraError:
            checks.append((f"refuses {label}", True))

    # And a transfer that never completes must time out rather than hang.
    ticks = iter([0.0] + [1000.0] * 50)
    try:
        scan(FakeCamera(frames[:1], repeats=50), clock=lambda: next(ticks))
        checks.append(("times out rather than hanging", False))
    except CameraError as e:
        checks.append(("times out rather than hanging", "gave up" in str(e)))

    # Emission.
    d = ConsoleDisplay(out=open("/dev/null", "w"))
    n = emit(d, payload, loops=2, chunk=100, sleep=lambda _s: None)
    checks.append(("emits every frame, every loop", len(d.frames) == n * 2))
    checks.append(("the emitted frames reassemble",
                   qr.decode(d.frames[:n]) == payload))

    d2 = ConsoleDisplay(out=open("/dev/null", "w"))
    emit(d2, b"short", loops=1, sleep=lambda _s: None)
    checks.append(("a short payload is a single frame", len(d2.frames) == 1))

    # A round trip through both halves, which is what the airgap actually is.
    d3 = ConsoleDisplay(out=open("/dev/null", "w"))
    emit(d3, payload, loops=1, chunk=64, sleep=lambda _s: None)
    checks.append(("emit then scan round trips",
                   scan(FakeCamera(d3.frames)) == payload))

    # ---- the other framing, through exactly the same scan ----

    ur_frames = ur.encode(payload, "crypto-psbt", max_fragment_len=100)
    got = scan_transfer(FakeCamera(ur_frames))
    checks.append(("collects a UR transfer without being told",
                   got.payload == payload))
    checks.append(("...and reports the framing back",
                   got.framing == UR and got.ur_type == "crypto-psbt"))
    checks.append(("a pNofM transfer reports its framing too",
                   scan_transfer(FakeCamera(frames)).framing == PNOFM))
    checks.append(("collects a UR transfer out of order",
                   scan(FakeCamera(list(reversed(ur_frames)))) == payload))

    # The reason UR is here: a frame the camera never manages to read.
    dropped = [f for f in ur_frames if not f.startswith("ur:crypto-psbt/2-")]
    more = ur.encode(payload, "crypto-psbt", max_fragment_len=100,
                     parts=len(ur_frames) * 3)[len(ur_frames):]
    checks.append(("a UR transfer survives a frame that is never read",
                   scan(FakeCamera(dropped + more)) == payload))
    try:
        scan(FakeCamera([f for f in frames if not f.startswith("p2of")] * 3))
        checks.append(("...where pNofM cannot, however long it loops", False))
    except CameraError:
        checks.append(("...where pNofM cannot, however long it loops", True))

    # Junk, and the other dialect, both stepped over rather than fatal.
    checks.append(("ignores UR frames during a pNofM transfer",
                   scan(FakeCamera([frames[0], ur_frames[0]] + frames[1:]))
                   == payload))
    checks.append(("ignores pNofM frames during a UR transfer",
                   scan(FakeCamera([ur_frames[0], frames[0]] + ur_frames[1:]))
                   == payload))

    d4 = ConsoleDisplay(out=open("/dev/null", "w"))
    n = emit(d4, payload, loops=3, chunk=100, sleep=lambda _s: None,
             framing=UR, ur_type="crypto-psbt")
    checks.append(("a UR loop's later passes are not repeats",
                   len(d4.frames) == n * 3 and len(set(d4.frames)) == n * 3))
    checks.append(("...and the first pass alone reassembles",
                   scan(FakeCamera(d4.frames[:n])) == payload))
    checks.append(("...as does any sufficient subset",
                   scan(FakeCamera(d4.frames[2:])) == payload))

    d5 = ConsoleDisplay(out=open("/dev/null", "w"))
    emit(d5, b"short", loops=2, sleep=lambda _s: None, framing=UR)
    checks.append(("a small UR payload stays a still image",
                   len(set(d5.frames)) == 1 and "-" not in d5.frames[0][3:12]))

    try:
        emit(d5, b"x", framing="semaphore", sleep=lambda _s: None)
        checks.append(("refuses a framing it does not have", False))
    except CameraError:
        checks.append(("refuses a framing it does not have", True))

    ok = True
    for label, good in checks:
        ok &= good
        print(f"  {label:<52}{'PASS' if good else 'FAIL'}")
    print("\n" + ("PASS" if ok else "FAIL"))
    print("\nThe webcam and the panel are unverified until they are on a bench.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_selftest())
