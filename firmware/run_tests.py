#!/usr/bin/env python3
"""Run every self-test in the firmware. No hardware required.

    python firmware/run_tests.py

This is what CI runs and what a reviewer should run first: the signing stack
against published test vectors, the gate logic, the tier policy, the
attestation format, and the full calibration round trip.

The signing suites are checked against the vectors published in the BIPs, RFC
6979, the EIPs and the Ethereum yellow paper — not against our own output.
During development they were also compared byte for byte against `embit` and
`eth-account`, which is why the low-R grinding matches Bitcoin Core and the
Ethereum signatures match every EVM library. Those packages are not
dependencies; the vectors they confirmed are baked into the suites.

Sensing thresholds are calibrated against physical samples at first build —
see BUILD.md section 13. VALIDATION.md is the verification status record.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent

SUITES = [
    ("hash primitives — RIPEMD-160 and Keccak-256 vectors",
     [sys.executable, "hashes.py"]),
    ("secp256k1 — RFC 6979, ECDSA, BIP-340, BIP-341",
     [sys.executable, "secp256k1.py"]),
    # The two fast scalar multiplies against the affine group law they are
    # optimisations of. A wrong answer here is a wrong signature, not a
    # failed assertion, so the fast paths are never the only implementation.
    ("curve arithmetic — the fast multiplies against the definition",
     [sys.executable, "test_curve.py"]),
    ("BIP-39 — wordlist integrity and the official vectors",
     [sys.executable, "bip39.py"]),
    ("BIP-32 — official vectors, hardened isolation, owns()",
     [sys.executable, "bip32.py"]),
    ("addresses — BIP-173/350 vectors, scripts, EIP-55",
     [sys.executable, "addresses.py"]),
    ("transactions — BIP-143 and BIP-341 sighash vectors",
     [sys.executable, "tx.py"]),
    ("ethereum — RLP, EIP-1559 encoding, recovery",
     [sys.executable, "eth.py"]),
    # The smart-account path: typed data the device builds from what it shows,
    # and the delegation that decides what every later signature means.
    ("EIP-712 and EIP-7702 — typed data, delegation, and what they bind",
     [sys.executable, "test_eip712.py"]),
    # The beacon, against the registry's own vectors, and the one operation
    # whose chain must not reach the seed.
    ("proof of life — the beacon digest, the period, and the unwrap it skips",
     [sys.executable, "test_beacon.py"]),
    # The third seed source, and the failure it would have had: a speckle
    # image is the PUF, so one frame is a constant, not a sample.
    ("chamber entropy — the residual, its health tests, and the XOR",
     [sys.executable, "test_chamber_trng.py"]),
    # The attestation with the device's name taken off it, and the key image
    # that stops one device voting twice without publishing a voting history.
    ("unlinkable attestation — LSAG, and what the key image links",
     [sys.executable, "test_ring.py"]),
    ("seed store — AES-256-GCM wrap and tamper detection",
     [sys.executable, "seedstore.py"]),
    ("QR transport — framing and hostile frames",
     [sys.executable, "qr.py"]),
    ("secure element driver — interface conformance",
     [sys.executable, "se_atecc.py"]),
    # The config zone is the one part of the build a mistake in is permanent,
    # so its encoder is checked here even though the tool lives in tools/.
    ("ATECC608B config zone — encoding, invariants, and the slot map",
     [sys.executable, "../tools/atecc_config.py", "selfcheck"]),
    ("secure element driver — the arithmetic, against a fake chip",
     [sys.executable, "test_se_atecc.py"]),
    ("display — layout limits and the colour rule",
     [sys.executable, "display.py"]),
    ("buttons — debounce, consent, PIN entry",
     [sys.executable, "buttons.py"]),
    ("camera — transfer collection and hostile frames",
     [sys.executable, "camera.py"]),
    ("wallet — end to end, and every footgun we could name",
     [sys.executable, "test_wallet.py"]),
    ("application loop — the seams between the parts",
     [sys.executable, "test_app.py"]),
    ("hardware drivers — do we call these libraries correctly",
     [sys.executable, "test_drivers.py"]),
    ("consensus — an independent interpreter runs our scripts",
     [sys.executable, "test_consensus.py"]),
    ("blood tier — 6 gates, 18 sample classes",
     [sys.executable, "calibrate.py", "selftest", "--n", "8"]),
    ("touch tier — 7 gates, 9 sample classes",
     [sys.executable, "touch_gate.py"]),
    ("tier policy — escalation and the floor",
     [sys.executable, "policy.py"]),
    ("attestation — BIP-340 vectors, quorum, malformed input",
     [sys.executable, "attest.py"]),
    ("duress PIN — a second wallet, and no way to tell",
     [sys.executable, "test_duress.py"]),
    ("cardiac identity — pipeline, and what it actually separates",
     [sys.executable, "test_cardiac_id.py"]),
    ("boot record — a damaged card says so instead of dying",
     [sys.executable, "test_boot_record.py"]),
    ("post-quantum attestation — LMS against RFC 8554 vectors",
     [sys.executable, "test_lms.py"]),
    ("optical PUF — BCH, drift tolerance, and failing closed on tamper",
     [sys.executable, "test_optical_puf.py"]),
    ("secure element — PIN counter, KDF binding, wipe",
     [sys.executable, "se.py"]),
    ("unlock chain — step order, refusals, key binding",
     [sys.executable, "test_signer.py"]),
    ("gate robustness — enrolment invariant, hostile captures",
     [sys.executable, "test_gate_robustness.py"]),
    # The runbook itself: provision.py driven as a subprocess, then the device
    # booted from what it wrote. Every other suite tests a module; this one
    # tests two commands in a row against one directory, which is where three
    # defects were living because nothing ever did it.
    ("first build — the documented sequence, end to end",
     [sys.executable, "../tools/test_first_build.py"]),
    # The bench tool's own arithmetic. Its checks need the parts, so nobody
    # can run them here -- but both of them shipped giving false alarms, and
    # the maths underneath does not need the parts.
    ("bench arithmetic — bounce measurement and the PIN budget",
     [sys.executable, "../tools/bench.py", "selftest"]),
    # Everything this device learns arrives as pixels through a lens, so the
    # parsers are the whole input attack surface. This holds each of them to
    # the exceptions it declares, on noise and on corrupted valid PSBTs.
    ("fuzzing — hostile bytes at every entry point",
     [sys.executable, "test_fuzz.py"]),
    ("drift margins — what the normalisation actually cancels",
     [sys.executable, "robustness.py", "--quick"]),
    ("speckle physics — exposure, frame rate and grain",
     [sys.executable, "speckle_sim.py", "--quick"]),
]


def calibration_round_trip() -> bool:
    """capture -> roc -> thresholds.json -> Thresholds.load().

    The loop that matters most and is easiest to break silently — the
    thresholds measured on your hardware have to be the ones the device loads.
    """
    sys.path.insert(0, str(HERE))
    from blood_gate import Thresholds, evaluate           # noqa: E402
    import calibrate                                       # noqa: E402

    with tempfile.TemporaryDirectory() as d:
        work = Path(d)
        calibrate.DATA = work / "captures"
        calibrate.DATA.mkdir()
        labels = ["genuine", "dye", "ketchup", "edta", "animal",
                  "deoxygenated", "null_cartridge", "empty"]
        for lab in labels:
            for seed in range(4):
                cap = calibrate.synth_capture(lab, seed)
                calibrate.save_capture(calibrate.DATA / f"{lab}_{seed:04d}.npz", cap)

        # npz round trip must be exact — a lossy capture format silently
        # changes what the thresholds were fitted to.
        one = calibrate.load_capture(calibrate.DATA / "genuine_0000.npz")
        ref = calibrate.synth_capture("genuine", 0)
        if evaluate(one).accepted != evaluate(ref).accepted:
            print("    capture round trip changed the verdict")
            return False

        import argparse
        cwd = Path.cwd()
        try:
            import os
            os.chdir(work)
            rc = calibrate.cmd_roc(argparse.Namespace(frr_budget=0.05, drift=0.0))
        finally:
            os.chdir(cwd)
        if rc != 0:
            return False

        out = work / "thresholds.json"
        if not out.exists():
            print("    roc did not write thresholds.json")
            return False
        th = Thresholds.load(out)
        if th == Thresholds():
            print("    thresholds.json loaded but changed nothing")
            return False
        if "calibrated" not in th.provenance(out):
            print("    provenance did not report the file")
            return False
        # And the calibrated thresholds must still separate the panel.
        for lab in labels:
            for seed in range(4):
                acc = evaluate(calibrate.synth_capture(lab, seed), th).accepted
                if acc != (lab == "genuine"):
                    print(f"    calibrated thresholds misclassify {lab}")
                    return False
    return True


def touch_calibration_round_trip() -> bool:
    """touch-capture -> touch-roc -> touch_thresholds.json -> load().

    The touch tier authorises far more signatures than the blood tier, so its
    calibration deserves the same guarantee: the numbers measured on your
    hardware are the numbers the device runs.
    """
    sys.path.insert(0, str(HERE))
    import calibrate                                       # noqa: E402
    import touch_gate as tg                                # noqa: E402
    import argparse, os                                    # noqa: E402

    with tempfile.TemporaryDirectory() as d:
        work = Path(d)
        calibrate.TOUCH_DATA = work / "touch_captures"
        calibrate.TOUCH_DATA.mkdir()
        th0 = tg.TouchThresholds()
        for lab in calibrate.TOUCH_PANEL:
            for seed in range(8):
                red, ir, bore = tg._synth(lab, seed, th0)
                calibrate.save_touch(calibrate.TOUCH_DATA / f"{lab}_{seed:04d}.npz",
                                     red, ir, bore, lab, th0.fs)
        cwd = Path.cwd()
        try:
            os.chdir(work)
            rc = calibrate.cmd_touch_roc(argparse.Namespace(frr_budget=0.05, drift=0.0))
        finally:
            os.chdir(cwd)
        if rc != 0:
            return False
        out = work / "touch_thresholds.json"
        if not out.exists():
            print("    touch-roc did not write touch_thresholds.json")
            return False
        th = tg.TouchThresholds.load(out)
        if th == tg.TouchThresholds():
            print("    touch_thresholds.json loaded but changed nothing")
            return False
        # The calibrated thresholds must still separate the panel. A threshold
        # that is also an analysis parameter breaks exactly here: it is fitted
        # under one detector and then judged under another.
        for lab in calibrate.TOUCH_PANEL:
            for seed in range(8):
                red, ir, bore = tg._synth(lab, seed, th0)
                acc = tg.evaluate(red, ir, bore, th, fs=th0.fs).accepted
                if acc != (lab == "genuine"):
                    print(f"    calibrated touch thresholds misclassify {lab}")
                    return False
    return True


def _pin_table(build_md: str) -> dict[int, str]:
    """{GPIO number: what BUILD.md says is on it}, from its own pin table.

    Handles every way that table writes a pin: `GPIO12`, `GPIO2/3`,
    `GPIO5, 13, 19`, `GPIO8-11` and `**GPIO26**`.
    """
    import re
    out: dict[int, str] = {}
    for ln in build_md.splitlines():
        if not ln.startswith("|"):
            continue
        cells = [c.strip().strip("*").strip() for c in ln.strip("|").split("|")]
        if len(cells) < 2 or not cells[0].upper().startswith("GPIO"):
            continue
        for part in re.split(r"[,/]", cells[0][4:]):
            part = part.strip()
            span = re.fullmatch(r"(\d+)\s*[\u2013-]\s*(\d+)", part)
            if span:
                for n in range(int(span.group(1)), int(span.group(2)) + 1):
                    out[n] = cells[1]
            elif part.isdigit():
                out[int(part)] = cells[1]
    return out


def _unixfs_cid(data: bytes) -> str:
    """The CIDv1 kubo gives this file: 256 KiB chunks, raw leaves, sha2-256.

    VALIDATION.md publishes the CID of the first-build frame so a reader can
    fetch it from IPFS rather than trusting this repository's copy. That is
    only worth anything while the two agree, and nothing else in the tree can
    notice if they stop. Recomputed here from the bytes on disk, with no
    dependency: UnixFS is a protobuf, and the two messages it needs are ten
    lines each.
    """
    import hashlib

    def varint(n: int) -> bytes:
        out = b""
        while True:
            b, n = n & 0x7F, n >> 7
            out += bytes([b | (0x80 if n else 0)])
            if not n:
                return out

    def blob(field: int, v: bytes) -> bytes:
        return varint(field << 3 | 2) + varint(len(v)) + v

    def num(field: int, v: int) -> bytes:
        return varint(field << 3) + varint(v)

    def cid(block: bytes, codec: int) -> bytes:
        return bytes([1, codec, 0x12, 0x20]) + hashlib.sha256(block).digest()

    chunks = [data[i:i + 262144] for i in range(0, len(data), 262144)]
    # Links (field 2) are serialised before Data (field 1), as go-merkledag
    # writes them; a link is hash, name and cumulative size.
    links = b"".join(
        blob(2, blob(1, cid(c, 0x55)) + blob(2, b"") + num(3, len(c)))
        for c in chunks)
    unixfs = num(1, 2) + num(3, len(data))          # Type = File, filesize
    unixfs += b"".join(num(4, len(c)) for c in chunks)
    root = cid(links + blob(1, unixfs), 0x70)

    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    bits = "".join(f"{b:08b}" for b in root)
    bits += "0" * (-len(bits) % 5)
    return "b" + "".join(alphabet[int(bits[i:i + 5], 2)]
                         for i in range(0, len(bits), 5))


def _docs_references_resolve(root) -> bool:
    """Every file, section and command the documentation names must exist.

    VALIDATION.md has claimed this for a while and nothing enforced it. Docs
    rot in a way code does not: a renamed script or a resectioned BUILD.md
    leaves a sentence that still reads correctly and sends somebody to a file
    that is not there. For a first builder following a runbook, that is the
    difference between a weekend and an evening.

    Three kinds of reference, all mechanical:
      `some/file.py`          must exist somewhere in the tracked tree
      BUILD.md section N      must be a section BUILD.md actually has
      python3 tool.py sub --f must name a script, a subcommand and flags the
                              script's own argparse offers
    """
    import re
    import subprocess

    ok = True
    docs = ["README.md", "BUILD.md", "VALIDATION.md", "PRINTING.md",
            "CONTRIBUTING.md", "BOUNTY.md", "SAFETY.md", "models/README.md"]
    tracked = set(subprocess.run(["git", "ls-files"], cwd=root,
                                 capture_output=True, text=True).stdout.split())
    if not tracked:                     # not a git checkout; nothing to check
        return True
    by_base: dict[str, list[str]] = {}
    for f in tracked:
        by_base.setdefault(f.rsplit("/", 1)[-1], []).append(f)

    # Written by the device or by calibration, so correctly absent from a
    # clean tree. Naming them is right; shipping them would not be.
    runtime = {"accounts.json", "chamber.npz", "thresholds.json",
               "touch_thresholds.json", "seed.blob", "SOFT-SE-INSECURE.json"}

    file_re = re.compile(
        r"`([A-Za-z0-9_./-]+\.(?:py|md|csv|json|stl|obj|svg|sol|service|txt|"
        r"yml|npz|html|js|gif|mp4|png))`")
    for d in docs:
        text = (root / d).read_text()
        for ref in sorted(set(file_re.findall(text))):
            base = ref.rsplit("/", 1)[-1]
            if base in runtime or ref in tracked:
                continue
            hits = by_base.get(base, [])
            if not hits:
                print(f"    {d} names {ref}, which does not exist")
                ok = False
            elif "/" in ref and not any(h.endswith(ref) for h in hits):
                print(f"    {d} names {ref}, which exists only as {hits[0]}")
                ok = False

    sections = {int(m.group(1)) for m in
                (re.match(r"^##\s+(\d+)\.", ln)
                 for ln in (root / "BUILD.md").read_text().splitlines())
                if m}
    # The section sign spelled as a character, not as \u00a7 -- this is a raw
    # string, so the escape would be six literal characters and the whole
    # alternative would never match. It didn't, and only the "section N"
    # spelling was ever checked.
    sec_re = re.compile("BUILD\\.md[, ]*(?:\u00a7|section\\s+)(\\d+)", re.I)
    for f in subprocess.run(["git", "ls-files", "*.py", "*.md", "*.sol", "*.js"],
                            cwd=root, capture_output=True,
                            text=True).stdout.split():
        for n in set(sec_re.findall((root / f).read_text(errors="ignore"))):
            if int(n) not in sections:
                print(f"    {f} points at BUILD.md section {n}, which does not exist")
                ok = False

    cmd_re = re.compile(r"^(?:python3?|py)\s+(\S+\.py)(.*)$")
    helps: dict[str, "str | None"] = {}
    for d in docs:
        for ln in (root / d).read_text().splitlines():
            line = ln.strip().lstrip("$ ").strip().split("#")[0].strip()
            m = cmd_re.match(line)
            if not m:
                continue
            script, rest = m.group(1), m.group(2).strip()
            hit = next((c for c in (script, f"firmware/{script}",
                                    f"tools/{script}", f"contracts/test/{script}")
                        if c in tracked), None)
            if hit is None:
                print(f"    {d} runs {script}, which does not exist")
                ok = False
                continue
            toks = rest.split()
            sub = toks[0] if toks and not toks[0].startswith("-") else None
            flags = [t for t in toks if t.startswith("--")]
            if not sub and not flags:
                continue
            if hit not in helps:
                r = subprocess.run([sys.executable, hit, "--help"], cwd=root,
                                   capture_output=True, text=True)
                # Only an argparse script can be introspected this way. The
                # self-testing modules have no parser and answer --help by
                # running their self-test, whose output says nothing about
                # flags -- so those fall back to reading the source.
                helps[hit] = r.stdout if r.stdout.lstrip().startswith("usage:") else None
            doc = helps[hit]
            src = (root / hit).read_text()
            if doc is None:
                for f_ in flags:
                    if f_ not in src:
                        print(f"    {d} passes {f_} to {script}, which does "
                              f"not mention it")
                        ok = False
                continue
            if sub and sub not in doc:
                print(f"    {d} runs `{script} {sub}`, which is not a subcommand")
                ok = False
            for f_ in flags:
                if f_ in doc:
                    continue
                subhelp = subprocess.run(
                    [sys.executable, hit] + ([sub] if sub else []) + ["--help"],
                    cwd=root, capture_output=True, text=True).stdout
                if f_ not in subhelp:
                    print(f"    {d} passes {f_} to `{script} {sub or ''}`.strip(), "
                          f"which does not offer it")
                    ok = False
    return ok


def docs_match_the_code() -> bool:
    """Counts quoted in the docs must equal counts the code actually has.

    Every one of these has drifted at least once: the panel gained a class and
    README kept the old number, the touch tier grew a seventh gate and its own
    banner still said six. A number in prose has no way to notice, so it gets
    checked here instead.
    """
    sys.path.insert(0, str(HERE))
    import calibrate                                       # noqa: E402
    import touch_gate as tg                                # noqa: E402
    from blood_gate import Thresholds                      # noqa: E402
    import attest, csv, re                                 # noqa: E402

    root = HERE.parent
    readme = (root / "README.md").read_text()
    validation = (root / "VALIDATION.md").read_text()
    build = (root / "BUILD.md").read_text()
    contributing = (root / "CONTRIBUTING.md").read_text()
    bounty = (root / "BOUNTY.md").read_text()

    n_blood = len(calibrate.PANEL)
    n_touch = len(tg.PANEL)
    n_bytes = attest.RECORD_LEN + attest.SIG_LEN
    ok = True

    def want(label, text, needle):
        nonlocal ok
        if needle not in text:
            print(f"    {label}: expected to find {needle!r}")
            ok = False

    def want_every(label, text, needle, n):
        """The same needle, where the document spells it more than once.

        `want` passes on one surviving copy, so a number quoted twice can go
        stale in one place and stay green -- which is how PRINTING.md could
        have carried two different screw lengths. Pin the count.
        """
        nonlocal ok
        got = text.count(needle)
        if got != n:
            print(f"    {label}: {needle!r} appears {got} times, expected {n}")
            ok = False

    # This runner's own suite labels, which nothing checked until one of them
    # spent a while claiming 17 classes for a panel of 18. A test runner that
    # misdescribes the test it is running is a small lie in the one place a
    # reader is most likely to trust.
    here = (root / "firmware" / "run_tests.py").read_text()
    want("run_tests blood label", here, f"6 gates, {n_blood} sample classes")
    want("run_tests touch label", here, f"7 gates, {n_touch} sample classes")

    want("README blood panel", readme, f"{n_blood} sample classes")
    want("VALIDATION blood panel", validation, f"{n_blood} sample classes")
    want("VALIDATION touch panel", validation, f"{n_touch} sample classes")
    want("README record size", readme, f"{n_bytes}-byte record")
    want("VALIDATION record size", validation, f"{n_bytes} bytes, exact")
    want("BUILD record size", build, f"{n_bytes} bytes, fits in a QR")

    # The BOM is what somebody spends money on. Its kit subtotals must equal
    # the figures the docs quote, to the cent.
    kits: dict[str, float] = {}
    with (root / "BOM.csv").open() as fh:
        for row in csv.DictReader(fh):
            kits[row["Kit"]] = kits.get(row["Kit"], 0.0) + float(row["Ext USD"] or 0)
    hw = kits.get("Reader", 0) + kits.get("Wallet", 0)
    allin = hw + kits["Reader consumable"]
    # BUILD.md quotes the exact subtotals; README rounds them for prose. Both
    # have to follow the same BOM, so both are checked against it.
    want("BUILD reader cost", build, f"${kits['Reader']:.2f}")
    want("BUILD consumables", build, f"${kits['Reader consumable']:.2f}")
    want("BUILD wallet cost", build, f"${kits['Wallet']:.2f}")
    want("BUILD hardware total", build, f"${hw:.2f}")
    want("BUILD all-in total", build, f"${allin:.2f}")
    # The full-device figure in the README's opening line. It went stale at $92
    # while the BOM said $94.40, because nothing checked it — the reader-kit
    # figures below were checked and stayed right.
    want("README full device cost", readme, f"${hw:.2f} of hardware")
    want("README reader cost", readme, f"${round(kits['Reader'])} of hardware")
    want("README consumables", readme, f"${round(kits['Reader consumable'])} of consumables")
    # CONTRIBUTING quotes the reader kit too, and was the one file this suite
    # did not read -- so it was the one file that went stale when the BOM
    # moved. Any document that names a price has to be checked against the
    # BOM, or it is only a matter of time.
    want("CONTRIBUTING reader cost", contributing,
         f"${round(kits['Reader'])} of hardware")
    # BOUNTY.md quotes both, and it is the document a stranger reads before
    # spending their own money. It went stale the moment the BOM moved,
    # because it was the one priced file this suite did not read.
    want("BOUNTY hardware cost", bounty, f"~${round(hw)} in hardware")
    want("BOUNTY consumables", bounty, f"~${round(kits['Reader consumable'])} in consumables")
    want("BOUNTY reader-only cost", bounty, f"${round(kits['Reader'])}")
    # Section 6's heading rounds and writes the currency differently, so the
    # exact-total checks above walked straight past it while it sat two
    # dollars stale. Prices get written more than one way; each way needs a
    # check or it is only the unchecked spelling that rots.
    want("BUILD section 6 heading", build,
         f"~US${round(hw)} complete, ~US${round(kits['Reader'])} for the reader alone")

    # How many suites this runner runs. Four documents quote the number and
    # all four were stale at once -- README said 33, VALIDATION said thirty,
    # BUILD said 32, CONTRIBUTING said five, and the runner ran 35. Nothing
    # checked it because the count lives in this file, which is the file a
    # reader is least likely to open and most likely to believe.
    # The pin map exists in THREE places: BUILD.md's table, which is what
    # somebody wires from; the firmware constants, which are what actually
    # drive the pin; and tools/gen_wiring.py, which draws the sheet. Nothing
    # tied them together, so a pin could move in one and stay put in the other
    # two -- and the failure is a laser that never lights, with no error
    # anywhere, on a bench, at the end of a build.
    import buttons, hardware                                # noqa: E402
    pins = _pin_table(build)
    wiring = (root / "tools" / "gen_wiring.py").read_text()
    for label, value, needle, in_sheet in (
        ("buttons.PIN_UP", buttons.PIN_UP, "UP", False),
        ("buttons.PIN_DOWN", buttons.PIN_DOWN, "DOWN", False),
        ("buttons.PIN_BACK", buttons.PIN_BACK, "BACK", False),
        ("buttons.PIN_CONFIRM", buttons.PIN_CONFIRM, "CONFIRM", False),
        ("hardware.PIN_LED2", hardware.PIN_LED2, "White LED", True),
        ("hardware.PIN_LASER", hardware.PIN_LASER, "Laser", True),
        ("hardware.PIN_IR", hardware.PIN_IR, "IR LED", True),
        ("hardware.PIN_CARTRIDGE", hardware.PIN_CARTRIDGE, "microswitch", True),
    ):
        row = pins.get(value)
        if row is None:
            print(f"    {label} is GPIO{value}, which BUILD.md's pin table "
                  f"does not list")
            ok = False
        elif needle.lower() not in row.lower():
            print(f"    {label} is GPIO{value}, but BUILD.md puts "
                  f"{row!r} there, not {needle!r}")
            ok = False
        if in_sheet and f'"GPIO{value}"' not in wiring:
            print(f"    {label} is GPIO{value}, which the wiring sheet "
                  f"(tools/gen_wiring.py) does not draw")
            ok = False

    # The I2C addresses a builder checks with i2cdetect.
    import se_atecc                                          # noqa: E402
    want("BUILD i2c address of the secure element", build,
         f"{se_atecc.I2C_ADDRESS:#04x}".replace("0x", "0x"))

    # The IPFS pointer beside the first-build frame, against the frame itself.
    frame = root / "diagrams" / "first-build.png"
    if frame.exists():
        want("VALIDATION first-build frame CID", validation,
             _unixfs_cid(frame.read_bytes()))

    # Every gate table in BUILD.md, against the dataclass the device compares
    # against. These are the numbers a builder reads to understand what the
    # device will reject, and they are the numbers calibration moves, so they
    # are exactly the kind that goes stale in prose and nowhere else. T5's
    # floor was raised from 5 ms to 15 after a synthetic metronome walked
    # through it (VALIDATION.md); the table kept 5 for as long as nothing read
    # it. Every row below is spelled the way BUILD.md spells it, because a
    # check on a different spelling is a check on nothing.
    b, tt = Thresholds(), tg.TouchThresholds()
    for label, needle in (
            ("G1", f"window**, {b.return_min}\u2013{b.return_max} of the white patch"),
            ("G2", f"NIR/Clear \u2265 {b.nir_scatter_min}"),
            ("G3", f"(R630\u2212R415)/(R630+R415) \u2265 {b.soret_index_min}"),
            ("G4", f"SAM cosine \u2265 {b.sam_cos_min}"),
            ("G5", f"`D(early) \u2265 {b.d_liquid_min:.2f}`, speckle contrast"),
            ("G6", f"`D(late) \u2264 {b.d_clot_max:.2f}`, drop \u2265 "
                   f"{b.d_drop_min:.2f}, \u03c1 \u2264 \u2212{-b.monotone_rho_max:.2f}"),
            ("T0", f"sample rate \u2265 {tt.fs_min:.0f} Hz"),
            ("T1", f"DC level {tt.dc_min * 100:.0f}\u2013{tt.dc_max * 100:.0f}%"),
            ("T2", f"Perfusion index {tt.perfusion_min * 100:.1f}\u2013"
                   f"{tt.perfusion_max * 100:.0f}%"),
            ("T3", f"frequency {tt.bpm_min:.0f}\u2013{tt.bpm_max:.0f} bpm"),
            ("T4", f"\u2265{tt.band_snr_min * 100:.0f}% of band power"),
            ("T5", f"RMSSD {tt.rmssd_min_ms:.0f}\u2013{tt.rmssd_max_ms:.0f} ms"),
            ("T6", f"ratio-of-ratios {tt.r_ratio_min:.2f}\u2013{tt.r_ratio_max:.2f}"),
            # Section 3 restates the motion gates in its own words before
            # section 7 tabulates them. Both spellings are checked, because a
            # needle that matches either one passes while the other goes stale.
            ("G5 restated", f"moving freely?** `D(early) \u2265 {b.d_liquid_min:.2f}`"),
            ("G6 restated", f"Did it stop?** `D(late) \u2264 {b.d_clot_max:.2f}`"),
            ("G6 trend restated",
             f"drop `\u2265 {b.d_drop_min:.2f}`, Spearman \u03c1 "
             f"`\u2264 \u2212{-b.monotone_rho_max:.2f}`"),
            ("capture length", f"**{b.duration_s:.0f} s** window"),
            ("early window", f"first {b.early_window_s:.0f} s"),
    ):
        want(f"BUILD {label} threshold", build, needle)

    # The itemised kit tables, not only the totals under them. The total-string
    # checks above pass on a table whose own rows add up to something else,
    # which is how the wallet kit came to list $35.30 of parts under a $34.70
    # heading. Sum the rows instead.
    def table_total(section: str, stop: str) -> float:
        body = build[build.index(section):]
        body = body[:body.index(stop)]
        total = 0.0
        for line in body.splitlines():
            cells = [c.strip() for c in line.split("|")]
            for c in cells[2:]:
                if re.fullmatch(r"\d+(?:\.\d+)?", c):
                    total += float(c)
                    break
        return round(total, 2)

    for label, section, stop, subtotal in (
            ("reader kit", "### Kit 1.", "Plus the reader consumables", kits["Reader"]),
            ("wallet kit", "### Kit 2,", "The signing firmware", kits["Wallet"]),
            ("section 6 parts", "## 6. Parts", "**Consumables:**", hw)):
        got = table_total(section, stop)
        if abs(got - subtotal) > 0.005:
            print(f"    BUILD's {label} table adds up to ${got:.2f}, but the "
                  f"BOM says ${subtotal:.2f}")
            ok = False

    # How many parts come out of gen_printables. README quoted ten while the
    # generator wrote eleven, because the count lives in a directory listing
    # and no sentence can notice one more file appearing beside it.
    n_print = len(list((root / "models" / "print").glob("*.stl")))
    word = {9: "Nine", 10: "Ten", 11: "Eleven", 12: "Twelve",
            13: "Thirteen"}.get(n_print, str(n_print))
    want("README printable count", readme, f"{word.lower()} printable STLs")
    want("README printed parts", readme, f"{word} parts are printed")
    want("PRINTING printed parts", (root / "PRINTING.md").read_text(),
         f"{word} parts.")

    # The screw that holds the case shut. It enters from the base and has to
    # cross the part line to reach an insert in the upper shell, so its length
    # is derived geometry rather than a preference -- and BUILD.md carried
    # M2.5x8, which stops 1 mm short of the part line and never enters the
    # insert at all. check_fit() proves the length; these are the documents a
    # builder actually orders from.
    sys.path.insert(0, str(root / "tools"))
    import gen_enclosure as enc                             # noqa: E402
    n_screw = f"{enc.SCREW_LEN:.0f}"
    want("BUILD screw length", build, f"M2.5\u00d7{n_screw}")
    want_every("PRINTING screw length", (root / "PRINTING.md").read_text(),
               f"M2.5 \u00d7 {n_screw}", 2)
    want("BOM screw length", (root / "BOM.csv").read_text(), f"M2.5x{n_screw}")

    # The switch bodies the deck is drilled for, against the ones the BOM
    # buys. gen_enclosure.check_fit() proves BUTTON_BODY fits the pitch; this
    # proves somebody ordering from BOM.csv ends up holding those parts. The
    # BOM used to buy four 12 mm switches for a deck whose three navigation
    # positions are 11 mm apart, where they foul each other and no cap of
    # theirs passes the 6.3 mm hole.
    bom = (root / "BOM.csv").read_text()
    for cap, body in sorted(enc.BUTTON_BODY.items()):
        n = sum(1 for _, d in enc.BUTTONS if d == cap)
        if f"{body:.0f}mm tactile" not in bom:
            print(f"    the deck has {n} button(s) needing a {body:.0f} mm "
                  f"switch body (\u00d8{cap} cap), and BOM.csv does not buy one")
            ok = False

    if not _docs_references_resolve(root):
        ok = False

    n_suites = len(SUITES) + len(IN_PROCESS)
    want("README suite count", readme, f"{n_suites} suites")
    want("VALIDATION suite count", validation, f"{n_suites} suites")
    want("BUILD suite count", build, f"{n_suites} suites")
    want("CONTRIBUTING suite count", contributing, f"{n_suites} suites")
    return ok


def schnorr_implementations_agree() -> bool:
    """attest.py carries its own BIP-340 so it can be audited standalone.

    Two copies of a signature scheme is a maintenance hazard: they can drift,
    and the drift shows up as an attestation nobody can verify. This pins them
    together, which is cheaper than merging them and keeps attest.py readable
    on its own.
    """
    sys.path.insert(0, str(HERE))
    import hashlib
    import attest
    import secp256k1

    for i in range(8):
        sk = hashlib.sha256(bytes([i])).digest()
        msg = hashlib.sha256(b"agree" + bytes([i])).digest()
        if attest.schnorr_pubkey(sk) != secp256k1.schnorr_pubkey(sk):
            print("    the two BIP-340 implementations disagree on a pubkey")
            return False
        a = attest.schnorr_sign(msg, sk)
        b = secp256k1.schnorr_sign(msg, sk)
        if a != b or not secp256k1.schnorr_verify(msg, attest.schnorr_pubkey(sk), a):
            print("    the two BIP-340 implementations disagree on a signature")
            return False
    return True


def prose_stays_flat() -> bool:
    """The reference documents are held to a cadence budget.

    docs_match_the_code() checks the numbers. This checks the prose, for the
    one failure that keeps recurring: a build document written in the voice of
    a pitch. tools/prose_lint.py owns the budgets and the reasoning.
    """
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "prose_lint", HERE.parent / "tools" / "prose_lint.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    ok, lines = mod.check()
    for line in lines:
        print(f"  {line}")
    if ok:
        print("  every document inside its budget, no banned phrases")
    return ok


# The checks that need to run in-process rather than as a subprocess.
# Counted rather than hardcoded, so adding one cannot leave the summary line
# quietly claiming a number it no longer runs. At module scope because
# docs_match_the_code() counts it: the suite total appears in four documents
# and drifted in all four at once.
IN_PROCESS = [
    ("BIP-340 — attest.py and secp256k1.py agree", schnorr_implementations_agree),
    ("calibration round trip — capture, sweep, load", calibration_round_trip),
    ("docs match the code — counts, record size, BOM totals", docs_match_the_code),
    ("prose stays flat — tic budgets and banned phrases", prose_stays_flat),
    ("touch calibration round trip — capture, sweep, load",
     touch_calibration_round_trip),
]


# The third-party packages the sensing and seed-store suites import. Checked
# up front because without them ten suites fail on import, and a bare "FAIL --
# 10 suite(s)" reads as a broken repository to the one audience that matters
# here: somebody who just cloned this to build the hardware. It is a missing
# dependency, and the runner should say so rather than leave them bisecting.
REQUIRED = [("numpy", "the gate maths"), ("scipy", "the gate maths"),
            ("cryptography", "the seed store")]


def _preflight() -> bool:
    import importlib.util
    missing = [(m, why) for m, why in REQUIRED
               if importlib.util.find_spec(m) is None]
    if not missing:
        return True
    print("=" * 66)
    print("MISSING DEPENDENCIES — this is not a regression.\n")
    for m, why in missing:
        print(f"  {m:<16}{why}")
    print("\n  python3 -m pip install -r firmware/requirements.txt\n")
    print("  On Raspberry Pi OS, Debian and current macOS, pip refuses to")
    print("  install into the system interpreter (PEP 668). Either use the")
    print("  packaged builds:\n")
    print("      sudo apt install python3-numpy python3-scipy "
          "python3-cryptography\n")
    print("  or a virtual environment:\n")
    print("      python3 -m venv .venv && . .venv/bin/activate")
    print("      pip install -r firmware/requirements.txt\n")
    print("  The signing stack itself is pure Python and needs none of this;")
    print("  run any of firmware/test_curve.py, test_wallet.py or tx.py")
    print("  directly to exercise it without installing anything.")
    print("=" * 66)
    return False


def main() -> int:
    if not _preflight():
        return 1
    failures = []
    for name, cmd in SUITES:
        print(f"\n=== {name} " + "=" * max(0, 60 - len(name)))
        r = subprocess.run(cmd, cwd=HERE)
        if r.returncode != 0:
            failures.append(name)

    for name, fn in IN_PROCESS:
        print(f"\n=== {name} " + "=" * max(0, 60 - len(name)))
        try:
            good = fn()
        except Exception as e:                               # noqa: BLE001
            print(f"    raised {type(e).__name__}: {e}")
            good = False
        print("PASS" if good else "FAIL")
        if not good:
            failures.append(name)

    print("\n" + "=" * 66)
    if failures:
        print(f"FAIL — {len(failures)} suite(s):")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"PASS — {len(SUITES) + len(IN_PROCESS)} suites.")
    print("\nSigning stack, unlock chain, gate logic, tier policy,")
    print("attestation and the calibration round trip all verified against")
    print("published test vectors. Sensing thresholds are calibrated to your")
    print("hardware at first build — BUILD.md section 13. The ATECC608B")
    print("itself is unverified until you run `python3 firmware/se_atecc.py")
    print("--probe` on a built device; VALIDATION.md tracks that.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
