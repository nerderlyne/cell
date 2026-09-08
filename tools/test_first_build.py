#!/usr/bin/env python3
"""The sequence a first builder actually types, driven end to end.

Every other suite tests a module. This one tests the RUNBOOK: it runs
`tools/provision.py` as a subprocess exactly as BUILD.md section 12 says to,
then boots `app.load_device` against the directory those commands wrote and
signs with it. Nothing here mocks the tools.

That seam had no coverage at all, and three defects were living in it:

    the boot path ignored the network in the record, so a device provisioned
    for testnet came up as mainnet, found none of its own accounts, and
    answered RECEIVE with "no account"

    registering a quorum defaulted to mainnet rather than to the network the
    device was on, and refused with a message blaming the xpub -- the one
    part that was correct

    the software secure element drew a fresh secret on every invocation, so
    `enroll-chamber --soft` could not open the seed `new --soft` had written.
    Enrolment is the one step with no way back except the words, and it was
    the one step nobody could practise

None of them could fail a unit test, because no unit test ran two commands in
a row against one directory.

Runs on the --soft path, so it proves the flow and nothing about the chip.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "firmware"))
sys.path.insert(0, str(ROOT / "tools"))

PIN = "12345678"
NETWORK = "testnet"
# A known mnemonic, so the rehearsal can rebuild the same keys the device did
# and hand it a PSBT it should be able to sign.
MNEMONIC = ("abandon abandon abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon about")

FAILURES: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {label:<56}{'PASS' if ok else 'FAIL'}"
          + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILURES.append(label)


def run(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    """One provision.py invocation, the way the runbook writes it."""
    return subprocess.run(
        [sys.executable, str(ROOT / "tools" / "provision.py"), *args],
        input=stdin, capture_output=True, text=True)


def _burst(size: int = 768, grain: int = 4, frames: int = 4, seed: int = 0,
           drift: float = 0.0):
    """A raw speckle burst, the shape hardware.read_chamber_burst returns.

    Raw rather than prepared: `enroll-chamber --from` runs optical_puf.prepare
    over what it loads, so handing it an already-prepared image would exercise
    a path the device never takes.
    """
    import numpy as np
    rng = np.random.default_rng(seed)
    base = np.random.default_rng(1234)
    def field(r):
        e = r.normal(size=(size, size)) + 1j * r.normal(size=(size, size))
        fy = np.fft.fftfreq(size)[:, None]
        fx = np.fft.fftfreq(size)[None, :]
        env = np.exp(-0.5 * (fy ** 2 + fx ** 2) * (2 * np.pi * grain) ** 2)
        return np.fft.ifft2(np.fft.fft2(e) * env)
    E = field(base)
    if drift:
        E = np.sqrt(1 - drift) * E + np.sqrt(drift) * field(rng)
    inten = np.abs(E) ** 2
    inten = inten / inten.mean()
    return inten[None, ...] + rng.normal(0, 0.02, (frames, size, size))


def main() -> int:
    import numpy as np

    import addresses
    import bip32
    import app
    import wallet
    from policy import Policy
    from tx import Transaction, TxIn, TxOut, ser_compact
    import psbt as psbtmod
    import provision as tool

    work = pathlib.Path(tempfile.mkdtemp(prefix="cell-firstbuild-"))
    d = work / "boot-cell"

    print("Runbook rehearsal — tools/provision.py, then the device it wrote\n")

    # ---- 1. restore a wallet, on testnet -------------------------------
    print(" provisioning")
    r = run("import", "--out", str(d), "--pin", PIN, "--soft",
            "--network", NETWORK, stdin=MNEMONIC + "\n")
    check("provision.py import runs", r.returncode == 0, r.stderr[-200:])
    check("...and verifies the seed reopens", "seed re-read and verified" in r.stdout)
    check("...and writes both files",
          (d / tool.BLOB).exists() and (d / tool.ACCOUNTS).exists())
    check("...and a soft-SE secret, so a second command sees the same chip",
          (d / tool.SOFT_SE).exists())

    rec = json.loads((d / tool.ACCOUNTS).read_text())
    check("the record names the network it was provisioned for",
          rec.get("network") == NETWORK, str(rec.get("network")))
    check("...and every account is filed under it",
          {a["network"] for a in rec["accounts"]} == {NETWORK, "ethereum"})

    r = run("show", "--dir", str(d))
    check("provision.py show runs", r.returncode == 0, r.stderr[-200:])
    check("...and prints the master fingerprint",
          rec["master_fingerprint"] in r.stdout)

    # ---- 2. register a chain and a quorum ------------------------------
    print("\n registration")
    r = run("chain", "--dir", str(d), "--id", "42161",
            "--name", "Arbitrum One", "--ticker", "ETH")
    check("provision.py chain runs", r.returncode == 0, r.stderr[-200:])
    check("...and the registration survives in the record",
          any(c["chain_id"] == 42161
              for c in json.loads((d / tool.ACCOUNTS).read_text())["chains"]))

    # A token, which is the other thing BUILD.md section 12 tells a builder to
    # register. It has to come AFTER the chain it lives on, and the ordering is
    # a real constraint rather than a stylistic one -- register_token refuses a
    # token on a chain the device cannot name.
    USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
    r = run("token", "--dir", str(d), "--chain-id", "42161",
            "--address", USDC, "--symbol", "USDC", "--decimals", "6")
    check("provision.py token runs", r.returncode == 0, r.stderr[-200:])
    check("...and reads the screen back to the builder",
          "SEND USDC ON ARBITRUM ONE" in r.stdout)
    check("...and says what the decimals mean, in units",
          "250000000" in r.stdout)
    check("...and the token survives in the record",
          any(t["symbol"] == "USDC" and t["decimals"] == 6
              for t in json.loads((d / tool.ACCOUNTS).read_text())["tokens"]))
    r_bad = run("token", "--dir", str(d), "--chain-id", "999999",
                "--address", USDC, "--symbol", "USDC", "--decimals", "6")
    check("...and a token on an unregistered chain is refused",
          r_bad.returncode != 0 and "Register the chain first" in r_bad.stdout)
    r_re = run("token", "--dir", str(d), "--chain-id", "42161",
               "--address", USDC, "--symbol", "USDC", "--decimals", "18")
    check("...and its decimal point cannot be moved afterwards",
          r_re.returncode != 0 and "refusing to relabel" in r_re.stdout)

    root = bip32.from_mnemonic(MNEMONIC)
    ms_path = wallet.multisig_account_path("multisig-p2wsh", 0, NETWORK)
    mine = [a for a in rec["accounts"] if a["script_type"] == "multisig-p2wsh"][0]
    lines = [f"thisdevice {rec['master_fingerprint']} {mine['path']} {mine['xpub']}"]
    for name, tag in (("alice", b"\x01"), ("bob", b"\x02")):
        import bip39
        other = bip32.from_mnemonic(bip39.entropy_to_mnemonic(tag * 32))
        lines.append(f"{name} {other.fingerprint().hex()} {ms_path} "
                     f"{other.derive(ms_path).neutered().serialize('xpub')}")
    cos = work / "cosigners.txt"
    cos.write_text("\n".join(lines) + "\n")

    # DELIBERATELY without --network. A builder on testnet forgets it, and the
    # refusal used to blame the xpub rather than name the network.
    r = run("multisig", "--dir", str(d), "--label", "treasury",
            "--threshold", "2", "--cosigners", str(cos))
    check("provision.py multisig defaults to the device's own network",
          r.returncode == 0, (r.stdout + r.stderr)[-220:])

    # And an explicit WRONG network still refuses, saying which.
    r_bad = run("multisig", "--dir", str(d), "--label", "wrong",
                "--threshold", "2", "--cosigners", str(cos),
                "--network", "mainnet")
    check("...and an explicitly wrong one is refused by name",
          r_bad.returncode != 0 and "mainnet" in r_bad.stdout)

    # ---- 2b. register a smart account, the way BUILD.md §12 writes it ----
    #
    # Driven as a subprocess for the same reason the commands above are: the
    # defects this file has found were all in the seams between one command
    # and the next against one directory, and none of them was reachable from
    # a unit test. The EVM side had never been driven this way at all.
    print("\n smart account")
    r = run("show", "--dir", str(d))
    evm = next((ln.split()[-1] for ln in r.stdout.splitlines()
                if "ethereum address" in ln), "")
    check("provision.py show prints the device's own EVM address",
          evm.startswith("0x") and len(evm) == 42, evm)

    IMPL = "0xD54cb65224410F3Ff97a8E72f363f224419f4FB0"
    EXEC = "0x00000000a72A30AdBf38e14d36BCE2610ec3973F"
    BOB = "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
    r = run("smart-account", "--dir", str(d), "--label", "treasury",
            "--address", "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
            "--chain-ids", "1,8453", "--implementation", IMPL,
            "--implementation-label", "Multisig v1",
            "--threshold", "2", "--owners", f"{evm},{BOB}",
            "--delay", "172800", "--executor", EXEC, "--fast-track")
    check("provision.py smart-account registers across two chains",
          r.returncode == 0, (r.stdout + r.stderr)[-260:])
    check("...and states the timelock it will put on the screen",
          "HELD 2d after relay" in r.stdout, r.stdout[-200:])

    # The check the EVM side never had: a quorum this device is not in.
    r_no = run("smart-account", "--dir", str(d), "--label", "notmine",
               "--address", "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
               "--chain-ids", "1", "--implementation", IMPL,
               "--threshold", "1", "--owners", BOB)
    check("...and refuses an account this device is not an owner of",
          r_no.returncode != 0 and "not among the owners" in r_no.stdout,
          (r_no.stdout + r_no.stderr)[-200:])

    # --delegated-eoa with no --address takes the device's own, which is the
    # only address a 7702 authorisation from this device can ever delegate.
    r_del = run("smart-account", "--dir", str(d), "--label", "mine",
                "--chain-ids", "1", "--implementation", IMPL,
                "--implementation-label", "Multisig v1",
                "--owners", evm, "--delegated-eoa")
    check("--delegated-eoa defaults to this device's own address",
          r_del.returncode == 0 and evm in r_del.stdout,
          (r_del.stdout + r_del.stderr)[-220:])

    # verify-account against a dump that agrees, and one that does not.
    good = work / "state-good.json"
    good.write_text(json.dumps({
        "owners": [evm, BOB], "threshold": 2, "delay": 172800,
        "executor": EXEC, "forwardEnabled": True, "implementation": IMPL}))
    r_v = run("verify-account", "--dir", str(d), "--label", "treasury",
              "--state", str(good))
    check("verify-account passes a dump that matches the record",
          r_v.returncode == 0 and "DIFFER" not in r_v.stdout,
          r_v.stdout[-260:])

    bad = work / "state-bad.json"
    bad.write_text(json.dumps({
        "owners": [BOB], "threshold": 1, "delay": 0,
        "executor": "0x" + "0" * 40, "forwardEnabled": False,
        "implementation": IMPL}))
    r_v2 = run("verify-account", "--dir", str(d), "--label", "treasury",
               "--state", str(bad))
    check("...and fails the 7702 init attack: owners swapped under the record",
          r_v2.returncode != 0 and "is NOT an owner on chain" in r_v2.stdout,
          r_v2.stdout[-300:])
    check("...naming the timelock that is not there either",
          "delay" in r_v2.stdout and "DIFFER" in r_v2.stdout)

    # ---- 3. boot the device the runbook just built ----------------------
    print("\n boot")
    dev = app.load_device(str(d), console=True)
    check("app.load_device boots from the written record", dev is not None)
    check("...on the network the record names", dev.network == NETWORK,
          dev.network)
    check("...and the registered chain reached the signing module",
          42161 in __import__("eth").CHAINS)
    check("...and the registered token with it",
          __import__("eth").token_of(42161, USDC) == ("USDC", 6))
    check("...and the quorum came back with it", len(dev.prov.multisig) == 1)

    out = dev.show_address()
    addr = next((ln.strip() for ln in dev.display.last if ln.strip().startswith("tb1")), "")
    check("RECEIVE shows a testnet address", out == "address" and addr.startswith("tb1"),
          f"{out} {addr}")

    # The export, from the record the runbook actually wrote rather than from
    # a Provisioning this test built. A testnet device must declare testnet in
    # every exported key, or a coordinator watches mainnet addresses that do
    # not exist and shows the owner nothing.
    import ur                                                  # noqa: E402
    body = dev.prov.account_export()
    item, rest = ur.cbor_decode(body)
    check("the record can be exported as a crypto-account",
          not rest and item.tag == ur.TAG_ACCOUNT
          and item.value[1] == int.from_bytes(
              dev.prov.master_fingerprint, "big"))
    keys = []
    # `desc`, not `d`: `d` is this test's provisioning directory, and rebinding
    # it here left `tool.load(d)` further down dividing a CBOR tag by a string.
    for desc in item.value[2]:
        inner = desc.value
        while isinstance(inner, ur.Tag):
            inner = inner.value
        keys.append(inner)
    check("...with a descriptor for every Bitcoin account",
          len(keys) == len([a for a in dev.prov.accounts
                            if a.script_type in ur.SCRIPT_EXPRESSIONS]))
    check("...every one of them declaring testnet",
          all(k[5].value[2] == ur.NETWORK_TESTNET for k in keys))
    check("...and it reassembles from its own UR frames",
          ur.reassemble(ur.encode(body, "crypto-account",
                                  max_fragment_len=80)) == body)

    # ---- 4. sign with it ------------------------------------------------
    print("\n signing")
    prov = tool.load(d)
    acct = root.derive(wallet.account_path("p2wpkh", 0, NETWORK))
    n0, ch = acct.derive([0, 0]), acct.derive([1, 0])
    spk = addresses.p2wpkh_script(n0.pubkey)
    parent = Transaction(2, [TxIn(b"\x77" * 32, 0)], [TxOut(200_000, spk)], 0)
    dest = addresses.script_to_address(
        addresses.p2wpkh_script(ch.pubkey), NETWORK)
    unsigned = Transaction(2, [TxIn(parent.txid(), 0)], [
        TxOut(150_000, addresses.address_to_script(dest, NETWORK)),
        TxOut(45_000, addresses.p2wpkh_script(ch.pubkey))], 0)
    p = psbtmod.PSBT(unsigned)
    kv = lambda t, e=b"": bytes([t]) + e
    p.globals[kv(psbtmod.GLOBAL_UNSIGNED_TX)] = unsigned.serialize(witness=False)
    p.inputs[0][kv(psbtmod.IN_NON_WITNESS_UTXO)] = parent.serialize()
    base = bip32.parse_path(wallet.account_path("p2wpkh", 0, NETWORK))
    origin = lambda tail: root.fingerprint() + b"".join(
        i.to_bytes(4, "little") for i in base + tail)
    p.inputs[0][kv(psbtmod.IN_BIP32_DERIVATION, n0.pubkey)] = origin([0, 0])
    p.outputs[1][kv(psbtmod.OUT_BIP32_DERIVATION, ch.pubkey)] = origin([1, 0])

    import hashlib
    signed = wallet.sign_psbt(
        p.serialize(), prov, __import__("se").SoftSE(
            pin=PIN, secret=tool._soft_secret(d)),
        Policy(), hashlib.sha256(b"fw").digest(), hashlib.sha256(b"cal").digest(),
        confirm=lambda lines: True,
        run_gate=lambda tier: (True, {"gate_scores": {}}),
        pin=PIN, network=NETWORK)
    check("the record the runbook wrote can sign a PSBT",
          signed.signatures == 1, str(signed.signatures))
    check("...and the change it derived is shown as its own",
          any("your wallet" in ln for ln in signed.display))

    # ---- 5. the irreversible step, rehearsed ---------------------------
    print("\n chamber enrolment (the step with no way back)")
    bursts = work / "bursts"
    bursts.mkdir()
    for i in range(3):
        np.save(bursts / f"read_{i}.npy", _burst(seed=i, drift=0.01 * i))
    blob_before = (d / tool.BLOB).read_bytes()
    r = run("enroll-chamber", "--dir", str(d), "--pin", PIN, "--soft",
            "--network", NETWORK, "--from", str(bursts))
    check("enroll-chamber runs on the rehearsal path",
          r.returncode == 0, (r.stdout + r.stderr)[-220:])
    check("...and writes the helper beside the seed", (d / tool.CHAMBER).exists())
    # Against what was there BEFORE. `!= b""` passed if enrolment had written
    # nothing at all, which is the failure this step exists to catch: the
    # helper on disk and the blob still wrapped under the old key.
    check("...and re-wraps the seed store",
          (d / tool.BLOB).read_bytes() not in (b"", blob_before))

    dev2 = app.load_device(str(d), console=True)
    check("the enrolled device boots and wires a chamber reader",
          dev2.read_chamber is not None)

    # And on a laptop the chamber cannot be READ -- which must not be reported
    # as tampering. This is the message a rehearsing builder actually meets.
    import signer as signer_mod
    try:
        dev2.read_chamber()
        got = "no error"
    except signer_mod.ChamberUnavailable as e:
        got = f"ChamberUnavailable: {e}"
    except Exception as e:                                      # noqa: BLE001
        got = f"{type(e).__name__}: {e}"
    check("a chamber that cannot be read says so, not 'restore from your words'",
          got.startswith("ChamberUnavailable"), got[:80])

    print("\n" + "-" * 66)
    if FAILURES:
        print(f"FAIL — {len(FAILURES)}:")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("PASS — the documented sequence works, end to end, on the soft path.")
    print("\nThis says the runbook is consistent with the code. It says nothing")
    print("about the chip, the sensors or the panel — VALIDATION.md tracks those.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
