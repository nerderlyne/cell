#!/usr/bin/env python3
"""Hostile bytes, at every point they can enter the device.

There is no wifi and no bluetooth, and on the shipped build no USB data path
either, so everything this device learns about the world arrives as pixels
through a lens. That makes the parsers the whole input attack surface, and it
means the interesting question is not "does a valid PSBT work" -- other suites
answer that -- but "what does an INVALID one do".

The property under test is narrow and checkable: every entry point may refuse,
and may only refuse in the ways it has declared. A parser that raises
something outside its own contract escapes the `except` clauses written around
it, and app.py's answer to an unexpected type is the "internal error" screen --
which is the traceback this design says a refusal must never be.

Two shapes of input, because they reach different code:

  FLAT     random and mutated bytes at each entry point. Finds the shallow
           failures -- a JSON document that is not an object, a length prefix
           that runs off the end.
  STRUCTURED  valid PSBTs of each script type, then bytes flipped inside them.
           This is the one that matters. Random bytes bounce off the magic
           number; a mutated valid PSBT gets all the way into summarize(),
           the change verification and the renderer, which is where the
           host-supplied fields actually get read.

Deterministic: one fixed seed, so a failure here is reproducible rather than a
thing that happened once on somebody's laptop.
"""

from __future__ import annotations

import random
import sys

import addresses
import app
import attest
import bip32
import eth
import ops
import psbt as psbtmod
import link
import qr
import ur
import secp256k1 as ec
import seedstore
import tx as txmod
import wallet
from tx import Transaction, TxIn, TxOut, ser_compact

SEED = 20260826
FLAT_N = 1500
STRUCTURED_N = 6000

MNEMONIC = "abandon " * 11 + "about"
FAILURES: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {label:<56}{'PASS' if ok else 'FAIL'}")
    if not ok and detail:
        print(f"      {detail}")
    if not ok:
        FAILURES.append(label)


def _mutate(rng: random.Random, b: bytes) -> bytes:
    out = bytearray(b)
    for _ in range(rng.randint(1, 6)):
        if not out or rng.random() < 0.3:
            out += bytes(rng.randrange(256) for _ in range(rng.randint(1, 40)))
        else:
            i = rng.randrange(len(out))
            r = rng.random()
            if r < 0.4:
                out[i] ^= 1 << rng.randrange(8)
            elif r < 0.7:
                out[i] = rng.randrange(256)
            else:
                del out[i:i + rng.randint(1, 8)]
    return bytes(out)


def flat_entry_points() -> None:
    """Each parser against noise, holding it to the exceptions it declares."""
    rng = random.Random(SEED)
    seeds = [b"", b"psbt\xff", b"psbt\xff\x01\x00", b"{}", b"4", b"[]", b"null",
             b'{"type":"cell-eth-tx"}', bytes(range(256)), b"\x00" * 64,
             b"\xff" * 64,
             # Seeds shaped like the newer entry points, so the mutator starts
             # from something that gets past the first character check rather
             # than bouncing off it.
             b'{"type":"cell-token-tx"}', b"ur:bytes/aeadaolazmjendeoti",
             b"ur:crypto-psbt/1-9/lpadascfadaxcywenbpljkhdcahkadae",
             b"cell1 cHNidP8BAHECAAAAAf==", b"cell1 ", b"ur:",
             ur.encode(b"a payload that is long enough to be split", "bytes",
                       max_fragment_len=12)[0].encode(),
             ur.encode_eth_sign_request(bytes(16), bytes.fromhex(
                 "02f0010984773594008506fc23ac008252089435353535353535353535"
                 "35353535353535353535880de0b6b3a764000080c0"), 2,
                 "m/44h/60h/0h/0/0", chain_id=1),
             eth.EthTransaction(
                 chain_id=1, nonce=9, max_priority_fee_per_gas=1,
                 max_fee_per_gas=2, gas_limit=21000,
                 to="0x3535353535353535353535353535353535353535",
                 value=1).signing_payload()]

    targets = {
        "PSBT.parse": (psbtmod.PSBT.parse,
                       (psbtmod.BadPSBT, txmod.BadTransaction, ValueError)),
        "Transaction.parse": (txmod.Transaction.parse,
                              (txmod.BadTransaction, ValueError)),
        # classify() takes anything and answers a string. It is the first thing
        # camera bytes meet, so it may not raise at all.
        "app.classify": (app.classify, ()),
        "app.parse_eth_request": (app.parse_eth_request,
                                  (ValueError, eth.BadEthTransaction,
                                   addresses.BadAddress, UnicodeDecodeError)),
        "qr.Collector.feed": (lambda d: qr.Collector().feed(d.decode("latin-1")),
                              (qr.BadFrame, ValueError)),
        # The other framing, which has considerably more surface than pNofM:
        # bytewords, CBOR, a part header, and fountain indexes derived from
        # attacker-chosen numbers. All of it reachable from the camera.
        "ur.Collector.feed": (lambda d: ur.Collector().feed(d.decode("latin-1")),
                              (ur.BadUR, ValueError)),
        "ur.parse": (lambda d: ur.parse(d.decode("latin-1")),
                     (ur.BadUR, ValueError)),
        "ur.cbor_decode": (ur.cbor_decode, (ur.BadUR, ValueError)),
        "app.parse_token_request": (app.parse_token_request,
                                    (ValueError, eth.BadEthTransaction,
                                     addresses.BadAddress, UnicodeDecodeError)),
        # The USB variant's framing. Off on the shipped build, and fuzzed
        # anyway: a variant nobody fuzzes is a variant with the soft spots.
        "link.decode_message": (link.decode_message,
                                (link.BadMessage, ValueError)),
        # EIP-4527. A tagged CBOR map from a browser, plus the one place the
        # device is handed an encoded transaction and has to rebuild it.
        "ur.decode_eth_sign_request": (ur.decode_eth_sign_request,
                                       (ur.BadUR, ValueError)),
        "app.parse_eth_sign_request": (app.parse_eth_sign_request,
                                       (ValueError, eth.BadEthTransaction,
                                        addresses.BadAddress, ur.BadUR)),
        "eth.from_signing_payload": (eth.from_signing_payload,
                                     (eth.BadEthTransaction,
                                      addresses.BadAddress, ValueError)),
        "eth.signature_from_raw": (eth.signature_from_raw,
                                   (eth.BadEthTransaction, ValueError)),
        "eth.decode_erc20_transfer": (eth.decode_erc20_transfer,
                                      (eth.BadEthTransaction,
                                       addresses.BadAddress, ValueError)),
        # A verifier that raises on a hostile record is a denial of service on
        # the co-signing flow, so this one may not raise either.
        "attest.verify_blob": (lambda d: attest.verify_blob(d, bytes(32),
                                                            bytes(32)), ()),
        "seedstore.SeedBlob.unpack": (seedstore.SeedBlob.unpack,
                                      (seedstore.SeedStoreError,)),
        "addresses.script_to_address": (addresses.script_to_address,
                                        (addresses.BadAddress, ValueError)),
        "bip32.ExtendedKey.deserialize":
            (lambda d: bip32.ExtendedKey.deserialize(d.decode("latin-1")),
             (ValueError,)),
    }

    print(f" flat — {FLAT_N} mutated inputs at each entry point")
    for name, (fn, allowed) in targets.items():
        escaped = None
        for _ in range(FLAT_N):
            data = _mutate(rng, rng.choice(seeds))
            try:
                fn(data)
            except allowed:
                pass
            except Exception as e:                              # noqa: BLE001
                escaped = f"{type(e).__name__}: {e}"[:70]
                break
        check(f"{name} only refuses in ways it declares", escaped is None,
              escaped or "")


def _valid_psbt(root, script_type: str) -> bytes:
    """A PSBT this device really would sign — the starting point to corrupt."""
    def kv(t, extra=b""):
        return bytes([t]) + extra

    fp = root.fingerprint()
    path = wallet.account_path(script_type)
    acct = root.derive(path)
    spend, change = acct.derive([0, 0]), acct.derive([1, 0])

    if script_type == "p2tr":
        out_s, _ = ec.taproot_tweak_pubkey(spend.pubkey[1:])
        out_c, _ = ec.taproot_tweak_pubkey(change.pubkey[1:])
        spk, cspk = addresses.p2tr_script(out_s), addresses.p2tr_script(out_c)
    elif script_type == "p2pkh":
        spk = addresses.p2pkh_script(spend.pubkey)
        cspk = addresses.p2pkh_script(change.pubkey)
    elif script_type == "p2sh-p2wpkh":
        spk = addresses.p2sh_p2wpkh_script(spend.pubkey)
        cspk = addresses.p2sh_p2wpkh_script(change.pubkey)
    else:
        spk = addresses.p2wpkh_script(spend.pubkey)
        cspk = addresses.p2wpkh_script(change.pubkey)

    parent = Transaction(2, [TxIn(b"\x11" * 32, 0)], [TxOut(200_000, spk)], 0)
    unsigned = Transaction(2, [TxIn(parent.txid(), 0)], [
        TxOut(150_000, addresses.address_to_script(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")),
        TxOut(45_000, cspk)], 0)
    p = psbtmod.PSBT(unsigned)
    p.globals[kv(psbtmod.GLOBAL_UNSIGNED_TX)] = unsigned.serialize(witness=False)
    m = p.inputs[0]
    m[kv(psbtmod.IN_NON_WITNESS_UTXO)] = parent.serialize()
    m[kv(psbtmod.IN_WITNESS_UTXO)] = ((200_000).to_bytes(8, "little")
                                      + ser_compact(len(spk)) + spk)
    if script_type == "p2sh-p2wpkh":
        m[kv(psbtmod.IN_REDEEM_SCRIPT)] = addresses.p2wpkh_script(spend.pubkey)

    base = bip32.parse_path(path)
    origin = lambda tail: fp + b"".join(  # noqa: E731
        i.to_bytes(4, "little") for i in base + tail)
    if script_type == "p2tr":
        m[kv(psbtmod.IN_TAP_INTERNAL_KEY)] = spend.pubkey[1:]
        m[kv(psbtmod.IN_TAP_BIP32_DERIVATION, spend.pubkey[1:])] = \
            b"\x00" + origin([0, 0])
        o = p.outputs[1]
        o[kv(psbtmod.OUT_TAP_INTERNAL_KEY)] = change.pubkey[1:]
        o[kv(psbtmod.OUT_TAP_BIP32_DERIVATION, change.pubkey[1:])] = \
            b"\x00" + origin([1, 0])
    else:
        m[kv(psbtmod.IN_BIP32_DERIVATION, spend.pubkey)] = origin([0, 0])
        o = p.outputs[1]
        o[kv(psbtmod.OUT_BIP32_DERIVATION, change.pubkey)] = origin([1, 0])
        if script_type == "p2sh-p2wpkh":
            o[kv(psbtmod.OUT_REDEEM_SCRIPT)] = addresses.p2wpkh_script(change.pubkey)
    return p.serialize()


def structured_psbts() -> None:
    """Valid PSBTs with bytes flipped inside them, driven to a drawn screen.

    All the way to render_for_display, because that is how far a hostile PSBT
    gets on the real device before anybody is asked for a PIN -- and because
    the screen has its own invariants, which a corrupted address field is
    exactly the thing that would break.
    """
    root = bip32.from_mnemonic(MNEMONIC)
    bases = [_valid_psbt(root, s)
             for s in ("p2wpkh", "p2tr", "p2pkh", "p2sh-p2wpkh")]
    clean = True
    for b in bases:
        try:
            psbtmod.PSBT.parse(b).summarize(root)
        except Exception:                                       # noqa: BLE001
            clean = False
    check("the uncorrupted PSBTs all analyse", clean)

    allowed = (psbtmod.BadPSBT, txmod.BadTransaction, addresses.BadAddress,
               ops.UnrenderableOperation, ValueError, ec.BadKey, bip32.BadPath)
    rng = random.Random(SEED + 1)
    escaped, reached, oversize = None, 0, None
    for _ in range(STRUCTURED_N):
        d = bytearray(rng.choice(bases))
        for _ in range(rng.randint(1, 5)):
            i = rng.randrange(len(d))
            r = rng.random()
            if r < 0.5:
                d[i] ^= 1 << rng.randrange(8)
            elif r < 0.8:
                d[i] = rng.randrange(256)
            else:
                del d[i:i + rng.randint(1, 4)]
        try:
            summary = psbtmod.PSBT.parse(bytes(d)).summarize(root)
            lines = ops.render_for_display(summary.spend,
                                           reserve=ops.CONFIRM_FOOTER_ROWS)
            reached += 1
            # The screen invariants, on a screen built from corrupted input.
            if any(len(ln) > ops.DISPLAY_COLS for ln in lines) or \
                    len(lines) + ops.CONFIRM_FOOTER_ROWS > ops.DISPLAY_ROWS:
                oversize = oversize or lines
        except allowed:
            pass
        except Exception as e:                                  # noqa: BLE001
            escaped = f"{type(e).__name__}: {e}"[:70]
            break

    print(f"\n structured — {STRUCTURED_N} mutated PSBTs, "
          f"{reached} still analysed and drawn")
    check("a corrupted PSBT only refuses in declared ways", escaped is None,
          escaped or "")
    check("...and any screen it does produce still fits the panel",
          oversize is None, repr(oversize)[:70] if oversize else "")
    check("...and corruption is actually reaching the analysis", reached > 100,
          f"only {reached} got past parse; the fuzzer is bouncing off the magic")


def encoder_properties() -> None:
    """Round trips over many random valid inputs, not a handful of vectors.

    The suites elsewhere pin these against published vectors, which is the
    right primary check and says nothing about the inputs nobody wrote a
    vector for. An encoder that is wrong for one value in ten thousand does
    not fail loudly -- it produces a different address, and the money goes
    there.
    """
    import random

    import bip39
    import qr as qrmod

    rng = random.Random(SEED + 2)
    print("\n properties — round trips over random valid inputs")

    # Every script type this device can own, on every network it knows.
    # NOTE testnet and regtest share base58 version bytes (0x6f / 0xc4), so a
    # legacy address really is valid on both; only the bech32 prefixes differ.
    # That is Bitcoin's design, not a leak, and the assertion allows for it.
    round_trip = cross = True
    for i in range(400):
        sk = __import__("hashlib").sha256(f"addr{i}".encode()).digest()
        pub = ec.pubkey_compressed(sk)
        xonly, _ = ec.taproot_tweak_pubkey(ec.schnorr_pubkey(sk))
        scripts = [addresses.p2wpkh_script(pub),
                   addresses.p2wsh_script(b"\x51" + pub),
                   addresses.p2tr_script(xonly),
                   addresses.p2pkh_script(pub),
                   addresses.p2sh_p2wpkh_script(pub)]
        for net in ("mainnet", "testnet", "regtest"):
            for spk in scripts:
                a = addresses.script_to_address(spk, net)
                if addresses.address_to_script(a, net) != spk:
                    round_trip = False
                other = "mainnet" if net != "mainnet" else "testnet"
                if a.startswith(addresses.NETWORKS[net]["hrp"] + "1"):
                    try:
                        addresses.address_to_script(a, other)
                        cross = False           # a bech32 address crossed nets
                    except addresses.BadAddress:
                        pass
    check("every script type round-trips on every network", round_trip)
    check("...and a bech32 address is refused on another network", cross)

    # The mutation that matters: an address that still decodes is money gone.
    charset, mutated, accepted = addresses.CHARSET, 0, 0
    for i in range(200):
        sk = __import__("hashlib").sha256(f"mut{i}".encode()).digest()
        a = addresses.script_to_address(addresses.p2wpkh_script(
            ec.pubkey_compressed(sk)))
        for _ in range(6):
            j = rng.randrange(a.index("1") + 1, len(a))
            c = rng.choice(charset)
            if c == a[j]:
                continue
            mutated += 1
            try:
                addresses.address_to_script(a[:j] + c + a[j + 1:])
                accepted += 1
            except addresses.BadAddress:
                pass
    check(f"all {mutated} single-character address mutations refused",
          accepted == 0, f"{accepted} decoded anyway")

    def nested(depth=0):
        if depth > 2 or rng.random() < 0.4:
            return bytes(rng.randrange(256) for _ in range(rng.randrange(0, 70)))
        return [nested(depth + 1) for _ in range(rng.randrange(0, 5))]
    check("RLP round-trips nested structures",
          all(eth.rlp_decode(eth.rlp_encode(v := nested())) == v
              for _ in range(1500)))

    # BIP-39's checksum is 4 bits for 12 words and 8 for 24, so a single wrong
    # word is undetectable about 1 time in 2^k -- 6% at twelve words, 0.4% at
    # twenty-four. That is the specification, not a defect, and asserting
    # "always caught" would be asserting something BIP-39 never promised. What
    # IS checkable is that the checksum still has the width it claims: a miss
    # rate far above 2^-k means it has stopped doing its job. It is also the
    # arithmetic behind provision.py defaulting to 24 words.
    ok_39, width = True, True
    words = bip39.wordlist()
    rates = []
    for n in (16, 20, 24, 28, 32):
        trials, missed = 200, 0
        for i in range(trials):
            e = __import__("hashlib").sha256(f"{n}-{i}".encode()).digest()[:n]
            m = bip39.entropy_to_mnemonic(e)
            if bip39.mnemonic_to_entropy(m) != e:
                ok_39 = False
            w = m.split()
            j = rng.randrange(len(w))
            w[j] = words[(words.index(w[j]) + rng.randrange(1, 2048)) % 2048]
            if bip39.validate(" ".join(w)):
                missed += 1
        k = n * 8 // 32
        rates.append((len(w), missed / trials, 2.0 ** -k))
        if missed / trials > 3 * 2.0 ** -k + 0.02:
            width = False
    check("BIP-39 round-trips at every length", ok_39)
    check("...and the checksum still has the width it claims", width,
          "; ".join(f"{n}w missed {r*100:.1f}% vs {e*100:.2f}%"
                    for n, r, e in rates))
    check("...and a word outside the list is always refused",
          not bip39.validate("satoshi " + " ".join(
              bip39.entropy_to_mnemonic(bytes(16)).split()[1:])))

    ok_qr = True
    for _ in range(300):
        payload = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 900)))
        frames = qrmod.encode(payload, chunk=rng.randrange(16, 300))
        shuffled = list(frames)
        rng.shuffle(shuffled)
        if qrmod.decode(shuffled) != payload or \
                qrmod.decode(frames + frames) != payload:
            ok_qr = False
    check("QR frames reassemble shuffled and duplicated", ok_qr)

    # The same property for UR, plus the one pNofM does not have: a fragment
    # that never arrives is recovered from the mixtures. Random sizes, random
    # fragment lengths, and a random pure fragment dropped every time.
    ok_ur = True
    ok_fountain = True
    for _ in range(120):
        payload = bytes(rng.randrange(256)
                        for _ in range(rng.randrange(1, 900)))
        frag = rng.randrange(12, 200)
        pure = ur.encode(payload, "bytes", max_fragment_len=frag)
        shuffled = list(pure)
        rng.shuffle(shuffled)
        if ur.decode(shuffled) != payload or ur.decode(pure + pure) != payload:
            ok_ur = False
        if len(pure) < 2:
            continue
        # Three passes' worth, so there are mixtures to recover from.
        loop = ur.encode(payload, "bytes", max_fragment_len=frag,
                         parts=len(pure) * 3)
        dropped = loop[rng.randrange(len(pure))]
        try:
            if ur.decode([f for f in loop if f != dropped]) != payload:
                ok_fountain = False
        except ur.BadUR:
            ok_fountain = False
    check("UR parts reassemble shuffled and duplicated", ok_ur)
    check("...and a fragment that never arrives is recovered", ok_fountain)


def main() -> int:
    print("Fuzzing — hostile bytes at every point they can enter\n")
    flat_entry_points()
    structured_psbts()
    encoder_properties()
    print("\n" + "-" * 66)
    if FAILURES:
        print(f"FAIL — {len(FAILURES)}:")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("PASS — every entry point refused within its own contract.")
    print("\nThis says the parsers fail cleanly. It says nothing about whether")
    print("they fail CORRECTLY — test_wallet.py is where that is argued.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
