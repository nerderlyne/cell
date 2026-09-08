#!/usr/bin/env python3
"""The whole device, driven end to end with fakes.

Everything below `app.py` already has its own tests. This file is about the
seams between them — the places where a correct component can still be used
wrongly, and where the ordering the design depends on could quietly stop
holding:

    the transaction is DISPLAYED before the PIN is asked for
    the PIN is asked for before the gate runs
    the gate runs before anything is unwrapped
    declining at any point signs nothing and says so
    every refusal is a screen the owner can read, never a traceback

A device that drops to a traceback in front of somebody holding a lancet has
failed at the only job it has, so the loop is driven with hostile input and
asserted to keep its footing.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import sys

import app
import bip32
import ops
import psbt as psbtmod
import eth
import link as lnk
import qr
import ur
import wallet
from buttons import BACK, CONFIRM, DOWN, UP, FakeButtons
from camera import FakeCamera
from display import ConsoleDisplay
from policy import Policy
from se import SoftSE
from test_wallet import MNEMONIC, build_multisig_psbt, build_psbt, multisig_parts

PIN = "12345678"
FW = hashlib.sha256(b"test firmware").digest()
CAL = hashlib.sha256(b"test thresholds").digest()

FAILURES: list[str] = []


def check(label: str, ok: bool) -> None:
    print(f"  {label:<58}{'PASS' if ok else 'FAIL'}")
    if not ok:
        FAILURES.append(label)


# --------------------------------------------------------------------------


def flat(text: str) -> str:
    """Every screen with the whitespace taken out.

    `_fail` wraps a refusal at the panel width by slicing, not at word
    boundaries, so "personal message" reaches the screen as "personal mess" +
    "age". The owner reads it; a substring search of the raw lines does not.
    """
    return re.sub(r"\s+", "", text)


def _renders(op) -> bool:
    """True if the operation can be shown to the owner at all."""
    try:
        ops.render_for_display(op, reserve=ops.CONFIRM_FOOTER_ROWS)
        return True
    except ops.UnrenderableOperation:
        return False


def pin_presses(pin: str = PIN) -> list[str]:
    """The button sequence that types a PIN on four buttons."""
    out = []
    for ch in pin:
        out += [UP] * int(ch) + [CONFIRM]
    return out


class Recorder(ConsoleDisplay):
    """A display that remembers every screen it was asked to paint."""

    def __init__(self):
        super().__init__(out=io.StringIO())
        self.screens: list[list[str]] = []

    def show(self, lines, highlight=None):
        # Recorded BEFORE the paint. ConsoleDisplay.show raises on a screen
        # that does not fit, so appending afterwards meant an oversized screen
        # was never recorded -- and the "no screen anywhere overflowed" sweep
        # at the end of this suite was checking a list that could not, by
        # construction, contain an offender.
        self.screens.append(list(lines))
        super().show(lines, highlight)

    def text(self) -> str:
        return "\n".join("\n".join(s) for s in self.screens)


def make_device(*, presses, frames, gate=None, policy=None, prov=None, se=None,
                network="mainnet", link=None):
    order: list[str] = []

    def default_gate(tier):
        order.append(f"gate:{tier.name}")
        return True, {"gate_scores": {"G1": 0.98}, "features": {"soret": 0.4}}

    se = se or SoftSE(pin=PIN)
    fake_buttons = FakeButtons(list(presses))
    if prov is None:
        prov = wallet.provision(MNEMONIC, se, PIN,
                                script_types=("p2wpkh", "p2tr", "p2sh-p2wpkh",
                                              "p2pkh"))
    d = app.Device(prov=prov, se=se, display=Recorder(),
                   buttons=fake_buttons, camera=FakeCamera(frames),
                   run_gate=gate or default_gate, policy=policy or Policy(),
                   fw_hash=FW, cal_hash=CAL, network=network,
                   # The device's own default is time.sleep, which is what
                   # gives the output QR its frame time. The suite has no
                   # camera to give it to.
                   sleep=lambda _s: None,
                   link=link,
                   clock=fake_buttons.now)
    return d, order


def main() -> int:
    print("Application loop — the seams between the parts\n")
    root = bip32.from_mnemonic(MNEMONIC)

    # ---- the happy path ------------------------------------------------
    print(" a signature, start to finish")
    blob = build_psbt(root, "p2wpkh")
    frames = qr.encode(blob)
    d, order = make_device(presses=[CONFIRM] + [CONFIRM] + pin_presses()
                           + [CONFIRM, CONFIRM],
                           frames=frames)
    outcome = d.run_once()
    check("a scanned PSBT is signed", outcome == "signed-psbt")
    text = d.display.text()
    check("the destination was shown in full",
          "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
          in text.replace("\n", "").replace(" ", ""))
    check("the amount was shown", "0.00150000 BTC" in text)
    check("the tier was stated", "requires" in text)
    check("the signed PSBT was emitted as QR frames", len(d.display.frames) > 0)
    emitted = qr.decode(d.display.frames)
    check("the emitted frames reassemble into a PSBT",
          emitted.startswith(psbtmod.PSBT_MAGIC))
    check("...carrying a signature", any(
        k[:1] == bytes([psbtmod.IN_PARTIAL_SIG])
        for k in psbtmod.PSBT.parse(emitted).inputs[0]))
    check("...and the attestation",
          psbtmod.PSBT.parse(emitted).get_proprietary(b"CELL", 1) is not None)

    # ---- the ordering the design rests on -------------------------------
    print("\n ordering")
    screens = d.display.screens

    def first_screen_matching(needle: str) -> int:
        for i, s in enumerate(screens):
            if needle in "\n".join(s):
                return i
        return 10**6

    i_amount = first_screen_matching("0.00150000 BTC")
    i_pin = first_screen_matching("ENTER PIN")
    i_gate = first_screen_matching("REQUIRED")
    check("the transaction is shown before the PIN is asked for",
          i_amount < i_pin)
    check("the PIN is asked for before the gate is run", i_pin < i_gate)
    check("the gate ran after both", order and order[0].startswith("gate:"))

    # ---- declining, at each point ---------------------------------------
    print("\n declining")
    d2, order2 = make_device(presses=[CONFIRM, BACK], frames=frames)
    check("declining at the confirmation signs nothing",
          d2.run_once() == "cancelled")
    check("...and no gate was run", order2 == [])
    check("...and it says so", "CANCELLED" in d2.display.text())
    check("...and nothing was emitted", d2.display.frames == [])

    d3, order3 = make_device(presses=[CONFIRM, CONFIRM, BACK], frames=frames)
    check("backing out of the PIN signs nothing", d3.run_once() == "cancelled")
    check("...and no gate was run", order3 == [])

    def failing_gate(tier):
        return False, {"message": "no pulse detected"}

    d4, _ = make_device(presses=[CONFIRM, CONFIRM] + pin_presses() + [CONFIRM],
                        frames=frames, gate=failing_gate)
    check("a failed gate signs nothing", d4.run_once() == "refused")
    check("...and the reason reaches the owner",
          "no pulse" in d4.display.text())
    check("...and nothing was emitted", d4.display.frames == [])

    # ---- a wrong PIN ----------------------------------------------------
    print("\n the PIN")
    se = SoftSE(pin=PIN)
    prov = wallet.provision(MNEMONIC, se, PIN,
                            script_types=("p2wpkh", "p2tr", "p2sh-p2wpkh", "p2pkh"))
    d5, order5 = make_device(presses=[CONFIRM, CONFIRM] + pin_presses("99999999")
                             + [CONFIRM],
                             frames=frames, se=se, prov=prov)
    check("a wrong PIN is refused", d5.run_once() == "refused")
    check("...and the gate never ran", order5 == [])
    check("...and the owner is told how many attempts remain",
          "attempts remaining" in d5.display.text())

    # ---- hostile and malformed input ------------------------------------
    print("\n hostile input")
    cases = [
        ("a PSBT with no key of ours",
         qr.encode(build_psbt(bip32.from_mnemonic(
             "zoo " * 11 + "wrong"), "p2wpkh"))),
        ("a truncated PSBT", qr.encode(blob[:-8])),
        ("a PSBT paying two destinations",
         qr.encode(build_psbt(root, "p2wpkh", send=100_000, change=45_000,
                              extra_outputs=((50_000,
                                              "bc1qrp33g0q5c5txsp9arysrx4k6zd"
                                              "kfs4nce4xj0gdcccefvpysxf3qccfmv3"),)))),
        ("a QR that is not a transaction at all", qr.encode(b"hello there")),
        ("a QR full of JSON that is not ours",
         qr.encode(json.dumps({"type": "something-else"}).encode())),
        ("an Ethereum request with an unknown field",
         qr.encode(json.dumps({"type": "cell-eth-tx", "chain_id": 1, "nonce": 0,
                               "max_priority_fee_per_gas": 1, "max_fee_per_gas": 2,
                               "gas_limit": 21000, "value": 0,
                               "to": "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
                               "data": "0xdeadbeef"}).encode())),
        ("an Ethereum request missing a field",
         qr.encode(json.dumps({"type": "cell-eth-tx", "chain_id": 1}).encode())),
    ]
    for label, fs in cases:
        dev, _ = make_device(presses=[CONFIRM] * 6, frames=fs)
        try:
            outcome = dev.run_once()
            survived = outcome in ("refused", "unknown-payload", "cancelled")
        except Exception as e:                                  # noqa: BLE001
            print(f"      raised {type(e).__name__}: {e}")
            survived = False
        check(f"refuses {label}", survived)
        check(f"...with a screen, not a traceback ({label[:28]})",
              survived and dev.display.screens
              and all(len(ln) <= ops.DISPLAY_COLS
                      for ln in dev.display.screens[-1]))

    # An incomplete transfer must be reported, not hung on.
    dev, _ = make_device(presses=[CONFIRM, CONFIRM], frames=frames[:-1])
    check("an incomplete scan is reported", dev.run_once() == "scan-failed")
    check("...in words", "SCAN FAILED" in dev.display.text())

    # ---- Ethereum -------------------------------------------------------
    print("\n ethereum")
    req = json.dumps({"type": "cell-eth-tx", "chain_id": 1, "nonce": 3,
                      "max_priority_fee_per_gas": 10**9,
                      "max_fee_per_gas": 25 * 10**9, "gas_limit": 21000,
                      "to": "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
                      "value": 10**17}).encode()
    d6, order6 = make_device(presses=[CONFIRM, CONFIRM] + pin_presses()
                             + [CONFIRM, CONFIRM],
                             frames=qr.encode(req))
    check("an Ethereum request is signed", d6.run_once() == "signed-eth")
    t6 = d6.display.text()
    check("the chain is named", "ETHEREUM" in t6.upper())
    check("the chain id is shown", "chain id 1" in t6)
    check("the nonce is shown", "nonce    3" in t6)
    check("the worst-case fee is shown", "max fee" in t6)
    check("amounts carry the chain's own ticker", "0.1 ETH" in t6)

    # A chain the owner registered renders under the name and denomination
    # they registered, not under a ticker the firmware assumed.
    eth.register_chain(137, "Polygon", "POL")
    req_pol = json.dumps({"type": "cell-eth-tx", "chain_id": 137, "nonce": 3,
                          "max_priority_fee_per_gas": 10**9,
                          "max_fee_per_gas": 25 * 10**9, "gas_limit": 21000,
                          "to": "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
                          "value": 10**17}).encode()
    d6b, _ = make_device(presses=[CONFIRM, CONFIRM] + pin_presses()
                         + [CONFIRM, CONFIRM],
                         frames=qr.encode(req_pol))
    check("a registered chain signs", d6b.run_once() == "signed-eth")
    t6b = d6b.display.text()
    check("...under its registered name", "POLYGON" in t6b.upper())
    check("...and its own ticker, not ETH", "0.1 POL" in t6b and "ETH" not in t6b)
    check("the raw transaction was emitted", len(d6.display.frames) > 0)
    raw = qr.decode(d6.display.frames)
    check("...and it is a typed EIP-1559 envelope", raw[0] == 0x02)

    # ---- the smart-account paths, through the loop ----------------------
    #
    # These three exist as wallet functions that nothing on the device could
    # reach: classify() knew "psbt" and "cell-eth-tx" and nothing else, so on
    # hardware there was no way to spend from a smart account, cancel a queued
    # transaction, or delegate. Every check below goes through run_once, which
    # is the only thing that proves the flow and not just the library.
    print("\n smart accounts")
    import eip712
    se_sa = SoftSE(pin=PIN)
    prov_sa = wallet.provision(MNEMONIC, se_sa, PIN, script_types=("p2wpkh",))
    eip712.ACCOUNTS.clear()
    me = prov_sa.eth_address()
    EXEC = "0x00000000a72A30AdBf38e14d36BCE2610ec3973F"
    IMPL = "0xD54cb65224410F3Ff97a8E72f363f224419f4FB0"
    prov_sa.register_smart_account(eip712.SmartAccount(
        label="treasury", address="0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
        chain_ids=(1, 8453), implementation=IMPL,
        implementation_label="Multisig v1", threshold=2,
        owners=(me, "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
        delay_seconds=172800, executor=EXEC, fast_track=True))

    def sa_device(doc, presses=None):
        return make_device(
            presses=presses or ([CONFIRM, CONFIRM] + pin_presses()
                                + [CONFIRM, CONFIRM]),
            frames=qr.encode(json.dumps(doc).encode()),
            se=se_sa, prov=prov_sa)

    d_sa, _ = sa_device({"type": "cell-account-execute", "account": "treasury",
                         "to": "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
                         "value": 10**17, "nonce": 4, "chain_id": 1})
    check("a smart-account spend signs through the loop",
          d_sa.run_once() == "signed-account-execute")
    t_sa = d_sa.display.text()
    check("the account is named on the screen", "SEND FROM TREASURY" in t_sa)
    check("the timelock is stated", "HELD 2d after relay" in t_sa)
    check("so is the unanimous fast track", "all 2 owners sign" in t_sa)
    check("the relayer, not the account, pays", "paid by whoever relays" in t_sa)
    env = json.loads(qr.decode(d_sa.display.frames))
    check("the emitted envelope is typed", env["type"] == "cell-signature")
    check("...names the request it answers",
          env["for"] == "cell-account-execute")
    check("...carries a 65-byte signature",
          len(bytes.fromhex(env["signature"][2:])) == 65)
    check("...and the digest the account will check",
          env["digest"] == "0x" + eip712.account("treasury").spend_digest(
              "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", 10**17, 4, 1).hex())
    check("...recovering to this device's own address",
          env["signer"].lower() == me.lower())

    d_c, order_c = sa_device({"type": "cell-account-cancel",
                              "account": "treasury", "tx_hash": "0x" + "ab" * 32,
                              "nonce": 5, "chain_id": 8453})
    check("a cancel signs through the loop",
          d_c.run_once() == "signed-account-cancel")
    t_c = d_c.display.text()
    check("the cancel names what it stops", "CANCEL A QUEUED TRANSACTION" in t_c)
    check("the queued hash is shown in full",
          ("ab" * 32) in t_c.replace("\n", "").replace(" ", ""))
    check("the second chain is named", "Base" in t_c)
    # The stop button must not cost a lancet. See ops.CancelQueued.
    check("cancelling ran at touch, not blood", "gate:TOUCH" in order_c)

    # A delegation is of THIS device's key, so it needs a record at this
    # device's own address. The treasury above is a contract account the
    # device merely co-owns, and delegating it would delegate the device.
    prov_sa.register_smart_account(eip712.SmartAccount(
        label="mine", address=me, chain_ids=(1,), implementation=IMPL,
        implementation_label="Multisig v1", threshold=1, owners=(me,),
        delegated_eoa=True))
    d_d, order_d = sa_device({"type": "cell-delegate", "account": "mine",
                              "nonce": 0, "chain_id": 1})
    check("a delegation signs through the loop",
          d_d.run_once() == "signed-delegation")
    t_d = d_d.display.text()
    check("the delegation screen names the code, not the account",
          "Multisig v1" in t_d)
    check("...and says the change persists", "delegated again" in t_d)
    check("a delegation costs blood, through the loop", "gate:BLOOD" in order_d)

    d_x, order_x = sa_device({"type": "cell-account-execute",
                              "account": "treasury",
                              "to": "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
                              "value": 1, "nonce": 4, "chain_id": 11155111},
                             presses=[CONFIRM] * 4)
    check("a chain the account is not registered on is refused",
          d_x.run_once() == "refused")
    check("...before the gate", order_x == [])

    d_y, order_y = sa_device({"type": "cell-delegate", "account": "treasury",
                              "nonce": 0, "chain_id": 1},
                             presses=[CONFIRM] * 4)
    check("delegating a co-owned contract account is refused",
          d_y.run_once() == "refused")
    check("...before the gate", order_y == [])

    # ---- multisig through the loop --------------------------------------
    print("\n multisig")
    se7 = SoftSE(pin=PIN)
    prov7 = wallet.provision(MNEMONIC, se7, PIN)
    ms, members = multisig_parts(root)
    prov7.register_multisig(ms)
    d7, _ = make_device(presses=[CONFIRM, CONFIRM] + pin_presses() + [CONFIRM, CONFIRM],
                        frames=qr.encode(build_multisig_psbt(ms, members)),
                        se=se7, prov=prov7)
    check("a registered quorum signs", d7.run_once() == "signed-psbt")
    check("the quorum is on the confirmation screen",
          "MULTISIG 2 of 3" in d7.display.text())

    # RECEIVE has to show where a quorum's funds actually live. Showing only
    # the single-sig address was a trap for exactly the owners who did the
    # harder thing: money sent there is spendable by this device alone, which
    # is the property multisig exists to remove.
    d7b, _ = make_device(presses=[CONFIRM], frames=[], se=se7, prov=prov7)
    check("RECEIVE shows the quorum's address, not just the single-sig one",
          d7b.show_address() == "address"
          and any("2 of 3" in ln for ln in d7b.display.last))
    check("...and the single-sig address is still there",
          any("single-sig" in ln for ln in d7b.display.last))

    # display.show refuses a screen that does not fit rather than truncating
    # it, so an unbounded list here is a crash on the RECEIVE button.
    se7c = SoftSE(pin=PIN)
    prov7c = wallet.provision(MNEMONIC, se7c, PIN)
    import bip39 as _bip39
    ms_path = wallet.multisig_account_path("multisig-p2wsh", 0, "mainnet")
    _mine = prov7c.account_for("multisig-p2wsh", "mainnet")
    me_cos = wallet.CoSigner(label="me",
                             fingerprint=prov7c.master_fingerprint.hex(),
                             path=_mine.path, xpub=_mine.xpub)

    def _other(tag):
        o = bip32.from_mnemonic(_bip39.entropy_to_mnemonic(bytes([tag]) * 32))
        return wallet.CoSigner(label=f"c{tag}", fingerprint=o.fingerprint().hex(),
                               path=ms_path,
                               xpub=o.derive(ms_path).neutered().serialize("xpub"))

    for i in range(5):
        prov7c.register_multisig(wallet.Multisig(
            label=f"q{i}", threshold=2,
            cosigners=[me_cos, _other(1 + i), _other(200 + i)],
            network="mainnet"))
    d7c, _ = make_device(presses=[CONFIRM], frames=[], se=se7c, prov=prov7c)
    check("five quorums do not overflow the RECEIVE screen",
          d7c.show_address() == "address")
    check("...it fits the panel exactly",
          len(d7c.display.last) <= app.ops.DISPLAY_ROWS)
    check("...and says how many it could not show",
          any("more quorum(s) not shown" in ln for ln in d7c.display.last))

    se8 = SoftSE(pin=PIN)
    prov8 = wallet.provision(MNEMONIC, se8, PIN)
    d8, order8 = make_device(presses=[CONFIRM] * 4,
                             frames=qr.encode(build_multisig_psbt(ms, members)),
                             se=se8, prov=prov8)
    check("an unregistered quorum is refused at the screen",
          d8.run_once() == "refused")
    check("...and never reached the gate", order8 == [])

    # ---- the tier still governs -----------------------------------------
    print("\n the gate still governs")
    d9, order9 = make_device(presses=[CONFIRM, CONFIRM] + pin_presses()
                             + [CONFIRM, CONFIRM],
                             frames=frames, policy=Policy(blood_above=1))
    d9.run_once()
    check("a spend above the floor demands blood", order9 == ["gate:BLOOD"])
    check("...and the owner is told what that means",
          "ten minutes" in d9.display.text())

    d10, order10 = make_device(presses=[CONFIRM, CONFIRM] + pin_presses()
                               + [CONFIRM, CONFIRM], frames=frames)
    d10.run_once()
    check("a small spend runs at touch", order10 == ["gate:TOUCH"])
    check("...and says so", "TOUCH REQUIRED" in d10.display.text())

    # ---- the read-only screens ------------------------------------------
    print("\n the screens that sign nothing")
    d11, order11 = make_device(presses=[UP, CONFIRM], frames=[])
    check("UP shows a receiving address", d11.run_once() == "address")
    addr_text = d11.display.text().replace("\n", "").replace(" ", "")
    expected = d11.prov.account_for("p2wpkh").xpub
    node = bip32.ExtendedKey.deserialize(expected).derive([0, 0])
    import addresses as addr_mod
    want = addr_mod.script_to_address(addr_mod.p2wpkh_script(node.pubkey))
    check("...and it is the address this seed derives", want in addr_text)
    check("...without unlocking anything", order11 == [])

    d12, order12 = make_device(presses=[DOWN, BACK], frames=[])
    check("DOWN shows the device's public identity", d12.run_once() == "keys")
    check("...including the fingerprint",
          d12.prov.master_fingerprint.hex() in d12.display.text())
    check("...without unlocking anything either", order12 == [])

    # Exporting the watch-only accounts, which is the other thing that screen
    # offers. It signs nothing and needs no seed, and it is behind a second
    # CONFIRM because an account xpub reveals every address the wallet will
    # ever use.
    d13, order13 = make_device(presses=[DOWN, CONFIRM, CONFIRM, CONFIRM],
                               frames=[])
    check("CONFIRM on that screen exports the accounts",
          d13.run_once() == "exported-accounts")
    check("...warning what an xpub reveals, before showing it",
          "everyaddressyouwilleveruse" in flat(d13.display.text()))
    check("...as a crypto-account UR a coordinator recognises",
          bool(d13.display.frames)
          and all(f.startswith("ur:crypto-account/")
                  for f in d13.display.frames))
    check("...and nothing was unlocked to build it", order13 == [])

    _acct = ur.reassemble(d13.display.frames)
    _item, _rest = ur.cbor_decode(_acct)
    check("the export is tag 311 naming this device's fingerprint",
          not _rest and _item.tag == ur.TAG_ACCOUNT
          and _item.value[1] == int.from_bytes(
              d13.prov.master_fingerprint, "big"))
    check("...with one descriptor per Bitcoin script type",
          len(_item.value[2]) == len([a for a in d13.prov.accounts
                                      if a.script_type
                                      in ur.SCRIPT_EXPRESSIONS]))
    check("...and the eth account is not among them, having no script",
          any(a.script_type == "eth" for a in d13.prov.accounts)
          and not any(a.script_type == "eth"
                      for a in d13.prov.accounts
                      if a.script_type in ur.SCRIPT_EXPRESSIONS))
    # Every exported key must be the one the recorded xpub holds, and public.
    _keys = []
    for _d in _item.value[2]:
        _inner = _d.value
        while isinstance(_inner, ur.Tag):
            _inner = _inner.value
        _keys.append(_inner)
    check("every exported key is a compressed public key",
          all(len(k[3]) == 33 and k[3][0] in (2, 3) for k in _keys))
    check("...and none of them claims to be private",
          all(2 not in k for k in _keys))
    _want = {bip32.ExtendedKey.deserialize(a.xpub).pubkey
             for a in d13.prov.accounts
             if a.script_type in ur.SCRIPT_EXPRESSIONS}
    check("...and each is an account key this device actually recorded",
          {k[3] for k in _keys} == _want)

    # BACK at the warning shows nothing at all.
    d14, _ = make_device(presses=[DOWN, CONFIRM, BACK, CONFIRM], frames=[])
    check("BACK at the warning shows no QR",
          d14.run_once() == "export-cancelled" and not d14.display.frames)


    # ---- the seam to the sensing half -----------------------------------
    # app.load_device wires the gates to the unlock chain. The gates return
    # rich result objects; the signer wants (passed, attestation). This is the
    # adapter, checked against the gates' REAL outputs rather than a mock,
    # because an adapter tested against its own idea of the shape is an
    # adapter that compiles and then fails on a bench.
    print("\n the seam to the gates")
    import blood_gate
    import calibrate
    import touch_gate

    ok_blood, att_blood = app.gate_result(
        blood_gate.evaluate(calibrate.synth_capture("genuine", 0)))
    check("a genuine blood capture is adapted as a pass", ok_blood is True)
    check("...carrying the gate scores the attestation hashes",
          "gate_scores" in att_blood and att_blood["gate_scores"])

    bad_blood, att_bad = app.gate_result(
        blood_gate.evaluate(calibrate.synth_capture("ketchup", 0)))
    check("a spoof is adapted as a failure", bad_blood is False)
    check("...with a message naming the gate that caught it",
          "message" in att_bad and len(att_bad["message"]) > 8)

    tth = touch_gate.TouchThresholds()
    red, ir, bore = touch_gate._synth("genuine", 0, tth)
    ok_touch, att_touch = app.gate_result(
        touch_gate.evaluate(red, ir, bore, tth, fs=tth.fs))
    check("a genuine touch capture is adapted as a pass", ok_touch is True)
    # The two tiers name their measurements differently — blood reports
    # gate_scores, touch reports features — and liveness_digest reads both.
    # What matters is not the key but that the record commits to the capture.
    check("...carrying measurements under one of the names the digest reads",
          bool(att_touch.get("gate_scores") or att_touch.get("features")))

    red_f, ir_f, bore_f = touch_gate._synth("pump_fake", 0, tth)
    ok_fake, att_fake = app.gate_result(
        touch_gate.evaluate(red_f, ir_f, bore_f, tth, fs=tth.fs))
    check("a pumped silicone finger is adapted as a failure", ok_fake is False)
    check("...with a message for the owner", "message" in att_fake)

    # And the digest the attestation commits to must actually change with the
    # capture, or the record attests to nothing in particular.
    import signer as signer_mod
    from policy import Tier as _Tier
    d_a = signer_mod.liveness_digest(_Tier.BLOOD, att_blood)
    d_b = signer_mod.liveness_digest(
        _Tier.BLOOD,
        app.gate_result(blood_gate.evaluate(calibrate.synth_capture("genuine", 1)))[1])
    check("two blood captures attest to different measurements", d_a != d_b)

    # The same must hold for touch, or the touch tier's attestation would be a
    # signed boolean rather than a claim about a capture.
    red_b, ir_b, bore_b = touch_gate._synth("genuine", 1, tth)
    t_a = signer_mod.liveness_digest(_Tier.TOUCH, att_touch)
    t_b = signer_mod.liveness_digest(_Tier.TOUCH, app.gate_result(
        touch_gate.evaluate(red_b, ir_b, bore_b, tth, fs=tth.fs))[1])
    check("two touch captures attest to different measurements", t_a != t_b)
    check("and a touch digest is not a blood digest", t_a != d_a)

    # The thresholds the device loads must be the ones it evaluates against.
    check("both gates expose the load() the device build calls",
          hasattr(blood_gate.Thresholds, "load")
          and hasattr(touch_gate.TouchThresholds, "load"))
    check("touch thresholds carry the capture parameters the adapter uses",
          hasattr(tth, "duration_s") and hasattr(tth, "fs"))

    # ---- the two tiers read their OWN calibration file -------------------
    print("\n each tier loads its own thresholds")
    import json as _json
    import tempfile as _tempfile
    from pathlib import Path as _Path
    with _tempfile.TemporaryDirectory() as _td:
        _d = _Path(_td)
        # A realistic pair: blood's file carries its 600 s capture length,
        # touch's carries a swept contact window.
        (_d / "thresholds.json").write_text(_json.dumps(
            {"duration_s": 600.0, "sam_cos_min": 0.997}))
        (_d / "touch_thresholds.json").write_text(_json.dumps(
            {"duration_s": 15.0, "dc_min": 0.11, "dc_max": 0.77}))

        _bt = blood_gate.Thresholds.load(_d / "thresholds.json")
        _tt = touch_gate.TouchThresholds.load(_d / "touch_thresholds.json")
        check("blood loads its own sweep", _bt.sam_cos_min == 0.997)
        check("touch loads its own sweep",
              _tt.dc_min == 0.11 and _tt.dc_max == 0.77)
        check("...and keeps its 15 s session, not blood's 600 s",
              _tt.duration_s == 15.0)

        # The bug this guards: handing blood's file to the touch loader. The
        # two dataclasses share exactly one field name, so every touch
        # threshold in it is dropped and duration_s crosses over -- a
        # ten-minute finger-hold, evaluated against shipped defaults.
        _crossed = touch_gate.TouchThresholds.load(_d / "thresholds.json")
        check("blood's file is NOT a valid source of touch thresholds",
              _crossed.duration_s != _tt.duration_s
              and _crossed.dc_min != _tt.dc_min)

        # cal_hash must commit to both, or the tier that signs most often is
        # the tier the attestation says nothing about.
        _h_both = blood_gate.calibration_hash(
            _d / "thresholds.json", _d / "touch_thresholds.json")
        _h_blood_only = blood_gate.calibration_hash(_d / "thresholds.json")
        check("the calibration hash covers both threshold sets",
              _h_both != _h_blood_only and len(_h_both) == 32)
        (_d / "touch_thresholds.json").write_text(_json.dumps({"dc_min": 0.5}))
        check("...so a changed touch sweep changes the attested hash",
              blood_gate.calibration_hash(
                  _d / "thresholds.json",
                  _d / "touch_thresholds.json") != _h_both)

    # ---- the empty bore is read BEFORE the finger is on the ring ---------
    print("\n touch reads the empty bore first")

    class _OrderingSensor(touch_gate.TouchSensor):
        """Records the order the gate drives it in.

        T1 is mean(red) / bore_red. A bore reference taken after the capture
        is taken through the finger, the ratio lands near 1, and the contact
        gate rejects every session -- genuine ones included. Nothing in the
        synthetic panel catches that, because _synth hands back a constant
        bore, so the order is asserted directly.
        """

        def __init__(self):
            self.calls = []

        def read_ppg(self, duration_s, fs):
            self.calls.append("ppg")
            r, i, _b = touch_gate._synth("genuine", 0, tth)
            return r, i, tth.fs

        def read_bore_reference(self):
            self.calls.append("bore")
            return (1.0, 1.0)

    _os = _OrderingSensor()
    _res = touch_gate.authorize(_os, tth)
    check("authorize reads the bore before the capture",
          _os.calls == ["bore", "ppg"])
    check("...and still accepts a genuine capture", _res.accepted is True)

    # ---- the tier floor prices everything that leaves the wallet ---------
    print("\n the tier floor prices the whole spend")
    from policy import Policy as _Policy, Tier as _T2
    import policy as _policy

    # blood above 0.1 BTC. The attack is a PSBT whose DESTINATION amount sits
    # under the floor while the value actually leaves via the fee, or via an
    # output the host labelled change and this wallet cannot derive.
    _pol = _Policy(blood_above=10_000_000)

    _honest = ops.BitcoinSpend(amount_sats=1_000, destination="bc1qx",
                               fee_sats=200)
    check("a small honest spend still runs at touch tier",
          _policy.decide(_pol, _honest.op_class(),
                         _honest.amount_for_policy()).tier_to_run is _T2.TOUCH)

    _fee_attack = ops.BitcoinSpend(amount_sats=1, destination="bc1qx",
                                   fee_sats=50_000_000)
    check("value routed through the fee escalates to blood",
          _policy.decide(_pol, _fee_attack.op_class(),
                         _fee_attack.amount_for_policy()).tier_to_run is _T2.BLOOD)

    _change_attack = ops.BitcoinSpend(
        amount_sats=1, destination="bc1qx", fee_sats=200,
        unverified_sats=50_000_000, unverified_address="bc1qattacker")
    check("value routed through an underivable 'change' output escalates",
          _policy.decide(_pol, _change_attack.op_class(),
                         _change_attack.amount_for_policy()).tier_to_run
          is _T2.BLOOD)

    _real_change = ops.BitcoinSpend(
        amount_sats=1_000, destination="bc1qx", fee_sats=200,
        change_sats=50_000_000)
    check("change the wallet DID derive does not escalate — it comes back",
          _policy.decide(_pol, _real_change.op_class(),
                         _real_change.amount_for_policy()).tier_to_run
          is _T2.TOUCH)

    _eth = ops.EthereumSpend(amount_wei=1, destination="0xabc", chain_id=1,
                             chain_name="Ethereum", nonce=0,
                             max_fee_wei=50_000_000, ticker="ETH")
    check("an Ethereum fee cap is priced too, as the screen's MOST line is",
          _policy.decide(_pol, _eth.op_class(),
                         _eth.amount_for_policy()).tier_to_run is _T2.BLOOD)

    # ---- the other framing, through the whole loop -----------------------
    #
    # The point is that nothing above camera.py knows which dialect arrived.
    # A UR request must be signed identically and answered in UR, because a
    # coordinator that speaks one framing need not speak the other.
    print("\n UR, end to end")
    ur_blob = build_psbt(root, "p2wpkh")
    d, _ = make_device(presses=[CONFIRM] + [CONFIRM] + pin_presses()
                       + [CONFIRM, CONFIRM],
                       frames=ur.encode(ur_blob, "crypto-psbt",
                                        max_fragment_len=200))
    check("a PSBT arriving as UR is signed", d.run_once() == "signed-psbt")
    check("the reply came back as UR, not pNofM",
          all(f.startswith("ur:crypto-psbt/") for f in d.display.frames))
    signed = ur.reassemble(d.display.frames)
    check("the UR reply is a signed PSBT",
          signed.startswith(psbtmod.PSBT_MAGIC)
          and any(k[:1] == bytes([psbtmod.IN_PARTIAL_SIG])
                  for k in psbtmod.PSBT.parse(signed).inputs[0]))
    check("...carrying the attestation, exactly as the QR path does",
          psbtmod.PSBT.parse(signed).get_proprietary(b"CELL", 1) is not None)
    check("the destination was still shown in full",
          "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
          in d.display.text().replace("\n", "").replace(" ", ""))

    # A pNofM request still comes back pNofM. Mirroring has to work both ways
    # or it is just a second default.
    d, _ = make_device(presses=[CONFIRM] + [CONFIRM] + pin_presses()
                       + [CONFIRM, CONFIRM],
                       frames=qr.encode(build_psbt(root, "p2wpkh")))
    d.run_once()
    check("a pNofM request is answered in pNofM",
          all(f.startswith("p") and not f.startswith("ur:")
              for f in d.display.frames))

    # ---- ERC-20, end to end ---------------------------------------------
    #
    # The one operation that carries calldata. What matters here is that the
    # screen names the token, shows BOTH addresses in full, and that an
    # unregistered token never reaches a PIN prompt.
    print("\n an ERC-20 transfer")
    USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
    PAYEE = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
    eth.register_token(1, USDC, "USDC", 6)

    def token_req(**over):
        doc = {"type": "cell-token-tx", "chain_id": 1, "nonce": 3,
               "max_priority_fee_per_gas": 1_000_000_000,
               "max_fee_per_gas": 30_000_000_000, "gas_limit": 65_000,
               "token": USDC, "to": PAYEE, "amount": 250_000_000}
        doc.update(over)
        return json.dumps(doc).encode()

    d, order = make_device(presses=[CONFIRM] + [CONFIRM] + pin_presses()
                           + [CONFIRM, CONFIRM],
                           frames=qr.encode(token_req()))
    outcome = d.run_once()
    check("a registered token transfer is signed", outcome == "signed-token")
    text = d.display.text()
    tight = flat(text)
    check("the screen named the token, not a selector",
          "SEND USDC ON ETHEREUM" in text)
    check("the amount was shown at the registered decimals",
          "250 USDC" in text)
    check("the recipient was shown in full", PAYEE in tight)
    check("the token contract was shown in full too", USDC in tight)
    check("the fee was denominated in the chain's own coin",
          "max fee  0.00195 ETH" in text)
    check("no calldata was ever put on the screen",
          "a9059cbb" not in tight)
    check("the raw transaction was emitted", len(d.display.frames) > 0)
    raw = qr.decode(d.display.frames)
    check("...as a type-2 transaction carrying the transfer",
          raw[:1] == bytes([eth.TX_TYPE_1559])
          and eth.rlp_decode(raw[1:])[7]
          == eth.encode_erc20_transfer(PAYEE, 250_000_000))

    # An unregistered token has to be refused BEFORE the owner spends a PIN
    # attempt on it, which is the whole reason the registry is consulted at
    # parse time rather than at signing time.
    d, order = make_device(presses=[CONFIRM, CONFIRM, CONFIRM],
                           frames=qr.encode(token_req(
                               token="0x1111111111111111111111111111111111111111")))
    check("an unregistered token is refused", d.run_once() == "refused")
    check("...before the gate ran", not order)
    # Flattened: _fail wraps at the panel width, so the command name is split
    # across two rows on screen. The owner reads it fine; a substring search
    # of the raw lines does not.
    check("...and the refusal says how to fix it",
          "provision.pytoken" in d.display.text().replace("\n", "")
          .replace(" ", ""))

    d, order = make_device(presses=[CONFIRM, CONFIRM, CONFIRM],
                           frames=qr.encode(token_req(data="0xdeadbeef")))
    check("a token request carrying calldata is refused",
          d.run_once() == "refused")
    check("...naming the field it would not accept",
          "data" in d.display.text())

    # The tier. A token amount cannot be compared against a native-unit floor,
    # so it must never be priced BELOW one.
    _tok = ops.TokenTransfer(
        amount_units=250_000_000, decimals=6, symbol="USDC",
        destination=PAYEE, contract=USDC, chain_id=1, chain_name="Ethereum",
        nonce=0, max_fee_wei=1_000, ticker="ETH")
    check("a token transfer is never priced below an amount floor",
          _policy.decide(_pol, _tok.op_class(),
                         _tok.amount_for_policy()).tier_to_run is _T2.BLOOD)
    check("...and an owner with no floor can still lock the class",
          _policy.decide(Policy(blood_locked=frozenset({"tx.token"})),
                         _tok.op_class(),
                         _tok.amount_for_policy()).tier_to_run is _T2.BLOOD)
    check("a token sent to its own contract is unrenderable",
          not _renders(ops.TokenTransfer(
              amount_units=1, decimals=6, symbol="USDC", destination=USDC,
              contract=USDC, chain_id=1, chain_name="Ethereum", nonce=0,
              max_fee_wei=1, ticker="ETH")))

    # ---- EIP-4527, which is what a browser wallet sends -------------------
    #
    # The transaction arrives ENCODED rather than as fields, so the checks that
    # matter are that the device rebuilds it, re-encodes it, and refuses if the
    # two differ by a byte -- and that the blind-signing data types are refused
    # by name rather than silently.
    print("\n an EIP-4527 request")
    RID = bytes(range(16))
    MY_ADDR = None

    def sign_request(**over):
        tx = eth.EthTransaction(
            chain_id=over.pop("chain_id", 1), nonce=4,
            max_priority_fee_per_gas=1_000_000_000,
            max_fee_per_gas=30_000_000_000, gas_limit=21_000,
            to="0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
            value=over.pop("value", 10**17))
        kw = {"request_id": RID, "sign_data": tx.signing_payload(),
              "data_type": 2, "path": wallet.eth_path(0, 0), "chain_id": 1}
        kw.update(over)
        return ur.encode(ur.encode_eth_sign_request(**kw), "eth-sign-request",
                         max_fragment_len=120)

    d, order = make_device(presses=[CONFIRM] + [CONFIRM] + pin_presses()
                           + [CONFIRM, CONFIRM],
                           frames=sign_request())
    outcome = d.run_once()
    check("an EIP-4527 request is signed", outcome == "signed-eth-request")
    text = d.display.text()
    check("the amount was rendered from the rebuilt transaction",
          "0.1 ETH" in text)
    check("the chain was named, not numbered alone", "ETHEREUM" in text)
    check("the destination was shown in full",
          "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
          in text.replace("\n", "").replace(" ", ""))
    check("the reply is an eth-signature, not another request",
          bool(d.display.frames)
          and all(f.startswith("ur:eth-signature/") for f in d.display.frames))
    sig_cbor = ur.reassemble(d.display.frames)
    item, rest = ur.cbor_decode(sig_cbor)
    check("...tagged 402 as the format says",
          not rest and isinstance(item, ur.Tag)
          and item.tag == ur.TAG_ETH_SIGNATURE)
    body = item.value
    check("...echoing the request id so a companion can match it",
          body[1].value == RID)
    check("...carrying 65 bytes of r, s and v",
          isinstance(body[2], bytes) and len(body[2]) == 65
          and body[2][64] in (0, 1))

    # The signature has to recover to this device's own address, or the
    # companion assembles a transaction credited to nobody.
    _tx = eth.from_signing_payload(
        ur.decode_eth_sign_request(
            ur.decode(sign_request()))["sign_data"])
    _r = int.from_bytes(body[2][:32], "big")
    _s = int.from_bytes(body[2][32:64], "big")
    check("the signature recovers to this device's address",
          eth.sender(_tx, _r, _s, body[2][64]) == d.prov.eth_address())

    # The blind-signing data types, each refused by name.
    for dtype, needle in ((3, "personal message"), (4, "EIP-712 typed data"),
                          (1, "legacy transaction")):
        d, order = make_device(presses=[CONFIRM, CONFIRM, CONFIRM],
                               frames=sign_request(data_type=dtype))
        got = d.run_once()
        check(f"data type {dtype} is refused", got == "refused")
        check(f"...and named as {needle}", flat(needle) in flat(d.display.text()))
        check(f"...before the gate ran", not order)

    # A payload that decodes to the same fields but is not the same bytes. RLP
    # has non-canonical spellings, and a device that signed one would display a
    # correct summary over a digest it had not reproduced.
    _canon = eth.EthTransaction(
        chain_id=1, nonce=4, max_priority_fee_per_gas=1_000_000_000,
        max_fee_per_gas=30_000_000_000, gas_limit=21_000,
        to="0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", value=10**17)
    _fields = eth.rlp_decode(_canon.signing_payload()[1:])
    _fields[1] = b"\x00\x04"                    # a leading zero on the nonce
    _noncanon = bytes([eth.TX_TYPE_1559]) + eth.rlp_encode(_fields)
    d, order = make_device(presses=[CONFIRM, CONFIRM, CONFIRM],
                           frames=sign_request(sign_data=_noncanon))
    check("a payload that does not re-encode to itself is refused",
          d.run_once() == "refused")
    check("...saying the two differ", "byteforbyte" in flat(d.display.text()))
    check("...before the gate ran", not order)

    # A request aimed at somebody else's key.
    d, order = make_device(presses=[CONFIRM, CONFIRM, CONFIRM],
                           frames=sign_request(path="m/44h/60h/9h/0/0"))
    check("a request for another derivation path is refused",
          d.run_once() == "refused")
    check("...naming both paths",
          "m/44h/60h/9h/0/0" in flat(d.display.text())
          and "m/44h/60h/0h/0/0" in flat(d.display.text()))
    d, order = make_device(presses=[CONFIRM, CONFIRM, CONFIRM],
                           frames=sign_request(address=bytes(range(20))))
    check("a request naming another address is refused",
          d.run_once() == "refused")
    check("...and says whose device this is",
          d.prov.eth_address() in flat(d.display.text()))

    # The outer chain id is a caption; the inner one is signed.
    d, order = make_device(presses=[CONFIRM, CONFIRM, CONFIRM],
                           frames=sign_request(chain_id=8453))
    check("a chain id disagreeing with the payload is refused",
          d.run_once() == "refused")
    check("...saying which one is signed",
          "Onlythesecond" in flat(d.display.text()))

    # ---- the USB build variant ------------------------------------------
    #
    # Same loop, same gate, same screens; a wire instead of a lens. What is
    # checked is that nothing about the authorisation changed and that the
    # reply goes back out the way it came in rather than onto a screen nobody
    # is pointing a camera at.
    print("\n the USB link variant")
    wire_blob = build_psbt(root, "p2wpkh")
    port = lnk.FakePort(lnk.encode_message(wire_blob))
    d, order = make_device(presses=[CONFIRM] + [CONFIRM] + pin_presses()
                           + [CONFIRM, CONFIRM],
                           frames=[], link=lnk.Link(port))
    check("a PSBT arriving over the wire is signed",
          d.run_once() == "signed-psbt")
    check("the waiting screen names the cable, not the camera",
          "over the cable" in d.display.text()
          and "front of the camera" not in d.display.text())
    check("the gate still ran", any(o.startswith("gate:") for o in order))
    check("the destination was still shown in full",
          "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
          in d.display.text().replace("\n", "").replace(" ", ""))
    check("nothing was put on screen as a QR", not d.display.frames)
    # FakePort records only writes -- the request came from its script -- so
    # everything here is the device's reply.
    got = lnk.Link(lnk.FakePort(bytes(port.written))).receive().payload
    check("the reply went back down the wire",
          got.startswith(psbtmod.PSBT_MAGIC)
          and any(k[:1] == bytes([psbtmod.IN_PARTIAL_SIG])
                  for k in psbtmod.PSBT.parse(got).inputs[0]))

    # A link build with nothing on the wire must go back to idle, not hang.
    d, order = make_device(presses=[CONFIRM, CONFIRM],
                           frames=[], link=lnk.Link(lnk.FakePort(b"")))
    d.link.receive = lambda **kw: (_ for _ in ()).throw(
        lnk.LinkError("no message from the companion in 180s"))
    check("silence on the wire is a screen, not a hang",
          d.run_once() == "scan-failed")
    check("...and it says what happened",
          "companion" in d.display.text())

    # ---- every screen fits the panel ------------------------------------
    print("\n every screen fits")
    over = []
    for dev in (d, d2, d4, d5, d6, d7, d9, d11, d12):
        for s in dev.display.screens:
            if len(s) > ops.DISPLAY_ROWS or any(len(ln) > ops.DISPLAY_COLS for ln in s):
                over.append(s)
    check("no screen anywhere overflowed the display", not over)
    if over:
        print(f"      first offender: {over[0]!r}")

    print("\n" + "-" * 66)
    if FAILURES:
        print(f"FAIL — {len(FAILURES)}:")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
