#!/usr/bin/env python3
"""Resolving names — WNS, GNS and ENS — on the machine that has a network.

`firmware/names.py` is the device side, and it holds no resolver at all: the
device has no network, so the only names it draws are pairs the owner
registered. This is where those pairs come from. It reads the three registries
over plain JSON-RPC, checks what it read, and prints an address for the owner
to compare against the name's own profile page before it goes anywhere near
`provision.py name`.

    export CELL_RPC=https://your-node
    python3 tools/ethnames.py resolve alice.wei --chain 8453
    python3 tools/ethnames.py reverse 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045

ONE DEFINITION OF A NAME, and it lives in `firmware/names.py` -- imported here
rather than restated, on `companion.py`'s reasoning. Normalisation and namehash
decide which token id gets read, so a second copy of them is a tool that
resolves a different name from the one the device will label.

THREE SYSTEMS, TWO SHAPES. WNS and GNS are one contract each: the ERC-721, the
registrar and the resolver in a single deployment, keyed by `uint256(namehash)`.
ENS is a registry that hands back a resolver address, which is then asked. The
namehash is identical in all three -- EIP-137 -- so the difference is one extra
call, not a second implementation.

WHAT IT VERIFIES. Reverse lookups are forward-verified: a primary name is only
reported after resolving it back to the address that claimed it. A reverse
record is a string its own subject wrote, and an unverified one is a label an
attacker chooses. Forward lookups are checked for collisions instead -- the
name is resolved in ENS as well as in the registry its suffix routes to, and
two systems answering with two different addresses is reported rather than
resolved. Neither check is the device's, and neither is trusted by it: this
prints, the owner reads, and `provision.py name` records what the owner
approved.

WHAT IT IS NOT. Not a wallet, not a registrar, and not on the signing path.
Nothing here has a key, and nothing here is imported by firmware.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "firmware"))

import names as nm                                             # noqa: E402
from addresses import script_to_address, to_checksum_address    # noqa: E402
from hashes import keccak256                                    # noqa: E402

# Mainnet. All three are on Ethereum, which is what "Ethereum-rooted" means
# here: a `.wei` name is an L1 record whatever chain its address is spent on.
#
# READ THESE OFF THE PROJECTS THEMSELVES BEFORE YOU TRUST WHAT THIS PRINTS. A
# wrong registry address is a resolver that answers confidently with somebody
# else's mapping, and no amount of checking downstream would catch it.
CONTRACTS = {
    # https://github.com/src-company/wei-names
    "wns": "0x0000000000696760E15f265e828DB644A0c242EB",
    # https://github.com/lucadonnoh/gwei-names
    "gns": "0x9D51D507BC7264d4fE8Ad1cf7Fe191933A0a81d6",
    # The ENS registry, unchanged since 2020. Resolvers are found through it.
    "ens": "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e",
}

ZERO = "0x" + "0" * 40


class ResolveError(Exception):
    """The lookup could not be completed. Distinct from "no such name".

    An RPC that timed out and a name nobody registered are different facts, and
    only one of them is safe to report as "this name does not exist".
    """


# --------------------------------------------------------------------------
# ABI, in the small
# --------------------------------------------------------------------------
# Six calls, one argument each or two. A library for this would be larger than
# the six calls. Selectors are derived rather than pasted, and the self-test
# pins that derivation against the four interface ids ENS publishes.

def selector(sig: str) -> bytes:
    return keccak256(sig.encode())[:4]


def _uint(n: int) -> bytes:
    return n.to_bytes(32, "big")


def _addr_arg(a: str) -> bytes:
    return bytes(12) + bytes.fromhex(a.removeprefix("0x"))


def _str_arg(s: str) -> bytes:
    b = s.encode()
    return _uint(32) + _uint(len(b)) + b + bytes(-len(b) % 32)


def _as_address(out: bytes) -> str | None:
    """A 20-byte address out of a 32-byte word, or None for the zero address.

    The zero address is how all three systems say "unset", so it is folded to
    None here rather than being passed on as a payee nobody controls.
    """
    if len(out) < 32:
        return None
    a = to_checksum_address(out[12:32].hex())
    return None if a == ZERO else a


def _as_bytes(out: bytes) -> bytes:
    """The payload of a dynamic `bytes`/`string` return."""
    if len(out) < 64:
        return b""
    off = int.from_bytes(out[:32], "big")
    if off + 32 > len(out):
        return b""
    n = int.from_bytes(out[off:off + 32], "big")
    return out[off + 32:off + 32 + n]


def coin_type(chain_id: int | None) -> int:
    """The SLIP-44 coin type an EVM chain's address is published under.

    Mainnet is 60, the coin type ether itself has. Every other EVM chain is
    ENSIP-11: the chain id with the top bit set. That single rule is what lets
    one name be a payee on Base and on Arbitrum without a second name, and what
    lets it publish a DIFFERENT address there when the mainnet one would be
    wrong -- see the note on `chains` in firmware/names.py.
    """
    if chain_id is None or chain_id == 1:
        return nm.COIN_ETH
    return nm.COIN_EVM | chain_id


def decode_coin_address(coin: int, raw: bytes) -> str | None:
    """The address inside an ENSIP-9 `addr(node, coinType)` return.

    An EVM coin type carries the twenty bytes. Bitcoin carries its scriptPubkey
    -- which is the honest encoding, because a Bitcoin address is a rendering
    of a script and not a thing in its own right -- so it goes back through the
    same `script_to_address` the signer uses.
    """
    if not raw:
        return None
    if coin == nm.COIN_BTC:
        try:
            return script_to_address(raw, "mainnet")
        except Exception:                                       # noqa: BLE001
            return None
    if len(raw) != 20 or not any(raw):
        return None
    return to_checksum_address(raw.hex())


# --------------------------------------------------------------------------
# The wire
# --------------------------------------------------------------------------

def rpc_call(url: str, to: str, data: bytes, timeout: float = 20.0) -> bytes:
    """One `eth_call`. Returns b"" for a revert or an empty result.

    A revert is not an error here: asking an unregistered token id for its
    address is exactly how you find out a name is unregistered, and half the
    lookups in this file are expected to come back empty.
    """
    body = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "eth_call",
        "params": [{"to": to, "data": "0x" + data.hex()}, "latest"],
    }).encode()
    # A User-Agent because several public endpoints refuse the default one
    # Python sends, and "403" is a confusing way to learn a name does not
    # exist.
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/json", "User-Agent": "cell/ethnames"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            reply = json.loads(r.read())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        raise ResolveError(f"{url} did not answer: {e}") from None
    if "error" in reply:
        return b""
    return bytes.fromhex(reply.get("result", "0x").removeprefix("0x"))


# --------------------------------------------------------------------------
# The three systems
# --------------------------------------------------------------------------

def _registry_id(url: str, system: str, name: str) -> int:
    """`uint256(namehash(name))`, cross-checked against the contract's own.

    We compute the token id locally -- it is EIP-137, and firmware/names.py
    already has it. This asks the contract for its answer too, and refuses to
    go on if the two disagree. It costs one call and it is the only thing that
    would catch a normalisation difference between this tool and the deployment
    it is reading, which is a difference that resolves the wrong name in
    silence.
    """
    local = int.from_bytes(nm.namehash(name), "big")
    out = rpc_call(url, CONTRACTS[system],
                   selector("computeId(string)") + _str_arg(name))
    if out:
        onchain = int.from_bytes(out[:32], "big")
        if onchain != local:
            raise ResolveError(
                f"{system.upper()} computes a different token id for {name!r} "
                f"than this tool does. Nothing was resolved.")
    return local


def resolve_in(url: str, system: str, name: str,
               chain_ids: tuple[int, ...] = ()) -> dict:
    """Every address one system publishes for one name.

    Returns {"eth": ..., "btc": ..., "chains": {id: address}}, with None and
    absent entries meaning the name published nothing there.
    """
    if system == "ens":
        return _resolve_ens(url, name, chain_ids)
    tid = _registry_id(url, system, name)
    at = CONTRACTS[system]

    def coin(cid: int | None):
        c = coin_type(cid)
        raw = _as_bytes(rpc_call(url, at, selector("addr(uint256,uint256)")
                                 + _uint(tid) + _uint(c)))
        return decode_coin_address(c, raw)

    # `resolve(uint256)` is the registries' shorthand for coin type 60, and it
    # falls back to the token's owner when no address was set -- so a freshly
    # registered name still names its holder. Asked first for that reason.
    eth = _as_address(rpc_call(url, at, selector("resolve(uint256)") + _uint(tid)))
    return {"eth": eth or coin(None), "btc": coin(nm.COIN_BTC),
            "chains": {c: a for c in chain_ids if (a := coin(c))}}


def _resolve_ens(url: str, name: str, chain_ids: tuple[int, ...]) -> dict:
    """ENS, through the registry to whatever resolver the name points at."""
    node = nm.namehash(name)
    resolver = _as_address(rpc_call(url, CONTRACTS["ens"],
                                    selector("resolver(bytes32)") + node))
    if resolver is None:
        return {"eth": None, "btc": None, "chains": {}}

    def coin(cid: int | None):
        c = coin_type(cid)
        raw = _as_bytes(rpc_call(url, resolver, selector("addr(bytes32,uint256)")
                                 + node + _uint(c)))
        return decode_coin_address(c, raw)

    eth = _as_address(rpc_call(url, resolver, selector("addr(bytes32)") + node))
    return {"eth": eth or coin(None), "btc": coin(nm.COIN_BTC),
            "chains": {c: a for c in chain_ids if (a := coin(c))}}


def reverse_in(url: str, system: str, address: str) -> str | None:
    """The primary name one system holds for an address, unverified."""
    if system == "ens":
        node = nm.namehash(f"{address.removeprefix('0x').lower()}.addr.reverse")
        resolver = _as_address(rpc_call(url, CONTRACTS["ens"],
                                        selector("resolver(bytes32)") + node))
        if resolver is None:
            return None
        raw = _as_bytes(rpc_call(url, resolver, selector("name(bytes32)") + node))
    else:
        raw = _as_bytes(rpc_call(url, CONTRACTS[system],
                                 selector("reverseResolve(address)")
                                 + _addr_arg(address)))
    try:
        return nm.normalize(raw.decode()) if raw else None
    except (UnicodeDecodeError, nm.BadName):
        # A reverse record is a string its subject chose. One this device could
        # not render is not an error, it is a record we decline to repeat.
        return None


# --------------------------------------------------------------------------
# What a caller actually asks for
# --------------------------------------------------------------------------

@dataclass
class Lookup:
    """What resolved, in which system, and what else claimed the same name."""

    name: str
    system: str
    eth: str | None = None
    btc: str | None = None
    chains: dict = field(default_factory=dict)
    # Every other system that answered for this name with a DIFFERENT address.
    # Not an error and not resolved either: two registries can legitimately
    # both hold `alice.example`, and which one the owner meant is not something
    # a tool can know.
    collisions: dict = field(default_factory=dict)

    @property
    def found(self) -> bool:
        return bool(self.eth or self.btc or self.chains)


def resolve(url: str, name: str, chain_ids: tuple[int, ...] = ()) -> Lookup:
    """Resolve a name in the system its suffix routes to, and check for a rival.

    The rival is always ENS, and only ENS: `.wei` and `.gwei` are claimed
    suffixes that ENS's root could in principle also carry, while `.eth` is
    reserved and no registry may take it. So at most one extra lookup, and it
    exists so that a name answered by two systems is reported instead of being
    resolved by whichever was asked first.
    """
    canonical = nm.normalize(name)
    system = nm.system_of(canonical)
    out = resolve_in(url, system, canonical, chain_ids)
    found = Lookup(name=canonical, system=system, eth=out["eth"],
                   btc=out["btc"], chains=out["chains"])
    if system != "ens":
        rival = resolve_in(url, "ens", canonical, chain_ids)
        if rival["eth"] and rival["eth"] != found.eth:
            found.collisions["ens"] = rival["eth"]
    return found


def reverse(url: str, address: str) -> tuple[str | None, dict]:
    """An address's primary name, forward-verified, WNS first.

    Returns (name, every candidate seen). A name is only returned after it
    resolves back to this address: an ENS reverse record is not self-validating
    -- anyone may point one at any name -- and a registry's is only as good as
    the forward record behind it. An unverified claim is reported in the
    candidates and never as the answer.
    """
    address = to_checksum_address(address)
    seen: dict[str, tuple[str, bool]] = {}
    answer = None
    for system in nm.SYSTEMS:
        claimed = reverse_in(url, system, address)
        if not claimed:
            continue
        back = resolve_in(url, system, claimed)["eth"]
        verified = back is not None and back.lower() == address.lower()
        seen[system] = (claimed, verified)
        if verified and answer is None:
            answer = claimed
    return answer, seen


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _url(args) -> str:
    url = args.rpc or os.environ.get("CELL_RPC")
    if not url:
        raise SystemExit("no RPC endpoint: pass --rpc, or set CELL_RPC")
    return url


def cmd_resolve(args) -> int:
    chain_ids = tuple(int(c) for c in args.chain)
    try:
        found = resolve(_url(args), args.name, chain_ids)
    except (nm.BadName, ResolveError) as e:
        print(f"Refused: {e}")
        return 1
    if not found.found:
        print(f"{found.name} is not registered in "
              f"{found.system.upper()}, or publishes no address.")
        return 1
    print(f"{found.name}  ({found.system.upper()})")
    if found.eth:
        print(f"  ethereum, and every EVM chain below that has no entry")
        print(f"    {found.eth}")
    for cid, addr in sorted(found.chains.items()):
        print(f"  chain {cid}, published by the name itself")
        print(f"    {addr}")
    if found.btc:
        print(f"  bitcoin")
        print(f"    {found.btc}")
    for system, addr in found.collisions.items():
        print(f"\n  ALSO CLAIMED: {system.upper()} resolves this name to")
        print(f"    {addr}")
        print("  Two systems, two addresses. Neither is more correct than the")
        print("  other; decide which one you meant before registering it.")
    print("\nCheck this against the name's own page before you register it.")
    return 0


def cmd_reverse(args) -> int:
    try:
        answer, seen = reverse(_url(args), args.address)
    except (ValueError, ResolveError) as e:
        print(f"Refused: {e}")
        return 1
    for system, (claimed, verified) in seen.items():
        mark = "verified" if verified else "NOT VERIFIED -- does not resolve back"
        print(f"  {system.upper():<4} {claimed:<34} {mark}")
    if answer is None:
        print(f"\n{args.address} has no verified primary name.")
        return 1
    print(f"\n{args.address} is {answer}")
    return 0


def _selftest() -> int:
    """Offline. The encoding, the coin types, and the selector derivation.

    Everything above that needs a network is untestable here by construction,
    which is the point of keeping the parts that do not need one separable.
    """
    ok = True

    def check(label, good):
        nonlocal ok
        ok &= bool(good)
        print(f"  {label}{'' if good else '   <-- UNEXPECTED'}")

    # ENS publishes these four as interface ids, and WNS advertises the same
    # four in `supportsInterface`. They are the only published check on the
    # selector derivation that also produces the registries' own.
    print("selectors, against the interface ids ENS and WNS publish")
    for sig, want in (("addr(bytes32)", "3b3b57de"),
                      ("addr(bytes32,uint256)", "f1cb7e06"),
                      ("text(bytes32,string)", "59d1d43c"),
                      ("contenthash(bytes32)", "bc1c58d1"),
                      ("resolver(bytes32)", "0178b8bf"),
                      ("name(bytes32)", "691f3431")):
        check(f"{sig:<22} 0x{want}", selector(sig).hex() == want)

    print("\nENSIP-11: which coin type a chain's address lives under")
    check("mainnet is coin type 60", coin_type(1) == 60)
    check("no chain given is coin type 60", coin_type(None) == 60)
    check("Base (8453) is 0x80002105", coin_type(8453) == 0x8000_2105)
    check("Arbitrum (42161) is 0x8000a4b1", coin_type(42161) == 0x8000_A4B1)

    print("\nargument encoding")
    check("a uint is one word", _uint(60) == bytes(31) + b"\x3c")
    check("an address is left-padded",
          _addr_arg("0x" + "11" * 20) == bytes(12) + b"\x11" * 20)
    check("a string is offset, length, then padded bytes",
          _str_arg("alice.wei") == _uint(32) + _uint(9)
          + b"alice.wei" + bytes(23))

    print("\nreturn decoding")
    check("a word decodes to a checksummed address",
          _as_address(bytes(12) + bytes.fromhex(
              "d8da6bf26964af9d7eed9e03e53415d37aa96045"))
          == "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045")
    check("the zero address decodes to nothing", _as_address(bytes(32)) is None)
    check("a short return decodes to nothing", _as_address(b"\x00") is None)
    check("a dynamic return yields its payload",
          _as_bytes(_str_arg("alice.wei")) == b"alice.wei")
    check("a truncated dynamic return yields nothing",
          _as_bytes(_uint(32) + _uint(9)) == b"")
    check("an out-of-range offset yields nothing",
          _as_bytes(_uint(1 << 40) + _uint(9)) == b"")

    # ENSIP-9 stores a Bitcoin address as its scriptPubkey. This is the one
    # from BIP-173's own vectors, so the decode is pinned to a published pair
    # rather than to whatever addresses.py happens to do.
    print("\nENSIP-9: a bitcoin address arrives as a script")
    script = bytes.fromhex("0014751e76e8199196d454941c45d1b3a323f1433bd6")
    check("a P2WPKH scriptPubkey decodes to its bech32 address",
          decode_coin_address(nm.COIN_BTC, script)
          == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    check("20 raw bytes on an EVM coin type are the address",
          decode_coin_address(60, b"\x11" * 20) == "0x" + "11" * 20)
    check("an empty record is no address",
          decode_coin_address(60, b"") is None)
    check("a malformed EVM record is no address",
          decode_coin_address(60, b"\x11" * 19) is None)
    check("an all-zero EVM record is no address",
          decode_coin_address(60, bytes(20)) is None)
    check("an unparseable script is no address",
          decode_coin_address(nm.COIN_BTC, b"\xff\xff") is None)

    print("\n" + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("resolve", help="a name to the addresses it publishes")
    p.add_argument("name", help="in full, with its suffix: alice.wei")
    p.add_argument("--rpc", help="JSON-RPC endpoint; or set CELL_RPC")
    p.add_argument("--chain", action="append", default=[], metavar="ID",
                   help="also read the address this name publishes for this "
                        "EVM chain (ENSIP-11). Repeatable.")
    p.set_defaults(fn=cmd_resolve)

    p = sub.add_parser("reverse", help="an address to its primary name")
    p.add_argument("address")
    p.add_argument("--rpc", help="JSON-RPC endpoint; or set CELL_RPC")
    p.set_defaults(fn=cmd_reverse)

    p = sub.add_parser("selftest", help="the offline half: encoding and coins")
    p.set_defaults(fn=lambda _: _selftest())

    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
