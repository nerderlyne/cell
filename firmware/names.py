"""Ethereum-rooted names — WNS, GNS and ENS, as things this device was told.

A name is not a shorter address. It is a claim, held by a contract on Ethereum
mainnet, that some label points at some bytes. This device cannot read that
contract. It has no network, and that is the whole design. So names follow the
rule CHAINS and TOKENS already follow, for the same reason:

    THE NAME NEVER ARRIVES WITH THE TRANSACTION.

An attacker who can label 0xBAD as "vitalik.eth" on the confirmation screen
does not have to beat a gate. The owner reads a name they recognise and presses
CONFIRM on somebody else's address. So a request carries addresses and nothing
else, and the only names this device will draw are ones the owner resolved,
checked and registered with `tools/provision.py name`. What is on the screen is
then the owner's own claim, with the same standing as a registered token
symbol.

AND THE NAME NEVER REPLACES THE ADDRESS. It goes above it, and the address is
still rendered in full underneath. A name here is a recognition aid for a payee
the owner has already approved once. The address is what is being confirmed,
and it is what the signature commits to.

THREE SYSTEMS, ONE ROOT. WNS (`.wei`) and GNS (`.gwei`) are single ERC-721
contracts on mainnet that are their own registrar and resolver; ENS is a
registry with resolvers behind it. All three hash a name identically -- EIP-137
namehash -- and all three answer for other chains and other coins through the
same SLIP-44 coin types. That is why one module covers all three: the
difference is a suffix and a contract address, and the contract addresses live
in `tools/ethnames.py`, which is the half of this that has a network.

PREFERENCE ORDER: WNS, then GNS, then ENS. It settles exactly one question --
which name to draw when the owner has registered several for one address -- and
something has to settle it, or the screen changes with dictionary order. This
project co-developed WNS, so the order is an admitted bias and not a ranking of
trust. It cannot change what an address is; every candidate in that tie is a
name the owner registered against the same bytes.

NO BARE LABELS. `alice` is a name in both WNS and GNS, pointing at two
different people, and a wallet that picks one is a wallet that picks wrong
half the time. Registration takes the name in full, suffix included.

ASCII ONLY, LOWERCASE. A label carrying a Cyrillic "a" renders as a Latin one
on a 40-column screen, which turns the recognition aid into the attack. ENSIP-15
is how the ecosystem normalises the rest of Unicode; the honest thing for a
device that has to be read across a room is to refuse what it cannot render
unambiguously.
"""

from __future__ import annotations

from dataclasses import dataclass

from addresses import (BadAddress, script_to_address, to_checksum_address,
                       valid_checksum_address)
from hashes import keccak256


class BadName(ValueError):
    """A name, or a registration, this device will not display."""


# Most preferred first. See the note on preference order above: this breaks
# display ties and does nothing else.
SYSTEMS = ("wns", "gns", "ens")

# The suffix each registry claims. Longest match wins, so `.gwei` is never read
# as a `.wei` name -- the two are one character apart and one of them is ours.
SUFFIXES = {".wei": "wns", ".gwei": "gns"}

# `.eth` is ENS's and no registry may take it. Rerouting the one name in the
# ecosystem that users are least likely to double-check is a phishing
# primitive, not a configuration choice.
RESERVED = (".eth",)

# SLIP-44 coin types, and the ENSIP-11 base an EVM chain's type is built from.
# A name publishes one address per coin type, so these are how "the same name
# on another chain" and "the same name on Bitcoin" are asked for.
COIN_BTC = 0
COIN_ETH = 60
COIN_EVM = 0x8000_0000        # | chain_id, per ENSIP-11

# `  to  ` is six columns of the forty ops.py has, and the address underneath
# needs the rest. A name longer than this would wrap, and a payee name that
# wraps is a payee name that can be made to read as another one. Enforced at
# registration rather than in `normalize`, because it is a fact about this
# screen and not about names: `namehash` has to be able to hash the 45-character
# `<address>.addr.reverse` that ENS reverse records live under.
MAX_NAME = 32

# What a label may contain, after normalisation. Deliberately narrower than
# either registry allows on chain -- see the note on ASCII at the top.
ALLOWED = set("abcdefghijklmnopqrstuvwxyz0123456789-_")


def normalize(name: str) -> str:
    """The canonical form of a name, or raise.

    Lowercase, trimmed, and checked label by label. This is the only place a
    name is turned into the string everything else compares and hashes, so a
    name that survives here is one `namehash` and the screen agree about.
    """
    if not isinstance(name, str):
        raise BadName("a name must be a string")
    out = name.strip().lower()
    if not out:
        raise BadName("a name cannot be empty")
    labels = out.split(".")
    for label in labels:
        if not label:
            raise BadName(f"{name!r} has an empty label")
        bad = sorted(set(label) - ALLOWED)
        if bad:
            raise BadName(
                f"{name!r} contains {''.join(bad)!r}, which this device will "
                f"not render: a name it cannot draw unambiguously is a name "
                f"it must not draw at all")
    return out


def system_of(name: str) -> str:
    """Which system a name belongs to, from its shape alone. No network.

    Suffix claims win, longest first, and everything else dotted is ENS --
    which is the fallback because ENS's root is the one that keeps growing, and
    a device that refused `.box` today would be wrong tomorrow. A bare label
    has no answer, so it raises rather than guessing between two registries.
    """
    norm = normalize(name)
    for suffix in sorted(SUFFIXES, key=len, reverse=True):
        if norm.endswith(suffix) and len(norm) > len(suffix):
            return SUFFIXES[suffix]
    if "." not in norm:
        raise BadName(
            f"{name!r} is a bare label. It is a name in more than one system, "
            f"pointing at more than one person; register it in full, with its "
            f"suffix.")
    return "ens"


def namehash(name: str) -> bytes:
    """EIP-137 namehash. WNS and GNS use it as the ERC-721 token id.

    Here rather than in the resolver because it is pure, it is eight lines, and
    the alternative is two copies of it -- the failure `companion.py` and
    `link.py` avoid one layer down. The self-test pins it to the node constants
    all three systems publish, so a wrong answer is a failed suite and not a
    lookup against the wrong token.
    """
    node = bytes(32)
    if name:
        for label in reversed(normalize(name).split(".")):
            node = keccak256(node + keccak256(label.encode()))
    return node


@dataclass(frozen=True)
class Name:
    """One name the owner registered, and the addresses under it.

    WHY THERE ARE THREE ADDRESS FIELDS AND NOT ONE. A name is rooted on
    Ethereum mainnet, but what it points at is not all one chain and not all
    one coin:

      `eth`     coin type 60. The default EVM address, used on every EVM chain
                the owner sends on -- which is what makes `alice.wei` a payee
                on Base and on Arbitrum without a second registration.
      `chains`  ENSIP-11 per-chain addresses, which override `eth` on the chain
                they name. Not decoration: a name can be an EOA on mainnet and
                a contract on Base, and the same twenty bytes on two chains can
                belong to two people. When the name publishes an override, the
                default is wrong there, and this device must know it.
      `btc`     coin type 0. A Bitcoin address the name publishes, so a `.wei`
                name is a payee on Bitcoin too. It is a separate record, never
                derived from the EVM address -- nothing derives one from the
                other, and a device that pretended otherwise would be inventing
                an address nobody controls.
    """

    name: str
    system: str
    eth: str | None = None
    btc: str | None = None
    chains: tuple[tuple[int, str], ...] = ()


# {canonical name: Name}. Empty on a fresh device, and filled from the
# provisioning record at boot -- see tools/provision.py name.
NAMES: dict[str, Name] = {}


def _key(address: str) -> str:
    """The form two addresses are compared in.

    EVM addresses are case-insensitive hex with a checksum in the
    capitalisation, so they fold. Bitcoin addresses do NOT: base58 carries
    information in its case, and lowercasing one produces a string that is not
    an address. So the fold is applied to the one that can take it and withheld
    from the one that cannot, which is the whole of the difference between the
    two chains here.
    """
    return address.lower() if address[:2].lower() == "0x" else address


def register_name(name: str, system: str, eth: str | None = None,
                  btc: str | None = None,
                  chains: dict[int, str] | None = None) -> Name:
    """Record one name the owner resolved and checked. Provisioning only.

    Re-registering identically is a no-op; re-registering differently is
    refused, exactly as for a token. A name that could be quietly repointed by
    a second run is a name that means nothing on screen -- and unlike a token
    symbol, the thing being repointed is where the money goes.
    """
    norm = normalize(name)
    if len(norm) > MAX_NAME:
        raise BadName(
            f"{name!r} is longer than {MAX_NAME} characters and would not fit "
            f"on the line above the address it names")
    routed = system_of(norm)
    if system != routed:
        raise BadName(
            f"{norm!r} is a {routed.upper()} name by its suffix, not "
            f"{str(system).upper()}. The suffix decides, or a name could be "
            f"registered against a system that never issued it.")
    if system not in SYSTEMS:
        raise BadName(f"unknown name system {system!r}")

    checked: dict[int, str] = {}
    for chain_id, addr in sorted((chains or {}).items()):
        if not isinstance(chain_id, int) or isinstance(chain_id, bool):
            raise BadName("a chain id must be an integer")
        # Imported here rather than at the top: ops.py draws every screen and
        # needs this module, and eth.py pulls in the curve. A per-chain address
        # is checked against the chains the owner registered for the same
        # reason a token is -- a typo'd chain id is an override that silently
        # never applies, and the owner sends to the mainnet address on Base
        # believing they had overridden it.
        import eth as ethmod
        if chain_id not in ethmod.CHAINS:
            raise BadName(
                f"chain {chain_id} is not registered on this device, so an "
                f"address for {norm} on it could never be displayed. Register "
                f"the chain first with `tools/provision.py chain`.")
        checked[chain_id] = _valid_eth(addr, f"{norm} on chain {chain_id}")

    record = Name(name=norm, system=system,
                  eth=_valid_eth(eth, norm) if eth else None,
                  btc=_valid_btc(btc, norm) if btc else None,
                  chains=tuple(sorted(checked.items())))
    if record.eth is None and record.btc is None and not record.chains:
        raise BadName(
            f"{norm} resolves to nothing this device could display. A name "
            f"with no address is not a payee.")
    existing = NAMES.get(norm)
    if existing is not None and existing != record:
        raise BadName(
            f"{norm} is already registered on this device against different "
            f"addresses; refusing to repoint it")
    NAMES[norm] = record
    return record


def _valid_eth(addr: str, what: str) -> str:
    if not valid_checksum_address(addr):
        raise BadName(
            f"{addr!r} for {what} is not a valid address, or its EIP-55 "
            f"checksum does not match its capitalisation")
    if int(addr.removeprefix("0x"), 16) == 0:
        raise BadName(f"{what} resolves to the zero address, which burns funds")
    return to_checksum_address(addr)


def _valid_btc(addr: str, what: str) -> str:
    """A Bitcoin address, checked by round-tripping it through its script.

    `addresses.address_to_script` is what the signer itself uses, so a name
    that registers cleanly here carries an address the spending path can
    actually pay -- rather than one that parses today and raises while the
    owner is holding a lancet.
    """
    from addresses import address_to_script
    for network in ("mainnet", "testnet", "regtest"):
        try:
            if script_to_address(address_to_script(addr, network),
                                 network) == addr:
                return addr
        except (BadAddress, ValueError):
            continue
    raise BadName(f"{addr!r} for {what} is not a Bitcoin address")


def address_for(name: str, chain_id: int | None = None) -> str | None:
    """The EVM address a registered name pays on one chain, or None.

    A per-chain override wins over the default; `chain_id=None` asks for the
    default itself, which is what the name is on Ethereum mainnet and on every
    chain that published nothing more specific.
    """
    record = NAMES.get(normalize(name))
    if record is None:
        return None
    if chain_id is not None:
        for cid, addr in record.chains:
            if cid == chain_id:
                return addr
    return record.eth


def btc_address_for(name: str) -> str | None:
    """The Bitcoin address a registered name pays, or None."""
    record = NAMES.get(normalize(name))
    return record.btc if record else None


def name_for(address: str, chain_id: int | None = None) -> str | None:
    """The owner's own name for an address, or None. Both chains, one call.

    THE REVERSE DIRECTION OBEYS THE OVERRIDES. An address that is the name's on
    mainnet is not the name's on a chain where the name published a different
    one, so this asks `address_for` per chain rather than matching the default
    everywhere. Getting that backwards would draw a familiar name over an
    address the name has explicitly disowned on the chain being signed for.

    A linear scan, over a list the owner typed by hand. An index would be
    faster and would be one more thing that can disagree with the record it was
    built from.
    """
    if not isinstance(address, str) or not address:
        return None
    key = _key(address)
    bitcoin = key[:2].lower() != "0x"
    hits = [n for n in NAMES.values()
            if (n.btc if bitcoin else address_for(n.name, chain_id))
            and _key(n.btc if bitcoin else address_for(n.name, chain_id)) == key]
    if not hits:
        return None
    # WNS, then GNS, then ENS, then alphabetically. See the note on preference
    # order at the top: this is a display tie-break among names the owner
    # registered against the same bytes, and it has to be deterministic or the
    # same screen renders differently on two boots.
    hits.sort(key=lambda n: (SYSTEMS.index(n.system), n.name))
    return hits[0].name


def _selftest() -> int:
    ok = True

    def check(label, good):
        nonlocal ok
        ok &= bool(good)
        print(f"  {label}{'' if good else '   <-- UNEXPECTED'}")

    # The node constants WNS, GNS and ENS each publish, which makes them
    # vectors rather than numbers somebody typed.
    print("EIP-137 namehash, against each system's published node")
    check("namehash('') is the zero node", namehash("") == bytes(32))
    check("namehash('eth')  = 0x93cd...c4ae", namehash("eth").hex() ==
          "93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae")
    check("namehash('wei')  = 0xa828...bd6f", namehash("wei").hex() ==
          "a82820059d5df798546bcc2985157a77c3eef25eba9ba01899927333efacbd6f")
    check("namehash('gwei') = 0xcca9...7d7f", namehash("gwei").hex() ==
          "cca9c7f2dbe2808af0de2982fc84314bfa68a82a6a60ad5cd757f91a233d7d7f")
    check("namehash('foo.eth') matches EIP-137", namehash("foo.eth").hex() ==
          "de9b09fd7c5f901e23a3f19fecc54828e9c848539801e86591bd9801b019f84f")
    check("a name hashes as its normalised form",
          namehash("Alice.WEI") == namehash("alice.wei"))

    print("\nrouting, from the shape alone")
    for name, want in (("alice.wei", "wns"), ("alice.gwei", "gns"),
                       ("vitalik.eth", "ens"), ("alice.box", "ens"),
                       ("sub.alice.wei", "wns")):
        check(f"{name:<14} -> {want}", system_of(name) == want)
    check(".gwei is not read as .wei", system_of("a.gwei") == "gns")
    check("the suffix alone is not a name", _raises(system_of, ".wei"))
    check("a bare label is refused", _raises(system_of, "alice"))
    check("a Cyrillic homograph is refused",
          _raises(normalize, "vitalik.еth"))
    check("a long name hashes but does not register",
          len(nm_long := "a" * MAX_NAME + ".wei") > MAX_NAME
          and namehash(nm_long) != bytes(32))

    NAMES.clear()
    A = "0x1111111111111111111111111111111111111111"
    B = "0x2222222222222222222222222222222222222222"
    BTC = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    # Base is built in, so the override below lands on a chain this device
    # can already name. 999 below is not, which is the case that must refuse.
    register_name("alice.wei", "wns", eth=A, btc=BTC, chains={8453: B})
    register_name("alice.eth", "ens", eth=A)

    print("\nforward: one name, three answers")
    check("mainnet default          -> A", address_for("alice.wei") == A)
    check("an unoverridden chain    -> A", address_for("alice.wei", 1) == A)
    check("the chain with a record  -> B", address_for("alice.wei", 8453) == B)
    check("bitcoin                  -> bc1q...", btc_address_for("alice.wei") == BTC)
    check("an unregistered name has no address", address_for("bob.wei") is None)

    print("\nreverse: what the screen draws over an address")
    check("WNS wins the tie over ENS", name_for(A) == "alice.wei")
    check("EIP-55 capitalisation folds", name_for(A.lower()) == "alice.wei")
    check("the override is named on its own chain",
          name_for(B, 8453) == "alice.wei")
    # A is still alice.eth's address on Base -- that name published no
    # override -- so the two rules show up on one line: alice.wei has disowned
    # A there, and the name drawn is the one that has not.
    check("the default is NOT the overriding name on its chain",
          name_for(A, 8453) == "alice.eth")
    check("the override is not the name off its chain", name_for(B) is None)
    check("a bitcoin address reverses too", name_for(BTC) == "alice.wei")
    check("an unknown address gets no name", name_for(B, 1) is None)

    print("\nregistration refuses what it cannot stand behind")
    check("a system that disagrees with the suffix",
          _raises(register_name, "alice.wei", "ens", eth=A))
    check("a name with no addresses at all",
          _raises(register_name, "empty.wei", "wns"))
    check("the zero address", _raises(register_name, "zero.wei", "wns",
                                      eth="0x" + "0" * 40))
    check("an address whose checksum does not match",
          _raises(register_name, "bad.wei", "wns",
                  eth="0xD8dA6BF26964aF9D7eEd9e03E53415D37aA96045"))
    check("an override on an unregistered chain",
          _raises(register_name, "far.wei", "wns", eth=A, chains={999: B}))
    check("not a bitcoin address",
          _raises(register_name, "nb.wei", "wns", btc="bc1qnotanaddress"))
    check("a name too long for the line above the address",
          _raises(register_name, "a" * MAX_NAME + ".wei", "wns", eth=A))
    register_name("alice.wei", "wns", eth=A, btc=BTC, chains={8453: B})
    check("an identical repeat is a no-op", len(NAMES) == 2)
    check("a silent repointing is refused",
          _raises(register_name, "alice.wei", "wns", eth=B))
    check("a refused registration is not recorded",
          address_for("alice.wei") == A and "zero.wei" not in NAMES)
    NAMES.clear()

    # The claim this whole module rests on, checked against the parser that
    # has to enforce it. `ops.parse` refuses a field no operation declares, so
    # there is no way for a request to carry a name -- and if some later
    # operation ever grows a `name` field, this fails.
    print("\nthe rule underneath all of it: a name cannot arrive with a request")
    import ops
    payload = {"type": "eth_spend", "amount_wei": 1, "destination": A, "chain_id": 1,
               "chain_name": "Ethereum", "nonce": 0, "max_fee_wei": 1}
    check("the request without one renders", bool(ops.parse(payload).render()))
    try:
        ops.parse({**payload, "name": "alice.wei"})
        named = False
    except ops.UnrenderableOperation:
        named = True
    check("the same request carrying a name is refused", named)

    print("\n" + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def _raises(fn, *a, **kw) -> bool:
    try:
        fn(*a, **kw)
    except BadName:
        return True
    return False


if __name__ == "__main__":
    raise SystemExit(_selftest())
