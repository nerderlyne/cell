"""Ethereum — RLP, EIP-1559 transactions, and the signing hash.

An Ethereum signature commits to the chain id, the nonce, both gas prices, the
gas limit, the recipient, the value and the calldata. All of it. A device that
signs "send 1 ETH to Alice" without committing to the rest is not signing what
the owner read: the same authorisation replays on another chain, or at a gas
limit that drains the account in fees, or with calldata that does something
else entirely.

So this module builds the whole transaction on the device, from fields the
device displays, and hashes what it built. It never accepts a digest to sign,
because a digest is exactly the thing the owner cannot read.

TYPE 2 (EIP-1559) ONLY. Legacy and EIP-2930 transactions are still valid on
chain, but supporting three encodings triples the surface for a device whose
whole argument is that it renders what it signs. Every chain CELL targets has
supported type 2 since 2021.

ONE SHAPE OF CALLDATA, AND THE DEVICE WRITES IT ITSELF. Arbitrary EVM calldata
cannot be rendered as a sentence the owner can evaluate — that is the scope
decision in BUILD.md section 5, and this module enforces it. The single
exception is an ERC-20 `transfer(address,uint256)` to a token registered by the
owner, and the exception is safe because of how it is taken:

    The device is never handed calldata. It is handed a token, a recipient and
    an amount, and it ENCODES the 68 bytes itself.

That inverts the usual risk. A device that decodes calldata has to be right
about every way 68 attacker-chosen bytes can be malformed, and a device that
encodes it has to be right about one function. `__post_init__` then decodes
what was built and checks it round-trips, so the path that reads calldata is
exercised on every transaction without ever being the path that trusts it.

The token's symbol and decimals come from `TOKENS`, which is registered out of
band exactly as `CHAINS` is, and for the identical reason: `decimals` is a
denomination. An attacker who supplies it supplies where the decimal point
goes, and "1000000 units" is one USDC or one million depending on a number
nobody can read off the screen.
"""

from __future__ import annotations

from dataclasses import dataclass

import secp256k1 as ec
from addresses import BadAddress, to_checksum_address, valid_checksum_address
from hashes import keccak256

TX_TYPE_1559 = 0x02

# Chain ids the device will sign for, as (name, ticker), so the display can say
# "Ethereum" and "ETH" rather than "chain 1" and a denomination it guessed —
# and so an unknown chain is a refusal rather than a number the owner cannot
# evaluate.
#
# Only chains this project can name without being told are built in. Every
# other EVM chain is registered by the owner, out of band, with
# `tools/provision.py chain`. That is the whole design, not a shortcut:
#
#   The name and the ticker are the only parts of the confirmation screen that
#   say WHICH NETWORK and WHICH DENOMINATION the owner is consenting to. The
#   signature commits to the chain id, but nobody reads a chain id. So those
#   two strings must never arrive with the transaction — an attacker who can
#   label chain 1 "Sepolia (test)" collects a signature on real money from an
#   owner who believed they were spending testnet play money, and one who can
#   label chain 137 "Ethereum" moves the owner onto the wrong network entirely.
#
# Registering it yourself makes the label your own claim rather than the
# coordinator's, which is the same argument that makes multisig quorums
# registration-only. It also means the firmware never has to assert that some
# chain's native token is ETH when it is not.
# WHAT EARNS A PLACE IN THIS TABLE. Not popularity. A chain is built in when
# the account contracts CELL signs for are deployed on it at the addresses
# BUILD.md quotes, so that an owner who registers a smart account has a chain
# already named for it and never has to type a chain id to get started. That
# set is Ethereum, Base and Robinhood, plus Sepolia to rehearse on. The rest of
# the deployment's chains -- Arbitrum, OP, MegaETH, Base Sepolia -- are one
# `provision.py chain` away and deliberately left there: a device that ships
# knowing every chain is a device whose chain names are somebody else's claim.
#
# All four are denominated in ETH. That is the only reason a ticker can be
# asserted here rather than asked for; an L2 with its own gas token would have
# to be registered by its owner like any other.
CHAINS: dict[int, tuple[str, str]] = {
    1: ("Ethereum", "ETH"),
    8453: ("Base", "ETH"),
    4663: ("Robinhood", "ETH"),
    11155111: ("Sepolia (test)", "tETH"),
}

# The name has to fit "SEND ON <NAME>" inside ops.DISPLAY_COLS (40), and the
# ticker has to sit after an amount without wrapping it. Both are also held to
# printable ASCII: a right-to-left override or a zero-width joiner in a chain
# name is a label that renders as something other than what was registered.
MAX_CHAIN_NAME = 24
MAX_TICKER = 8


def register_chain(chain_id: int, name: str, ticker: str) -> None:
    """Teach this device one more chain, by name and native-token ticker.

    PROVISIONING ONLY. Never call this with anything that arrived alongside a
    transaction — see the note on CHAINS above for what that would cost. The
    device loads registrations from its provisioning record at boot, which is
    written with the case open by someone holding the device.

    Re-registering a built-in chain is refused outright. Everything else is
    idempotent for an identical repeat and a refusal for a conflicting one, so
    a second registration can never silently rename a chain the owner has
    already been reading on screen.
    """
    if not isinstance(chain_id, int) or isinstance(chain_id, bool) or chain_id < 1:
        raise BadEthTransaction("chain id must be a positive integer")
    if chain_id in BUILTIN_CHAINS:
        raise BadEthTransaction(
            f"chain {chain_id} is built in as {BUILTIN_CHAINS[chain_id][0]!r} "
            f"and cannot be relabelled")
    for label, value, cap in (("name", name, MAX_CHAIN_NAME),
                              ("ticker", ticker, MAX_TICKER)):
        if not isinstance(value, str) or not value.strip():
            raise BadEthTransaction(f"chain {label} must be a non-empty string")
        if value != value.strip():
            raise BadEthTransaction(f"chain {label} has leading or trailing space")
        if len(value) > cap:
            raise BadEthTransaction(
                f"chain {label} {value!r} is longer than {cap} characters and "
                f"would not fit the confirmation screen")
        if any(c < " " or c > "~" for c in value):
            raise BadEthTransaction(
                f"chain {label} {value!r} has characters outside printable "
                f"ASCII; the owner cannot trust what such a label renders as")
    existing = CHAINS.get(chain_id)
    if existing is not None and existing != (name, ticker):
        raise BadEthTransaction(
            f"chain {chain_id} is already registered as {existing[0]!r} "
            f"({existing[1]}); refusing to rename it to {name!r} ({ticker})")
    CHAINS[chain_id] = (name, ticker)


BUILTIN_CHAINS = dict(CHAINS)

# --------------------------------------------------------------------------
# ERC-20 tokens
# --------------------------------------------------------------------------

# {(chain_id, contract address lowercased): (symbol, decimals)}.
#
# NOTHING IS BUILT IN, and that is not laziness. A chain can be named from its
# id by anyone who reads the registry, and this project can assert that chain 1
# is Ethereum. A token contract cannot be named that way: `0xA0b8...eB48` is
# USDC on Ethereum because Circle says so, and a device that shipped with that
# mapping would be asserting a fact about someone else's deployment on every
# chain its owner later registered. So the owner registers each one, having
# checked the address against a source they trust, and the label is then their
# claim. Same rule as CHAINS, same rule as a multisig quorum.
#
# Keyed on the chain as well as the address because the same address is a
# different contract on different chains, and a token registered on Ethereum
# must not silently name a contract on Base.
TOKENS: dict[tuple[int, str], tuple[str, int]] = {}

# A symbol has to sit after an amount without wrapping the line, on the same
# reasoning as MAX_TICKER. 18 decimals is ether's own scale and the practical
# ceiling; 36 is where a fixed-point amount stops fitting a screen at all.
MAX_SYMBOL = 8
MAX_DECIMALS = 36

# transfer(address,uint256) -- keccak256 of the signature, first four bytes.
# Checked against that derivation in the self-test rather than trusted as a
# constant somebody typed.
ERC20_TRANSFER = bytes.fromhex("a9059cbb")
ERC20_TRANSFER_LEN = 4 + 32 + 32


def register_token(chain_id: int, address: str, symbol: str,
                   decimals: int) -> None:
    """Teach this device one ERC-20 token, by contract, symbol and decimals.

    PROVISIONING ONLY, for the reason in the note on TOKENS above. The chain
    has to be registered first: a token on a chain the device cannot name is a
    token whose transfers it could not render anyway, and refusing here means
    the owner finds out while holding the device rather than while holding a
    lancet.

    Re-registering identically is a no-op; re-registering differently is
    refused, so a second run can never silently move a symbol or a decimal
    point that the owner has already been reading on screen.
    """
    if not isinstance(chain_id, int) or isinstance(chain_id, bool):
        raise BadEthTransaction("chain id must be an integer")
    if chain_id not in CHAINS:
        raise BadEthTransaction(
            f"chain {chain_id} is not registered on this device, so a token "
            f"on it could not be displayed. Register the chain first with "
            f"`tools/provision.py chain`.")
    if not valid_checksum_address(address):
        raise BadEthTransaction(
            f"token contract {address!r} is not a valid address, or its "
            f"EIP-55 checksum does not match its capitalisation")
    if int(address.removeprefix("0x"), 16) == 0:
        raise BadEthTransaction("the zero address is not a token contract")
    if not isinstance(symbol, str) or not symbol.strip():
        raise BadEthTransaction("token symbol must be a non-empty string")
    if symbol != symbol.strip():
        raise BadEthTransaction("token symbol has leading or trailing space")
    if len(symbol) > MAX_SYMBOL:
        raise BadEthTransaction(
            f"token symbol {symbol!r} is longer than {MAX_SYMBOL} characters "
            f"and would not fit beside an amount")
    if any(c < " " or c > "~" for c in symbol):
        raise BadEthTransaction(
            f"token symbol {symbol!r} has characters outside printable ASCII; "
            f"the owner cannot trust what such a label renders as")
    if not isinstance(decimals, int) or isinstance(decimals, bool) \
            or not 0 <= decimals <= MAX_DECIMALS:
        raise BadEthTransaction(
            f"token decimals must be a whole number between 0 and "
            f"{MAX_DECIMALS}")
    # The native ticker is what an amount of the chain's own coin is displayed
    # in. A token that borrows it makes "1.5 ETH" ambiguous between the coin
    # that pays the fee and the token being moved, on the same screen.
    if symbol == CHAINS[chain_id][1]:
        raise BadEthTransaction(
            f"{symbol!r} is chain {chain_id}'s native ticker; a token sharing "
            f"it would be indistinguishable from the coin paying the fee")
    key = (chain_id, address.lower())
    existing = TOKENS.get(key)
    if existing is not None and existing != (symbol, decimals):
        raise BadEthTransaction(
            f"{address} on chain {chain_id} is already registered as "
            f"{existing[0]!r} with {existing[1]} decimals; refusing to "
            f"relabel it {symbol!r} with {decimals}")
    TOKENS[key] = (symbol, decimals)


def token_of(chain_id: int, address: str) -> tuple[str, int] | None:
    """The (symbol, decimals) registered for a contract, or None."""
    return TOKENS.get((chain_id, address.lower()))


def encode_erc20_transfer(to: str, amount: int) -> bytes:
    """Build `transfer(address,uint256)` calldata. The device's own bytes."""
    if not valid_checksum_address(to):
        raise BadEthTransaction(
            f"token recipient {to!r} is not a valid address, or its EIP-55 "
            f"checksum does not match its capitalisation")
    if int(to.removeprefix("0x"), 16) == 0:
        raise BadEthTransaction("refusing to send tokens to the zero address")
    if not isinstance(amount, int) or isinstance(amount, bool) or amount < 0:
        raise BadEthTransaction("token amount must be a non-negative integer")
    if amount >> 256:
        raise BadEthTransaction("token amount does not fit a uint256")
    return (ERC20_TRANSFER
            + bytes(12) + int(to.removeprefix("0x"), 16).to_bytes(20, "big")
            + amount.to_bytes(32, "big"))


def decode_erc20_transfer(data: bytes) -> tuple[str, int]:
    """The inverse. Refuses anything that is not exactly this one call.

    Strict about the twelve leading zero bytes of the address argument. ABI
    encoding left-pads a 20-byte address into a 32-byte word, so those bytes
    are structurally zero -- and a decoder that skips them is a decoder that
    reads the low 20 bytes of a word carrying something else entirely and calls
    the result a recipient.
    """
    if len(data) != ERC20_TRANSFER_LEN:
        raise BadEthTransaction(
            f"an ERC-20 transfer is {ERC20_TRANSFER_LEN} bytes of calldata, "
            f"not {len(data)}")
    if data[:4] != ERC20_TRANSFER:
        raise BadEthTransaction(
            f"calldata calls 0x{data[:4].hex()}, and the only function this "
            f"device signs is transfer(address,uint256) "
            f"(0x{ERC20_TRANSFER.hex()})")
    if data[4:16] != bytes(12):
        raise BadEthTransaction(
            "the recipient argument is not a left-padded address")
    to = to_checksum_address(data[16:36].hex())
    return to, int.from_bytes(data[36:], "big")


class BadEthTransaction(ValueError):
    """A transaction this device will not build or sign."""


# --------------------------------------------------------------------------
# RLP
# --------------------------------------------------------------------------


def _rlp_len(prefix: int, n: int) -> bytes:
    if n < 56:
        return bytes([prefix + n])
    length = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([prefix + 55 + len(length)]) + length


def rlp_encode(item) -> bytes:
    """Bytes, ints (as minimal big-endian) and lists. RLP has nothing else."""
    if isinstance(item, bool):
        raise BadEthTransaction("RLP has no boolean type")
    if isinstance(item, int):
        if item < 0:
            raise BadEthTransaction("RLP cannot encode a negative integer")
        item = item.to_bytes((item.bit_length() + 7) // 8, "big")
    if isinstance(item, (bytes, bytearray)):
        b = bytes(item)
        if len(b) == 1 and b[0] < 0x80:
            return b
        return _rlp_len(0x80, len(b)) + b
    if isinstance(item, (list, tuple)):
        body = b"".join(rlp_encode(i) for i in item)
        return _rlp_len(0xC0, len(body)) + body
    raise BadEthTransaction(f"cannot RLP-encode {type(item).__name__}")


def rlp_decode(data: bytes):
    """Only used by the tests, to prove the encoder round trips."""
    out, rest = _rlp_decode_one(data)
    if rest:
        raise BadEthTransaction(f"{len(rest)} trailing bytes after RLP item")
    return out


def _rlp_decode_one(d: bytes):
    """One RLP item, strictly.

    Every length is checked against what is actually there, and both
    non-canonical forms are refused. Python slicing truncates silently, so
    `0x8203` -- a string declaring two bytes and carrying one -- used to decode
    to a one-byte string with no complaint, and `0x8100` decoded a value whose
    canonical spelling is `0x00`. A round-trip proof against a decoder that
    accepts more than the encoder emits proves less than it looks like.
    """
    if not d:
        raise BadEthTransaction("RLP input is empty")

    def _need(n: int, what: str) -> None:
        if len(d) < n:
            raise BadEthTransaction(f"RLP {what} is truncated: needs {n} "
                                    f"bytes, has {len(d)}")

    def _length(ln: int, what: str) -> int:
        _need(1 + ln, f"{what} length")
        if d[1] == 0:
            raise BadEthTransaction(f"non-canonical RLP {what} length")
        n = int.from_bytes(d[1:1 + ln], "big")
        if n < 56:
            raise BadEthTransaction(
                f"non-canonical RLP {what}: {n} bytes belongs in the short form")
        return n

    p = d[0]
    if p < 0x80:
        return d[:1], d[1:]
    if p < 0xB8:
        n = p - 0x80
        _need(1 + n, "string")
        if n == 1 and d[1] < 0x80:
            raise BadEthTransaction("non-canonical single-byte RLP string")
        return d[1:1 + n], d[1 + n:]
    if p < 0xC0:
        ln = p - 0xB7
        n = _length(ln, "string")
        _need(1 + ln + n, "string")
        return d[1 + ln:1 + ln + n], d[1 + ln + n:]
    if p < 0xF8:
        n = p - 0xC0
        _need(1 + n, "list")
        body, rest = d[1:1 + n], d[1 + n:]
    else:
        ln = p - 0xF7
        n = _length(ln, "list")
        _need(1 + ln + n, "list")
        body, rest = d[1 + ln:1 + ln + n], d[1 + ln + n:]
    items = []
    while body:
        item, body = _rlp_decode_one(body)
        items.append(item)
    return items, rest


# --------------------------------------------------------------------------
# Transactions
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class EthTransaction:
    """An EIP-1559 transaction, built from displayed fields.

    `max_fee_per_gas * gas_limit` is the worst case the owner can be charged,
    and it is that number — not the tip, not the base fee — that the display
    shows, because it is the only one that bounds the loss.
    """

    chain_id: int
    nonce: int
    max_priority_fee_per_gas: int
    max_fee_per_gas: int
    gas_limit: int
    to: str
    value: int
    data: bytes = b""

    def __post_init__(self):
        # bool before the membership test. `True in CHAINS` matches chain 1,
        # so EthTransaction(chain_id=True, ...) constructed and chain_name()
        # answered "Ethereum". It failed closed later, at sighash(), with
        # "RLP has no boolean type" -- a message about an encoder, for a
        # request that was wrong about which network it was for.
        if isinstance(self.chain_id, bool):
            raise BadEthTransaction("chain id must be an integer, not a bool")
        if self.chain_id not in CHAINS:
            raise BadEthTransaction(
                f"chain id {self.chain_id} is not one this device recognises. "
                f"Signing for an unnamed chain means the owner cannot tell "
                f"which network the transfer lands on. Register it first with "
                f"`tools/provision.py chain`.")
        for name in ("nonce", "max_priority_fee_per_gas", "max_fee_per_gas",
                     "gas_limit", "value"):
            v = getattr(self, name)
            if not isinstance(v, int) or isinstance(v, bool) or v < 0:
                raise BadEthTransaction(f"{name} must be a non-negative integer")
        if self.max_priority_fee_per_gas > self.max_fee_per_gas:
            raise BadEthTransaction("priority fee exceeds the max fee per gas")
        if self.gas_limit < 21000:
            raise BadEthTransaction("gas limit below the 21000 minimum for a transfer")
        if self.data:
            # The one permitted shape, checked here rather than at the call
            # site so nothing can construct a transaction this module would
            # not have built itself.
            if token_of(self.chain_id, self.to) is None:
                raise BadEthTransaction(
                    "this device refuses transactions carrying calldata. The "
                    "one exception is an ERC-20 transfer to a token this "
                    "device has been told about, and "
                    f"{self.to} is not a registered token on chain "
                    f"{self.chain_id}. Register it with "
                    "`tools/provision.py token`, or send no calldata.")
            recipient, amount = decode_erc20_transfer(self.data)
            if encode_erc20_transfer(recipient, amount) != self.data:
                # Unreachable through `token_transfer()` below, which is the
                # only thing that builds this. Kept because it is the check
                # that would catch a future path accepting calldata from
                # outside: ABI encoding has exactly one spelling, and bytes
                # that decode to a recipient and an amount but do not re-encode
                # to themselves are carrying something in the padding.
                raise BadEthTransaction(
                    "calldata decodes to a transfer but does not re-encode to "
                    "the bytes supplied; it carries more than it declares")
            if self.value:
                # The screen would have to say two amounts in two
                # denominations, only one of which the token contract sees.
                raise BadEthTransaction(
                    "an ERC-20 transfer carrying native value as well is two "
                    "transfers on one screen; this device signs one")
        if not valid_checksum_address(self.to):
            raise BadEthTransaction(
                f"recipient {self.to!r} is not a valid address, or its EIP-55 "
                f"checksum does not match its capitalisation")
        if int(self.to.removeprefix("0x"), 16) == 0:
            raise BadEthTransaction("refusing to send to the zero address")

    # ---- encoding ----

    def to_bytes(self) -> bytes:
        return int(self.to.removeprefix("0x"), 16).to_bytes(20, "big")

    def _fields(self) -> list:
        return [self.chain_id, self.nonce, self.max_priority_fee_per_gas,
                self.max_fee_per_gas, self.gas_limit, self.to_bytes(),
                self.value, self.data, []]        # empty access list

    def signing_payload(self) -> bytes:
        return bytes([TX_TYPE_1559]) + rlp_encode(self._fields())

    def sighash(self) -> bytes:
        """keccak256 of the typed payload. This is what gets signed."""
        return keccak256(self.signing_payload())

    def encode_signed(self, r: int, s: int, y_parity: int) -> bytes:
        """The raw transaction to broadcast, ready for eth_sendRawTransaction."""
        if y_parity not in (0, 1):
            raise BadEthTransaction("y_parity must be 0 or 1")
        return bytes([TX_TYPE_1559]) + rlp_encode(
            self._fields() + [y_parity, r, s])

    def txid(self, r: int, s: int, y_parity: int) -> str:
        return "0x" + keccak256(self.encode_signed(r, s, y_parity)).hex()

    # ---- display ----

    def max_fee_wei(self) -> int:
        return self.max_fee_per_gas * self.gas_limit

    def chain_name(self) -> str:
        return CHAINS[self.chain_id][0]

    def ticker(self) -> str:
        """The native token's symbol. Not every EVM chain denominates in ETH."""
        return CHAINS[self.chain_id][1]

    # ---- the ERC-20 path ----

    @property
    def is_token_transfer(self) -> bool:
        return bool(self.data)

    def token(self) -> tuple[str, int]:
        """(symbol, decimals) for the contract this transaction calls."""
        found = token_of(self.chain_id, self.to)
        if found is None:
            raise BadEthTransaction(f"{self.to} is not a registered token")
        return found

    def token_transfer_fields(self) -> tuple[str, int]:
        """(recipient, amount) as the calldata says, decoded not remembered.

        The confirmation screen reads from here rather than from whatever was
        passed to `token_transfer` below, so what the owner is shown comes out
        of the bytes the signature will commit to. If the two ever disagreed,
        the screen would follow the signature.
        """
        return decode_erc20_transfer(self.data)


def token_transfer(chain_id: int, nonce: int, max_priority_fee_per_gas: int,
                   max_fee_per_gas: int, gas_limit: int, token: str,
                   to: str, amount: int) -> EthTransaction:
    """An ERC-20 transfer, as an EIP-1559 transaction this device built.

    `to` is the recipient of the tokens and `token` is the contract, which is
    where the transaction is actually addressed. That inversion is the whole
    reason this needs a named constructor rather than a raw EthTransaction:
    getting it backwards produces a transaction that pays the token contract
    in tokens, which is a real and unrecoverable way to lose money, and it is
    a mistake nobody can spot on a confirmation screen because both fields are
    addresses.
    """
    if token_of(chain_id, token) is None:
        raise BadEthTransaction(
            f"{token} is not a registered token on chain {chain_id}. This "
            f"device will not sign a transfer of something it cannot name. "
            f"Register it first with `tools/provision.py token`.")
    return EthTransaction(
        chain_id=chain_id, nonce=nonce,
        max_priority_fee_per_gas=max_priority_fee_per_gas,
        max_fee_per_gas=max_fee_per_gas, gas_limit=gas_limit,
        to=token, value=0, data=encode_erc20_transfer(to, amount))


def from_signing_payload(payload: bytes) -> EthTransaction:
    """Rebuild a transaction from the bytes a companion wants signed.

    THIS IS THE ONE PLACE THE DEVICE IS HANDED AN ENCODED TRANSACTION, and it
    is handled by refusing to trust the encoding. EIP-4527 -- what MetaMask's
    and Rabby's QR-account flows emit -- carries `signData`, an EIP-2718
    payload, rather than the fields this module normally builds from. A device
    that hashed those bytes and signed the digest would be signing something it
    never read, which is the thing `eth.py` exists not to do.

    So the bytes are decoded into fields, an EthTransaction is built from those
    fields by the ordinary constructor -- every check in `__post_init__`
    applies -- and then THIS module re-encodes it and compares byte for byte
    with what arrived. What the owner sees is what the device derived, and a
    payload carrying anything the decoder dropped fails the comparison instead
    of being signed quietly.

    That last step is what makes the round trip a security control rather than
    a formality. RLP has non-canonical spellings -- a leading zero on an
    integer, a long-form length prefix for a short string -- and each one
    decodes to the same fields and re-encodes to different bytes. A device
    without this check would display a correct summary and sign a digest over
    a payload it had not reproduced.
    """
    if not payload or payload[0] != TX_TYPE_1559:
        got = f"0x{payload[:1].hex()}" if payload else "nothing"
        raise BadEthTransaction(
            f"this device signs EIP-1559 (type 2) transactions; the request "
            f"carries {got}. Legacy and EIP-2930 encodings are refused -- see "
            f"the note at the top of eth.py.")
    fields = rlp_decode(payload[1:])
    if not isinstance(fields, list) or len(fields) != 9:
        raise BadEthTransaction(
            f"an unsigned type-2 transaction has nine RLP fields, not "
            f"{len(fields) if isinstance(fields, list) else 'a non-list'}")
    chain_id, nonce, tip, max_fee, gas, to, value, data, access = fields
    for name, v in (("chain id", chain_id), ("nonce", nonce),
                    ("max priority fee", tip), ("max fee", max_fee),
                    ("gas limit", gas), ("value", value)):
        if not isinstance(v, bytes):
            raise BadEthTransaction(f"{name} is an RLP list, not an integer")
    if not isinstance(to, bytes) or len(to) != 20:
        # An empty `to` is a contract creation. It is legal, it is not a
        # transfer, and there is no destination to put on the screen.
        raise BadEthTransaction(
            "the recipient is not a twenty-byte address. This device does not "
            "sign contract creations.")
    if not isinstance(data, bytes):
        raise BadEthTransaction("calldata is an RLP list, not a byte string")
    if access != []:
        # Renderable in principle, and not rendered: an access list changes
        # what the transaction costs and nothing about what it does, so it
        # would be a field on the screen the owner could not act on.
        raise BadEthTransaction(
            "this device signs transactions with an empty access list")
    tx = EthTransaction(
        chain_id=int.from_bytes(chain_id, "big"),
        nonce=int.from_bytes(nonce, "big"),
        max_priority_fee_per_gas=int.from_bytes(tip, "big"),
        max_fee_per_gas=int.from_bytes(max_fee, "big"),
        gas_limit=int.from_bytes(gas, "big"),
        to=to_checksum_address(to.hex()),
        value=int.from_bytes(value, "big"),
        data=data)
    if tx.signing_payload() != payload:
        raise BadEthTransaction(
            "this device re-encodes what it was asked to sign and compares it "
            "byte for byte. The two differ, so the payload carries something "
            "the fields on screen do not describe. Refused.")
    return tx


def signature_from_raw(raw: bytes) -> bytes:
    """The 65-byte r || s || v an EIP-4527 reply carries, out of a signed tx.

    Read back out of the encoded transaction rather than passed alongside it,
    for the same reason the confirmation screen reads a token transfer's
    recipient out of its calldata: if the two could disagree, this is the one
    that the chain would act on.
    """
    if not raw or raw[0] != TX_TYPE_1559:
        raise BadEthTransaction("not a type-2 transaction")
    fields = rlp_decode(raw[1:])
    if not isinstance(fields, list) or len(fields) != 12:
        raise BadEthTransaction("a signed type-2 transaction has twelve fields")
    y, r, s = fields[9], fields[10], fields[11]
    parity = int.from_bytes(y, "big")
    if parity not in (0, 1):
        raise BadEthTransaction("y_parity is not 0 or 1")
    return (int.from_bytes(r, "big").to_bytes(32, "big")
            + int.from_bytes(s, "big").to_bytes(32, "big")
            + bytes([parity]))


def sign(tx: EthTransaction, seckey: bytes) -> tuple[int, int, int]:
    """Returns (r, s, y_parity). Verifies before returning.

    Ethereum verifies by recovering the
    sender from the signature, so a wrong parity byte produces a transaction
    that is valid-looking and credited to an address nobody controls.
    """
    digest = tx.sighash()
    # No low-R grinding here: it is a Bitcoin size optimisation, and every
    # Ethereum library signs with plain RFC 6979. Matching them byte for byte
    # keeps the cross-check in the tests meaningful.
    r, s, rec = ec.ecdsa_sign(digest, seckey, grind_low_r=False)
    y_parity = rec & 1
    if ec.ecdsa_recover(digest, r, s, y_parity) != ec.pubkey_compressed(seckey):
        raise BadEthTransaction("signature does not recover to the signing key")
    return r, s, y_parity


def sender(tx: EthTransaction, r: int, s: int, y_parity: int) -> str:
    """Recover the sender address, as a node would."""
    from addresses import eth_address
    return eth_address(ec.ecdsa_recover(tx.sighash(), r, s, y_parity))


# --------------------------------------------------------------------------


def _selftest() -> int:
    print("Ethereum — RLP, EIP-1559 encoding, signature recovery\n")
    checks = []

    # RLP vectors from the Ethereum yellow paper and the standard test set.
    for item, want in [
        (b"dog", "83646f67"),
        (b"", "80"),
        (b"\x00", "00"),
        (b"\x0f", "0f"),
        (b"\x04\x00", "820400"),
        (0, "80"),
        (15, "0f"),
        (1024, "820400"),
        ([], "c0"),
        ([b"cat", b"dog"], "c88363617483646f67"),
        ([[], [[]], [[], [[]]]], "c7c0c1c0c3c0c1c0"),
        (b"a" * 56, "b838" + "61" * 56),
    ]:
        checks.append((f"RLP {str(item)[:24]}", rlp_encode(item).hex() == want))

    checks.append(("RLP round trips a nested list",
                   rlp_decode(rlp_encode([b"cat", [b"dog", b""], b"x" * 100]))
                   == [b"cat", [b"dog", b""], b"x" * 100]))
    for bad in (-1, True, 3.5, None):
        try:
            rlp_encode(bad)
            checks.append((f"RLP refuses {bad!r}", False))
        except BadEthTransaction:
            checks.append((f"RLP refuses {bad!r}", True))

    # A transaction signed with the well-known EIP-155 example key.
    sk = bytes.fromhex(
        "4646464646464646464646464646464646464646464646464646464646464646")
    from addresses import eth_address
    me = eth_address(ec.pubkey_compressed(sk))
    checks.append(("key derives the known address",
                   me == "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F"))

    t = EthTransaction(chain_id=1, nonce=9,
                       max_priority_fee_per_gas=2_000_000_000,
                       max_fee_per_gas=30_000_000_000,
                       gas_limit=21000,
                       to="0x3535353535353535353535353535353535353535",
                       value=10**18)
    r, s, yp = sign(t, sk)
    checks.append(("signs and recovers to the sender", sender(t, r, s, yp) == me))
    checks.append(("signing is deterministic", sign(t, sk) == (r, s, yp)))
    checks.append(("typed envelope starts with 0x02",
                   t.signing_payload()[0] == TX_TYPE_1559))
    checks.append(("signed encoding starts with 0x02",
                   t.encode_signed(r, s, yp)[0] == TX_TYPE_1559))
    checks.append(("signed encoding round trips through RLP",
                   len(rlp_decode(t.encode_signed(r, s, yp)[1:])) == 12))
    checks.append(("txid is 32 bytes of hex", len(t.txid(r, s, yp)) == 66))

    # Every signed field must change the digest. This is the test that would
    # catch a field accidentally left out of _fields().
    base = t.sighash()
    variants = {
        "chain_id": {"chain_id": 11155111},
        "nonce": {"nonce": 10},
        "priority fee": {"max_priority_fee_per_gas": 3_000_000_000},
        "max fee": {"max_fee_per_gas": 31_000_000_000},
        "gas limit": {"gas_limit": 22000},
        "recipient": {"to": "0x3535353535353535353535353535353535353536"},
        "value": {"value": 10**18 + 1},
    }
    for name, change in variants.items():
        fields = {**t.__dict__, **change}
        checks.append((f"digest commits to the {name}",
                       EthTransaction(**fields).sighash() != base))

    # The refusals.
    def refuses(label, **kw):
        fields = {**t.__dict__, **kw}
        try:
            EthTransaction(**fields)
            checks.append((label, False))
        except (BadEthTransaction, BadAddress):
            checks.append((label, True))

    refuses("refuses calldata", data=b"\xa9\x05\x9c\xbb")
    refuses("refuses an unknown chain id", chain_id=999999)
    refuses("refuses a gas limit below 21000", gas_limit=20999)
    refuses("refuses a negative value", value=-1)
    refuses("refuses a priority fee above the max fee",
            max_priority_fee_per_gas=40_000_000_000)
    refuses("refuses the zero address",
            to="0x0000000000000000000000000000000000000000")
    refuses("refuses a bad EIP-55 checksum",
            to="0x5aAeb6053F3E94C9b9A09f33669435E7Ef1Beaed")
    refuses("refuses a short address", to="0x353535")

    # An address given in lowercase claims no checksum and is accepted; the
    # display then shows it checksummed so the owner sees the canonical form.
    ok_lower = EthTransaction(**{**t.__dict__,
                                 "to": "0x3535353535353535353535353535353535353535"})
    checks.append(("lowercase address accepted",
                   ok_lower.to_bytes().hex() == "35" * 20))
    checks.append(("display form is checksummed",
                   to_checksum_address(ok_lower.to)
                   == "0x3535353535353535353535353535353535353535"))

    # Worst-case fee, which is the number the owner is shown.
    checks.append(("max fee is price times limit",
                   t.max_fee_wei() == 30_000_000_000 * 21000))
    checks.append(("chain is named", t.chain_name() == "Ethereum"))
    checks.append(("chain carries its ticker", t.ticker() == "ETH"))

    # ---- registered chains ----
    #
    # The device ships knowing two chains and is taught the rest. What matters
    # here is that a registration cannot quietly relabel a chain the owner has
    # already been reading on screen, and cannot smuggle a label that renders
    # as something other than what was registered.
    def reg_refuses(label, cid, name, ticker):
        try:
            register_chain(cid, name, ticker)
            checks.append((label, False))
        except BadEthTransaction:
            checks.append((label, True))

    # The built-in set is asserted, not merely counted. A chain that appears
    # here without a deliberate edit is a name the device would assert on a
    # confirmation screen without anybody having decided it should.
    checks.append(("ships with the chains the account contracts are on",
                   BUILTIN_CHAINS == {1: ("Ethereum", "ETH"),
                                      8453: ("Base", "ETH"),
                                      4663: ("Robinhood", "ETH"),
                                      11155111: ("Sepolia (test)", "tETH")}))
    checks.append(("every built-in name fits the confirmation screen",
                   all(len(n) <= MAX_CHAIN_NAME and len(t) <= MAX_TICKER
                       and all(" " <= c <= "~" for c in n + t)
                       for n, t in BUILTIN_CHAINS.values())))
    def _relabel_refused(cid) -> bool:
        try:
            register_chain(cid, "Somewhere Else", "XYZ")
        except BadEthTransaction:
            return True
        return False

    checks.append(("and none of them can be relabelled",
                   all(_relabel_refused(cid) for cid in BUILTIN_CHAINS)))
    checks.append(("an unregistered chain has no name", 42161 not in CHAINS))

    register_chain(42161, "Arbitrum One", "ETH")
    checks.append(("a registered chain is signable",
                   EthTransaction(**{**t.__dict__, "chain_id": 42161})
                   .chain_name() == "Arbitrum One"))
    register_chain(137, "Polygon", "POL")
    checks.append(("a registered chain keeps its own ticker",
                   EthTransaction(**{**t.__dict__, "chain_id": 137})
                   .ticker() == "POL"))

    register_chain(137, "Polygon", "POL")     # identical repeat is a no-op
    checks.append(("re-registering the same chain is idempotent",
                   CHAINS[137] == ("Polygon", "POL")))
    reg_refuses("refuses to rename a registered chain", 137, "Ethereum", "ETH")
    reg_refuses("refuses to relabel a built-in chain", 1, "Sepolia", "tETH")
    reg_refuses("refuses a chain id below one", 0, "Zero", "ETH")
    reg_refuses("refuses an empty chain name", 999, "", "ETH")
    reg_refuses("refuses an empty ticker", 999, "Somechain", "")
    reg_refuses("refuses a name too long for the screen",
                999, "A" * (MAX_CHAIN_NAME + 1), "ETH")
    reg_refuses("refuses a ticker too long for the screen",
                999, "Somechain", "T" * (MAX_TICKER + 1))
    reg_refuses("refuses a name with a direction override",
                999, "Ether\u202eum", "ETH")
    reg_refuses("refuses a name with a zero-width joiner",
                999, "Ether\u200dum", "ETH")
    reg_refuses("refuses a padded name", 999, " Ethereum ", "ETH")
    checks.append(("a refused registration is not recorded", 999 not in CHAINS))

    # ---- rebuilding an encoded transaction (EIP-4527) ----
    #
    # The one place the device is handed an encoded transaction. The property
    # that makes it safe is the round trip: decode to fields, rebuild by the
    # ordinary constructor, re-encode, and compare byte for byte.
    checks.append(("a signing payload rebuilds to the same transaction",
                   from_signing_payload(t.signing_payload()) == t))
    r0, s0, y0 = sign(t, sk)
    checks.append(("a 65-byte signature reads back out of a signed tx",
                   signature_from_raw(t.encode_signed(r0, s0, y0))
                   == r0.to_bytes(32, "big") + s0.to_bytes(32, "big")
                   + bytes([y0])))

    def payload_refuses(label, fn):
        try:
            fn()
            checks.append((label, False))
        except (BadEthTransaction, BadAddress):
            checks.append((label, True))

    # RLP has non-canonical spellings. Each decodes to the same fields and
    # re-encodes to different bytes, so a device without the comparison would
    # display a correct summary over a digest it had not reproduced.
    _f = rlp_decode(t.signing_payload()[1:])
    for label, mutate in (
        ("a leading zero on the nonce",
         lambda f: f.__setitem__(1, b"\x00" + f[1])),
        ("a leading zero on the value",
         lambda f: f.__setitem__(6, b"\x00" + f[6])),
        ("a leading zero on the chain id",
         lambda f: f.__setitem__(0, b"\x00" + f[0])),
    ):
        g = list(_f)
        mutate(g)
        payload_refuses(f"refuses {label}",
                        lambda g=g: from_signing_payload(
                            bytes([TX_TYPE_1559]) + rlp_encode(g)))

    payload_refuses("refuses a legacy encoding",
                    lambda: from_signing_payload(b"\xf8" + b"\x00" * 40))
    payload_refuses("refuses an EIP-2930 encoding",
                    lambda: from_signing_payload(b"\x01" + rlp_encode(_f)))
    payload_refuses("refuses an empty payload",
                    lambda: from_signing_payload(b""))
    payload_refuses("refuses the wrong number of fields",
                    lambda: from_signing_payload(
                        bytes([TX_TYPE_1559]) + rlp_encode(_f[:8])))
    payload_refuses("refuses a contract creation",
                    lambda: from_signing_payload(
                        bytes([TX_TYPE_1559])
                        + rlp_encode(_f[:5] + [b""] + _f[6:])))
    payload_refuses("refuses a non-empty access list",
                    lambda: from_signing_payload(
                        bytes([TX_TYPE_1559])
                        + rlp_encode(_f[:8] + [[[bytes(20), []]]])))
    payload_refuses("refuses an integer field encoded as a list",
                    lambda: from_signing_payload(
                        bytes([TX_TYPE_1559])
                        + rlp_encode([[]] + _f[1:])))
    payload_refuses("refuses a signed transaction where an unsigned one belongs",
                    lambda: from_signing_payload(
                        t.encode_signed(r0, s0, y0)))
    payload_refuses("refuses reading a signature out of an unsigned tx",
                    lambda: signature_from_raw(t.signing_payload()))

    # ---- ERC-20 ----
    #
    # The one shape of calldata this device signs. What matters here is that
    # the encoder produces exactly what every other ERC-20 implementation
    # does, that nothing else gets through, and that a token cannot be
    # relabelled once the owner has been reading it on a screen.
    from hashes import keccak256
    checks.append(("the transfer selector is keccak of the signature",
                   ERC20_TRANSFER
                   == keccak256(b"transfer(address,uint256)")[:4]))
    checks.append(("nothing ships pre-registered", TOKENS == {}))

    USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
    VITALIK = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
    register_token(1, USDC, "USDC", 6)

    # Byte for byte against the calldata any ERC-20 library emits: selector,
    # the recipient left-padded into a word, then the amount.
    want_data = ("a9059cbb"
                 "000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa96045"
                 "000000000000000000000000000000000000000000000000000000000ee6b280")
    tt = token_transfer(1, 7, 1_000_000_000, 30_000_000_000, 65_000,
                        USDC, VITALIK, 250_000_000)
    checks.append(("calldata matches the canonical ABI encoding",
                   tt.data.hex() == want_data))
    checks.append(("the transaction is addressed to the CONTRACT",
                   tt.to == USDC))
    checks.append(("...and carries no native value", tt.value == 0))
    checks.append(("it reports itself a token transfer", tt.is_token_transfer))
    checks.append(("a plain transfer does not", not t.is_token_transfer))
    checks.append(("the token is named from the registration",
                   tt.token() == ("USDC", 6)))
    checks.append(("recipient and amount are decoded from the calldata",
                   tt.token_transfer_fields() == (VITALIK, 250_000_000)))
    checks.append(("the sighash covers the calldata",
                   tt.sighash()
                   != EthTransaction(**{**tt.__dict__, "data": b""}).sighash()))

    # A signature over it recovers, exactly as a value transfer's does. The
    # ERC-20 path must not become a second signing path.
    r_, s_, y_ = sign(tt, sk)
    checks.append(("a token transfer signs and recovers", sender(tt, r_, s_, y_) == me))
    checks.append(("...and re-decodes from the raw transaction",
                   rlp_decode(tt.encode_signed(r_, s_, y_)[1:])[7]
                   == bytes.fromhex(want_data)))

    # The composition that comes free: a token transfer arriving encoded is
    # rebuilt as a token transfer, because __post_init__ is the same code.
    checks.append(("an encoded ERC-20 transfer rebuilds as one",
                   from_signing_payload(tt.signing_payload()) == tt))

    def tok_refuses(label, fn):
        try:
            fn()
            checks.append((label, False))
        except (BadEthTransaction, BadAddress):
            checks.append((label, True))

    tok_refuses("refuses a transfer of an unregistered token",
                lambda: token_transfer(1, 0, 1, 2, 65_000,
                                       "0x1111111111111111111111111111111111111111",
                                       VITALIK, 1))
    tok_refuses("refuses a token on a chain it knows but did not register it on",
                lambda: token_transfer(8453, 0, 1, 2, 65_000, USDC, VITALIK, 1))
    tok_refuses("refuses tokens to the zero address",
                lambda: token_transfer(
                    1, 0, 1, 2, 65_000, USDC,
                    "0x0000000000000000000000000000000000000000", 1))
    tok_refuses("refuses an amount past a uint256",
                lambda: token_transfer(1, 0, 1, 2, 65_000, USDC, VITALIK,
                                       1 << 256))
    tok_refuses("refuses a negative amount",
                lambda: token_transfer(1, 0, 1, 2, 65_000, USDC, VITALIK, -1))
    tok_refuses("refuses a boolean amount",
                lambda: token_transfer(1, 0, 1, 2, 65_000, USDC, VITALIK, True))

    # Calldata arriving from outside, which is the path that must stay shut.
    tok_refuses("still refuses arbitrary calldata to a plain address",
                lambda: EthTransaction(**{**t.__dict__, "data": b"\x01\x02\x03"}))
    tok_refuses("refuses calldata to an address that is not a token",
                lambda: EthTransaction(**{**t.__dict__,
                                          "data": bytes.fromhex(want_data)}))
    tok_refuses("refuses another selector at the token",
                lambda: EthTransaction(
                    **{**tt.__dict__,
                       "data": bytes.fromhex("095ea7b3" + want_data[8:])}))
    tok_refuses("refuses calldata of the wrong length",
                lambda: EthTransaction(**{**tt.__dict__,
                                          "data": tt.data + b"\x00"}))
    tok_refuses("refuses a recipient word that is not a padded address",
                lambda: EthTransaction(
                    **{**tt.__dict__,
                       "data": tt.data[:4] + b"\xff" * 12 + tt.data[16:]}))
    tok_refuses("refuses a token transfer that also sends native value",
                lambda: EthTransaction(**{**tt.__dict__, "value": 1}))

    def token_reg_refuses(label, *a):
        try:
            register_token(*a)
            checks.append((label, False))
        except (BadEthTransaction, BadAddress):
            checks.append((label, True))

    register_token(1, USDC, "USDC", 6)          # identical repeat is a no-op
    checks.append(("re-registering the same token is idempotent",
                   TOKENS[(1, USDC.lower())] == ("USDC", 6)))
    token_reg_refuses("refuses to move a registered token's decimal point",
                      1, USDC, "USDC", 18)
    token_reg_refuses("refuses to rename a registered token",
                      1, USDC, "USDT", 6)
    token_reg_refuses("refuses a token on an unregistered chain",
                      999999, USDC, "USDC", 6)
    token_reg_refuses("refuses the zero address as a contract",
                      1, "0x0000000000000000000000000000000000000000", "ZERO", 6)
    token_reg_refuses("refuses a bad EIP-55 checksum on a contract",
                      1, "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB49", "X", 6)
    token_reg_refuses("refuses an empty symbol", 1, VITALIK, "", 6)
    token_reg_refuses("refuses a symbol too long for the screen",
                      1, VITALIK, "T" * (MAX_SYMBOL + 1), 6)
    token_reg_refuses("refuses a symbol with a direction override",
                      1, VITALIK, "US‮DC", 6)
    token_reg_refuses("refuses a padded symbol", 1, VITALIK, " USDC ", 6)
    token_reg_refuses("refuses decimals past the ceiling",
                      1, VITALIK, "BIG", MAX_DECIMALS + 1)
    token_reg_refuses("refuses negative decimals", 1, VITALIK, "NEG", -1)
    token_reg_refuses("refuses boolean decimals", 1, VITALIK, "BOO", True)
    # A token calling itself ETH on Ethereum would put two different things
    # under one denomination on the same screen: the tokens moving and the
    # coin paying the fee.
    token_reg_refuses("refuses a symbol that shadows the native ticker",
                      1, VITALIK, "ETH", 18)
    checks.append(("a refused token registration is not recorded",
                   (1, VITALIK.lower()) not in TOKENS))

    # Zero decimals is legal and some real tokens use it.
    register_token(137, "0x1111111111111111111111111111111111111111", "WHOLE", 0)
    checks.append(("a zero-decimal token is registrable",
                   token_of(137, "0x1111111111111111111111111111111111111111")
                   == ("WHOLE", 0)))
    checks.append(("the same address on another chain is a different token",
                   token_of(1, "0x1111111111111111111111111111111111111111")
                   is None))

    ok = True
    for label, good in checks:
        ok &= good
        print(f"  {label:<48}{'PASS' if good else 'FAIL'}")
    print("\n" + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_selftest())
