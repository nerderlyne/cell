#!/usr/bin/env python3
"""EIP-712 typed data, and the EIP-7702 delegation authorisation.

WHY THIS EXISTS. BUILD.md section 5 says the device never builds a transaction:
it signs an authorisation and the companion submits it. `eth.py` does not
actually work that way. It builds a whole EIP-1559 transaction, holds the
account's nonce, and prices `gas_limit * max_fee_per_gas`, because an EOA has
no other way to move value.

A smart account does. The authorisation is an EIP-712 `Execute` message, the
account's own contract holds the nonce, and whoever relays it pays the gas. So
the device signs three fields and a domain, holds no gas, and never has to
reason about a fee it cannot bound. That is the shape section 5 describes.

WHAT IT WILL SIGN. One thing: a value transfer out of a registered smart
account, with empty calldata. `Execute(address target, uint256 value, bytes
data, uint32 nonce)` with `data` empty renders as a sentence:

    SEND 1.5 ETH from treasury, to 0xCD2a..., account nonce 7, on Ethereum

Calldata stays refused, for the reason in BUILD.md section 5. That includes the
account's own governance calls, which are `execute(target=self, data=...)`:
changing owners, changing the threshold, cancelling a queued transaction. Those
are renderable in principle, from a fixed table of selectors decoded on the
device, and they are deliberately not here yet. A self-call is refused.

THE DOMAIN IS THE REPLAY DEFENCE. `chainId` and `verifyingContract` are inside
the domain separator, so an Execute signature is bound to one chain and one
deployment. That is strictly more than the EOA path pins, which is why the
registration below records the account address rather than accepting it from
the payload: an attacker who can choose `verifyingContract` can ask for a
signature that authorises a spend from an account the owner has never seen.

EIP-7702, AND WHY IT IS BLOOD-LOCKED. A delegation authorisation is
`keccak(0x05 || rlp([chain_id, address, nonce]))`. Three fields, all
displayable. It also hands the account's entire behaviour to a contract, at
which point every later signature means whatever that contract says it means.
It is reprovisioning under another name, so `ops.Delegation` reports
`account.delegate` and `policy.ALWAYS_BLOOD` holds it.

Two rules the device enforces on it, both of which have cost people accounts:

  chain_id 0 is refused. It is legal, and it means the authorisation is valid
  on every chain that exists and every chain that ever will.

  The implementation must be registered first. The signature commits to the
  address it delegates to; it does not commit to what that address contains.

WHAT THIS DOES NOT SOLVE. A 7702 authorisation does not commit to the
initialisation call that has to run in the same transaction, so a relayer can
delegate to the implementation the owner approved and initialise it with their
own owners. That is security consideration 2 of the EIP itself. It cannot be
closed by signing the authorisation alone, so `provision.py` records the
expected post-delegation state and `VALIDATION.md` carries the gap open.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import eth
from addresses import to_checksum_address, valid_checksum_address
from hashes import keccak256


class BadTypedData(ValueError):
    """A typed-data message this device will not build or sign."""


# EIP-712 section "Definition of domainSeparator". Only these four fields, in
# this order: a domain with a salt or a different field order is a different
# separator, and this device only signs for accounts it registered itself.
DOMAIN_TYPEHASH = keccak256(
    b"EIP712Domain(string name,string version,uint256 chainId,"
    b"address verifyingContract)")

# Transcribed from the account contract. If a deployment uses a different
# struct, every signature this device makes for it is a signature over a
# message that deployment will not recognise -- which fails closed, but it
# fails after the owner has already bled.
EXECUTE_TYPEHASH = keccak256(
    b"Execute(address target,uint256 value,bytes data,uint32 nonce)")

MAGIC_7702 = 0x05
UINT32_MAX = 2**32 - 1
UINT256_MAX = 2**256 - 1
ZERO_ADDRESS = "0x" + "0" * 40

# keccak("cancelQueued(bytes32)")[:4], recomputed rather than pasted so that a
# transcription slip cannot make the device sign a call it names something
# else. This is the ONLY function selector the firmware knows, and it stays
# that way: a table of selectors is a table of things the screen has to be
# able to say, and every entry is a new sentence to get right.
CANCEL_QUEUED_SELECTOR = keccak256(b"cancelQueued(bytes32)")[:4]


def _word(value: int) -> bytes:
    """One ABI word. Rejects anything that does not fit, instead of masking."""
    if not 0 <= value <= UINT256_MAX:
        raise BadTypedData(f"{value} does not fit a uint256")
    return value.to_bytes(32, "big")


def _address_word(addr: str) -> bytes:
    """An address as a left-padded ABI word, checksum checked on the way."""
    return b"\x00" * 12 + _address_bytes(addr)


def _is_zero_address(addr: str) -> bool:
    """True for the zero address, however it was spelled.

    `_address_bytes` accepts an address with or without the 0x, so a guard that
    compares against the prefixed string alone lets the unprefixed spelling of
    the same twenty zero bytes straight through.
    """
    return int(addr.removeprefix("0x"), 16) == 0


def _address_bytes(addr: str) -> bytes:
    if not isinstance(addr, str):
        raise BadTypedData(f"address must be a string, got {type(addr).__name__}")
    a = addr.removeprefix("0x")
    if len(a) != 40 or any(c not in "0123456789abcdefABCDEF" for c in a):
        raise BadTypedData(f"{addr!r} is not a 20-byte hex address")
    if not valid_checksum_address(addr):
        # A mixed-case address that fails EIP-55 is a typo or a substitution.
        # Refusing costs a re-scan; accepting costs the transfer.
        raise BadTypedData(f"{addr} fails its EIP-55 checksum")
    return bytes.fromhex(a)


def domain_separator(name: str, version: str, chain_id: int,
                     verifying_contract: str) -> bytes:
    """hashStruct of the EIP712Domain, built here and never accepted ready-made."""
    if not name or not version:
        raise BadTypedData("a domain needs both a name and a version")
    return keccak256(DOMAIN_TYPEHASH
                     + keccak256(name.encode())
                     + keccak256(version.encode())
                     + _word(chain_id)
                     + _address_word(verifying_contract))


def digest(separator: bytes, struct_hash: bytes) -> bytes:
    r"""The signing digest: keccak(0x19 0x01 || domainSeparator || hashStruct).

    Kept separate from the struct hashing so the published Ether Mail vector in
    the EIP can be run through the same code the device uses, rather than
    through a test-only reimplementation of it.
    """
    if len(separator) != 32 or len(struct_hash) != 32:
        raise BadTypedData("domain separator and struct hash are 32 bytes each")
    return keccak256(b"\x19\x01" + separator + struct_hash)


def execute_struct_hash(target: str, value: int, data: bytes,
                        nonce: int) -> bytes:
    """hashStruct of one Execute message.

    `data` is hashed rather than inlined because it is a dynamic type, and it
    is required to be empty because this device does not sign calldata. The
    single exception goes through `cancel_struct_hash` below, which builds its
    own calldata rather than accepting any.
    """
    if data:
        raise BadTypedData(
            "this device refuses an Execute carrying calldata. It signs value "
            "transfers out of a smart account and nothing else. See BUILD.md "
            "section 5.")
    return _execute_struct_hash(target, value, data, nonce)


def cancel_struct_hash(account: str, tx_hash: bytes, nonce: int) -> bytes:
    """hashStruct of the one Execute this device signs WITH calldata.

    Separated from `execute_struct_hash` on purpose, rather than added to it
    as a flag. A flag on the general function is a flag somebody eventually
    passes from a caller that took `data` off a payload, and then the rule
    that this device does not sign calldata is enforced by whoever remembered
    to pass False. Here the calldata is not a parameter at all: the selector
    is a module constant and the only variable is 32 bytes of hash, so there
    is no shape this function can be talked into producing.
    """
    if len(tx_hash) != 32:
        raise BadTypedData(
            f"a queued-transaction hash is 32 bytes, got {len(tx_hash)}")
    if int.from_bytes(tx_hash, "big") == 0:
        raise BadTypedData(
            "refusing to cancel the zero hash; no transaction has it")
    return _execute_struct_hash(account, 0, CANCEL_QUEUED_SELECTOR + tx_hash,
                                nonce)


def _execute_struct_hash(target: str, value: int, data: bytes,
                         nonce: int) -> bytes:
    if not 0 <= nonce <= UINT32_MAX:
        raise BadTypedData(f"nonce {nonce} does not fit the account's uint32")
    return keccak256(EXECUTE_TYPEHASH
                     + _address_word(target)
                     + _word(value)
                     + keccak256(data)
                     + _word(nonce))


# --------------------------------------------------------------------------
# Registered accounts
#
# Same argument as eth.register_chain and wallet.register_multisig. The device
# cannot tell whose account an address is, so it is told once, out of band, and
# refuses everything it was not told about. Without this, "sign an Execute for
# verifyingContract X" is a request the owner has no way to evaluate.
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class SmartAccount:
    """One account this device is willing to authorise spends from."""

    label: str
    address: str                    # the account itself, EIP-55
    # ONE ACCOUNT, MANY CHAINS. The factory deploys by deterministic salt and
    # the implementation is a singleton, so a quorum lives at the SAME address
    # on every chain it was summoned on. Recording one chain per registration
    # would force the owner to register the same address eight times under
    # eight labels -- "treasury-base", "treasury-op" -- and the screen would
    # then name the label rather than the network, which is the one thing the
    # label must not be trusted to do.
    #
    # So the record holds the set, and the chain comes from the REQUEST. That
    # is safe here and nowhere else: `chainId` is inside the domain separator,
    # so a request naming the wrong chain produces a signature that deployment
    # will not accept, and the chain is on the confirmation screen by name
    # either way. What the request may not choose is the address.
    chain_ids: tuple[int, ...]
    implementation: str             # the code the account runs, EIP-55
    # What to call that code on the delegation screen. Empty until the owner
    # records one, and ops.Delegation refuses to render without it: the
    # account's own label is a name for the account, not for the code it is
    # about to start running.
    implementation_label: str = ""
    threshold: int = 1
    owners: tuple[str, ...] = ()
    domain_name: str = "Multisig"
    domain_version: str = "1"
    # True when the account is an EOA that delegated to `implementation` under
    # EIP-7702. Recorded because it changes what the account is worth: the key
    # behind that address stays a superuser, so a timelock on this account
    # bounds a relayer and does not bound the key holder.
    delegated_eoa: bool = False
    # THE TIMELOCK, IN SECONDS, AND WHY IT IS ON THE SCREEN. The account
    # contract packs a `delay` beside its nonce and threshold. When it is
    # non-zero, `execute` does not execute: it writes `queued[hash] =
    # block.timestamp + delay` and the transaction runs later, through
    # `executeQueued`. The signed `Execute` struct is `(target, value, data,
    # nonce)` and commits to NONE of that, so one signature means "send now"
    # or "send in two days" depending on chain state this device cannot read.
    #
    # A confirmation screen that cannot tell those apart is asking for blood
    # against an outcome the owner has not been shown. So the delay is
    # recorded out of band, exactly like the account address and for exactly
    # the same reason, and `ops.SmartAccountExecute` puts it on the screen.
    # Recorded wrong, it misinforms; absent, it misinforms silently.
    delay_seconds: int = 0
    # The executor module. It is the one caller the delay does not apply to
    # (`msg.sender == executor` executes immediately), so an owner reading
    # "QUEUES FOR 48h" needs to know a second address can skip that.
    executor: str = ZERO_ADDRESS
    # Whether the executor's fast track is switched on for this account
    # (`TimelockExecutor.forwardEnabled[account]`).
    #
    # WHY THE DEVICE HAS TO KNOW. The executor verifies the SAME EIP-712
    # Execute digest the account does, so one signature from this device is
    # accepted by both routes and the companion picks which. Through the
    # account it queues for `delay_seconds`; through the executor, with every
    # owner's signature and this flag on, it runs immediately. The owner is
    # consenting to whichever the companion chooses, so the screen has to name
    # both -- a screen that promises a two-day window over a signature that
    # can execute in the next block is worse than one that says nothing.
    #
    # Unanimity is what makes that acceptable rather than a hole: fast-tracking
    # needs ALL owners, so this device is one of the signatures required, and
    # no quorum short of everyone can shorten a delay behind its owner's back.
    fast_track: bool = False

    def check(self) -> None:
        for role, text in (("account", self.label),
                           ("implementation", self.implementation_label)):
            if role == "implementation" and not text:
                continue                # optional; the delegation screen asks
            if not text or len(text) > 16:
                raise BadTypedData(f"an {role} label is 1 to 16 characters")
            # `isprintable` admits double-width CJK, which len() counts as
            # one and the panel paints as two -- a 16-character label measured
            # 16 to check_fits and overflowed "SEND FROM {label}". East Asian
            # Wide and Fullwidth are the two classes that do it.
            import unicodedata
            if any(c < " " or c == "\x7f" or not c.isprintable()
                   or unicodedata.east_asian_width(c) in ("W", "F")
                   or unicodedata.combining(c) for c in text):
                raise BadTypedData(
                    f"{role} label {text!r} carries a character the display "
                    f"cannot render as one column")
        if not self.chain_ids:
            raise BadTypedData(
                f"account {self.label!r} is registered on no chain at all")
        if len(set(self.chain_ids)) != len(self.chain_ids):
            raise BadTypedData("the same chain is listed twice")
        for cid in self.chain_ids:
            if not isinstance(cid, int) or isinstance(cid, bool) or cid <= 0:
                raise BadTypedData(
                    "chain id 0 is every chain at once. Register the ones you "
                    "mean.")
            if cid not in eth.CHAINS:
                raise BadTypedData(
                    f"chain {cid} is not registered on this device, so the "
                    f"confirmation screen could not name the network. "
                    f"Register the chain first.")
        for role, addr in (("account", self.address),
                           ("implementation", self.implementation)):
            _address_bytes(addr)
            if _is_zero_address(addr):
                raise BadTypedData(f"the {role} address is the zero address")
        if self.address.lower() == self.implementation.lower():
            raise BadTypedData(
                "the account and its implementation are the same address")
        if not 1 <= self.threshold <= max(1, len(self.owners) or 1):
            raise BadTypedData(
                f"{self.threshold} of {len(self.owners)} is not a usable quorum")
        for owner in self.owners:
            _address_bytes(owner)
        if len(set(o.lower() for o in self.owners)) != len(self.owners):
            raise BadTypedData("two owners are the same address")
        # `delay` is a uint32 in the account's packed storage slot. A value
        # past that does not mean "a very long timelock", it means the number
        # the owner typed is not the number the contract will hold.
        if not isinstance(self.delay_seconds, int) or isinstance(self.delay_seconds, bool):
            raise BadTypedData("the delay must be a whole number of seconds")
        if not 0 <= self.delay_seconds <= UINT32_MAX:
            raise BadTypedData(
                f"a delay of {self.delay_seconds} s does not fit the uint32 "
                f"the account stores it in")
        _address_bytes(self.executor)
        if not _is_zero_address(self.executor):
            if self.executor.lower() == self.address.lower():
                raise BadTypedData(
                    "the executor and the account are the same address")
            if self.delay_seconds == 0:
                # Not fatal on chain, but it is always a mistake in a record:
                # the executor exists to bypass a delay, so recording one
                # beside no delay means the owner has misread their own
                # deployment, and the screen would go on to say "executes
                # immediately" for both callers.
                raise BadTypedData(
                    "an executor is recorded but the delay is zero. The "
                    "executor's only privilege is skipping the delay, so one "
                    "of the two is wrong. Check the account with "
                    "`provision.py verify-account`.")
        if self.fast_track:
            if _is_zero_address(self.executor):
                raise BadTypedData(
                    "the fast track is recorded as enabled but no executor is "
                    "recorded. `forwardEnabled` is a flag on the executor; "
                    "without one there is nothing to fast-track through.")
            if not self.owners:
                # The fast track costs every owner's signature, and the screen
                # says so by counting them. With no owners recorded there is
                # no number to say, and "runs now if all owners sign" over an
                # unknown quorum size tells the owner nothing they can check.
                raise BadTypedData(
                    "the fast track needs every owner's signature, so the "
                    "owners must be recorded for the screen to say how many.")

    def on_chain(self, chain_id: int) -> int:
        """Check a request's chain against the record, and hand it back.

        Every digest below takes the chain from its caller, so this is the one
        place that decides whether the caller was allowed to name it.
        """
        if chain_id not in self.chain_ids:
            raise BadTypedData(
                f"account {self.label!r} is registered on "
                f"{', '.join(eth.CHAINS[c][0] for c in self.chain_ids)}, and "
                f"the request named chain {chain_id}. Register the account on "
                f"that chain before signing for it.")
        return chain_id

    def separator(self, chain_id: int) -> bytes:
        return domain_separator(self.domain_name, self.domain_version,
                                self.on_chain(chain_id), self.address)

    def cancel_digest(self, tx_hash: bytes, nonce: int, chain_id: int) -> bytes:
        """The one self-call this device signs: cancel a queued transaction.

        Every other `execute(target=self, data=...)` is refused, and this is
        not an exception to that rule so much as the reason the rule can be
        kept. `cancelQueued(bytes32)` is the ONLY way to stop a transaction the
        timelock has already accepted, and a device that can queue but cannot
        cancel has handed its owner a delay they cannot use: the point of a
        timelock is the window it opens to react, and reacting is this call.

        It is safe to render where the others are not because its calldata has
        exactly one shape. Four bytes of a selector this module fixes, then one
        32-byte hash and nothing after it, so the screen can state the whole of
        what the signature commits to. `ops.CancelQueued` shows that hash in
        full, and the owner matches it against the queue in their companion.

        It also cannot move value: `value` is zero by construction here, and
        the account is calling itself.
        """
        return digest(self.separator(chain_id),
                      cancel_struct_hash(self.address, tx_hash, nonce))

    def spend_digest(self, target: str, value: int, nonce: int,
                     chain_id: int) -> bytes:
        """What the owner's signature will commit to, built from what it shows."""
        if target.lower() == self.address.lower():
            # execute(target=self, ...) is how owners, threshold, delay and
            # queued transactions are changed. All of it is calldata, so none
            # of it can be rendered yet, so none of it is signed yet.
            raise BadTypedData(
                "refusing a call from the account to itself. That is how the "
                "account's own configuration is changed, and it travels as "
                "calldata this device cannot render. The one exception is "
                "cancelling a queued transaction; ask for that operation by "
                "name instead of addressing a transfer at the account.")
        if _is_zero_address(target):
            # eth.EthTransaction refuses this outright. A burn addressed
            # through a smart account is the same irreversible mistake, and
            # the owner has no way to read it off a screen of hex zeros.
            raise BadTypedData("refusing to send to the zero address")
        return digest(self.separator(chain_id),
                      execute_struct_hash(target, value, b"", nonce))


ACCOUNTS: dict[str, SmartAccount] = {}


def register_account(account: SmartAccount) -> None:
    """Record an account, refusing a relabel of one already registered."""
    account.check()
    existing = ACCOUNTS.get(account.label)
    if existing is not None and existing != account:
        raise BadTypedData(
            f"account {account.label!r} is already registered at "
            f"{existing.address} on chain(s) "
            f"{', '.join(str(c) for c in existing.chain_ids)}. Registering a "
            f"second account under one label means the confirmation screen "
            f"names the wrong one.")
    for other in ACCOUNTS.values():
        if other.label == account.label:
            continue
        clash = sorted(set(other.chain_ids) & set(account.chain_ids))
        if other.address.lower() == account.address.lower() and clash:
            raise BadTypedData(
                f"{account.address} on chain "
                f"{', '.join(str(c) for c in clash)} is already registered as "
                f"{other.label!r}")
    ACCOUNTS[account.label] = account


def account(label: str) -> SmartAccount:
    try:
        return ACCOUNTS[label]
    except KeyError:
        raise BadTypedData(
            f"no smart account registered as {label!r}. This device signs for "
            f"{', '.join(sorted(ACCOUNTS)) or 'no accounts yet'}.") from None


# --------------------------------------------------------------------------
# EIP-7702
# --------------------------------------------------------------------------


def delegation_digest(chain_id: int, address: str, nonce: int) -> bytes:
    """keccak(0x05 || rlp([chain_id, address, nonce])), per EIP-7702.

    The nonce here is the EOA's own transaction nonce, not an account nonce.
    """
    if chain_id == 0:
        raise BadTypedData(
            "refusing a delegation with chain id 0. That is valid on every "
            "chain at once, including chains that do not exist yet, and it "
            "cannot be revoked on a chain the owner never uses.")
    if chain_id < 0:
        raise BadTypedData("negative chain id")
    if not 0 <= nonce <= UINT256_MAX:
        raise BadTypedData(f"nonce {nonce} does not fit a uint256")
    payload = eth.rlp_encode([chain_id, _address_bytes(address), nonce])
    return keccak256(bytes([MAGIC_7702]) + payload)


def _selftest() -> int:                                     # pragma: no cover
    import test_eip712
    return test_eip712.main()


if __name__ == "__main__":                                  # pragma: no cover
    raise SystemExit(_selftest())
