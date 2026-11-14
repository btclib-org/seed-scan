# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Account discovery on a public bundle: which accounts were used, and what for.

`scan` reads the text of a bundle, with `seed_scan.bundle` alone, and
asks a `btclib_wallet.fetch.history.HistoryReader` which of its Bitcoin
accounts have history, and a `seed_scan.evm.Node` which of its accounts
of the coins that chain reads were used on the EVM chain it serves. It
reads no secret: a bundle holds none, and `seed_scan.bundle.loads`
refuses a key that is not public. `seed_scan.cli` gives it an Electrum
server, an EVM node or both, each named by the user. A coin whose
backend is not given is listed as not checked.

Bitcoin and the EVM chains' coins are the coins read. For Bitcoin,
for each reading, each BIP43 purpose is read from account 0 up, as
BIP44's *Account discovery* reads it, until ``account_gap`` accounts in
a row have no history; an Electrum reading has one account, which is
read alone. Each account is `btclib_wallet.bip44.discover_account` on
the receive and change descriptors the bundle holds, each branch read
until ``gap_limit`` indexes in a row have no history. A purpose whose
accounts in the bundle end before that gap is reached is said to be cut
short, since an account after them may be used. Every other coin of the
bundle is listed as not checked, with the reason.

The caller names the EVM chain the node serves, a key of
`seed_scan.evm.EVM_CHAINS`, and a node whose ``eth_chainId`` answers
another chain id is refused before any address is asked. The accounts
read are those of the coins its `seed_scan.evm.EvmChain` lists:
Ethereum's on each chain, Ethereum Classic's too on Ethereum Classic,
and BNB's too on BNB Smart Chain; an account of a coin one chain alone
reads is listed as not checked on any other. Each coin's accounts are
read the same way as Bitcoin's, purpose by purpose and with the same two
bounds, on the receive branch alone: the addresses of an account are
those of the keys ``0/0``, ``0/1`` and on below its ``xpub``, as
`coin_addresses.evm` writes them. A legacy layout, of purpose ``null``,
is one account, read alone as an Electrum reading's is, and on no
branch: its addresses are those of the keys ``0``, ``1`` and on below
its ``xpub``. An address is used where the node answers a balance or a
nonce other than zero, each at the block tag ``latest``. That is the
chain's native asset alone: an address that only ever received tokens
has neither, and reads as unused, as no token balance is asked in this
version.

The balance of an account is read off the history discovery returns: an
output paying one of its used scripts counts until a transaction of that
history spends it. ``confirmed`` is what the confirmed transactions leave
unspent; ``unconfirmed`` is the change the mempool's transactions make to
it, negative where they spend a confirmed output. The balance of a used
address is read the same way off its own script, so the addresses' add
up to the account's. The history is what the reader answers, so the
balance is only as complete as the server's list. Two transactions of a
history that spend one output, as a replacement and the transaction it
replaces do, would both count, where at most one can confirm: the
mempool part of an answer is no snapshot, so the account is read again
once, and refused where that read lists two such transactions too. So
is an account whose used positions are not each within ``gap_limit`` of
the one before: discovery reads in windows, and a payment a window
found, which the last read no longer lists, leaves the positions it led
to past the gap.

The result is one JSON object, which `dumps` writes. It holds public data
only. Its members:

- ``format``: the string ``"seed-scan-scan"``.
- ``version``: the integer `VERSION`. A change of meaning takes a new
  version.
- ``bundle``: the SHA-256 of the bundle's text, UTF-8 encoded, as hex.
- ``server``: the Electrum server asked, as the user named it, or
  ``null`` where none was.
- ``gap_limit`` and ``account_gap``: the bound of the search, `GAP_LIMIT`
  and `ACCOUNT_GAP` unless the caller gives others.
- ``searched``: one object per reading and purpose read: ``reading``, the
  position of the reading in the bundle; ``purpose``, ``null`` for an
  Electrum reading; ``accounts``, how many accounts were read, from 0;
  and ``cut_short``, true where the bundle's accounts end before the
  account gap was reached.
- ``used``: one object per Bitcoin account with history, in the order
  read:
  ``reading``, ``purpose``, ``account`` and ``path``, as the bundle has
  them; ``addresses``, each used position as ``branch``, ``index``,
  ``address``, and its ``confirmed`` and ``unconfirmed`` balance in
  satoshis; ``transactions``, each as ``tx_id``, in display order,
  and ``height``, ``null`` for the mempool's; ``confirmed`` and
  ``unconfirmed``, in satoshis; and ``tip``, the height and block id the
  history was read up to.
- ``not_checked``: one object per reading and coin not read, with
  ``reading``, ``coin`` and ``reason``: `NO_SERVER` for Bitcoin,
  `NO_NODE` for a coin an EVM chain reads, the coin's `OTHER_CHAIN` for
  a coin one chain alone reads on a node of another chain, and
  `NOT_READ` for every other coin.
- ``evm``: ``null`` where no EVM node was asked, or the EVM scan:
  ``node``, the node asked, as its scheme, host and port, with no path
  or query; ``chain``, the chain read, a key of
  `seed_scan.evm.EVM_CHAINS`; ``chain_id``, as the node answered it,
  which is that chain's; ``block``, the latest block's number, asked
  before the first address; ``searched``, as above, with ``coin`` after
  ``reading`` and ``purpose`` ``null`` for a legacy layout, for the
  accounts of each coin read; and ``used``, one object per account with
  a used address: ``coin``, ``reading``, ``purpose``, ``account`` and
  ``path``, as the bundle has them; ``addresses``, each used address as
  ``index``, on the receive branch or, for a legacy layout, below the
  key itself, ``address``, ``balance`` and ``nonce``; and ``balance``,
  the sum of the addresses' balances.

A balance in ``evm`` is in wei, 10**-18 of the chain's native asset,
written as a string of decimal digits: RFC 8259's section 6 holds an
integer past 2**53 to be one JSON readers may not agree on.

`loads` reads a result back, against the text of the bundle it was made
from.
"""

from __future__ import annotations

import contextlib
import json
import re
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from functools import partial
from hashlib import sha256
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, TypeVar

from bip32_descriptors.bip32 import BIP32KeyData
from btclib.tx import OutPoint, TxOut
from btclib_wallet.bip44 import AccountUse, discover_account
from btclib_wallet.descriptors import Descriptor, parse
from btclib_wallet.fetch.history import HistoryReader, ScriptHistory
from coin_addresses.evm import address_from_pub_key

from seed_scan.bundle import Account, Bundle, Reading
from seed_scan.bundle import loads as bundle_loads
from seed_scan.evm import EVM_CHAINS, EvmChain, Node
from seed_scan.exceptions import SeedScanTypeError, SeedScanValueError

if TYPE_CHECKING:
    from collections.abc import Callable

__all__ = [
    "ACCOUNT_GAP",
    "FORMAT",
    "GAP_LIMIT",
    "NOT_READ",
    "NO_NODE",
    "NO_SERVER",
    "OTHER_CHAIN",
    "VERSION",
    "Address",
    "EvmAccount",
    "EvmAddress",
    "EvmScan",
    "EvmSearched",
    "NotRead",
    "ScanResult",
    "Searched",
    "Tip",
    "Transaction",
    "UsedAccount",
    "dumps",
    "loads",
    "parse_server",
    "scan",
]

#: The value of the ``format`` member.
FORMAT = "seed-scan-scan"

#: The value of the ``version`` member this module writes.
VERSION = 1

#: BIP44's gap limit, the default of ``gap_limit``.
GAP_LIMIT = 20

#: The default of ``account_gap``. BIP44 stops at the first account whose
#: external chain has no transactions; a recovery would rather over-search.
ACCOUNT_GAP = 3

#: The coins `scan` reads: Bitcoin, and those an EVM chain reads.
_BITCOIN = "bitcoin"
_EVM_COINS = tuple(
    dict.fromkeys(coin for chain in EVM_CHAINS.values() for coin in chain.coins)
)

#: The chain `scan` reads where the caller names none.
_DEFAULT_CHAIN = "ethereum"

#: The ``reason`` Bitcoin is not checked for, where no server is given.
NO_SERVER = "no Electrum server was named"

#: The ``reason`` an EVM coin is not checked for, where no node is given.
NO_NODE = "no EVM node was named"

#: The ``reason`` a coin one EVM chain alone reads is not checked for,
#: where the node serves another chain, by coin.
OTHER_CHAIN = MappingProxyType(
    {
        coin: f"read on {chain.title} alone, and the node serves another chain"
        for chain in EVM_CHAINS.values()
        for coin in chain.coins
        if sum(coin in other.coins for other in EVM_CHAINS.values()) == 1
    }
)

#: The ``reason`` every other coin is not checked for.
NOT_READ = "scan reads Bitcoin and the EVM chains' coins alone in this version"

# the last port, and the digits it takes, leading zeros aside
_MAX_PORT = 65535
_PORT_DIGITS = 5
# the first hardened index
_HARDENED = 0x80000000
# a transaction or a block id, as hex
_ID = re.compile(r"[0-9a-f]{64}")
# a balance in wei, as `dumps` writes it: decimal digits, no leading zero
_WEI = re.compile(r"0|[1-9][0-9]{0,77}")
# what bounds a balance in wei: an EVM word
_WORD = 2**256
# what bounds a balance in satoshis: 21 million bitcoin, Bitcoin Core's
# MAX_MONEY, which no amount of the chain passes
_MAX_SATOSHI = 21_000_000 * 100_000_000
# the refusal of a balance past it
_OUTSIDE = "a balance outside 0 to 21 million bitcoin"

_T = TypeVar("_T")
_U = TypeVar("_U")


@dataclass(frozen=True)
class Address:
    """A used position of an account: where it is, its address, its balance."""

    branch: int
    index: int
    address: str
    confirmed: int
    unconfirmed: int


@dataclass(frozen=True)
class Transaction:
    """A transaction of an account's history, and its height or ``None``."""

    tx_id: str
    height: int | None


@dataclass(frozen=True)
class Tip:
    """The block a history was read up to."""

    height: int
    block_id: str


@dataclass(frozen=True)
class UsedAccount:
    """An account with history: where it is, what it used, what it holds."""

    reading: int
    purpose: int | None
    account: int
    path: str
    addresses: tuple[Address, ...]
    transactions: tuple[Transaction, ...]
    confirmed: int
    unconfirmed: int
    tip: Tip


@dataclass(frozen=True)
class Searched:
    """The accounts of one reading and purpose that were read."""

    reading: int
    purpose: int | None
    accounts: int
    cut_short: bool


@dataclass(frozen=True)
class NotRead:
    """A coin of a reading that `scan` does not read, and why."""

    reading: int
    coin: str
    reason: str


@dataclass(frozen=True)
class EvmAddress:
    """A used EVM address: its index, its balance in wei, its nonce."""

    index: int
    address: str
    balance: str
    nonce: int


@dataclass(frozen=True)
class EvmSearched:
    """The accounts of one reading, coin and purpose read on the EVM chain."""

    reading: int
    coin: str
    purpose: int | None
    accounts: int
    cut_short: bool


@dataclass(frozen=True)
class EvmAccount:
    """An account with a used address on the EVM chain, its balance in wei."""

    coin: str
    reading: int
    purpose: int | None
    account: int
    path: str
    addresses: tuple[EvmAddress, ...]
    balance: str


@dataclass(frozen=True)
class EvmScan:
    """What the EVM node answered: the module docstring's ``evm``."""

    node: str
    chain: str
    chain_id: int
    block: int
    searched: tuple[EvmSearched, ...]
    used: tuple[EvmAccount, ...]


@dataclass(frozen=True)
class ScanResult:
    """What `scan` found: the module docstring's top-level object."""

    bundle: str
    server: str | None
    gap_limit: int
    account_gap: int
    searched: tuple[Searched, ...]
    used: tuple[UsedAccount, ...]
    not_checked: tuple[NotRead, ...]
    evm: EvmScan | None


def dumps(result: ScanResult) -> str:
    """Return the JSON text of a scan result, members in a fixed order."""
    document = {"format": FORMAT, "version": VERSION, **asdict(result)}
    return json.dumps(document, indent=2) + "\n"


def _descriptors(account: Account, where: str) -> tuple[Descriptor, ...]:
    """Return an account's descriptors, parsed.

    `seed_scan.bundle.loads` has read them as the receive and change
    descriptors over the account's own xpub, which holds no private key and
    ranges every index, checksum included; what it does not verify is that
    the key is a point of the curve, and `parse` does. Its refusal may quote
    the descriptor, so it is not kept: the refusal says where the account is
    in the bundle, raised outside `suppress` so that the error is not its
    context.
    """
    descriptors: tuple[Descriptor, ...] = ()
    with contextlib.suppress(TypeError, ValueError):
        descriptors = tuple(parse(text) for text in account.descriptors)
    if not descriptors:
        err_msg = f"bundle: {where}: a descriptor that does not parse"
        raise SeedScanValueError(err_msg)
    return descriptors


def _key(account: Account, where: str) -> BIP32KeyData:
    """Return an account's extended public key, decoded.

    `seed_scan.bundle.loads` has checked its Base58Check, its version and
    its length; what it does not check is that the key is a point of the
    curve, and decoding does. The refusal is raised outside `suppress`,
    so that the error is not its context.
    """
    key = None
    with contextlib.suppress(TypeError, ValueError):
        key = BIP32KeyData.b58decode(account.xpub)
    if key is None:
        raise SeedScanValueError(f"bundle: {where}: an xpub that does not decode")
    return key


#: A reading's accounts of one coin, by purpose, each beside what it is
#: read with.
_Purposes = dict[int | None, list[tuple[Account, _T]]]


def _numbered(position: int, purposes: _Purposes[_T]) -> None:
    """Refuse a purpose whose accounts are not numbered from 0 with no gap.

    That is how `identify` writes them, and a layout of purpose ``None``,
    Electrum's or an EVM coin's legacy one, has one.
    """
    for purpose, accounts in purposes.items():
        numbers = [account.account for account, _ in accounts]
        if numbers != list(range(len(numbers))) or (purpose is None and numbers != [0]):
            err_msg = f"bundle: reading {position}: accounts not numbered from 0"
            raise SeedScanValueError(err_msg)


#: A reading's accounts of each EVM coin, by coin, in the bundle's order.
_EvmCoins = dict[str, _Purposes[BIP32KeyData]]

#: A reading's Bitcoin accounts, its EVM coins' and its other coins.
_Plan = tuple[_Purposes[tuple[Descriptor, ...]], _EvmCoins, list[str]]


def _plan(position: int, reading: Reading) -> _Plan:
    """Return a reading's Bitcoin and EVM accounts, and its other coins."""
    bitcoin: _Purposes[tuple[Descriptor, ...]] = {}
    evm: _EvmCoins = {}
    others: list[str] = []
    for number, account in enumerate(reading.accounts):
        where = f"reading {position}, account {number}"
        if account.coin == _BITCOIN:
            descriptors = _descriptors(account, where)
            bitcoin.setdefault(account.purpose, []).append((account, descriptors))
        elif account.coin in _EVM_COINS:
            key = _key(account, where)
            purposes = evm.setdefault(account.coin, {})
            purposes.setdefault(account.purpose, []).append((account, key))
        elif account.coin not in others:
            others.append(account.coin)
    _numbered(position, bitcoin)
    for purposes in evm.values():
        _numbered(position, purposes)
    return bitcoin, evm, others


def _owned_outputs(
    history: ScriptHistory, scripts: frozenset[bytes]
) -> dict[OutPoint, tuple[TxOut, bool]]:
    """Return each output paying one of `scripts`, and whether it confirmed."""
    return {
        OutPoint(entry.tx.id, vout): (tx_out, entry.block is not None)
        for entry in history.txs
        for vout, tx_out in enumerate(entry.tx.vout)
        if tx_out.script_pub_key.script in scripts
    }


def _balances(
    history: ScriptHistory, scripts: frozenset[bytes]
) -> dict[bytes, tuple[int, int]]:
    """Return the confirmed balance of each script, and the mempool's change.

    The history is read once for every script. General, so it goes to
    btclib-wallet with btclib-org/btclib-wallet#860.
    """
    spent_confirmed = {
        tx_in.prev_out for entry in history.txs if entry.block for tx_in in entry.tx.vin
    }
    spent = {tx_in.prev_out for entry in history.txs for tx_in in entry.tx.vin}
    confirmed = dict.fromkeys(scripts, 0)
    total = dict.fromkeys(scripts, 0)
    for point, (out, in_block) in _owned_outputs(history, scripts).items():
        script = out.script_pub_key.script
        if in_block and point not in spent_confirmed:
            confirmed[script] += out.value
        if point not in spent:
            total[script] += out.value
    return {
        script: (confirmed[script], total[script] - confirmed[script])
        for script in scripts
    }


def _bounded(confirmed: int, unconfirmed: int) -> bool:
    """Answer whether a balance is one unspent outputs can make.

    What the confirmed transactions leave, and with the mempool's change,
    is unspent outputs: from 0 to 21 million bitcoin.
    """
    return (
        0 <= confirmed <= _MAX_SATOSHI and 0 <= confirmed + unconfirmed <= _MAX_SATOSHI
    )


def _spends_one_output_twice(history: ScriptHistory) -> bool:
    """Answer whether two transactions of `history` spend the same output.

    A coinbase input spends no output, and is skipped.
    """
    spender: dict[OutPoint, bytes] = {}
    for entry in history.txs:
        for tx_in in entry.tx.vin:
            if tx_in.is_coinbase:
                continue
            if spender.setdefault(tx_in.prev_out, entry.tx.id) != entry.tx.id:
                return True
    return False


def _reachable(indexes: Sequence[int], gap_limit: int) -> bool:
    """Answer whether a branch read from 0 reaches every one of `indexes`.

    The read goes on while fewer than `gap_limit` indexes in a row are
    unused, so each used index is less than `gap_limit` past the one
    before it, or past the start.
    """
    last = -1
    for index in sorted(indexes):
        if index - last > gap_limit:
            return False
        last = index
    return True


def _unsound(use: AccountUse, gap_limit: int) -> str:
    """Return what makes a discovery no answer to rely on, or ``""``.

    Two transactions spending one output, which would both count; or a
    used position that a branch read under `gap_limit` does not reach:
    the windows of the read found a payment before it that the last read
    no longer lists, taken out by a reorganization or the mempool.
    """
    if _spends_one_output_twice(use.history):
        return "two transactions spend one output"
    if not all(_reachable(indexes, gap_limit) for indexes in use.used):
        return "a used position past the gap limit"
    return ""


def _read_account(
    descriptors: tuple[Descriptor, ...],
    reader: HistoryReader,
    gap_limit: int,
    where: str,
) -> AccountUse | None:
    """Return the discovery of an account, read again once where `_unsound`.

    Refused where both reads are.
    """
    err_msg = ""
    for _ in range(2):
        use = discover_account(descriptors, reader, gap_limit=gap_limit)
        if use is None or not (err_msg := _unsound(use, gap_limit)):
            return use
    raise SeedScanValueError(f"{where}: {err_msg}, in both reads of it")


def _used_account(
    reading: int, account: Account, use: AccountUse, where: str
) -> UsedAccount:
    """Return what an account's discovery found, as public data.

    Refused where the balance of the account or of a used address is not
    `_bounded`, as `loads` refuses it; `where` names the account in the
    refusal.
    """
    history = use.history
    positions = [
        (branch, index, script_pub_key)
        for branch, indexes in enumerate(use.used)
        for index in indexes
        for script_pub_key in use.descriptors[branch].script_pub_keys(index)
    ]
    balances = _balances(history, frozenset(s.script for _, _, s in positions))
    addresses = [
        Address(branch, index, s.address, *balances[s.script])
        for branch, index, s in positions
    ]
    confirmed = sum(c for c, _ in balances.values())
    unconfirmed = sum(u for _, u in balances.values())
    if not all(_bounded(*b) for b in [*balances.values(), (confirmed, unconfirmed)]):
        raise SeedScanValueError(f"{where}: {_OUTSIDE}")
    return UsedAccount(
        reading=reading,
        purpose=account.purpose,
        account=account.account,
        path=account.path,
        addresses=tuple(addresses),
        transactions=tuple(
            Transaction(
                entry.tx.id.hex(), None if entry.block is None else entry.block.height
            )
            for entry in history.txs
        ),
        confirmed=confirmed,
        unconfirmed=unconfirmed,
        tip=Tip(history.tip.height, history.tip.block_id.hex()),
    )


def _limit(value: int, name: str) -> int:
    """Return a bound of the search, refusing one that is no integer from 1."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeedScanTypeError(f"invalid {name} type: {type(value).__name__}")
    if value < 1:
        raise SeedScanValueError(f"invalid {name}: {value} is below 1")
    return value


def _bitcoin_account(
    reading: int,
    account: Account,
    descriptors: tuple[Descriptor, ...],
    *,
    reader: HistoryReader,
    gap_limit: int,
) -> UsedAccount | None:
    """Return what a Bitcoin account used, or None where it used nothing."""
    where = f"reading {reading}, account {account.path}"
    use = _read_account(descriptors, reader, gap_limit, where)
    return None if use is None else _used_account(reading, account, use, where)


def _evm_account(
    reading: int, account: Account, key: BIP32KeyData, *, node: Node, gap_limit: int
) -> EvmAccount | None:
    """Return an EVM account's used addresses, or None where none is.

    The receive branch, or the key itself for a legacy layout, is read
    from index 0 until `gap_limit` indexes in a row are unused.
    """
    branch = _branch(account, key)
    addresses: list[EvmAddress] = []
    index = unused = 0
    while unused < gap_limit:
        address = address_from_pub_key(branch.derive(index).sec)
        balance, nonce = node.balance(address), node.nonce(address)
        if balance or nonce:
            addresses.append(EvmAddress(index, address, str(balance), nonce))
            unused = 0
        else:
            unused += 1
        index += 1
    if not addresses:
        return None
    return EvmAccount(
        coin=account.coin,
        reading=reading,
        purpose=account.purpose,
        account=account.account,
        path=account.path,
        addresses=tuple(addresses),
        balance=str(sum(int(found.balance) for found in addresses)),
    )


def _branch(account: Account, key: BIP32KeyData) -> BIP32KeyData:
    """Return the key whose children are an EVM account's addresses.

    The receive branch below the account's key, or the key itself for a
    legacy layout, of purpose None.
    """
    return key if account.purpose is None else key.derive(0)


def _discover(
    reading: int,
    purpose: int | None,
    accounts: Sequence[tuple[Account, _T]],
    read: Callable[[Account, _T], _U | None],
    account_gap: int,
) -> tuple[Searched, list[_U]]:
    """Read the accounts of one purpose in order, until the account gap.

    `read` answers what an account used, or None where it used nothing.
    `discover_accounts` reads Bitcoin's accounts the same way, and
    refuses a purpose whose accounts end before the gap, dropping what it
    found (btclib-org/btclib-wallet#859): here that purpose is cut short.
    """
    used: list[_U] = []
    unused = done = 0
    for account, what in accounts:
        if unused == account_gap:
            break
        found = read(account, what)
        done += 1
        if found is None:
            unused += 1
        else:
            unused = 0
            used.append(found)
    cut_short = purpose is not None and unused < account_gap
    return Searched(reading, purpose, done, cut_short), used


def _backends(
    reader: HistoryReader | None, server: str | None, node: Node | None
) -> None:
    """Refuse a server named without its reader, and a scan of nothing."""
    if reader is not None and not isinstance(server, str):
        raise SeedScanTypeError(f"invalid server type: {type(server).__name__}")
    if isinstance(server, str):
        parse_server(server, "server")
    if reader is None and server is not None:
        raise SeedScanValueError("a server is named, and no reader asks it")
    if reader is None and node is None:
        raise SeedScanValueError("neither a reader nor a node is given")


def scan(
    text: str,
    reader: HistoryReader | None,
    *,
    server: str | None = None,
    node: Node | None = None,
    evm_chain: str = _DEFAULT_CHAIN,
    gap_limit: int = GAP_LIMIT,
    account_gap: int = ACCOUNT_GAP,
) -> ScanResult:
    """Run account discovery on the bundle whose text is `text`.

    `reader` reads Bitcoin's accounts, and `server` is what the result
    names as the server it asks; `node` reads the accounts of the coins
    `evm_chain` reads, a key of `seed_scan.evm.EVM_CHAINS`, which the
    node serves. Either may be None, and not both; a coin whose backend
    is None is listed as not checked. The bundle is read, and every
    account of it checked, before `reader` or `node` is asked anything.
    An `evm_chain` not in `seed_scan.evm.EVM_CHAINS` is refused without
    quoting it, and one that is no string is a `SeedScanTypeError`.
    Refused, as `seed_scan.bundle.loads` refuses it: text that is not a
    bundle. Refused as a `SeedScanValueError` too: a descriptor that
    does not parse, as one whose key is no point of the curve, an
    extended public key that does not decode, accounts not numbered from
    0, and a `server` that `parse_server` refuses. A bound below 1 is
    refused, and one that is no integer is a `SeedScanTypeError`, as is
    a `server` that is no string beside a `reader`. Refused once
    `reader` is asked: an account whose history lists two transactions
    spending one output, or whose used positions a read under
    `gap_limit` does not reach, in two reads; and an account whose
    balance, or a used address's, is outside 0 to 21 million bitcoin,
    which `loads` would refuse. Refused once `node` is asked: a node
    whose chain id is not `evm_chain`'s.
    """
    bundle = bundle_loads(text)
    _backends(reader, server, node)
    chain = _evm_chain(evm_chain)
    gap_limit = _limit(gap_limit, "gap_limit")
    account_gap = _limit(account_gap, "account_gap")
    plans = [_plan(n, reading) for n, reading in enumerate(bundle.readings)]
    searched: list[Searched] = []
    used: list[UsedAccount] = []
    not_checked: list[NotRead] = []
    for n, (bitcoin, evm_coins, others) in enumerate(plans):
        if reader is None and bitcoin:
            not_checked.append(NotRead(n, _BITCOIN, NO_SERVER))
        not_checked += [
            NotRead(n, coin, NO_NODE if node is None else OTHER_CHAIN[coin])
            for coin in evm_coins
            if node is None or coin not in chain.coins
        ]
        not_checked += [NotRead(n, coin, NOT_READ) for coin in others]
        if reader is None:
            continue
        read = partial(_bitcoin_account, n, reader=reader, gap_limit=gap_limit)
        for purpose, accounts in bitcoin.items():
            done, found = _discover(n, purpose, accounts, read, account_gap)
            searched.append(done)
            used += found
    evm = None
    if node is not None:
        evm = _scan_evm(plans, node, chain, (gap_limit, account_gap))
    return ScanResult(
        bundle=sha256(text.encode("utf-8")).hexdigest(),
        server=server,
        gap_limit=gap_limit,
        account_gap=account_gap,
        searched=tuple(searched),
        used=tuple(used),
        not_checked=tuple(not_checked),
        evm=evm,
    )


def _evm_chain(name: str) -> EvmChain:
    """Return the EVM chain `name` names, refusing one scan does not read."""
    if not isinstance(name, str):
        raise SeedScanTypeError(f"invalid evm_chain type: {type(name).__name__}")
    if name not in EVM_CHAINS:
        raise SeedScanValueError("invalid evm_chain: not one scan reads")
    return EVM_CHAINS[name]


def _scan_evm(
    plans: Sequence[_Plan], node: Node, chain: EvmChain, bounds: tuple[int, int]
) -> EvmScan:
    """Ask the node its chain id and latest block, then read the accounts.

    A node whose chain id is not `chain`'s is refused before its latest
    block is asked, without quoting the chain id it answered. `bounds`
    are ``gap_limit`` and ``account_gap``.
    """
    gap_limit, account_gap = bounds
    chain_id = node.chain_id()
    if chain_id != chain.chain_id:
        raise SeedScanValueError(f"the node does not serve {chain.title}")
    block = node.block_number()
    searched: list[EvmSearched] = []
    used: list[EvmAccount] = []
    for n, (_, evm_coins, _) in enumerate(plans):
        read = partial(_evm_account, n, node=node, gap_limit=gap_limit)
        for coin, purposes in evm_coins.items():
            if coin not in chain.coins:
                continue
            for purpose, accounts in purposes.items():
                done, found = _discover(n, purpose, accounts, read, account_gap)
                searched.append(
                    EvmSearched(n, coin, purpose, done.accounts, done.cut_short)
                )
                used += found
    return EvmScan(node.name, chain.name, chain_id, block, tuple(searched), tuple(used))


def parse_server(text: str, name: str) -> tuple[str, int]:
    """Return the host and port of an Electrum server named ``host:port``.

    The one rule ``seed-scan scan --server`` takes a server by and `loads`
    reads ``server`` by, so that every result `scan` writes reads back.
    The host is not empty, and holds no space and no character that does
    not print; an IPv6 host is in brackets, which are dropped. The port
    is ASCII digits naming 1 to 65535, leading zeros allowed. Anything
    else is refused, as a `SeedScanValueError` opening with `name` and
    quoting nothing.
    """
    host, colon, port = text.rpartition(":")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not (
        colon
        and host
        and host.isprintable()
        and not any(c.isspace() for c in host)
        and port.isascii()
        and port.isdigit()
    ):
        raise SeedScanValueError(f"{name} is not host:port")
    # checked before `int`, which refuses a string of too many digits
    digits = port.lstrip("0")
    if len(digits) > _PORT_DIGITS or not 0 < int(digits or "0") <= _MAX_PORT:
        raise SeedScanValueError(f"{name}: the port is not 1 to 65535")
    return host, int(digits)


def _member(document: dict[str, Any], key: str, kind: type | tuple[type, ...]) -> Any:
    """Return one member of an object, refusing it missing or of a wrong type.

    `bool` is an `int` to `isinstance`, so it is refused where an integer
    is asked for.
    """
    if key not in document:
        raise SeedScanValueError(f"scan result: missing member {key!r}")
    value = document[key]
    kinds = kind if isinstance(kind, tuple) else (kind,)
    if (isinstance(value, bool) and bool not in kinds) or not isinstance(value, kinds):
        err_msg = f"scan result: member {key!r} of type {type(value).__name__}"
        raise SeedScanTypeError(err_msg)
    return value


def _count(document: dict[str, Any], key: str, least: int = 0) -> int:
    """Return a member that is an integer from `least`, unquoted."""
    value: int = _member(document, key, int)
    if value < least:
        raise SeedScanValueError(f"scan result: member {key!r} is below {least}")
    return value


def _height(document: dict[str, Any]) -> int | None:
    """Return the ``height`` member: an integer from 0, or ``None``."""
    if _member(document, "height", (int, type(None))) is None:
        return None
    return _count(document, "height")


def _id(document: dict[str, Any], key: str) -> str:
    """Return a member that is a transaction or block id, 64 hex characters."""
    value: str = _member(document, key, str)
    if not _ID.fullmatch(value):
        raise SeedScanValueError(f"scan result: member {key!r} is not an id")
    return value


def _wei(document: dict[str, Any], key: str) -> str:
    """Return a member that is a balance in wei, as `dumps` writes one."""
    value: str = _member(document, key, str)
    if not _WEI.fullmatch(value) or int(value) >= _WORD:
        raise SeedScanValueError(f"scan result: member {key!r} is not a wei balance")
    return value


def _objects(document: dict[str, Any], key: str) -> list[dict[str, Any]]:
    """Return a member that is a list of objects."""
    values: list[object] = _member(document, key, list)
    objects: list[dict[str, Any]] = []
    for value in values:
        if not isinstance(value, dict):
            err_msg = f"scan result: an item of {key!r} of type {type(value).__name__}"
            raise SeedScanTypeError(err_msg)
        objects.append(value)
    return objects


def _where(document: dict[str, Any]) -> tuple[int, int | None]:
    """Return the ``reading`` and ``purpose`` members of an object."""
    purpose = _member(document, "purpose", (int, type(None)))
    return (
        _count(document, "reading"),
        None if purpose is None else _count(document, "purpose"),
    )


#: A bundle's accounts of one coin, by reading, purpose and number.
_Held = dict[tuple[int, int | None, int], Account]


def _held(bundle: Bundle, coin: str) -> _Held:
    """Return the bundle's accounts of one coin."""
    return {
        (n, account.purpose, account.account): account
        for n, reading in enumerate(bundle.readings)
        for account in reading.accounts
        if account.coin == coin
    }


def _searched(document: dict[str, Any], accounts: _Held) -> Searched:
    """Read one ``searched`` object: the accounts it read are the bundle's."""
    reading, purpose = _where(document)
    read = _count(document, "accounts", 1)
    if (reading, purpose, read - 1) not in accounts:
        raise SeedScanValueError("scan result: a search reads no account of the bundle")
    return Searched(reading, purpose, read, _member(document, "cut_short", bool))


def _searches(
    document: dict[str, Any], accounts: _Held
) -> dict[tuple[int, int | None], Searched]:
    """Read a ``searched`` member, each purpose searched once."""
    searched: dict[tuple[int, int | None], Searched] = {}
    for item in _objects(document, "searched"):
        done = _searched(item, accounts)
        if (done.reading, done.purpose) in searched:
            raise SeedScanValueError("scan result: a purpose searched twice")
        searched[done.reading, done.purpose] = done
    return searched


def _account(
    document: dict[str, Any],
    accounts: _Held,
    searched: dict[tuple[int, int | None], Searched],
) -> tuple[int, int | None, Account]:
    """Return the reading, purpose and account a used object names.

    The account is one the result says it searched, and the ``path`` the
    bundle's.
    """
    reading, purpose = _where(document)
    number = _count(document, "account")
    done = searched.get((reading, purpose))
    account = accounts.get((reading, purpose, number))
    if done is None or account is None or number >= done.accounts:
        raise SeedScanValueError("scan result: a used account was not searched")
    if _member(document, "path", str) != account.path:
        raise SeedScanValueError("scan result: member 'path' is not the account's")
    return reading, purpose, account


def _sats(document: dict[str, Any]) -> tuple[int, int]:
    """Return the ``confirmed`` and ``unconfirmed`` members of an object.

    A balance `_bounded` takes.
    """
    confirmed = _count(document, "confirmed")
    unconfirmed: int = _member(document, "unconfirmed", int)
    if not _bounded(confirmed, unconfirmed):
        raise SeedScanValueError(f"scan result: {_OUTSIDE}")
    return confirmed, unconfirmed


def _gaps(indexes: dict[int, list[int]], gap_limit: int) -> None:
    """Refuse used positions a branch read under `gap_limit` does not reach."""
    if not all(_reachable(branch, gap_limit) for branch in indexes.values()):
        raise SeedScanValueError("scan result: an address past the gap limit")


def _addresses(
    document: dict[str, Any], account: Account, gap_limit: int
) -> tuple[Address, ...]:
    """Read a Bitcoin account's used positions, each the bundle's there."""
    descriptors = _descriptors(account, f"account {account.path}")
    addresses: list[Address] = []
    for position in _objects(document, "addresses"):
        branch = _count(position, "branch")
        index = _count(position, "index")
        if (branch, index) in {(a.branch, a.index) for a in addresses}:
            raise SeedScanValueError("scan result: an address listed twice")
        address: str = _member(position, "address", str)
        # an index of 2^31 and above would be hardened, which no
        # descriptor of the bundle derives
        if (
            index >= _HARDENED
            or branch >= len(descriptors)
            or address
            not in (s.address for s in descriptors[branch].script_pub_keys(index))
        ):
            err_msg = "scan result: an address is not the bundle's at its position"
            raise SeedScanValueError(err_msg)
        addresses.append(Address(branch, index, address, *_sats(position)))
    if not addresses:
        raise SeedScanValueError("scan result: a used account lists no address")
    branches: dict[int, list[int]] = {}
    for a in addresses:
        branches.setdefault(a.branch, []).append(a.index)
    _gaps(branches, gap_limit)
    return tuple(addresses)


def _used(
    document: dict[str, Any],
    accounts: _Held,
    searched: dict[tuple[int, int | None], Searched],
    gap_limit: int,
) -> UsedAccount:
    """Read one ``used`` object: a Bitcoin account the result searched.

    Its history holds what its use and its balance need: a transaction
    at least, a confirmed one where a confirmed balance is, and one of
    the mempool's where the mempool changes the balance of an address,
    even where the changes of its addresses cancel out.
    """
    reading, purpose, account = _account(document, accounts, searched)
    tip: dict[str, Any] = _member(document, "tip", dict)
    addresses = _addresses(document, account, gap_limit)
    transactions = tuple(
        Transaction(_id(t, "tx_id"), _height(t))
        for t in _objects(document, "transactions")
    )
    confirmed, unconfirmed = _sats(document)
    in_blocks = any(t.height is not None for t in transactions)
    in_mempool = any(t.height is None for t in transactions)
    if (
        not transactions
        or (confirmed and not in_blocks)
        or (any(a.unconfirmed for a in addresses) and not in_mempool)
    ):
        err_msg = "scan result: a balance or a use no transaction listed gives"
        raise SeedScanValueError(err_msg)
    sums = (sum(a.confirmed for a in addresses), sum(a.unconfirmed for a in addresses))
    if sums != (confirmed, unconfirmed):
        err_msg = "scan result: the addresses' balances are not the account's"
        raise SeedScanValueError(err_msg)
    return UsedAccount(
        reading=reading,
        purpose=purpose,
        account=account.account,
        path=account.path,
        addresses=addresses,
        transactions=transactions,
        confirmed=confirmed,
        unconfirmed=unconfirmed,
        tip=Tip(_count(tip, "height"), _id(tip, "block_id")),
    )


def _evm_addresses(
    document: dict[str, Any], account: Account, gap_limit: int
) -> tuple[EvmAddress, ...]:
    """Read an EVM account's used addresses, each the bundle's there.

    Each holds a balance or a nonce, as `scan` lists no other.
    """
    branch = _branch(account, _key(account, f"account {account.path}"))
    addresses: list[EvmAddress] = []
    for position in _objects(document, "addresses"):
        index = _count(position, "index")
        if index in {a.index for a in addresses}:
            raise SeedScanValueError("scan result: an address listed twice")
        address: str = _member(position, "address", str)
        # an index of 2^31 and above would be hardened, a key the xpub
        # does not derive
        if index >= _HARDENED or address != address_from_pub_key(
            branch.derive(index).sec
        ):
            err_msg = "scan result: an address is not the bundle's at its position"
            raise SeedScanValueError(err_msg)
        balance, nonce = _wei(position, "balance"), _count(position, "nonce")
        if balance == "0" and nonce == 0:
            raise SeedScanValueError("scan result: an unused address listed as used")
        addresses.append(EvmAddress(index, address, balance, nonce))
    _gaps({0: [a.index for a in addresses]}, gap_limit)
    return tuple(addresses)


def _evm_used(
    document: dict[str, Any],
    accounts: _Held,
    searched: dict[tuple[int, int | None], Searched],
    gap_limit: int,
) -> EvmAccount:
    """Read one ``used`` object of ``evm``: an account of its coin it searched.

    `accounts` and `searched` are those of the object's coin.
    """
    reading, purpose, account = _account(document, accounts, searched)
    addresses = _evm_addresses(document, account, gap_limit)
    if not addresses:
        raise SeedScanValueError("scan result: a used account lists no address")
    balance = str(sum(int(a.balance) for a in addresses))
    if _member(document, "balance", str) != balance:
        err_msg = "scan result: the addresses' balances are not the account's"
        raise SeedScanValueError(err_msg)
    return EvmAccount(
        coin=account.coin,
        reading=reading,
        purpose=purpose,
        account=account.account,
        path=account.path,
        addresses=addresses,
        balance=balance,
    )


def _agrees(done: Searched, used: set[int], held: int, account_gap: int) -> bool:
    """Answer whether a search's accounts, used ones and ``cut_short`` agree.

    `scan` reads a purpose's accounts from 0 and stops once `account_gap`
    of them in a row are unused, or once the bundle's `held` accounts run
    out: then, and only then, the purpose is cut short. The one account
    of a layout of purpose None is read alone and never cut short.
    """
    if done.purpose is None:
        return not done.cut_short
    unused = 0
    for number in range(done.accounts):
        if unused == account_gap:
            return False
        unused = 0 if number in used else unused + 1
    if unused == account_gap:
        return not done.cut_short
    return done.cut_short and done.accounts == held


def _check_searches(
    searched: dict[tuple[int, int | None], Searched],
    used: Sequence[UsedAccount | EvmAccount],
    accounts: _Held,
    account_gap: int,
) -> None:
    """Refuse a search whose accounts and ``cut_short`` are not `scan`'s."""
    for (reading, purpose), done in searched.items():
        numbers = {
            u.account for u in used if (u.reading, u.purpose) == (reading, purpose)
        }
        held = sum((r, p) == (reading, purpose) for r, p, _ in accounts)
        if not _agrees(done, numbers, held, account_gap):
            err_msg = "scan result: a search's accounts and 'cut_short' do not agree"
            raise SeedScanValueError(err_msg)


def _keyed(used: Sequence[UsedAccount | EvmAccount]) -> None:
    """Refuse a used account listed twice: its balance would count twice."""
    keys = [(u.reading, u.purpose, u.account) for u in used]
    if len(set(keys)) != len(keys):
        raise SeedScanValueError("scan result: a used account listed twice")


def _evm_coin(document: dict[str, Any], chain: EvmChain) -> str:
    """Return the ``coin`` member of an object of ``evm``: one `chain` reads."""
    coin: str = _member(document, "coin", str)
    if coin not in chain.coins:
        raise SeedScanValueError("scan result: a coin the chain does not read")
    return coin


#: The searches of each coin of ``evm``, by reading and purpose.
_EvmSearches = dict[str, dict[tuple[int, int | None], Searched]]


def _evm_searches(
    evm: dict[str, Any], bundle: Bundle, chain: EvmChain
) -> tuple[_EvmSearches, tuple[EvmSearched, ...]]:
    """Read the ``searched`` member of ``evm``: by coin, and in its order.

    Each object is read as `_searches` reads Bitcoin's, against the
    bundle's accounts of its coin, and each coin's purposes are searched
    once.
    """
    by_coin: _EvmSearches = {}
    in_order: list[EvmSearched] = []
    for item in _objects(evm, "searched"):
        coin = _evm_coin(item, chain)
        done = _searched(item, _held(bundle, coin))
        of_coin = by_coin.setdefault(coin, {})
        if (done.reading, done.purpose) in of_coin:
            raise SeedScanValueError("scan result: a purpose searched twice")
        of_coin[done.reading, done.purpose] = done
        in_order.append(
            EvmSearched(done.reading, coin, done.purpose, done.accounts, done.cut_short)
        )
    return by_coin, tuple(in_order)


def _evm(
    document: dict[str, Any], bundle: Bundle, bounds: tuple[int, int]
) -> EvmScan | None:
    """Read the ``evm`` member: ``null``, or the EVM scan.

    `bounds` are the result's ``gap_limit`` and ``account_gap``.
    """
    gap_limit, account_gap = bounds
    evm: dict[str, Any] | None = _member(document, "evm", (dict, type(None)))
    if evm is None:
        return None
    node: str = _member(evm, "node", str)
    name = None
    # a refusal of the name is raised outside `suppress`, so that it
    # chains none
    with contextlib.suppress(SeedScanTypeError, SeedScanValueError):
        name = Node(node).name
    if name != node:
        err_msg = "scan result: member 'node' is not a scheme, host and port"
        raise SeedScanValueError(err_msg)
    chain_name: str = _member(evm, "chain", str)
    chain = EVM_CHAINS.get(chain_name)
    if chain is None:
        raise SeedScanValueError("scan result: member 'chain' is not one scan reads")
    if _count(evm, "chain_id") != chain.chain_id:
        raise SeedScanValueError("scan result: member 'chain_id' is not the chain's")
    searched, in_order = _evm_searches(evm, bundle, chain)
    used: list[EvmAccount] = []
    for item in _objects(evm, "used"):
        coin = _evm_coin(item, chain)
        held = _held(bundle, coin)
        used.append(_evm_used(item, held, searched.get(coin, {}), gap_limit))
    for coin in chain.coins:
        of_coin = [u for u in used if u.coin == coin]
        _keyed(of_coin)
        _check_searches(
            searched.get(coin, {}), of_coin, _held(bundle, coin), account_gap
        )
    return EvmScan(
        node=node,
        chain=chain.name,
        chain_id=chain.chain_id,
        block=_count(evm, "block"),
        searched=in_order,
        used=tuple(used),
    )


def _not_read(
    document: dict[str, Any], bundle: Bundle, reasons: dict[str, str | None]
) -> NotRead:
    """Read one ``not_checked`` object: a coin of that reading, not read.

    `reasons` gives the reason of Bitcoin and of each EVM coin, or None
    where the result reads that coin; any other coin's is `NOT_READ`.
    """
    reading = _count(document, "reading")
    coin: str = _member(document, "coin", str)
    coins = (
        {a.coin for a in bundle.readings[reading].accounts}
        if reading < len(bundle.readings)
        else set()
    )
    if coin not in coins:
        raise SeedScanValueError("scan result: a coin not checked is not the bundle's")
    reason = reasons.get(coin, NOT_READ)
    if reason is None:
        raise SeedScanValueError("scan result: a coin read is listed as not checked")
    if _member(document, "reason", str) != reason:
        err_msg = "scan result: member 'reason' is not the format's for that coin"
        raise SeedScanValueError(err_msg)
    return NotRead(reading, coin, reason)


def loads(text: str, bundle: str) -> ScanResult:
    """Read a scan result back from its JSON text, against its bundle.

    `bundle` is the text of the bundle the result was made from, which
    `seed_scan.bundle.loads` reads. Refused, as a `SeedScanValueError`:
    text that is not JSON, another ``format``, another ``version``, a
    missing member, a negative count, a bound below 1, a result whose
    ``bundle`` is not the SHA-256 of `bundle`, a result naming neither a
    server nor a node, a Bitcoin search with no server, a purpose
    searched twice, a used account or an address listed twice, and a
    number too long for Python to read. The bundle is refused as `scan`
    refuses it. A member of the wrong type is a `SeedScanTypeError`.
    Members this version does not name are ignored. A refusal names the
    member, never its value.

    A reader echoes the text members, so each holds only what the format
    defines: a ``server`` that `parse_server` takes; a ``node`` that
    `seed_scan.evm.Node` takes, and names as it is written; a ``chain``
    of `seed_scan.evm.EVM_CHAINS`, with that chain's ``chain_id``, and a
    ``coin`` in ``evm`` that the chain reads; ids of 64 hex characters;
    a balance in wei of decimal digits, below 2**256; a ``reason`` that
    is the one `scan` gives that coin, for a coin of that reading it did
    not read. What the result says of the bundle is checked against it:
    each search and each used account names accounts of the bundle of
    its coin, a used account one its search read, its ``path`` the
    bundle's, each address the one the account's keys give at that
    position, an EVM address with a balance or a nonce, and each
    account's balance the sum of its addresses'. Each search's
    ``accounts`` and ``cut_short`` are the ones `scan` gives for the
    used accounts listed, the bundle's accounts and ``account_gap``.

    What a used account lists is what `scan` could have found: an
    address at least, each branch's used positions within ``gap_limit``
    of the one before, from index 0; for Bitcoin, a transaction at least,
    a confirmed one where ``confirmed`` is not 0 and one of the mempool's
    where an address's ``unconfirmed`` is not 0, and balances that leave
    from 0 to 21 million bitcoin unspent.
    """
    read = bundle_loads(bundle)
    # refused as `scan` refuses it: a descriptor or a key that does not
    # parse, or accounts not numbered from 0 with no gap
    for n, reading in enumerate(read.readings):
        _plan(n, reading)
    document = _document(text)
    digest = sha256(bundle.encode("utf-8")).hexdigest()
    if _member(document, "bundle", str) != digest:
        raise SeedScanValueError("scan result: made from another bundle")
    server: str | None = _member(document, "server", (str, type(None)))
    if server is not None:
        parse_server(server, "scan result: member 'server'")
    gap_limit = _count(document, "gap_limit", 1)
    account_gap = _count(document, "account_gap", 1)
    accounts = _held(read, _BITCOIN)
    searched = _searches(document, accounts)
    if server is None and searched:
        raise SeedScanValueError("scan result: a Bitcoin search with no server")
    used = [
        _used(item, accounts, searched, gap_limit)
        for item in _objects(document, "used")
    ]
    _keyed(used)
    _check_searches(searched, used, accounts, account_gap)
    evm = _evm(document, read, (gap_limit, account_gap))
    if server is None and evm is None:
        raise SeedScanValueError("scan result: it names neither a server nor a node")
    reasons: dict[str, str | None] = {_BITCOIN: NO_SERVER if server is None else None}
    for coin in _EVM_COINS:
        reasons[coin] = NO_NODE
        if evm is not None:
            reasons[coin] = (
                None if coin in EVM_CHAINS[evm.chain].coins else OTHER_CHAIN[coin]
            )
    return ScanResult(
        bundle=digest,
        server=server,
        gap_limit=gap_limit,
        account_gap=account_gap,
        searched=tuple(searched.values()),
        used=tuple(used),
        not_checked=tuple(
            _not_read(n, read, reasons) for n in _objects(document, "not_checked")
        ),
        evm=evm,
    )


def _document(text: str, form: str = FORMAT, version: int = VERSION) -> dict[str, Any]:
    """Return the JSON object of a result, of format `form` and `version`."""
    if not isinstance(text, str):
        raise SeedScanTypeError(f"scan result: text of type {type(text).__name__}")
    document: object = None
    try:
        document = json.loads(text)
    except json.JSONDecodeError as e:
        where = f"not JSON, at line {e.lineno} column {e.colno}"
    except ValueError:
        # an integer of more digits than `sys.get_int_max_str_digits`
        where = "a number too long to read"
    else:
        where = ""
    # raised outside the `except`, for `seed_scan.bundle.loads`'s reason
    if where:
        raise SeedScanValueError(f"scan result: {where}")
    if not isinstance(document, dict):
        raise SeedScanTypeError(f"scan result: a JSON {type(document).__name__}")
    if _member(document, "format", str) != form:
        raise SeedScanValueError(f"scan result: format is not {form!r}")
    if _member(document, "version", int) != version:
        raise SeedScanValueError(f"scan result: version is not {version}")
    return document
