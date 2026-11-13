# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Account discovery on a public bundle: which accounts were used, and what for.

`scan` reads the text of a bundle, with `seed_scan.bundle` alone, and
asks a `btclib_wallet.fetch.history.HistoryReader` which of its Bitcoin
accounts have history, and a `seed_scan.evm.Node` which of its Ethereum
accounts were used. It reads no secret: a bundle holds none, and
`seed_scan.bundle.loads` refuses a key that is not public.
`seed_scan.cli` gives it an Electrum server, an Ethereum node or both,
each named by the user. A coin whose backend is not given is listed as
not checked.

Bitcoin and Ethereum are the coins read. For Bitcoin, for each reading,
each BIP43 purpose is read
from account 0 up, as BIP44's *Account discovery* reads it, until
``account_gap`` accounts in a row have no history; an Electrum reading
has one account, which is read alone. Each account is
`btclib_wallet.bip44.discover_account` on the receive and change
descriptors the bundle holds, each branch read until ``gap_limit``
indexes in a row have no history. A purpose whose accounts in the bundle
end before that gap is reached is said to be cut short, since an account
after them may be used. Every other coin of the bundle is listed as not
checked, with the reason.

Ethereum's accounts are read the same way, purpose by purpose and with
the same two bounds, on the receive branch alone: the addresses of an
account are those of the keys ``0/0``, ``0/1`` and on below its
``xpub``, as `coin_addresses.evm` writes them. An address is used where
the node answers a balance or a nonce other than zero, each at the
block tag ``latest``. That is ether alone: an address that only ever
received tokens has neither, and reads as unused, as no token balance
is asked in this version.

The balance of an account is read off the history discovery returns: an
output paying one of its used scripts counts until a transaction of that
history spends it. ``confirmed`` is what the confirmed transactions leave
unspent; ``unconfirmed`` is the change the mempool's transactions make to
it, negative where they spend a confirmed output. The history is what the
reader answers, so the balance is only as complete as the server's list.

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
  them; ``addresses``, each used position as ``branch``, ``index`` and
  ``address``; ``transactions``, each as ``tx_id``, in display order,
  and ``height``, ``null`` for the mempool's; ``confirmed`` and
  ``unconfirmed``, in satoshis; and ``tip``, the height and block id the
  history was read up to.
- ``not_checked``: one object per reading and coin not read, with
  ``reading``, ``coin`` and ``reason``.
- ``evm``: ``null`` where no Ethereum node was asked, or the Ethereum
  scan: ``node``, the node asked, as its scheme, host and port, with no
  path or query; ``chain_id``, as the node answered it; ``block``, the
  latest block's number, asked before the first address; ``searched``,
  as above, for Ethereum's accounts; and ``used``, one object per
  account with a used address: ``reading``, ``purpose``, ``account`` and
  ``path``, as the bundle has them; ``addresses``, each used address as
  ``index``, on the receive branch, ``address``, ``balance`` and
  ``nonce``; and ``balance``, the sum of the addresses' balances.

A balance in ``evm`` is in wei, written as a string of decimal digits:
an ether is 10**18 wei, and RFC 8259's section 6 holds an integer past
2**53 to be one JSON readers may not agree on.
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from functools import partial
from hashlib import sha256
from typing import TYPE_CHECKING, TypeVar

from bip32_descriptors.bip32 import BIP32KeyData
from btclib.tx import OutPoint, TxOut
from btclib_wallet.bip44 import AccountUse, discover_account
from btclib_wallet.descriptors import Descriptor, parse
from btclib_wallet.fetch.history import HistoryReader, ScriptHistory
from coin_addresses.evm import address_from_pub_key

from seed_scan.bundle import Account, Reading, loads
from seed_scan.evm import Node
from seed_scan.exceptions import SeedScanTypeError, SeedScanValueError

if TYPE_CHECKING:
    from collections.abc import Callable

__all__ = [
    "ACCOUNT_GAP",
    "FORMAT",
    "GAP_LIMIT",
    "VERSION",
    "Address",
    "EvmAccount",
    "EvmAddress",
    "EvmScan",
    "NotRead",
    "ScanResult",
    "Searched",
    "Tip",
    "Transaction",
    "UsedAccount",
    "dumps",
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

#: The coins `scan` reads.
_BITCOIN = "bitcoin"
_ETHEREUM = "ethereum"

#: Why a coin of the bundle is not read: its backend was not given, or
#: this version reads it not at all.
_NO_SERVER = "no Electrum server was named"
_NO_NODE = "no Ethereum node was named"
_NOT_READ = "scan reads Bitcoin and Ethereum alone in this version"

_T = TypeVar("_T")
_U = TypeVar("_U")


@dataclass(frozen=True)
class Address:
    """A used position of an account: its branch, its index, its address."""

    branch: int
    index: int
    address: str


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
    """A used Ethereum address: its index, its balance in wei, its nonce."""

    index: int
    address: str
    balance: str
    nonce: int


@dataclass(frozen=True)
class EvmAccount:
    """An Ethereum account with a used address, and its balance in wei."""

    reading: int
    purpose: int | None
    account: int
    path: str
    addresses: tuple[EvmAddress, ...]
    balance: str


@dataclass(frozen=True)
class EvmScan:
    """What the Ethereum node answered: the module docstring's ``evm``."""

    node: str
    chain_id: int
    block: int
    searched: tuple[Searched, ...]
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
    descriptors over the account's own xpub, which holds no private key
    and ranges every index; what it does not verify is the checksum, and
    `parse` does. Its refusal may quote the descriptor, so it is not
    kept: the refusal says where the account is in the bundle, raised
    outside `suppress` so that the error is not its context.
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

    That is how `identify` writes them, and an Electrum reading, of
    purpose ``None``, has one.
    """
    for purpose, accounts in purposes.items():
        numbers = [account.account for account, _ in accounts]
        if numbers != list(range(len(numbers))) or (purpose is None and numbers != [0]):
            err_msg = f"bundle: reading {position}: accounts not numbered from 0"
            raise SeedScanValueError(err_msg)


def _plan(
    position: int, reading: Reading
) -> tuple[_Purposes[tuple[Descriptor, ...]], _Purposes[BIP32KeyData], list[str]]:
    """Return a reading's Bitcoin and Ethereum accounts, and its other coins."""
    bitcoin: _Purposes[tuple[Descriptor, ...]] = {}
    ethereum: _Purposes[BIP32KeyData] = {}
    others: list[str] = []
    for number, account in enumerate(reading.accounts):
        where = f"reading {position}, account {number}"
        if account.coin == _BITCOIN:
            descriptors = _descriptors(account, where)
            bitcoin.setdefault(account.purpose, []).append((account, descriptors))
        elif account.coin == _ETHEREUM:
            key = _key(account, where)
            ethereum.setdefault(account.purpose, []).append((account, key))
        elif account.coin not in others:
            others.append(account.coin)
    _numbered(position, bitcoin)
    _numbered(position, ethereum)
    return bitcoin, ethereum, others


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


def _balance(history: ScriptHistory, scripts: frozenset[bytes]) -> tuple[int, int]:
    """Return the confirmed balance of `scripts`, and the mempool's change.

    General, so it goes to btclib-wallet with btclib-org/btclib-wallet#860.
    """
    owned = _owned_outputs(history, scripts)
    spent_confirmed = {
        tx_in.prev_out for entry in history.txs if entry.block for tx_in in entry.tx.vin
    }
    spent = {tx_in.prev_out for entry in history.txs for tx_in in entry.tx.vin}
    confirmed = sum(
        out.value
        for point, (out, in_block) in owned.items()
        if in_block and point not in spent_confirmed
    )
    total = sum(out.value for point, (out, _) in owned.items() if point not in spent)
    return confirmed, total - confirmed


def _used_account(reading: int, account: Account, use: AccountUse) -> UsedAccount:
    """Return what an account's discovery found, as public data."""
    addresses: list[Address] = []
    scripts: set[bytes] = set()
    for branch, indexes in enumerate(use.used):
        for index in indexes:
            for script_pub_key in use.descriptors[branch].script_pub_keys(index):
                scripts.add(script_pub_key.script)
                addresses.append(Address(branch, index, script_pub_key.address))
    history = use.history
    confirmed, unconfirmed = _balance(history, frozenset(scripts))
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
    use = discover_account(descriptors, reader, gap_limit=gap_limit)
    return None if use is None else _used_account(reading, account, use)


def _evm_account(
    reading: int, account: Account, key: BIP32KeyData, *, node: Node, gap_limit: int
) -> EvmAccount | None:
    """Return an Ethereum account's used addresses, or None where none is.

    The receive branch is read from index 0 until `gap_limit` indexes in
    a row are unused.
    """
    branch = key.derive(0)
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
        reading=reading,
        purpose=account.purpose,
        account=account.account,
        path=account.path,
        addresses=tuple(addresses),
        balance=str(sum(int(found.balance) for found in addresses)),
    )


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
    gap_limit: int = GAP_LIMIT,
    account_gap: int = ACCOUNT_GAP,
) -> ScanResult:
    """Run account discovery on the bundle whose text is `text`.

    `reader` reads Bitcoin's accounts, and `server` is what the result
    names as the server it asks; `node` reads Ethereum's. Either may be
    None, and not both; a coin whose backend is None is listed as not
    checked. The bundle is read, and every account of it checked, before
    `reader` or `node` is asked anything. Refused, as
    `seed_scan.bundle.loads` refuses it: text that is not a bundle.
    Refused as a `SeedScanValueError` too: a descriptor whose checksum
    does not verify, an extended public key that does not decode, and
    accounts not numbered from 0. A bound below 1 is refused, and one
    that is no integer is a `SeedScanTypeError`, as is a `server` that is
    no string beside a `reader`.
    """
    bundle = loads(text)
    _backends(reader, server, node)
    gap_limit = _limit(gap_limit, "gap_limit")
    account_gap = _limit(account_gap, "account_gap")
    plans = [_plan(n, reading) for n, reading in enumerate(bundle.readings)]
    searched: list[Searched] = []
    used: list[UsedAccount] = []
    not_checked: list[NotRead] = []
    for n, (bitcoin, ethereum, others) in enumerate(plans):
        if reader is None and bitcoin:
            not_checked.append(NotRead(n, _BITCOIN, _NO_SERVER))
        if node is None and ethereum:
            not_checked.append(NotRead(n, _ETHEREUM, _NO_NODE))
        not_checked += [NotRead(n, coin, _NOT_READ) for coin in others]
        if reader is None:
            continue
        read = partial(_bitcoin_account, n, reader=reader, gap_limit=gap_limit)
        for purpose, accounts in bitcoin.items():
            done, found = _discover(n, purpose, accounts, read, account_gap)
            searched.append(done)
            used += found
    evm = None if node is None else _scan_evm(plans, node, gap_limit, account_gap)
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


def _scan_evm(
    plans: Sequence[
        tuple[_Purposes[tuple[Descriptor, ...]], _Purposes[BIP32KeyData], list[str]]
    ],
    node: Node,
    gap_limit: int,
    account_gap: int,
) -> EvmScan:
    """Ask the node its chain id and latest block, then read the accounts."""
    chain_id, block = node.chain_id(), node.block_number()
    searched: list[Searched] = []
    used: list[EvmAccount] = []
    for n, (_, ethereum, _) in enumerate(plans):
        read = partial(_evm_account, n, node=node, gap_limit=gap_limit)
        for purpose, accounts in ethereum.items():
            done, found = _discover(n, purpose, accounts, read, account_gap)
            searched.append(done)
            used += found
    return EvmScan(node.name, chain_id, block, tuple(searched), tuple(used))
