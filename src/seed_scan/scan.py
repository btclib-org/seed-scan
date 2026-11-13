# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Account discovery on a public bundle: which accounts were used, and what for.

`scan` reads the text of a bundle, with `seed_scan.bundle` alone, and
asks a `btclib_wallet.fetch.history.HistoryReader` which of its accounts
have history. It reads no secret: a bundle holds none, and
`seed_scan.bundle.loads` refuses a key that is not public.
`seed_scan.cli` gives it an Electrum server the user names.

Bitcoin is the coin read. For each reading, each BIP43 purpose is read
from account 0 up, as BIP44's *Account discovery* reads it, until
``account_gap`` accounts in a row have no history; an Electrum reading
has one account, which is read alone. Each account is
`btclib_wallet.bip44.discover_account` on the receive and change
descriptors the bundle holds, each branch read until ``gap_limit``
indexes in a row have no history. A purpose whose accounts in the bundle
end before that gap is reached is said to be cut short, since an account
after them may be used. Every other coin of the bundle is listed as not
checked, with the reason.

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
- ``server``: the server asked, as the user named it.
- ``gap_limit`` and ``account_gap``: the bound of the search, `GAP_LIMIT`
  and `ACCOUNT_GAP` unless the caller gives others.
- ``searched``: one object per reading and purpose read: ``reading``, the
  position of the reading in the bundle; ``purpose``, ``null`` for an
  Electrum reading; ``accounts``, how many accounts were read, from 0;
  and ``cut_short``, true where the bundle's accounts end before the
  account gap was reached.
- ``used``: one object per account with history, in the order read:
  ``reading``, ``purpose``, ``account`` and ``path``, as the bundle has
  them; ``addresses``, each used position as ``branch``, ``index`` and
  ``address``; ``transactions``, each as ``tx_id``, in display order,
  and ``height``, ``null`` for the mempool's; ``confirmed`` and
  ``unconfirmed``, in satoshis; and ``tip``, the height and block id the
  history was read up to.
- ``not_checked``: one object per reading and coin not read, with
  ``reading``, ``coin`` and ``reason``.
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from hashlib import sha256

from btclib.tx import OutPoint, TxOut
from btclib_wallet.bip44 import AccountUse, discover_account
from btclib_wallet.descriptors import Descriptor, parse
from btclib_wallet.fetch.history import HistoryReader, ScriptHistory

from seed_scan.bundle import Account, Reading, loads
from seed_scan.exceptions import SeedScanTypeError, SeedScanValueError

__all__ = [
    "ACCOUNT_GAP",
    "FORMAT",
    "GAP_LIMIT",
    "VERSION",
    "Address",
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

#: The coin `scan` reads.
_BITCOIN = "bitcoin"


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
class ScanResult:
    """What `scan` found: the module docstring's top-level object."""

    bundle: str
    server: str
    gap_limit: int
    account_gap: int
    searched: tuple[Searched, ...]
    used: tuple[UsedAccount, ...]
    not_checked: tuple[NotRead, ...]


def dumps(result: ScanResult) -> str:
    """Return the JSON text of a scan result, members in a fixed order."""
    document = {"format": FORMAT, "version": VERSION, **asdict(result)}
    return json.dumps(document, indent=2) + "\n"


def _descriptors(account: Account, where: str) -> tuple[Descriptor, ...]:
    """Return an account's descriptors, parsed.

    `seed_scan.bundle.loads` has read them as the receive and change
    descriptors over the account's own xpub, which holds no private key
    and ranges every index, checksum included; what it does not verify is
    that the key is a point of the curve, and `parse` does. Its refusal may quote the descriptor, so it is not
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


def _plan(
    position: int, reading: Reading
) -> tuple[dict[int | None, list[tuple[Account, tuple[Descriptor, ...]]]], list[str]]:
    """Return a reading's Bitcoin accounts by purpose, and its other coins.

    The accounts of a purpose are numbered from 0 with no gap, as
    `identify` writes them, and an Electrum reading, of purpose ``None``,
    has one.
    """
    purposes: dict[int | None, list[tuple[Account, tuple[Descriptor, ...]]]] = {}
    others: list[str] = []
    for number, account in enumerate(reading.accounts):
        if account.coin != _BITCOIN:
            if account.coin not in others:
                others.append(account.coin)
            continue
        where = f"reading {position}, account {number}"
        descriptors = _descriptors(account, where)
        purposes.setdefault(account.purpose, []).append((account, descriptors))
    for purpose, accounts in purposes.items():
        numbers = [account.account for account, _ in accounts]
        if numbers != list(range(len(numbers))) or (purpose is None and numbers != [0]):
            err_msg = f"bundle: reading {position}: accounts not numbered from 0"
            raise SeedScanValueError(err_msg)
    return purposes, others


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


def _discover(
    reading: int,
    purpose: int | None,
    accounts: Sequence[tuple[Account, tuple[Descriptor, ...]]],
    reader: HistoryReader,
    bounds: tuple[int, int],
) -> tuple[Searched, list[UsedAccount]]:
    """Read the accounts of one purpose in order, until the account gap.

    `discover_accounts` reads them the same way, and refuses a purpose
    whose accounts end before the gap, dropping what it found
    (btclib-org/btclib-wallet#859): here that purpose is cut short.
    """
    gap_limit, account_gap = bounds
    used: list[UsedAccount] = []
    unused = read = 0
    for account, descriptors in accounts:
        if unused == account_gap:
            break
        use = discover_account(descriptors, reader, gap_limit=gap_limit)
        read += 1
        if use is None:
            unused += 1
        else:
            unused = 0
            used.append(_used_account(reading, account, use))
    cut_short = purpose is not None and unused < account_gap
    return Searched(reading, purpose, read, cut_short), used


def scan(
    text: str,
    reader: HistoryReader,
    *,
    server: str,
    gap_limit: int = GAP_LIMIT,
    account_gap: int = ACCOUNT_GAP,
) -> ScanResult:
    """Run account discovery on the bundle whose text is `text`.

    `server` is what the result names as the server `reader` asks. The
    bundle is read, and every account of it checked, before `reader` is
    asked anything. Refused, as `seed_scan.bundle.loads` refuses it: text
    that is not a bundle. Refused as a `SeedScanValueError` too: a
    descriptor that does not parse, as one whose key is no point of the
    curve, and accounts not numbered from 0. A bound below 1 is refused, and one that is no
    integer is a `SeedScanTypeError`.
    """
    bundle = loads(text)
    if not isinstance(server, str):
        raise SeedScanTypeError(f"invalid server type: {type(server).__name__}")
    bounds = (_limit(gap_limit, "gap_limit"), _limit(account_gap, "account_gap"))
    plans = [_plan(n, reading) for n, reading in enumerate(bundle.readings)]
    searched: list[Searched] = []
    used: list[UsedAccount] = []
    not_checked: list[NotRead] = []
    for n, (purposes, others) in enumerate(plans):
        for purpose, accounts in purposes.items():
            done, found = _discover(n, purpose, accounts, reader, bounds)
            searched.append(done)
            used += found
        reason = "scan reads Bitcoin alone in this version"
        not_checked += [NotRead(n, coin, reason) for coin in others]
    return ScanResult(
        bundle=sha256(text.encode("utf-8")).hexdigest(),
        server=server,
        gap_limit=gap_limit,
        account_gap=account_gap,
        searched=tuple(searched),
        used=tuple(used),
        not_checked=tuple(not_checked),
    )
