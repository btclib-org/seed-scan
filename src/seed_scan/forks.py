# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What a bundle's keys hold on a chain forked from Bitcoin.

`forks` reads the text of a bundle, with `seed_scan.bundle` alone, and
asks a `btclib_wallet.fetch.history.HistoryReader` on a chain forked
from Bitcoin which of the bundle's accounts have history there. It reads
no secret, as `seed_scan.scan` reads none. `seed_scan.cli` gives it an
Electrum server the user names for that chain, and refuses one whose
blocks at the chain's checkpoints are another chain's.

`CHAINS` holds the chains read: Bitcoin Cash, in this version. A key's
coins at a fork are on both chains, at the same script, and a wallet of
the new chain may since have used the key at Bitcoin's paths or at a
coin type of its own: `seed_scan.identify`'s comment on its `COINS`
cites the Bitcoin Cash wallets that derive at m/44h/145h and at m/44h/0h.
So the accounts read are those whose script Bitcoin Cash spends with
the key, P2PKH: each Bitcoin account whose descriptors are ``pkh``, as
BIP44's purpose and Electrum's standard reading have them, and each
account of the chain's own coin, whose descriptors are built here as
`seed_scan.identify` builds them to search an address. Each is read as
`seed_scan.scan` reads a Bitcoin account, with the same two bounds. A
Bitcoin account of another script is listed as not checked, with the
reason: Bitcoin Cash's transactions carry no witness, so a key does not
sign for a segwit script there. The bundle's other coins are `scan`'s,
and are not listed.

The balance of an account is read as `seed_scan.scan` reads it, off the
history the server answers for the chain. ``at_fork`` is read off the
same history, from the transactions confirmed below the chain's
`Chain.fork_height`, which Bitcoin's history holds too: what the account
held when the chains parted. An output carrying CashTokens holds the
token prefix before its script, in the same length field, as the
CashTokens specification's *Token Encoding* says
(https://github.com/cashtokens/cashtokens/blob/41d2444c17bbfb456d4061953a3ed0e32161571b/readme.md#token-encoding):
it is not read as paying the script, so its satoshis are not counted,
and an account paid only through such outputs reads as unused.

The result is one JSON object, which `dumps` writes. It holds public data
only. Its members:

- ``format``: the string ``"seed-scan-forks"``.
- ``version``: the integer `VERSION`. A change of meaning takes a new
  version.
- ``bundle``: the SHA-256 of the bundle's text, UTF-8 encoded, as hex.
- ``chain``: the chain read, a key of `CHAINS`.
- ``server``: the server asked, as the user named it.
- ``fork_height``: the height of the chain's first block of its own.
- ``gap_limit`` and ``account_gap``: the bound of the search, as in
  `seed_scan.scan`'s result.
- ``searched``: one object per reading, coin and purpose read:
  ``reading``, ``coin``, ``purpose``, ``accounts`` and ``cut_short``, as
  `seed_scan.scan`'s result has them.
- ``used``: one object per account with history on the chain, in the
  order read: ``coin``; the members of an item of `seed_scan.scan`'s
  ``used``, each address in Bitcoin's legacy format, which spells the
  same script on Bitcoin Cash; and ``at_fork``, in satoshis.
- ``not_checked``: one object per reading, coin and purpose not read,
  with ``reading``, ``coin``, ``purpose`` and ``reason``.
"""

from __future__ import annotations

import contextlib
import json
from dataclasses import asdict, dataclass, fields, replace
from functools import partial
from hashlib import sha256
from types import MappingProxyType

from btclib_wallet.bip44 import AccountUse
from btclib_wallet.descriptors import Descriptor, parse
from btclib_wallet.fetch.history import HistoryReader

from seed_scan.bundle import Account, Reading, loads
from seed_scan.exceptions import SeedScanTypeError, SeedScanValueError
from seed_scan.scan import (
    ACCOUNT_GAP,
    GAP_LIMIT,
    Address,
    Tip,
    Transaction,
    _balances,
    _descriptors,
    _discover,
    _limit,
    _numbered,
    _Purposes,
    _read_account,
    _used_account,
    parse_server,
)

__all__ = [
    "BITCOIN_CASH",
    "CHAINS",
    "FORMAT",
    "VERSION",
    "Chain",
    "ForkAccount",
    "ForkSearched",
    "ForksResult",
    "Skipped",
    "dumps",
    "forks",
]

#: The value of the ``format`` member.
FORMAT = "seed-scan-forks"

#: The value of the ``version`` member this module writes.
VERSION = 1

#: The coin whose accounts a chain forked from Bitcoin shares.
_BITCOIN = "bitcoin"

#: Why a Bitcoin account of a segwit script is not read.
_NO_WITNESS = (
    "a segwit script: Bitcoin Cash's transactions carry no witness, so a key"
    " does not sign for it there"
)


@dataclass(frozen=True)
class Chain:
    """A chain forked from Bitcoin, and how its server is told from another's.

    `name` is how the command and the result name it, and the coin of its
    own accounts in a bundle. `title` is how a summary and a refusal name
    it. `fork_height` is the height of its first block of its own.
    `checkpoints` are heights and the id of the chain's block at each, as
    hex in display order: a server answering another block at one of them
    serves another chain, though it shares Bitcoin's genesis block.
    """

    name: str
    title: str
    fork_height: int
    checkpoints: tuple[tuple[int, str], ...]


#: Bitcoin Cash. Its checkpoints are two of Bitcoin Cash Node's, the fork
#: block, which Electron Cash pins too, and the latest of the list. A chain
#: that parted from Bitcoin Cash before that height has another block
#: there, as eCash has from 661648 on. The sources:
#: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/e13b48e37b3005dca9a316f75aea456697a5dfd6/src/chainparams.cpp#L269-271
#: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/e13b48e37b3005dca9a316f75aea456697a5dfd6/src/chainparams.cpp#L323
#: https://github.com/Electron-Cash/Electron-Cash/blob/7f4afadbf62a6daa1d6d0563d0951141ddcc6a7c/electroncash/networks.py#L68-L70
#: https://github.com/Bitcoin-ABC/bitcoin-abc/blob/988b903deb04311b12ba067734dab3ff9f5411a7/src/networks/abc/checkpoints.cpp#L58-L61
BITCOIN_CASH = Chain(
    name="bitcoin-cash",
    title="Bitcoin Cash",
    fork_height=478559,
    checkpoints=(
        (478559, "000000000000000000651ef99cb9fcbe0dadde1d424bd9f15ff20136191a5eec"),
        (970892, "000000000000000000e76270e57f4ebbd2b282db46a1695984935126c0a68cd8"),
    ),
)

#: The chains `forks` reads, by name.
CHAINS = MappingProxyType({BITCOIN_CASH.name: BITCOIN_CASH})


@dataclass(frozen=True)
class ForkSearched:
    """The accounts of one reading, coin and purpose that were read."""

    reading: int
    coin: str
    purpose: int | None
    accounts: int
    cut_short: bool


@dataclass(frozen=True)
class ForkAccount:
    """An account with history on the chain, and what it held at the fork."""

    coin: str
    reading: int
    purpose: int | None
    account: int
    path: str
    addresses: tuple[Address, ...]
    transactions: tuple[Transaction, ...]
    confirmed: int
    unconfirmed: int
    tip: Tip
    at_fork: int


@dataclass(frozen=True)
class Skipped:
    """The accounts of a reading, coin and purpose not read, and why."""

    reading: int
    coin: str
    purpose: int | None
    reason: str


@dataclass(frozen=True)
class ForksResult:
    """What `forks` found: the module docstring's top-level object."""

    bundle: str
    chain: str
    server: str
    fork_height: int
    gap_limit: int
    account_gap: int
    searched: tuple[ForkSearched, ...]
    used: tuple[ForkAccount, ...]
    not_checked: tuple[Skipped, ...]


def dumps(result: ForksResult) -> str:
    """Return the JSON text of a forks result, members in a fixed order."""
    document = {"format": FORMAT, "version": VERSION, **asdict(result)}
    return json.dumps(document, indent=2) + "\n"


def _own_descriptors(
    reading: Reading, account: Account, where: str
) -> tuple[Descriptor, ...]:
    """Return the receive and change descriptors of an account of the chain.

    P2PKH over the account's xpub, with its key origin. `parse` checks that
    the key is a point of the curve; its refusal may quote the key, so it
    is not kept, as `seed_scan.scan` does not keep it.
    """
    origin = f"[{reading.master_fingerprint}{account.path[1:]}]"
    descriptors: tuple[Descriptor, ...] = ()
    with contextlib.suppress(TypeError, ValueError):
        descriptors = tuple(
            parse(f"pkh({origin}{account.xpub}/{branch}/*)") for branch in (0, 1)
        )
    if not descriptors:
        err_msg = f"bundle: {where}: a descriptor that does not parse"
        raise SeedScanValueError(err_msg)
    return descriptors


#: A reading's accounts of one coin, by purpose, each beside its
#: descriptors.
_Accounts = _Purposes[tuple[Descriptor, ...]]


def _plan(
    position: int, reading: Reading, chain: Chain
) -> tuple[tuple[tuple[str, _Accounts], ...], list[Skipped]]:
    """Return a reading's accounts the chain spends, by coin and purpose.

    Bitcoin's first, then the chain's own; beside them, the Bitcoin
    accounts of a segwit script, one item per purpose. The accounts of
    each coin are numbered as `seed_scan.scan` holds them to be.
    """
    bitcoin: _Accounts = {}
    own: _Accounts = {}
    skipped: list[Skipped] = []
    for number, account in enumerate(reading.accounts):
        where = f"reading {position}, account {number}"
        if account.coin == chain.name:
            descriptors = _own_descriptors(reading, account, where)
            own.setdefault(account.purpose, []).append((account, descriptors))
        elif account.coin != _BITCOIN:
            continue
        elif all(text.startswith("pkh(") for text in account.descriptors):
            descriptors = _descriptors(account, where)
            bitcoin.setdefault(account.purpose, []).append((account, descriptors))
        else:
            skip = Skipped(position, account.coin, account.purpose, _NO_WITNESS)
            if skip not in skipped:
                skipped.append(skip)
    _numbered(position, bitcoin)
    _numbered(position, own)
    return ((_BITCOIN, bitcoin), (chain.name, own)), skipped


def _at_fork(use: AccountUse, fork_height: int) -> int:
    """Return what the used scripts of an account held below `fork_height`.

    The confirmed balance of `seed_scan.scan`, on the transactions of the
    history confirmed below that height.
    """
    scripts = frozenset(
        script_pub_key.script
        for branch, indexes in enumerate(use.used)
        for index in indexes
        for script_pub_key in use.descriptors[branch].script_pub_keys(index)
    )
    before = tuple(
        entry
        for entry in use.history.txs
        if entry.block is not None and entry.block.height < fork_height
    )
    balances = _balances(replace(use.history, txs=before), scripts)
    return sum(confirmed for confirmed, _ in balances.values())


def _fork_account(
    reading: int,
    account: Account,
    descriptors: tuple[Descriptor, ...],
    *,
    coin: str,
    reader: HistoryReader,
    gap_limit: int,
    fork_height: int,
) -> ForkAccount | None:
    """Return what an account used on the chain, or None where it used nothing.

    Read as `seed_scan.scan` reads a Bitcoin account.
    """
    where = f"reading {reading}, account {account.path}"
    use = _read_account(descriptors, reader, gap_limit, where)
    if use is None:
        return None
    found = _used_account(reading, account, use)
    members = {field.name: getattr(found, field.name) for field in fields(found)}
    return ForkAccount(coin=coin, at_fork=_at_fork(use, fork_height), **members)


def forks(
    text: str,
    reader: HistoryReader,
    *,
    chain: str,
    server: str,
    gap_limit: int = GAP_LIMIT,
    account_gap: int = ACCOUNT_GAP,
) -> ForksResult:
    """Run account discovery on a chain forked from Bitcoin, for a bundle.

    `text` is the bundle's text, `chain` a key of `CHAINS`, and `server`
    what the result names as the server `reader` asks, which serves that
    chain. The bundle is read, and every account it reads checked, before
    `reader` is asked anything. Refused as `seed_scan.scan.scan` refuses
    them: text that is not a bundle, a descriptor or an xpub that does not
    parse, accounts not numbered from 0, a `server` that
    `seed_scan.scan.parse_server` refuses, a bound below 1, and an account
    whose discovery `seed_scan.scan` refuses in both reads of it. A
    `chain` not in `CHAINS` is refused too, without quoting it. A
    `chain`, a `server` or a bound of a wrong type is a
    `SeedScanTypeError`.
    """
    bundle = loads(text)
    if not isinstance(chain, str):
        raise SeedScanTypeError(f"invalid chain type: {type(chain).__name__}")
    if chain not in CHAINS:
        raise SeedScanValueError("invalid chain: not one forks reads")
    if not isinstance(server, str):
        raise SeedScanTypeError(f"invalid server type: {type(server).__name__}")
    parse_server(server, "server")
    fork = CHAINS[chain]
    gap_limit = _limit(gap_limit, "gap_limit")
    account_gap = _limit(account_gap, "account_gap")
    plans = [_plan(n, reading, fork) for n, reading in enumerate(bundle.readings)]
    searched: list[ForkSearched] = []
    used: list[ForkAccount] = []
    not_checked: list[Skipped] = []
    for n, (coins, skipped) in enumerate(plans):
        for coin, purposes in coins:
            read = partial(
                _fork_account,
                n,
                coin=coin,
                reader=reader,
                gap_limit=gap_limit,
                fork_height=fork.fork_height,
            )
            for purpose, accounts in purposes.items():
                done, found = _discover(n, purpose, accounts, read, account_gap)
                searched.append(
                    ForkSearched(n, coin, purpose, done.accounts, done.cut_short)
                )
                used += found
        not_checked += skipped
    return ForksResult(
        bundle=sha256(text.encode("utf-8")).hexdigest(),
        chain=chain,
        server=server,
        fork_height=fork.fork_height,
        gap_limit=gap_limit,
        account_gap=account_gap,
        searched=tuple(searched),
        used=tuple(used),
        not_checked=tuple(not_checked),
    )
