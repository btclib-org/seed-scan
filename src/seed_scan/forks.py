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

`CHAINS` holds the chains read. A key's coins at a fork are on both
chains, at the same script, and a wallet of the new chain may since have
used the key at Bitcoin's paths or at a coin type of its own:
`seed_scan.identify`'s comment on its `COINS` cites the wallets of each
chain and the paths they derive at. Bitcoin SV parted from Bitcoin Cash
after Bitcoin Cash parted from Bitcoin, so it also holds what a key held
on Bitcoin Cash at that later split. And a base58 address spells the
same script on each of these chains, so a payment made on one chain to
an address of another chain's wallet is at that wallet's path.

So the accounts read, on whichever chain, are those whose script the
chain spends with the key, P2PKH: each Bitcoin account whose descriptors
are ``pkh``, as BIP44's purpose and Electrum's standard reading have
them, and each account of a coin of `CHAINS`, P2PKH over its xpub. Each
is read as `seed_scan.scan` reads a Bitcoin account, with the same two
bounds. A Bitcoin account of another script is listed as not checked,
with the reason: the chain's transactions carry no witness, so a key
does not sign for a segwit script there. The bundle's other coins are
`scan`'s, and are not listed.

The balance of an account is read as `seed_scan.scan` reads it, off the
history the server answers for the chain. ``at_fork`` is read off the
same history, from the transactions confirmed below the chain's
`Chain.fork_height`, which Bitcoin's history holds too: what the account
held when the chain parted from Bitcoin, which for Bitcoin SV is Bitcoin
Cash's fork, not its own later split from Bitcoin Cash.

On Bitcoin Cash, an output carrying CashTokens holds the token prefix
before its script, in the same length field, as the CashTokens
specification's *Token Encoding* says
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
- ``fork_height``: the height of the chain's first block that is not
  Bitcoin's.
- ``gap_limit`` and ``account_gap``: the bound of the search, as in
  `seed_scan.scan`'s result.
- ``searched``: one object per reading, coin and purpose read:
  ``reading``, ``coin``, ``purpose``, ``accounts`` and ``cut_short``, as
  `seed_scan.scan`'s result has them.
- ``used``: one object per account with history on the chain, in the
  order read: ``coin``; the members of an item of `seed_scan.scan`'s
  ``used``, each address in Bitcoin's legacy format, which spells the
  same script on each chain of `CHAINS`; and ``at_fork``, in satoshis.
- ``not_checked``: one object per reading, coin and purpose not read,
  with ``reading``, ``coin``, ``purpose`` and ``reason``.

`loads` reads a result back, against the text of the bundle it was made
from.
"""

from __future__ import annotations

import contextlib
import json
from dataclasses import asdict, dataclass, fields, replace
from functools import partial
from hashlib import sha256
from types import MappingProxyType
from typing import Any

from btclib_wallet.bip44 import AccountUse
from btclib_wallet.descriptors import Descriptor, parse
from btclib_wallet.fetch.history import HistoryReader

from seed_scan.bundle import Account, Bundle, Reading
from seed_scan.bundle import loads as bundle_loads
from seed_scan.exceptions import SeedScanTypeError, SeedScanValueError
from seed_scan.scan import (
    _OUTSIDE,
    ACCOUNT_GAP,
    GAP_LIMIT,
    Address,
    Searched,
    Tip,
    Transaction,
    UsedAccount,
    _balances,
    _bounded,
    _check_searches,
    _count,
    _descriptors,
    _discover,
    _document,
    _Held,
    _keyed,
    _limit,
    _member,
    _numbered,
    _objects,
    _Purposes,
    _read_account,
    _searched,
    _used,
    _used_account,
    _where,
    parse_server,
)

__all__ = [
    "BITCOIN_CASH",
    "BITCOIN_SV",
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
    "loads",
]

#: The value of the ``format`` member.
FORMAT = "seed-scan-forks"

#: The value of the ``version`` member this module writes.
VERSION = 1

#: The coin whose accounts a chain forked from Bitcoin shares.
_BITCOIN = "bitcoin"


@dataclass(frozen=True)
class Chain:
    """A chain forked from Bitcoin, and how its server is told from another's.

    `name` is how the command and the result name it, and the coin of its
    own accounts in a bundle. `title` is how a summary and a refusal name
    it. `fork_height` is the height of its first block that is not
    Bitcoin's.
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

#: Bitcoin SV, which holds Bitcoin Cash's blocks up to their own split.
#: Its checkpoints are the fork block from Bitcoin, which ElectrumSV pins,
#: and ElectrumSV's checkpoint after the split, which tells it from Bitcoin
#: Cash. None of the Bitcoin SV node's checkpoints does: its list ends at
#: 530359, whose id Bitcoin Cash Node's list holds too. The sources:
#: https://github.com/electrumsv/electrumsv/blob/7ab1c7ceaaaa0f8079da21356989d9b250e874b4/electrumsv/networks.py#L62-L74
#: https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/chainparams.cpp#L1157-L1159
#: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/e13b48e37b3005dca9a316f75aea456697a5dfd6/src/chainparams.cpp#L275-277
BITCOIN_SV = Chain(
    name="bitcoin-sv",
    title="Bitcoin SV",
    fork_height=478559,
    checkpoints=(
        (478559, "000000000000000000651ef99cb9fcbe0dadde1d424bd9f15ff20136191a5eec"),
        (773040, "000000000000000007a8838b1ead3b288c504de5eee26f3189fdbcd0b1a006ac"),
    ),
)

#: The chains `forks` reads, by name, in the order their accounts are read.
CHAINS = MappingProxyType({chain.name: chain for chain in (BITCOIN_CASH, BITCOIN_SV)})


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


def _own_texts(reading: Reading, account: Account) -> tuple[str, ...]:
    """Return the receive and change descriptors of an account of `CHAINS`.

    P2PKH over the account's xpub, with its key origin, as text.
    """
    origin = f"[{reading.master_fingerprint}{account.path[1:]}]"
    return tuple(f"pkh({origin}{account.xpub}/{branch}/*)" for branch in (0, 1))


def _own_descriptors(
    reading: Reading, account: Account, where: str
) -> tuple[Descriptor, ...]:
    """Return `_own_texts`, parsed.

    `parse` checks that the key is a point of the curve; its refusal may
    quote the key, so it is not kept, as `seed_scan.scan` does not keep it.
    """
    descriptors: tuple[Descriptor, ...] = ()
    with contextlib.suppress(TypeError, ValueError):
        descriptors = tuple(parse(text) for text in _own_texts(reading, account))
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

    Bitcoin's first, then each coin of `CHAINS`, in its order; beside
    them, the Bitcoin accounts of a segwit script, one item per purpose.
    The accounts of each coin are numbered as `seed_scan.scan` holds them
    to be.
    """
    coins: dict[str, _Accounts] = {coin: {} for coin in (_BITCOIN, *CHAINS)}
    no_witness = (
        f"a segwit script: {chain.title}'s transactions carry no witness, so a"
        " key does not sign for it there"
    )
    skipped: list[Skipped] = []
    for number, account in enumerate(reading.accounts):
        where = f"reading {position}, account {number}"
        if account.coin in CHAINS:
            descriptors = _own_descriptors(reading, account, where)
        elif account.coin != _BITCOIN:
            continue
        elif all(text.startswith("pkh(") for text in account.descriptors):
            descriptors = _descriptors(account, where)
        else:
            skip = Skipped(position, account.coin, account.purpose, no_witness)
            if skip not in skipped:
                skipped.append(skip)
            continue
        purposes = coins[account.coin]
        purposes.setdefault(account.purpose, []).append((account, descriptors))
    for purposes in coins.values():
        _numbered(position, purposes)
    return tuple(coins.items()), skipped


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

    Read as `seed_scan.scan` reads a Bitcoin account, its balance bounded
    as `seed_scan.scan` bounds it. What it held at the fork is held to the
    same bound.
    """
    where = f"reading {reading}, account {account.path}"
    use = _read_account(descriptors, reader, gap_limit, where)
    if use is None:
        return None
    found = _used_account(reading, account, use, where)
    at_fork = _at_fork(use, fork_height)
    if not _bounded(at_fork, 0):
        raise SeedScanValueError(f"{where}: {_OUTSIDE}")
    return _forked(coin, found, at_fork)


def _forked(coin: str, found: UsedAccount, at_fork: int) -> ForkAccount:
    """Return a used account of `coin`, with what it held at the fork."""
    members = {field.name: getattr(found, field.name) for field in fields(found)}
    return ForkAccount(coin=coin, at_fork=at_fork, **members)


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
    `seed_scan.scan.parse_server` refuses, a bound below 1, an account
    whose discovery `seed_scan.scan` refuses in both reads of it, and an
    account whose balance, or a used address's, is outside 0 to 21 million
    bitcoin. So is one whose holding at the fork is outside that bound. A
    `chain` not in `CHAINS` is refused too, without quoting it. A `chain`,
    a `server` or a bound of a wrong type is a `SeedScanTypeError`.
    """
    bundle = bundle_loads(text)
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


#: How `seed_scan.scan`'s reader opens a refusal, and how `loads` opens it.
_SCAN_RESULT = "scan result: "
_FORKS_RESULT = "forks result: "


def _coin(document: dict[str, Any], held: dict[str, _Held]) -> str:
    """Return the ``coin`` member of an object: one whose accounts are read."""
    coin: str = _member(document, "coin", str)
    if coin not in held:
        raise SeedScanValueError("forks result: member 'coin' is not one forks reads")
    return coin


#: A coin's searches, by reading and purpose.
_Searches = dict[tuple[int, int | None], Searched]


def _searches(
    document: dict[str, Any], held: dict[str, _Held]
) -> tuple[dict[str, _Searches], tuple[ForkSearched, ...]]:
    """Read the ``searched`` member: each search once, of accounts read.

    Returns the searches of each coin, and all of them in order.
    """
    searched: dict[str, _Searches] = {coin: {} for coin in held}
    order: list[ForkSearched] = []
    for item in _objects(document, "searched"):
        coin = _coin(item, held)
        if (*_where(item), 0) not in held[coin]:
            raise SeedScanValueError("forks result: a search of accounts not read")
        done = _searched(item, held[coin])
        if (done.reading, done.purpose) in searched[coin]:
            raise SeedScanValueError("forks result: a purpose searched twice")
        searched[coin][done.reading, done.purpose] = done
        order.append(
            ForkSearched(
                done.reading, coin, done.purpose, done.accounts, done.cut_short
            )
        )
    return searched, tuple(order)


def _held_at_fork(document: dict[str, Any], found: UsedAccount, height: int) -> int:
    """Return the ``at_fork`` member of a used account.

    What transactions confirmed below the fork `height` leave: a balance
    `_bounded` takes, and one of them listed where it is not 0.
    """
    at_fork = _count(document, "at_fork")
    if not _bounded(at_fork, 0):
        raise SeedScanValueError(f"forks result: {_OUTSIDE}")
    before = (t.height for t in found.transactions if t.height is not None)
    if at_fork and all(h >= height for h in before):
        err_msg = "forks result: a balance at the fork no transaction listed gives"
        raise SeedScanValueError(err_msg)
    return at_fork


def _skip(document: dict[str, Any], skipped: list[Skipped]) -> Skipped:
    """Read one ``not_checked`` object: one `forks` writes for the bundle."""
    reading, purpose = _where(document)
    coin: str = _member(document, "coin", str)
    skip = Skipped(reading, coin, purpose, _member(document, "reason", str))
    if skip not in skipped:
        err_msg = "forks result: an item of 'not_checked' is not one forks writes"
        raise SeedScanValueError(err_msg)
    return skip


def _held(bundle: Bundle, chain: Chain) -> tuple[dict[str, _Held], list[Skipped]]:
    """Return the accounts `forks` reads, by coin, and those it does not.

    The bundle is refused as `forks` refuses it. An account of the chain's
    own coin holds no descriptor in the bundle, and is given here the ones
    `forks` reads it with.
    """
    held: dict[str, _Held] = {_BITCOIN: {}, chain.name: {}}
    skipped: list[Skipped] = []
    for n, reading in enumerate(bundle.readings):
        coins, skips = _plan(n, reading, chain)
        skipped += skips
        for coin, purposes in coins:
            for purpose, accounts in purposes.items():
                for account, _ in accounts:
                    texts = account.descriptors
                    if coin == chain.name:
                        texts = _own_texts(reading, account)
                    held[coin][n, purpose, account.account] = replace(
                        account, descriptors=texts
                    )
    return held, skipped


def _used_accounts(
    document: dict[str, Any],
    held: dict[str, _Held],
    searched: dict[str, _Searches],
    bounds: tuple[int, int],
    fork_height: int,
) -> tuple[ForkAccount, ...]:
    """Read the ``used`` member, as `seed_scan.scan` reads its own, by coin.

    `bounds` are the result's ``gap_limit`` and ``account_gap``.
    """
    gap_limit, account_gap = bounds
    found: dict[str, list[UsedAccount]] = {coin: [] for coin in held}
    used: list[ForkAccount] = []
    for item in _objects(document, "used"):
        coin = _coin(item, held)
        account = _used(item, held[coin], searched[coin], gap_limit)
        found[coin].append(account)
        used.append(_forked(coin, account, _held_at_fork(item, account, fork_height)))
    for coin, accounts in found.items():
        _keyed(accounts)
        _check_searches(searched[coin], accounts, held[coin], account_gap)
    return tuple(used)


def _result(text: str, bundle: str) -> ForksResult:
    """Return `loads`'s answer, its refusals opening as `seed_scan.scan`'s."""
    read = bundle_loads(bundle)
    document = _document(text, FORMAT, VERSION)
    digest = sha256(bundle.encode("utf-8")).hexdigest()
    if _member(document, "bundle", str) != digest:
        raise SeedScanValueError("forks result: made from another bundle")
    chain: str = _member(document, "chain", str)
    if chain not in CHAINS:
        raise SeedScanValueError("forks result: member 'chain' is not one forks reads")
    fork = CHAINS[chain]
    if _count(document, "fork_height") != fork.fork_height:
        err_msg = "forks result: member 'fork_height' is not the chain's"
        raise SeedScanValueError(err_msg)
    held, skipped = _held(read, fork)
    server: str = _member(document, "server", str)
    parse_server(server, "forks result: member 'server'")
    gap_limit = _count(document, "gap_limit", 1)
    account_gap = _count(document, "account_gap", 1)
    searched, order = _searches(document, held)
    bounds = (gap_limit, account_gap)
    used = _used_accounts(document, held, searched, bounds, fork.fork_height)
    return ForksResult(
        bundle=digest,
        chain=chain,
        server=server,
        fork_height=fork.fork_height,
        gap_limit=gap_limit,
        account_gap=account_gap,
        searched=order,
        used=used,
        not_checked=tuple(
            _skip(item, skipped) for item in _objects(document, "not_checked")
        ),
    )


def loads(text: str, bundle: str) -> ForksResult:
    """Read a forks result back from its JSON text, against its bundle.

    Read as `seed_scan.scan.loads` reads a scan result, and refused as it
    refuses one, each refusal opening with ``forks result:``. A used
    account and a search name accounts of the bundle that `forks` reads,
    by coin. Refused besides: a ``chain`` not in `CHAINS`, unquoted; a
    ``fork_height`` that is not the chain's; an ``at_fork`` outside 0 to
    21 million bitcoin, or not 0 where no transaction listed is confirmed
    below the fork height; and an item of ``not_checked`` that is not one
    `forks` writes for the bundle, its reason included.
    """
    try:
        return _result(text, bundle)
    except (SeedScanTypeError, SeedScanValueError) as e:
        message = str(e)
        if not message.startswith(_SCAN_RESULT):
            raise
        kind = type(e)
    # raised outside the `except`, so that the refusal has no context
    raise kind(_FORKS_RESULT + message.removeprefix(_SCAN_RESULT))
