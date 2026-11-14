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
chain and the paths they derive at. Bitcoin SV and eCash each parted
from Bitcoin Cash after Bitcoin Cash parted from Bitcoin, so each also
holds what a key held on Bitcoin Cash at its own later split. And a
base58 address spells the same script on each of these chains, so a
payment made on one chain to an address of another chain's wallet is at
that wallet's path.

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
held when the chain parted from Bitcoin, which for Bitcoin SV and eCash
is Bitcoin Cash's fork, not their own later split from Bitcoin Cash.

Each token protocol below writes its tokens either in the script of the
output holding them, or in an ``OP_RETURN`` output of the transaction.
`seed_scan.report` names the protocols of each chain, and says that
their tokens are not checked.

Where the tokens are in the script, the output is not read as paying
the account's script, so its satoshis are not counted, and an account
paid only through such outputs reads as unused. These are:

- on Bitcoin Cash, CashTokens, whose token prefix stands before the
  script, in the same length field, as the CashTokens specification's
  *Token Encoding* says
  (https://github.com/cashtokens/cashtokens/blob/41d2444c17bbfb456d4061953a3ed0e32161571b/readme.md#token-encoding);
- on Bitcoin SV, STAS, whose script is a P2PKH followed by the token's
  own, or from STAS 3 the owner's hash followed by it, and whose tokens
  are the output's satoshis
  (https://github.com/stas-token/stas-sdk/blob/6bdd953c8c8073cca34e41e997ba3e9de49e2394/lib/scripts/stasScripts.js#L1,
  https://github.com/stassso/STAS-3-script-templates/blob/38b334f988c600865a0b45804fc7cc18a54f6dd9/Template%20STAS%203.0,
  https://github.com/stas-token/stas-sdk/blob/6bdd953c8c8073cca34e41e997ba3e9de49e2394/README.md?plain=1#L336);
- on Bitcoin SV, BSV-20 and BSV-21, whose 1Sat Ordinals inscription
  stands in the script beside the one that locks it, typically a P2PKH,
  and gives the amount the output holds
  (https://github.com/BitcoinSchema/1sat-ordinals/blob/4f6d8d78d90acd807843cd254a9068586c793c20/README.md?plain=1#L18-L32,
  https://github.com/BitcoinSchema/1sat-ordinals/blob/4f6d8d78d90acd807843cd254a9068586c793c20/fungible-tokens/bsv20.md?plain=1#L84-L95,
  https://github.com/BitcoinSchema/1sat-ordinals/blob/4f6d8d78d90acd807843cd254a9068586c793c20/fungible-tokens/bsv-21.md?plain=1#L163-L174).

Where the tokens are in an ``OP_RETURN`` output, the output holding them
pays its script as any output does: where that is an account's P2PKH,
its satoshis are counted, and its tokens are not read. These are:

- SLP, on Bitcoin Cash and eCash, whose first output, an ``OP_RETURN``,
  gives the tokens each later output holds, as SLP's specification and
  its parser in ecash-lib say
  (https://github.com/simpleledger/slp-specifications/blob/bc2632c19cfa841ca7dce2e5b7b2860d76bb5447/slp-token-type-1.md?plain=1#L197,
  https://github.com/simpleledger/slp-specifications/blob/bc2632c19cfa841ca7dce2e5b7b2860d76bb5447/slp-token-type-1.md?plain=1#L401,
  https://github.com/Bitcoin-ABC/bitcoin-abc/blob/988b903deb04311b12ba067734dab3ff9f5411a7/modules/ecash-lib/src/token/slp.parse.ts#L79-L89);
  and on Bitcoin SV, which holds the SLP outputs made before it parted
  from Bitcoin Cash at Bitcoin Cash's upgrade of November 2018, SLP's
  specification being published before that upgrade
  (https://github.com/simpleledger/slp-specifications/commit/71a821b850639e0a4ed71303f30f53d9949bdcec,
  https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/e13b48e37b3005dca9a316f75aea456697a5dfd6/src/chainparams.cpp#L125-126);
- ALP, on eCash, written in that same first output
  (https://github.com/Bitcoin-ABC/bitcoin-abc/blob/988b903deb04311b12ba067734dab3ff9f5411a7/doc/standards/alp.md#11-empp);
- on Bitcoin SV, Run, whose tokens are jigs held by P2PKH outputs,
  generally dust, their amounts being what the actions in the
  transaction's ``OP_RETURN`` output leave in them
  (https://github.com/runonbitcoin/walleteering/blob/28ed62edd9886e0e4cd4cc702c6f373561eccbf7/guide/01-background.md?plain=1#L15-L17,
  https://github.com/runonbitcoin/walleteering/blob/28ed62edd9886e0e4cd4cc702c6f373561eccbf7/guide/01-background.md?plain=1#L47-L50,
  https://github.com/runonbitcoin/run-sdk/blob/aea17210bf40095d17413f39e9d961da0ece9100/lib/kernel/metadata.js#L25-L39);
- on Bitcoin SV, Tokenized, whose holders are P2PKH addresses, and whose
  settlement's ``OP_RETURN`` output gives the balance of the address of
  each output it names
  (https://github.com/tokenized/docs/blob/bd495cc0b3bb5652f70b810bed6e46791c410651/concepts-transactions.md?plain=1#L15,
  https://github.com/tokenized/specification/blob/84dbb49995b63c85fe9bc57b35e415d9d5faca3e/dist/markdown/protocol-actions.md?plain=1#L4516-L4524).

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
    "ECASH",
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

#: eCash, which holds Bitcoin Cash's blocks up to its own split, at
#: Bitcoin Cash's upgrade of November 2020. Its checkpoints are the fork
#: block from Bitcoin, which Electrum ABC pins; Bitcoin ABC's checkpoint
#: at that upgrade, where Bitcoin Cash Node's list holds another block;
#: and the latest of Bitcoin ABC's list. Its wallets write an address in
#: CashAddr, with the prefix ``ecash``, and its base58 prefixes are
#: Bitcoin's, so the legacy address of the result spells the same script.
#: The sources:
#: https://github.com/Bitcoin-ABC/bitcoin-abc/blob/988b903deb04311b12ba067734dab3ff9f5411a7/electrum/electrumabc/networks.py#L106-L110
#: https://github.com/Bitcoin-ABC/bitcoin-abc/blob/988b903deb04311b12ba067734dab3ff9f5411a7/src/networks/abc/checkpoints.cpp#L58-L61
#: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/e13b48e37b3005dca9a316f75aea456697a5dfd6/src/chainparams.cpp#L290-292
#: https://github.com/Bitcoin-ABC/bitcoin-abc/blob/988b903deb04311b12ba067734dab3ff9f5411a7/src/networks/abc/checkpoints.cpp#L106-L109
#: https://github.com/Bitcoin-ABC/bitcoin-abc/blob/988b903deb04311b12ba067734dab3ff9f5411a7/src/kernel/chainparams.cpp#L198-L203
ECASH = Chain(
    name="ecash",
    title="eCash",
    fork_height=478559,
    checkpoints=(
        (478559, "000000000000000000651ef99cb9fcbe0dadde1d424bd9f15ff20136191a5eec"),
        (661648, "000000000000000004284c9d8b2c8ff731efeaec6be50729bdc9bd07f910757d"),
        (949200, "000000000000000098694560815190dba8bbe2f06c08a7c23837df3c4886cba2"),
    ),
)

#: The chains `forks` reads, by name, in the order their accounts are read.
CHAINS = MappingProxyType(
    {chain.name: chain for chain in (BITCOIN_CASH, BITCOIN_SV, ECASH)}
)


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

    The bundle is refused as `forks` refuses it. An account of a coin of
    `CHAINS` holds no descriptor in the bundle, and is given here the ones
    `forks` reads it with.
    """
    held: dict[str, _Held] = {coin: {} for coin in (_BITCOIN, *CHAINS)}
    skipped: list[Skipped] = []
    for n, reading in enumerate(bundle.readings):
        coins, skips = _plan(n, reading, chain)
        skipped += skips
        for coin, purposes in coins:
            for purpose, accounts in purposes.items():
                for account, _ in accounts:
                    texts = account.descriptors
                    if coin in CHAINS:
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
