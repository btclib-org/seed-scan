# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What `identify`, `scan` and `forks` found, as text a person acts on.

`report` reads the text of a bundle and, where they are given, of the
scan result and the forks results made from it, with
`seed_scan.bundle.loads`, `seed_scan.scan.loads` and
`seed_scan.forks.loads`. It reads no secret, since none holds one, and
opens no connection. Every coin and purpose of the bundle is listed:
as read, with what its used accounts hold, or as not checked, with the
reason; and so is every one a forks result reads, on its chain. A user
acts on "nothing found", so what was not searched is said, never passed
over.

The report is lines of UTF-8 text, each ending in a newline, in this
order. ``<...>`` stands for a value and ``...`` for more of the same;
every other character is literal.

- ``seed-scan report <VERSION>``: `VERSION` says the layout below. A
  change of meaning takes a new version.
- ``bundle: sha256 <hex>``: the SHA-256 of the bundle's text, UTF-8
  encoded; `seed_scan.cli` says how the command reads the file.
- ``scan: sha256 <hex>``, the SHA-256 of the scan result's text, then
  ``server: <host:port>`` or ``server: none``, ``node: <url>, chain id
  <n>, latest block <n> before the first address was read`` or ``node:
  none``, and ``bounds: account gap <n>, gap limit <n>``; or ``scan:
  none`` alone, where no result is given. Where a node is named,
  ``ethereum tokens: not checked: <reason>`` follows the node's line.
- per forks result, in the order given, ``forks: sha256 <hex>``, the
  SHA-256 of its text, then ``chain: <title>, forked from Bitcoin at
  height <n>``, ``server: <host:port>`` and ``bounds: account gap <n>,
  gap limit <n>``, then for a Bitcoin Cash result ``cashtokens: not
  checked: <reason>``, and for an eCash result ``slp and alp tokens: not
  checked: <reason>``; or ``forks: none`` alone, where none is given.
- ``claims: <scheme>, ...``: the schemes that claim the words, or
  ``claims: none``.
- ``not derived: <scheme>: <reason>``: one line per scheme the words
  claim and `identify` did not derive.
- ``address search: none``; or ``address search: not run: <reason>``;
  or ``address search: <address>, <n> positions, accounts 0 to <n>,
  indexes 0 to <n>``, then ``found: reading <n>, <path>`` per match, or
  ``found: none``.
- per reading, ``reading <n>: <scheme>, passphrase <n>, master
  fingerprint <hex>``, with ``, languages <code> ...`` after the scheme
  of a BIP39 reading. Then, two spaces in, per coin and purpose of its
  accounts, in the bundle's order, ``<coin>, purpose <n>`` or, for
  Electrum's layout, ``<coin>, Electrum account``, followed by:

  - ``: not checked: <reason>``, where the scan result does not read
    it, or no result is given;
  - or ``: accounts 0 to <n> read, <n> used``, then ``, cut short: run
    identify with --accounts above <n>, then scan`` where the bundle's
    accounts end before the account gap was reached.

  Four spaces in, per used Bitcoin account, ``account <n>, <path>: <n>
  sat confirmed, <n> sat unconfirmed, <n> transactions, read up to
  height <n>``; and six spaces in, per used address, ``<receive or
  change> <path> <address>: <n> sat confirmed, <n> sat unconfirmed``,
  the path being the address's own. Per used Ethereum account,
  ``account <n>, <path>: <n> wei at latest``; and per used address,
  ``receive <path> <address>: <n> wei, nonce <n>``. Each Ethereum
  balance and nonce is the node's answer at the block tag ``latest``
  when that address was read, which may be a later block than the
  node's line names: that number marks when the Ethereum scan began,
  and no state the balances share.

  Then, per forks result, two spaces in, per coin and purpose of the
  reading's accounts of Bitcoin and of each coin of
  `seed_scan.forks.CHAINS`, ``<coin>, purpose <n>, on <title>`` or
  ``<coin>, Electrum account, on <title>``, followed by what was read or
  not checked as above, the rerun ending ``, then forks``. Four spaces
  in, per used account, ``account <n>, <path>: <n> sat confirmed, <n>
  sat unconfirmed, <n> sat at the fork, <n> transactions, read up to
  height <n>``, then its used addresses as a Bitcoin account's.
- ``total: bitcoin, <n> sat confirmed, <n> sat unconfirmed, <n> used
  accounts, each account key once``, where a server is named, and
  ``total: ethereum, <n> wei, <n> used accounts, each account key
  once``, where a node is; per forks result, ``total: <chain>, <n> sat
  confirmed, <n> sat unconfirmed, <n> sat at the fork, <n> used
  accounts, each account key once``. Two readings can hold the same
  account keys, as the same passphrase typed twice gives: each is
  listed with its accounts, and a total counts once the accounts paid by
  the same outputs, those of one key read as one script type.
- ``digest: sha256 <hex>``: the SHA-256 of every line above it, so that
  ``sed '$d' report.txt | shasum -a 256`` gives it back.
"""

from __future__ import annotations

import re
from hashlib import sha256
from typing import TYPE_CHECKING, TypeVar

from seed_scan.bundle import Account, Bundle, Reading, Search
from seed_scan.bundle import loads as bundle_loads
from seed_scan.exceptions import SeedScanTypeError, SeedScanValueError
from seed_scan.forks import (
    BITCOIN_CASH,
    CHAINS,
    ECASH,
    ForkAccount,
    ForkSearched,
    ForksResult,
)
from seed_scan.forks import loads as forks_loads
from seed_scan.scan import EvmAccount, ScanResult, Searched, UsedAccount
from seed_scan.scan import loads as scan_loads

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

__all__ = [
    "NOT_IN_FORKS",
    "NOT_IN_SCAN",
    "NO_CASHTOKENS",
    "NO_SCAN",
    "NO_SLP_ALP",
    "NO_TOKENS",
    "VERSION",
    "report",
]

#: The version the first line names.
VERSION = 1

#: Why an account is not checked where no scan result is given.
NO_SCAN = "no scan result was given"

#: Why an account is not checked where the scan result does not read it.
NOT_IN_SCAN = "the scan result does not read it"

#: Why Ethereum's tokens are not checked where the node was asked.
NO_TOKENS = (
    "scan asks ether and nonces alone, so an address that only received"
    " tokens reads as unused"
)

#: Why an account is not checked where the forks result does not read it.
NOT_IN_FORKS = "the forks result does not read it"

#: Why CashTokens are not checked where a Bitcoin Cash forks result is given.
NO_CASHTOKENS = (
    "forks does not read an output carrying them as paying its script, so its"
    " satoshis are not counted, and an account paid only through such outputs"
    " reads as unused"
)

#: Why SLP and ALP tokens are not checked where an eCash forks result is
#: given.
NO_SLP_ALP = (
    "forks counts the satoshis of an output holding them, and does not read"
    " the tokens, which the transaction's first output assigns to it"
)

_BRANCHES = ("receive", "change")

#: A coin, reading and purpose, the key of a search and of its accounts.
_Key = tuple[str, int, int | None]


def _search(search: Search | None) -> list[str]:
    """Return the lines of the address search."""
    if search is None:
        return ["address search: none"]
    if not search.checked:
        return [f"address search: not run: {search.reason}"]
    lines = [
        (
            f"address search: {search.address}, {search.searched} positions,"
            f" accounts 0 to {search.accounts - 1}, indexes 0 to {search.indexes - 1}"
        )
    ]
    lines += [f"found: reading {m.reading}, {m.path}" for m in search.matches]
    return lines if search.matches else [*lines, "found: none"]


def _reading(n: int, reading: Reading) -> str:
    """Return the line that opens a reading."""
    scheme = reading.scheme
    if reading.languages:
        scheme += f", languages {' '.join(reading.languages)}"
    return (
        f"reading {n}: {scheme}, passphrase {reading.passphrase},"
        f" master fingerprint {reading.master_fingerprint}"
    )


def _used(used: UsedAccount | ForkAccount) -> list[str]:
    """Return the lines of a used Bitcoin account and of its used addresses.

    An account a forks result lists says what it held at the fork too.
    """
    at_fork = ""
    if isinstance(used, ForkAccount):
        at_fork = f" {used.at_fork} sat at the fork,"
    lines = [
        (
            f"    account {used.account}, {used.path}: {used.confirmed} sat"
            f" confirmed, {used.unconfirmed} sat unconfirmed,{at_fork}"
            f" {len(used.transactions)} transactions, read up to height"
            f" {used.tip.height}"
        )
    ]
    lines += [
        f"      {_BRANCHES[a.branch]} {used.path}/{a.branch}/{a.index}"
        f" {a.address}: {a.confirmed} sat confirmed,"
        f" {a.unconfirmed} sat unconfirmed"
        for a in used.addresses
    ]
    return lines


def _evm_used(used: EvmAccount) -> list[str]:
    """Return the lines of a used Ethereum account and of its used addresses."""
    lines = [f"    account {used.account}, {used.path}: {used.balance} wei at latest"]
    lines += [
        f"      receive {used.path}/0/{a.index} {a.address}: {a.balance} wei,"
        f" nonce {a.nonce}"
        for a in used.addresses
    ]
    return lines


def _read(
    done: Searched | ForkSearched, used: int, held: int, command: str = "scan"
) -> str:
    """Return what a search read, and the rerun a cut short one asks for.

    `command` is the one that wrote the result, run again after identify.
    """
    line = f": accounts 0 to {done.accounts - 1} read, {used} used"
    if done.cut_short:
        line += (
            f", cut short: run identify with --accounts above {held}, then {command}"
        )
    return line


#: The lines of each used account of a search.
_Found = dict[_Key, list[list[str]]]


def _found(result: ScanResult | None) -> tuple[dict[_Key, Searched], _Found]:
    """Return each search of a result, and the lines of its used accounts."""
    if result is None:
        return {}, {}
    searched = {("bitcoin", s.reading, s.purpose): s for s in result.searched}
    lines: _Found = {}
    for used in result.used:
        lines.setdefault(("bitcoin", used.reading, used.purpose), []).append(
            _used(used)
        )
    evm = result.evm
    if evm is not None:
        searched |= {("ethereum", s.reading, s.purpose): s for s in evm.searched}
        for account in evm.used:
            key = ("ethereum", account.reading, account.purpose)
            lines.setdefault(key, []).append(_evm_used(account))
    return searched, lines


def _groups(reading: Reading) -> dict[tuple[str, int | None], int]:
    """Return how many accounts a reading holds of each coin and purpose."""
    groups: dict[tuple[str, int | None], int] = {}
    for account in reading.accounts:
        key = (account.coin, account.purpose)
        groups[key] = groups.get(key, 0) + 1
    return groups


def _kind(purpose: int | None) -> str:
    """Return how a line names a purpose."""
    return "Electrum account" if purpose is None else f"purpose {purpose}"


def _forked(n: int, reading: Reading, result: ForksResult) -> list[str]:
    """Return the lines of what a forks result read of a reading."""
    title = CHAINS[result.chain].title
    searched = {(s.coin, s.purpose): s for s in result.searched if s.reading == n}
    reasons = {
        (s.coin, s.purpose): s.reason for s in result.not_checked if s.reading == n
    }
    lines: list[str] = []
    for (coin, purpose), held in _groups(reading).items():
        if coin not in {"bitcoin", *CHAINS}:
            continue
        line = f"  {coin}, {_kind(purpose)}, on {title}"
        done = searched.get((coin, purpose))
        if done is None:
            reason = reasons.get((coin, purpose), NOT_IN_FORKS)
            lines.append(f"{line}: not checked: {reason}")
            continue
        used = [
            u
            for u in result.used
            if (u.coin, u.reading, u.purpose) == (coin, n, purpose)
        ]
        lines.append(line + _read(done, len(used), held, "forks"))
        for one in used:
            lines += _used(one)
    return lines


def _readings(
    bundle: Bundle, result: ScanResult | None, forked: Sequence[ForksResult]
) -> list[str]:
    """Return the lines of each reading, its coins and purposes, in order.

    Those of each forks result follow scan's.
    """
    searched, found = _found(result)
    reasons: dict[tuple[int, str], str] = {}
    if result is not None:
        reasons = {(n.reading, n.coin): n.reason for n in result.not_checked}
    lines: list[str] = []
    for n, reading in enumerate(bundle.readings):
        lines.append(_reading(n, reading))
        for (coin, purpose), held in _groups(reading).items():
            line = f"  {coin}, {_kind(purpose)}"
            done = searched.get((coin, n, purpose))
            if done is None:
                reason = reasons.get((n, coin), NOT_IN_SCAN)
                if result is None:
                    reason = NO_SCAN
                lines.append(f"{line}: not checked: {reason}")
                continue
            used = found.get((coin, n, purpose), [])
            lines.append(line + _read(done, len(used), held))
            for one in used:
                lines += one
        for fork in forked:
            lines += _forked(n, reading, fork)
    return lines


def _scanned(result: ScanResult) -> list[str]:
    """Return the lines naming what a scan result asked, and its bounds."""
    evm = result.evm
    lines = [f"server: {result.server or 'none'}"]
    if evm is None:
        lines.append("node: none")
    else:
        lines += [
            (
                f"node: {evm.node}, chain id {evm.chain_id}, latest block"
                f" {evm.block} before the first address was read"
            ),
            f"ethereum tokens: not checked: {NO_TOKENS}",
        ]
    lines.append(
        f"bounds: account gap {result.account_gap}, gap limit {result.gap_limit}"
    )
    return lines


def _forks(result: ForksResult, text: str) -> list[str]:
    """Return the lines naming a forks result, what it asked and its bounds."""
    lines = [
        f"forks: sha256 {_digest(text)}",
        (
            f"chain: {CHAINS[result.chain].title}, forked from Bitcoin at height"
            f" {result.fork_height}"
        ),
        f"server: {result.server}",
        f"bounds: account gap {result.account_gap}, gap limit {result.gap_limit}",
    ]
    if result.chain == BITCOIN_CASH.name:
        lines.append(f"cashtokens: not checked: {NO_CASHTOKENS}")
    elif result.chain == ECASH.name:
        lines.append(f"slp and alp tokens: not checked: {NO_SLP_ALP}")
    return lines


_Used = TypeVar("_Used", UsedAccount, EvmAccount, ForkAccount)


#: A key origin of a descriptor, which changes none of its scripts.
_ORIGIN = re.compile(r"\[[^]]*\]")


def _scripts(account: Account) -> tuple[str, ...]:
    """Return what gives an account's scripts or addresses.

    Its xpub, and its descriptors without key origin or checksum: two
    accounts of one key and one script type are paid by the same outputs,
    whatever path the origin names.
    """
    return (
        account.xpub,
        *(_ORIGIN.sub("", text.partition("#")[0]) for text in account.descriptors),
    )


def _p2pkh(account: Account) -> tuple[str, ...]:
    """Return what gives the scripts of an account `forks` reads: its xpub.

    Each account a forks result lists is read as P2PKH over its xpub's
    receive and change branches, whatever its coin.
    """
    return (account.xpub,)


def _once(
    bundle: Bundle,
    used: Sequence[tuple[str, _Used]],
    key: Callable[[Account], tuple[str, ...]] = _scripts,
) -> list[_Used]:
    """Return the used accounts, the first of each `key`.

    `used` pairs each account with its coin. Two accounts of one `key`
    hold the same funds, which a total counts once.
    """
    accounts = {
        (account.coin, n, account.purpose, account.account): account
        for n, reading in enumerate(bundle.readings)
        for account in reading.accounts
    }
    first: dict[tuple[str, ...], _Used] = {}
    for coin, one in used:
        account = accounts[coin, one.reading, one.purpose, one.account]
        first.setdefault(key(account), one)
    return list(first.values())


def _totals(bundle: Bundle, result: ScanResult) -> list[str]:
    """Return the total of each coin the result reads, each key once."""
    lines = []
    if result.server is not None:
        used = _once(bundle, [("bitcoin", u) for u in result.used])
        lines.append(
            f"total: bitcoin, {sum(u.confirmed for u in used)} sat confirmed,"
            f" {sum(u.unconfirmed for u in used)} sat unconfirmed,"
            f" {len(used)} used accounts, each account key once"
        )
    if result.evm is not None:
        accounts = _once(bundle, [("ethereum", u) for u in result.evm.used])
        lines.append(
            f"total: ethereum, {sum(int(u.balance) for u in accounts)} wei,"
            f" {len(accounts)} used accounts, each account key once"
        )
    return lines


def _forks_total(bundle: Bundle, result: ForksResult) -> str:
    """Return the total of a forks result, each key once, whatever its coin."""
    used = _once(bundle, [(u.coin, u) for u in result.used], _p2pkh)
    return (
        f"total: {result.chain}, {sum(u.confirmed for u in used)} sat confirmed,"
        f" {sum(u.unconfirmed for u in used)} sat unconfirmed,"
        f" {sum(u.at_fork for u in used)} sat at the fork,"
        f" {len(used)} used accounts, each account key once"
    )


def report(bundle: str, result: str | None = None, forks: Sequence[str] = ()) -> str:
    """Return the report on a bundle and on the results made from it.

    :param bundle: the bundle's text.
    :param result: the scan result's text, or ``None`` where there is
        none, as after `scan` refused, or its server or its node failed:
        scan's lines then list every account as not checked.
    :param forks: the texts of the forks results, one per chain.
    :returns: the report, the module docstring's layout.

    Refused as `seed_scan.bundle.loads`, `seed_scan.scan.loads` and
    `seed_scan.forks.loads` refuse their texts, a result made from
    another bundle among them, and where two forks results are of one
    chain. ``forks`` other than a list or a tuple is a
    `SeedScanTypeError`, before any text is read.
    """
    if not isinstance(forks, list | tuple):
        raise SeedScanTypeError(f"invalid forks type: {type(forks).__name__}")
    read = bundle_loads(bundle)
    scanned = None
    lines = [f"seed-scan report {VERSION}", f"bundle: sha256 {_digest(bundle)}"]
    if result is None:
        lines.append("scan: none")
    else:
        scanned = scan_loads(result, bundle)
        lines += [f"scan: sha256 {_digest(result)}", *_scanned(scanned)]
    forked = [forks_loads(text, bundle) for text in forks]
    if len({f.chain for f in forked}) != len(forked):
        raise SeedScanValueError("forks results: two of one chain")
    for fork, text in zip(forked, forks, strict=True):
        lines += _forks(fork, text)
    if not forked:
        lines.append("forks: none")
    lines.append(f"claims: {', '.join(read.claims) or 'none'}")
    lines += [f"not derived: {n.scheme}: {n.reason}" for n in read.not_checked]
    lines += _search(read.search)
    lines += _readings(read, scanned, forked)
    if scanned is not None:
        lines += _totals(read, scanned)
    lines += [_forks_total(read, fork) for fork in forked]
    text = "".join(f"{line}\n" for line in lines)
    return f"{text}digest: sha256 {_digest(text)}\n"


def _digest(text: str) -> str:
    """Return the SHA-256 of a text, UTF-8 encoded, as hex."""
    return sha256(text.encode("utf-8")).hexdigest()
