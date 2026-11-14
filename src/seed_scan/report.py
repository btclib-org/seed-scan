# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What `identify` and `scan` found, as text a person reads and acts on.

`report` reads the text of a bundle and, where one is given, of the scan
result made from it, with `seed_scan.bundle.loads` and
`seed_scan.scan.loads`. It reads no secret, since neither holds one, and
opens no connection. Every coin and purpose of the bundle is listed:
as read, with what its used accounts hold, or as not checked, with the
reason. A user acts on "nothing found", so what was not searched is
said, never passed over.

The report is lines of UTF-8 text, each ending in a newline, in this
order. ``<...>`` stands for a value and ``...`` for more of the same;
every other character is literal.

- ``seed-scan report <VERSION>``: `VERSION` says the layout below. A
  change of meaning takes a new version.
- ``bundle: sha256 <hex>``: the SHA-256 of the bundle's text, UTF-8
  encoded; `seed_scan.cli` says how the command reads the file.
- ``scan: sha256 <hex>``, the SHA-256 of the scan result's text, then
  ``server: <host:port>`` or ``server: none``, ``node: <url>, <chain>,
  chain id <n>, latest block <n> before the first address was read`` or
  ``node: none``, and ``bounds: account gap <n>, gap limit <n>``; or
  ``scan: none`` alone, where no result is given. ``<chain>`` is the
  title of the EVM chain the node serves, and where a node is named,
  ``<chain> tokens: not checked: <reason>`` follows the node's line.
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
  Electrum's layout, ``<coin>, Electrum account``, or, for an EVM coin's
  legacy layout, ``<coin>, legacy account``, with ``, on <chain>`` after
  a coin the node's chain reads, followed by:

  - ``: not checked: <reason>``, where the scan result does not read
    it, or no result is given;
  - or ``: accounts 0 to <n> read, <n> used``, then ``, cut short: run
    identify with --accounts above <n>, then scan`` where the bundle's
    accounts end before the account gap was reached.

  Four spaces in, per used Bitcoin account, ``account <n>, <path>: <n>
  sat confirmed, <n> sat unconfirmed, <n> transactions, read up to
  height <n>``; and six spaces in, per used address, ``<receive or
  change> <path> <address>: <n> sat confirmed, <n> sat unconfirmed``,
  the path being the address's own. Per used account the node read,
  ``account <n>, <path>: <n> wei at latest``; and per used address,
  ``receive <path> <address>: <n> wei, nonce <n>``, with ``address`` for
  ``receive`` in a legacy account, whose addresses are on no branch.
  Each such balance and nonce is the node's answer at the block tag
  ``latest`` when that address was read, which may be a later block
  than the node's line names: that number marks when the EVM scan
  began, and no state the balances share.
- ``total: bitcoin, <n> sat confirmed, <n> sat unconfirmed, <n> used
  accounts, each account key once``, where a server is named, and
  ``total: <chain name>, <n> wei of <symbol>, <n> used accounts, each
  account key once``, where a node is, the name and the symbol being
  those `seed_scan.evm.EVM_CHAINS` gives the node's chain. Two readings
  can hold the same account keys, as the same passphrase typed twice
  gives: each is listed with its accounts, and a total counts the funds
  of a key once.
- ``digest: sha256 <hex>``: the SHA-256 of every line above it, so that
  ``sed '$d' report.txt | shasum -a 256`` gives it back.
"""

from __future__ import annotations

from hashlib import sha256
from typing import TYPE_CHECKING, TypeVar

from seed_scan.bundle import Account, Bundle, Reading, Search
from seed_scan.bundle import loads as bundle_loads
from seed_scan.evm import EVM_CHAINS
from seed_scan.scan import EvmAccount, EvmSearched, ScanResult, Searched, UsedAccount
from seed_scan.scan import loads as scan_loads

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

__all__ = [
    "NOT_IN_SCAN",
    "NO_SCAN",
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

#: Why an EVM chain's tokens are not checked where the node was asked.
NO_TOKENS = (
    "scan asks the native asset's balances and nonces alone, so an address"
    " that only received tokens reads as unused"
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


def _used(used: UsedAccount) -> list[str]:
    """Return the lines of a used Bitcoin account and of its used addresses."""
    lines = [
        (
            f"    account {used.account}, {used.path}: {used.confirmed} sat"
            f" confirmed, {used.unconfirmed} sat unconfirmed,"
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
    """Return the lines of a used EVM account and of its used addresses.

    A legacy account's addresses are its key's own children.
    """
    lines = [f"    account {used.account}, {used.path}: {used.balance} wei at latest"]
    kind, branch = ("address", "") if used.purpose is None else ("receive", "/0")
    lines += [
        f"      {kind} {used.path}{branch}/{a.index} {a.address}: {a.balance} wei,"
        f" nonce {a.nonce}"
        for a in used.addresses
    ]
    return lines


def _read(done: Searched | EvmSearched, used: int, held: int) -> str:
    """Return what a search read, and the rerun a cut short one asks for."""
    line = f": accounts 0 to {done.accounts - 1} read, {used} used"
    if done.cut_short:
        line += f", cut short: run identify with --accounts above {held}, then scan"
    return line


#: The lines of each used account of a search.
_Found = dict[_Key, list[list[str]]]

#: Each search of a result, Bitcoin's and the node's.
_Searches = dict[_Key, Searched | EvmSearched]


def _found(result: ScanResult | None) -> tuple[_Searches, _Found]:
    """Return each search of a result, and the lines of its used accounts."""
    if result is None:
        return {}, {}
    searched: _Searches = {
        ("bitcoin", s.reading, s.purpose): s for s in result.searched
    }
    lines: _Found = {}
    for used in result.used:
        lines.setdefault(("bitcoin", used.reading, used.purpose), []).append(
            _used(used)
        )
    evm = result.evm
    if evm is not None:
        searched |= {(s.coin, s.reading, s.purpose): s for s in evm.searched}
        for account in evm.used:
            key = (account.coin, account.reading, account.purpose)
            lines.setdefault(key, []).append(_evm_used(account))
    return searched, lines


def _readings(bundle: Bundle, result: ScanResult | None) -> list[str]:
    """Return the lines of each reading, its coins and purposes, in order."""
    searched, found = _found(result)
    reasons: dict[tuple[int, str], str] = {}
    chain = None
    if result is not None:
        reasons = {(n.reading, n.coin): n.reason for n in result.not_checked}
        chain = None if result.evm is None else EVM_CHAINS[result.evm.chain].title
    lines: list[str] = []
    for n, reading in enumerate(bundle.readings):
        lines.append(_reading(n, reading))
        groups: dict[tuple[str, int | None], int] = {}
        for account in reading.accounts:
            key = (account.coin, account.purpose)
            groups[key] = groups.get(key, 0) + 1
        for (coin, purpose), held in groups.items():
            kind = f"purpose {purpose}"
            if purpose is None:
                kind = "Electrum account" if coin == "bitcoin" else "legacy account"
            line = f"  {coin}, {kind}"
            done = searched.get((coin, n, purpose))
            if done is None:
                reason = reasons.get((n, coin), NOT_IN_SCAN)
                if result is None:
                    reason = NO_SCAN
                lines.append(f"{line}: not checked: {reason}")
                continue
            if isinstance(done, EvmSearched):
                line += f", on {chain}"
            used = found.get((coin, n, purpose), [])
            lines.append(line + _read(done, len(used), held))
            for one in used:
                lines += one
    return lines


def _scanned(result: ScanResult) -> list[str]:
    """Return the lines naming what a scan result asked, and its bounds."""
    evm = result.evm
    lines = [f"server: {result.server or 'none'}"]
    if evm is None:
        lines.append("node: none")
    else:
        title = EVM_CHAINS[evm.chain].title
        lines += [
            (
                f"node: {evm.node}, {title}, chain id {evm.chain_id}, latest"
                f" block {evm.block} before the first address was read"
            ),
            f"{title} tokens: not checked: {NO_TOKENS}",
        ]
    lines.append(
        f"bounds: account gap {result.account_gap}, gap limit {result.gap_limit}"
    )
    return lines


_Used = TypeVar("_Used", UsedAccount, EvmAccount)


def _scripts(account: Account) -> tuple[str, ...]:
    """Return what gives an account's scripts or addresses.

    Its xpub and its descriptors. An EVM account has none, and its
    addresses are those of its xpub's receive branch, whatever its coin,
    or of its xpub itself for a legacy layout, of purpose None, so the
    layout is part of what gives them.
    """
    if account.descriptors:
        return (account.xpub, *account.descriptors)
    return (account.xpub, "legacy" if account.purpose is None else "receive")


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
        lines.append(_evm_total(bundle, result.evm.chain, result.evm.used))
    return lines


def _evm_total(bundle: Bundle, chain: str, used: tuple[EvmAccount, ...]) -> str:
    """Return the total of the EVM chain the node serves, each key once.

    Whatever its coin: an Ethereum and an Ethereum Classic account of one
    key are read at the same addresses, on the same chain.
    """
    accounts = _once(bundle, [(u.coin, u) for u in used])
    return (
        f"total: {chain}, {sum(int(u.balance) for u in accounts)} wei of"
        f" {EVM_CHAINS[chain].symbol}, {len(accounts)} used accounts, each account"
        " key once"
    )


def report(bundle: str, result: str | None = None) -> str:
    """Return the report on a bundle and on the scan result made from it.

    :param bundle: the bundle's text.
    :param result: the scan result's text, or ``None`` where there is
        none, as after `scan` refused, or its server or its node failed:
        every account is then not checked.
    :returns: the report, the module docstring's layout.

    Refused as `seed_scan.bundle.loads` and `seed_scan.scan.loads` refuse
    their texts, a result made from another bundle among them.
    """
    read = bundle_loads(bundle)
    scanned = None
    lines = [f"seed-scan report {VERSION}", f"bundle: sha256 {_digest(bundle)}"]
    if result is None:
        lines.append("scan: none")
    else:
        scanned = scan_loads(result, bundle)
        lines += [f"scan: sha256 {_digest(result)}", *_scanned(scanned)]
    lines.append(f"claims: {', '.join(read.claims) or 'none'}")
    lines += [f"not derived: {n.scheme}: {n.reason}" for n in read.not_checked]
    lines += _search(read.search)
    lines += _readings(read, scanned)
    if scanned is not None:
        lines += _totals(read, scanned)
    text = "".join(f"{line}\n" for line in lines)
    return f"{text}digest: sha256 {_digest(text)}\n"


def _digest(text: str) -> str:
    """Return the SHA-256 of a text, UTF-8 encoded, as hex."""
    return sha256(text.encode("utf-8")).hexdigest()
