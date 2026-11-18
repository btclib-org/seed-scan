# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `seed_scan.scan`, over a chain kept in memory.

The bundles are `identify`'s, on the vectors `tests/identify_test.py`
names, and the addresses the scan reports are checked against the ones
BIP84 and BIP86 publish for them.
"""

from __future__ import annotations

import dataclasses
import json
from hashlib import sha256
from typing import TYPE_CHECKING, Any

import pytest
from bip32_descriptors.bip32 import BIP32KeyData, xpub_from_xprv
from bip32_descriptors.descriptors import add_checksum, parse
from bip39_slip39 import bip39
from btclib.script import ScriptPubKey
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from btclib_wallet.bip44 import discover_account
from btclib_wallet.exceptions import FetchError, RpcError
from btclib_wallet.fetch.history import (
    BlockRef,
    HistoryTx,
    ScriptHistory,
    history_scripts,
)
from coin_addresses.evm import address_from_pub_key

from seed_scan import cli
from seed_scan import scan as scan_module
from seed_scan.bundle import dumps, loads
from seed_scan.evm import EVM_CHAINS, Node, quantity
from seed_scan.exceptions import SeedScanTypeError, SeedScanValueError
from seed_scan.forks import forks
from seed_scan.identify import identify
from seed_scan.report import report
from seed_scan.scan import (
    FORMAT,
    NO_NODE,
    NOT_READ,
    OTHER_CHAIN,
    VERSION,
    Address,
    EvmAddress,
    EvmSearched,
    EvmTokenBalance,
    NotRead,
    Searched,
    Tip,
    _too_deep,
    parse_server,
    scan,
)
from seed_scan.scan import loads as scan_loads

from .evm_test import Ethereum, response
from .identify_test import (
    ABANDON,
    BIP84_CHANGE,
    BIP86_RECEIVE,
    SEGWIT,
    SEGWIT_CHANGE,
    SHARES,
    Prompt,
    no_share,
)
from .no_secret_test import (
    Secrets,
    assert_json_secret_free,
    assert_lines_secret_free,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Sequence
    from urllib.request import Request

    from btclib.alias import Octets
    from btclib_wallet.bip44 import AccountUse
    from btclib_wallet.fetch.history import HistoryReader

#: The block every confirmed payment is in, and the tip.
BLOCK = BlockRef(1, b"\x01" * 32)
TIP = BlockRef(2, b"\x02" * 32)

#: A script that is none of the bundle's.
ELSEWHERE = ScriptPubKey(b"\x00\x14" + bytes(20))


class Chain:
    """A `HistoryReader` over transactions kept in memory."""

    def __init__(self, *entries: HistoryTx) -> None:
        """Keep the transactions, confirmed ones first.

        :param entries: the transactions and their blocks.
        """
        self.entries = entries
        self.asked = 0

    def get_history(
        self, scripts: Iterable[Octets | ScriptPubKey], start_height: int = 0
    ) -> ScriptHistory:
        """Answer the transactions that pay or spend from the scripts.

        :param scripts: the scripts asked for.
        :param start_height: the height the read starts from.
        :returns: the transactions, up to the tip.
        """
        self.asked += 1
        wanted = history_scripts(scripts)
        paying = {
            OutPoint(entry.tx.id, vout)
            for entry in self.entries
            for vout, out in enumerate(entry.tx.vout)
            if out.script_pub_key.script in wanted
        }
        txs = tuple(
            entry
            for entry in self.entries
            if any(out.script_pub_key.script in wanted for out in entry.tx.vout)
            or any(tx_in.prev_out in paying for tx_in in entry.tx.vin)
        )
        return ScriptHistory(BlockRef(start_height, bytes(32)), TIP, txs)


#: A reader no refusal may reach: each test refusing a bundle checks that
#: it was asked nothing.
NEVER = Chain()


@pytest.fixture(autouse=True)
def never_asked() -> Iterator[None]:
    """Fail a test after which `NEVER` was asked anything.

    :yields: once the test has run.
    """
    yield
    assert NEVER.asked == 0


def pay(n: int, *outputs: tuple[ScriptPubKey, int], spends: Tx | None = None) -> Tx:
    """Return a transaction paying each output, from outside or from `spends`.

    :param n: what tells two payments from outside apart.
    :param outputs: each script and the satoshis paid to it.
    :param spends: the transaction whose output 0 this one spends.
    :returns: the transaction.
    """
    prev_out = OutPoint(b"\xff" * 28 + n.to_bytes(4, "big"), 0)
    if spends is not None:
        prev_out = OutPoint(spends.id, 0)
    return Tx(
        vin=[TxIn(prev_out)], vout=[TxOut(value, script) for script, value in outputs]
    )


def script(text: str, path: str, branch: int, index: int) -> ScriptPubKey:
    """Return the script at a position of an account of a bundle.

    :param text: the bundle's text.
    :param path: the account's path.
    :param branch: 0 for receive, 1 for change.
    :param index: the index on the branch.
    :returns: the script.
    """
    (account,) = [a for r in loads(text).readings for a in r.accounts if a.path == path]
    return parse(account.descriptors[branch]).script_pub_keys(index)[0]


@pytest.fixture(scope="module")
def abandon() -> str:
    """Return the bundle of BIP84's mnemonic, five accounts of each purpose.

    :returns: its text.
    """
    return dumps(identify(ABANDON, [""], no_share, accounts=5))


def test_used_addresses_transactions_and_balance(abandon: str) -> None:
    """A payment, its spend to change, and the mempool's change to both."""
    receive = script(abandon, "m/84h/0h/0h", 0, 3)
    change = script(abandon, "m/84h/0h/0h", 1, 0)
    paid = pay(1, (receive, 10_000))
    spent = pay(2, (change, 4_000), (ELSEWHERE, 5_000), spends=paid)
    incoming = pay(3, (receive, 2_000))
    outgoing = pay(4, (ELSEWHERE, 3_000), spends=spent)
    chain = Chain(
        HistoryTx(paid, BLOCK),
        HistoryTx(spent, BLOCK),
        HistoryTx(incoming, None),
        HistoryTx(outgoing, None),
    )
    result = scan(abandon, chain, server="localhost:50002")
    (used,) = result.used
    assert (used.reading, used.purpose, used.account) == (0, 84, 0)
    assert used.path == "m/84h/0h/0h"
    assert used.addresses == (
        Address(0, 3, receive.address, 0, 2_000),
        Address(1, 0, BIP84_CHANGE, 4_000, -4_000),
    )
    assert [t.height for t in used.transactions] == [1, 1, None, None]
    assert used.transactions[0].tx_id == paid.id.hex()
    assert (used.confirmed, used.unconfirmed) == (4_000, 2_000 - 4_000)
    assert used.tip == Tip(2, TIP.block_id.hex())
    assert Searched(0, 84, 4, cut_short=False) in result.searched
    assert Searched(0, 44, 3, cut_short=False) in result.searched


def test_discover_account_reads_text(
    abandon: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each branch reaches `discover_account` as a str, not a `Descriptor`.

    It refuses a `Descriptor` of a package other than its own, and the
    bundle's are parsed with `bip32_descriptors`.

    :param abandon: the bundle's text.
    :param monkeypatch: what records the type of each branch handed.
    """
    real = discover_account
    handed: list[list[type]] = []

    def discover(
        descriptors: Sequence[str], reader: HistoryReader, *, gap_limit: int
    ) -> AccountUse | None:
        handed.append([type(descriptor) for descriptor in descriptors])
        return real(descriptors, reader, gap_limit=gap_limit)

    monkeypatch.setattr(scan_module, "discover_account", discover)
    scan(abandon, Chain(), server="s:1")
    assert handed
    assert all(types == [str, str] for types in handed)


def replacements(text: str) -> tuple[HistoryTx, HistoryTx, HistoryTx]:
    """Return a confirmed payment, and two replacements spending it to change.

    :param text: the bundle's text.
    :returns: the payment of 10,000 sat, and the replacements paying 9,000
        and 8,000 of it to the account's change.
    """
    receive = script(text, "m/84h/0h/0h", 0, 3)
    change = script(text, "m/84h/0h/0h", 1, 0)
    paid = pay(1, (receive, 10_000))
    return (
        HistoryTx(paid, BLOCK),
        HistoryTx(pay(0, (change, 9_000), spends=paid), None),
        HistoryTx(pay(0, (change, 8_000), spends=paid), None),
    )


def test_a_double_spend_is_read_again(
    abandon: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A history listing a replacement and what it replaced is read again.

    :param abandon: the bundle's text.
    :param monkeypatch: what gives the account's second read the mempool
        after the replacement.
    """
    paid, first, second = replacements(abandon)
    chains = [Chain(paid, first, second), Chain(paid, first)]
    real = discover_account

    def discover(
        descriptors: Sequence[str], reader: HistoryReader, *, gap_limit: int
    ) -> AccountUse | None:
        use = real(descriptors, chains[0], gap_limit=gap_limit)
        if use is not None and len(chains) > 1:
            chains.pop(0)
        return use

    monkeypatch.setattr(scan_module, "discover_account", discover)
    (used,) = scan(abandon, chains[0], server="s:1").used
    assert (used.confirmed, used.unconfirmed) == (10_000, 9_000 - 10_000)


def test_a_double_spend_in_both_reads_is_refused(
    abandon: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both replacements would count, where at most one can confirm.

    :param abandon: the bundle's text.
    :param monkeypatch: what counts the reads of the account.
    """
    chain = Chain(*replacements(abandon))
    real = discover_account
    found: list[AccountUse] = []

    def discover(
        descriptors: Sequence[str], reader: HistoryReader, *, gap_limit: int
    ) -> AccountUse | None:
        use = real(descriptors, reader, gap_limit=gap_limit)
        if use is not None:
            found.append(use)
        return use

    monkeypatch.setattr(scan_module, "discover_account", discover)
    err_msg = (
        "^reading 0, account m/84h/0h/0h: "
        "two transactions spend one output, in both reads of it$"
    )
    with pytest.raises(SeedScanValueError, match=err_msg):
        scan(abandon, chain, server="s:1")
    assert len(found) == 2


def past_the_gap(use: AccountUse) -> AccountUse:
    """Return a discovery whose one used position lies past the gap limit.

    As where the windows found a payment at an index the last read no
    longer lists, and went on reading past it.

    :param use: a discovery.
    :returns: the same, its receive branch used at index 25 alone.
    """
    return dataclasses.replace(use, used=((25,), ()))


@pytest.mark.parametrize("reads", [1, 2])
def test_a_use_past_the_gap_limit_is_read_again(
    abandon: str, monkeypatch: pytest.MonkeyPatch, reads: int
) -> None:
    """Read again once, and refused where the second read is the same.

    :param abandon: the bundle's text.
    :param monkeypatch: what makes the first `reads` reads of the account
        list a position past the gap.
    :param reads: how many reads do.
    """
    receive = script(abandon, "m/84h/0h/0h", 0, 3)
    chain = Chain(HistoryTx(pay(1, (receive, 1)), BLOCK))
    real = discover_account
    found: list[AccountUse] = []

    def discover(
        descriptors: Sequence[str], reader: HistoryReader, *, gap_limit: int
    ) -> AccountUse | None:
        use = real(descriptors, reader, gap_limit=gap_limit)
        if use is None:
            return None
        found.append(use)
        return past_the_gap(use) if len(found) <= reads else use

    monkeypatch.setattr(scan_module, "discover_account", discover)
    if reads == 1:
        (used,) = scan(abandon, chain, server="s:1").used
        assert [(a.branch, a.index) for a in used.addresses] == [(0, 3)]
        return
    err_msg = (
        "^reading 0, account m/84h/0h/0h: "
        "a used position past the gap limit, in both reads of it$"
    )
    with pytest.raises(SeedScanValueError, match=err_msg):
        scan(abandon, chain, server="s:1")
    assert len(found) == 2


def test_coinbases_spend_no_output(abandon: str) -> None:
    """Two coinbases share the input that spends nothing, and both count.

    :param abandon: the bundle's text.
    """
    receive = script(abandon, "m/84h/0h/0h", 0, 0)
    coinbases = [
        Tx(vin=[TxIn(OutPoint(), height)], vout=[TxOut(50_000, receive)])
        for height in (b"\x01\x02", b"\x01\x03")
    ]
    chain = Chain(*(HistoryTx(tx, BLOCK) for tx in coinbases))
    (used,) = scan(abandon, chain, server="s:1").used
    assert (used.confirmed, used.unconfirmed) == (100_000, 0)


#: 21 million bitcoin, in satoshis: what no balance passes.
MAX_MONEY = 21 * 10**14


@pytest.mark.parametrize(
    "indexes, blocks",
    [
        # one address paid twice, in blocks
        ((0, 0), (BLOCK, BLOCK)),
        # two addresses, each within the bound, the account past it
        ((0, 1), (BLOCK, BLOCK)),
        # a confirmed balance within the bound, and the mempool's past it
        ((0, 0), (BLOCK, None)),
    ],
)
def test_a_balance_past_21_million_bitcoin_is_refused(
    abandon: str, indexes: tuple[int, int], blocks: tuple[BlockRef | None, ...]
) -> None:
    """Two payments of 15 million bitcoin: refused, as `loads` refuses them.

    :param abandon: the bundle's text.
    :param indexes: the receive index each payment pays.
    :param blocks: the block each payment is in, or None for the mempool.
    """
    chain = Chain(
        *(
            HistoryTx(pay(n, (script(abandon, "m/84h/0h/0h", 0, i), 15 * 10**14)), b)
            for n, (i, b) in enumerate(zip(indexes, blocks, strict=True))
        )
    )
    err_msg = (
        "^reading 0, account m/84h/0h/0h: a balance outside 0 to 21 million bitcoin$"
    )
    with pytest.raises(SeedScanValueError, match=err_msg):
        scan(abandon, chain, server="s:1")


def test_a_balance_of_21_million_bitcoin_is_written_and_read_back(
    abandon: str,
) -> None:
    """The bound itself, half confirmed and half in the mempool, loads."""
    half = MAX_MONEY // 2
    chain = Chain(
        HistoryTx(pay(1, (script(abandon, "m/84h/0h/0h", 0, 0), half)), BLOCK),
        HistoryTx(pay(2, (script(abandon, "m/84h/0h/0h", 0, 1), half)), None),
    )
    result = scan(abandon, chain, server="s:1")
    (used,) = result.used
    assert (used.confirmed, used.unconfirmed) == (half, half)
    assert scan_module.loads(scan_module.dumps(result), abandon) == result


def test_nothing_used_reads_three_accounts_of_each_purpose(abandon: str) -> None:
    """With no history, each purpose stops at the default account gap."""
    result = scan(abandon, Chain(), server="s:1")
    assert not result.used
    assert [(s.purpose, s.accounts) for s in result.searched] == [
        (44, 3),
        (49, 3),
        (84, 3),
        (86, 3),
    ]


def test_a_purpose_cut_short_where_the_accounts_end(abandon: str) -> None:
    """Accounts 0 and 2 used: the bundle's accounts end before the gap."""
    first = script(abandon, "m/86h/0h/0h", 0, 0)
    third = script(abandon, "m/86h/0h/2h", 0, 0)
    assert first.address == BIP86_RECEIVE
    chain = Chain(HistoryTx(pay(1, (first, 1), (third, 1)), BLOCK))
    result = scan(abandon, chain, server="s:1")
    assert [u.account for u in result.used] == [0, 2]
    assert Searched(0, 86, 5, cut_short=True) in result.searched


def test_the_default_account_gap_reads_past_two_unused_accounts(
    abandon: str,
) -> None:
    """Account 2 used and accounts 0 and 1 not: found by default."""
    third = script(abandon, "m/49h/0h/2h", 1, 4)
    chain = Chain(HistoryTx(pay(1, (third, 7)), None))
    assert not scan(abandon, chain, server="s:1", account_gap=2).used
    result = scan(abandon, chain, server="s:1")
    (used,) = result.used
    assert (used.path, used.addresses[0].index) == ("m/49h/0h/2h", 4)
    assert (used.confirmed, used.unconfirmed) == (0, 7)
    assert Searched(0, 49, 5, cut_short=True) in result.searched


def test_a_wider_account_gap_reads_past_three_unused_accounts(abandon: str) -> None:
    """Account 3 used and accounts 0 to 2 not: found with a gap of 4 alone."""
    fourth = script(abandon, "m/44h/0h/3h", 0, 0)
    chain = Chain(HistoryTx(pay(1, (fourth, 1)), BLOCK))
    assert not scan(abandon, chain, server="s:1").used
    (used,) = scan(abandon, chain, server="s:1", account_gap=4).used
    assert used.path == "m/44h/0h/3h"


def test_the_gap_limit_ends_a_branch(abandon: str) -> None:
    """A payment at index 3 is past a gap limit of 3."""
    receive = script(abandon, "m/84h/0h/0h", 0, 3)
    chain = Chain(HistoryTx(pay(1, (receive, 1)), BLOCK))
    assert not scan(abandon, chain, server="s:1", gap_limit=3).used
    assert scan(abandon, chain, server="s:1", gap_limit=4).used


def test_an_electrum_reading_has_one_account() -> None:
    """Its account is read alone, whatever the account gap."""
    text = dumps(identify(SEGWIT, [""], no_share, accounts=1))
    (account,) = loads(text).readings[0].accounts
    change = parse(account.descriptors[1]).script_pub_keys(0)[0]
    assert change.address == SEGWIT_CHANGE
    chain = Chain(HistoryTx(pay(1, (change, 5)), BLOCK))
    result = scan(text, chain, server="s:1", account_gap=5)
    assert result.searched == (Searched(0, None, 1, cut_short=False),)
    (used,) = result.used
    assert (used.purpose, used.addresses) == (
        None,
        (Address(1, 0, SEGWIT_CHANGE, 5, 0),),
    )


def test_the_other_coins_are_not_checked(abandon: str) -> None:
    """Each coin not read is listed once per reading, with the reason."""
    result = scan(abandon, Chain(), server="s:1")
    reason = "scan reads Bitcoin and the EVM chains' coins alone in this version"
    assert result.not_checked == (
        NotRead(0, "ethereum", "no EVM node was named"),
        NotRead(0, "ethereum-classic", "no EVM node was named"),
        NotRead(0, "bnb", "no EVM node was named"),
        *(
            NotRead(0, coin, reason)
            for coin in (
                "bitcoin-cash",
                "bitcoin-sv",
                "ecash",
                "ecash-tokens",
                "slp-tokens",
                "litecoin",
                "dogecoin",
            )
        ),
    )
    assert result.evm is None


def test_the_result_is_versioned_json_naming_the_bundle(abandon: str) -> None:
    """`dumps` writes the format, the version, the digest and the server."""
    result = scan(abandon, Chain(), server="node.local:50002")
    document = json.loads(scan_module.dumps(result))
    assert list(document)[:4] == ["format", "version", "bundle", "server"]
    assert (document["format"], document["version"]) == (FORMAT, VERSION)
    assert document["bundle"] == sha256(abandon.encode()).hexdigest()
    assert document["server"] == "node.local:50002"
    assert (document["gap_limit"], document["account_gap"]) == (20, 3)


def test_nothing_scan_writes_holds_a_secret(abandon: str) -> None:
    """No piece of the mnemonic's secrets is in the scan result."""
    receive = script(abandon, "m/84h/0h/0h", 0, 0)
    chain = Chain(HistoryTx(pay(1, (receive, 1)), BLOCK))
    text = scan_module.dumps(scan(abandon, chain, server="s:1"))
    assert '"used": [\n    {' in text
    secrets = Secrets()
    secrets.sentence(ABANDON)
    paths = sorted({a.path for r in loads(abandon).readings for a in r.accounts})
    secrets.seed(bip39.seed_from_mnemonic(ABANDON, ""), paths)
    assert_json_secret_free(text, secrets.every())


def edited(text: str, path: str, **members: object) -> str:
    """Return a bundle with members of one account replaced.

    :param text: the bundle's text.
    :param path: the account's path.
    :param members: the members and their new values.
    :returns: the edited bundle's text.
    """
    document = json.loads(text)
    for reading in document["readings"]:
        for account in reading["accounts"]:
            if account["path"] == path:
                account.update(members)
    return json.dumps(document)


#: The master xprv of BIP84's mnemonic, which a descriptor must not hold.
XPRV = BIP32KeyData.from_seed(bip39.seed_from_mnemonic(ABANDON, "")).b58encode()


@pytest.mark.parametrize(
    "descriptors",
    [
        [],
        ["wpkh(not a key)#00000000"],
        [f"wpkh({XPRV}/0/*)"],
        [add_checksum(f"wpkh({XPRV}/0/*)")],
        [add_checksum(f"wpkh({xpub_from_xprv(XPRV)}/0/0)")],
    ],
)
def test_an_account_without_its_public_descriptors_is_refused(
    abandon: str, descriptors: list[str]
) -> None:
    """`loads` refuses it, before the reader is asked, quoting no descriptor.

    A private key is refused whether its checksum is right or not, and so
    is a descriptor that ranges no index.

    :param abandon: the bundle.
    :param descriptors: what replaces the account's descriptors.
    """
    text = edited(abandon, "m/84h/0h/1h", descriptors=descriptors)
    with pytest.raises(SeedScanValueError) as caught:
        scan(text, NEVER, server="s:1")
    message = str(caught.value)
    assert (
        message == "bundle: member 'descriptors' is not the account's two descriptors"
    )
    assert caught.value.__context__ is None


def test_a_key_off_the_curve_is_refused(abandon: str) -> None:
    """`loads` reads a key's encoding, and `parse` that it is a point.

    Its x is 5, and 5**3 + 7 is no square modulo secp256k1's prime, so no
    point has it: the xpub's version, length, checksum and prefix are
    valid, and its descriptors carry their checksums.
    """
    document = json.loads(abandon)
    (account,) = [
        a for a in document["readings"][0]["accounts"] if a["path"] == "m/84h/0h/1h"
    ]
    data = BIP32KeyData.b58decode(account["xpub"], check_validity=False)
    off_curve = BIP32KeyData(
        data.version,
        data.depth,
        data.parent_fingerprint,
        data.index,
        data.chain_code,
        b"\x02" + (5).to_bytes(32, "big"),
        check_validity=False,
    ).b58encode(check_validity=False)
    descriptors = [
        add_checksum(d.split("#")[0].replace(account["xpub"], off_curve))
        for d in account["descriptors"]
    ]
    edited_text = edited(
        abandon, "m/84h/0h/1h", xpub=off_curve, descriptors=descriptors
    )
    loads(edited_text)
    with pytest.raises(SeedScanValueError) as caught:
        scan(edited_text, NEVER, server="s:1")
    message = str(caught.value)
    assert message == "bundle: reading 0, account 11: a descriptor that does not parse"
    assert caught.value.__context__ is None


def test_accounts_not_numbered_from_0_are_refused(abandon: str) -> None:
    """A purpose's accounts are 0 to n - 1, in order."""
    text = edited(abandon, "m/84h/0h/1h", account=2)
    with pytest.raises(SeedScanValueError, match="accounts not numbered from 0"):
        scan(text, NEVER, server="s:1")


def _deep_account(text: str, path: str, depth: int, purpose: int) -> tuple[str, int]:
    """Return a bundle whose account at `path` has a key of `depth`.

    Its number in its reading comes back with it.

    The key's own checks are skipped, as a bundle is read with them
    skipped: a key whose depth disagrees with the path above it still
    decodes, and its descriptors are re-checksummed.

    :param text: the bundle's text.
    :param path: the account's path.
    :param depth: the depth its xpub is re-encoded at.
    :param purpose: which of the accounts at that path, as the kept one.
    :returns: the edited bundle's text, and the account's place in its reading.
    """
    document = json.loads(text)
    number = 0
    for reading in document["readings"]:
        for index, account in enumerate(reading["accounts"]):
            if account["path"] != path or account["purpose"] != purpose:
                continue
            number = index
            old = account["xpub"]
            data = BIP32KeyData.b58decode(old, check_validity=False)
            deep = BIP32KeyData(
                data.version,
                depth,
                data.parent_fingerprint,
                data.index,
                data.chain_code,
                data.key,
                check_validity=False,
            ).b58encode(check_validity=False)
            account["xpub"] = deep
            account["descriptors"] = [
                add_checksum(d.split("#")[0].replace(old, deep))
                for d in account["descriptors"]
            ]
    return json.dumps(document), number


def _no_scan_result() -> str:
    """Return the text of a scan result that searched and used nothing."""
    return json.dumps(
        {
            "format": "seed-scan-scan",
            "version": 1,
            "bundle": "0" * 64,
            "server": None,
            "gap_limit": 20,
            "account_gap": 5,
            "searched": [],
            "used": [],
            "not_checked": [],
            "evm": None,
        }
    )


@pytest.mark.parametrize(
    "path, purpose, depth",
    [
        ("m/84h/0h/0h", 84, 255),
        ("m/84h/0h/0h", 84, 254),
        ("m/44h/0h/0h", 44, 254),
    ],
)
def test_a_bitcoin_xpub_too_deep_to_derive_is_refused(
    abandon: str, path: str, purpose: int, depth: int
) -> None:
    """A Bitcoin account's key two levels above its addresses is refused.

    Its addresses are two levels below the key (`/0/i`), and BIP32 stops
    at depth 255, so a key at 254 or 255 cannot reach them: btclib-wallet
    raised `BTClibValueError` there. `scan`, `scan.loads`, `report` and
    `forks` refuse with `SeedScanValueError` before a reader is asked.
    """
    text, number = _deep_account(abandon, path, depth, purpose)
    loads(text)
    message = f"bundle: reading 0, account {number}: an xpub too deep to derive"
    with pytest.raises(SeedScanValueError) as caught:
        scan(text, NEVER, server="s:1")
    assert str(caught.value) == message
    assert caught.value.__context__ is None

    with pytest.raises(SeedScanValueError, match="an xpub too deep to derive"):
        scan_loads(_no_scan_result(), text)
    with pytest.raises(SeedScanValueError, match="an xpub too deep to derive"):
        report(text, _no_scan_result())


@pytest.mark.parametrize("depth", [255, 254])
def test_a_fork_account_too_deep_is_refused_by_forks(abandon: str, depth: int) -> None:
    """`forks` builds a fork account's descriptors, and refuses one too deep.

    Its own descriptors are two below the key, as Bitcoin's are, so a key
    at 254 or 255 cannot reach them.
    """
    text, number = _deep_account(abandon, "m/44h/145h/0h", depth, 44)
    loads(text)
    with pytest.raises(SeedScanValueError) as caught:
        forks(text, NEVER, chain="bitcoin-cash", server="s:1")
    assert (
        str(caught.value)
        == f"bundle: reading 0, account {number}: an xpub too deep to derive"
    )
    assert caught.value.__context__ is None


def test_a_musig_reaches_as_far_as_its_deepest_participant() -> None:
    """`tr(musig(...))` is as deep as its deepest key; a fixed one is not.

    These two branches of `_reach` are read here rather than through a
    bundle: an account's descriptors are over its own xpub, so a `musig()`
    and a key fixed in the text never reach `seed_scan.scan._too_deep`
    from a scan.
    """
    master = xpub_from_xprv(XPRV)
    data = BIP32KeyData.b58decode(master)
    deep = BIP32KeyData(
        data.version,
        254,
        data.parent_fingerprint,
        data.index,
        data.chain_code,
        data.key,
    ).b58encode(check_validity=False)
    # 254 below, then the branch and the index: 256.
    assert _too_deep(parse(f"tr(musig({master}/0/*,{deep}/0/*))"))
    # secp256k1's generator, fixed in the descriptor: no path to derive.
    generator = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    assert not _too_deep(parse(f"pkh({generator})"))


def test_a_bitcoin_xpub_at_253_still_reads(abandon: str) -> None:
    """One level short of the limit, the addresses below it are read."""
    text, _ = _deep_account(abandon, "m/84h/0h/0h", 253, 84)
    result = scan(text, Chain(), server="s:1")
    assert result.used == () and result.searched != ()


def test_an_electrum_reading_with_two_accounts_is_refused() -> None:
    """Electrum's layout has one account."""
    text = dumps(identify(SEGWIT, [""], no_share, accounts=1))
    document = json.loads(text)
    accounts = document["readings"][0]["accounts"]
    accounts.append(dict(accounts[0], account=1))
    with pytest.raises(SeedScanValueError, match="accounts not numbered from 0"):
        scan(json.dumps(document), NEVER, server="s:1")


def test_a_text_that_is_no_bundle_is_refused() -> None:
    """`seed_scan.bundle.loads` refuses it, quoting nothing of it."""
    with pytest.raises(SeedScanValueError) as caught:
        scan(ABANDON, NEVER, server="s:1")
    assert ABANDON.split()[0] not in str(caught.value)


@pytest.mark.parametrize(
    "bounds, error",
    [
        ({"gap_limit": 0}, SeedScanValueError),
        ({"account_gap": 0}, SeedScanValueError),
        ({"gap_limit": True}, SeedScanTypeError),
        ({"account_gap": 1.0}, SeedScanTypeError),
        ({"server": None}, SeedScanTypeError),
    ],
)
def test_the_arguments_are_checked_before_the_reader_is_asked(
    abandon: str, bounds: dict[str, object], error: type[Exception]
) -> None:
    """A bound below 1, a bound or a server of a wrong type.

    :param abandon: the bundle.
    :param bounds: the arguments given beside the bundle and the reader.
    :param error: what is raised.
    """
    arguments: dict[str, object] = {"server": "s:1", **bounds}
    with pytest.raises(error):
        scan(abandon, NEVER, **arguments)  # type: ignore[arg-type]


#: The address of m/44h/60h/0h/0/0 for BIP84's mnemonic, as Nethereum's
#: README derives it, `address0` under *BIP32 Key Derivation*:
#:
#: repo    Nethereum/Nethereum
#: path    src/Nethereum.Wallet/README.md
#: commit  cde9ee8d69a08f700398abfd5a8c5d1a7bbdfd3f
#: blob    19bbd360d2c03aa105d1bd28e89af87ef4ee2642
NETHEREUM_ADDRESS = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"


def eth_address(text: str, path: str, index: int, *, legacy: bool = False) -> str:
    """Return the address at an index of an Ethereum account of a bundle.

    :param text: the bundle's text.
    :param path: the account's path.
    :param index: the index on the receive branch, or below the key
        itself for a legacy layout, the position of its key for one held
        key by key.
    :param legacy: whether the account is a legacy layout, of no purpose,
        whose key can also be an account's of a purpose.
    :returns: the address, EIP-55 encoded.
    """
    (account,) = [
        a
        for r in loads(text).readings
        for a in r.accounts
        if a.path == path and (a.purpose is None) == legacy
    ]
    if account.keys:
        return address_from_pub_key(bytes.fromhex(account.keys[index]))
    below = f"m/{index}" if legacy else f"m/0/{index}"
    key = BIP32KeyData.b58decode(account.xpub).derive(below)
    return address_from_pub_key(key.sec)


def node(fake: Ethereum) -> Node:
    """Return a node answered by a fake, with no socket.

    :param fake: the fake.
    :returns: the node.
    """
    return Node("https://node.example/rpc", transport=fake)


def test_the_first_ethereum_address_is_the_published_one(abandon: str) -> None:
    """The receive branch below the bundle's xpub, as Nethereum derives it."""
    assert eth_address(abandon, "m/44h/60h/0h", 0) == NETHEREUM_ADDRESS


def test_an_ethereum_address_with_a_balance_or_a_nonce_is_used(abandon: str) -> None:
    """Either is enough; the balance is in wei, as decimal digits."""
    first = eth_address(abandon, "m/44h/60h/0h", 0)
    sixth = eth_address(abandon, "m/44h/60h/0h", 5)
    third = eth_address(abandon, "m/44h/60h/2h", 0)
    fake = Ethereum({first: 10**18, third: 1}, {sixth: 4}, chain_id=1)
    result = scan(abandon, None, node=node(fake))
    evm = result.evm
    assert evm is not None
    assert (evm.node, evm.chain, evm.chain_id, evm.block) == (
        "https://node.example",
        "ethereum",
        1,
        16,
    )
    first_account, third_account = evm.used
    assert first_account.path == "m/44h/60h/0h"
    assert first_account.addresses == (
        EvmAddress(0, first, str(10**18), 0, 16, ()),
        EvmAddress(5, sixth, "0", 4, 16, ()),
    )
    assert first_account.balance == str(10**18)
    assert (third_account.account, third_account.balance) == (2, "1")
    assert evm.searched == (
        EvmSearched(0, "ethereum", 44, 5, cut_short=True),
        EvmSearched(0, "ethereum", None, 2, cut_short=False),
    )
    assert fake.asked[:2] == ["eth_chainId", "eth_blockNumber"]
    assert result.server is None
    assert not result.searched
    assert not result.used


def test_the_ethereum_bounds_are_the_bitcoin_ones(abandon: str) -> None:
    """An index past the gap limit, an account past the account gap."""
    late = eth_address(abandon, "m/44h/60h/0h", 3)
    fourth = eth_address(abandon, "m/44h/60h/3h", 0)
    fake = Ethereum({late: 1, fourth: 1})
    evm = scan(abandon, None, node=node(fake), gap_limit=3).evm
    assert evm is not None
    assert not evm.used
    assert evm.searched == (
        EvmSearched(0, "ethereum", 44, 3, cut_short=False),
        EvmSearched(0, "ethereum", None, 2, cut_short=False),
    )
    evm = scan(abandon, None, node=node(fake), gap_limit=4, account_gap=4).evm
    assert evm is not None
    assert [u.account for u in evm.used] == [0, 3]
    nothing = Ethereum()
    scan(abandon, None, node=node(nothing))
    # two requests ahead, then per address its balance and nonce and one
    # per token: three accounts of 20, and each legacy layout's 20
    tokens = len(EVM_CHAINS["ethereum"].tokens)
    assert len(nothing.asked) == 2 + (2 + tokens) * 20 * (3 + 2)


def test_mews_mnemonic_addresses_are_read_below_m_44h_60h(abandon: str) -> None:
    """MyEtherWallet's n-th address of a mnemonic is m/44h/60h/<n>.

    Derived here from the seed by BIP32 alone: unhardened children of the
    key at m/44h/60h, read on no branch, which no account of a purpose
    reaches. Its tokens are read as an account's of a purpose are.
    """
    master = BIP32KeyData.from_seed(bip39.seed_from_mnemonic(ABANDON, ""))
    second = address_from_pub_key(master.derive("m/44h/60h/1").sec)
    fake = Ethereum({second: 7}, tokens={(USDT.contract, second): 3})
    evm = scan(abandon, None, node=node(fake)).evm
    assert evm is not None
    (used,) = evm.used
    assert (used.coin, used.purpose, used.account, used.path) == (
        "ethereum",
        None,
        1,
        "m/44h/60h",
    )
    usdt = (EvmTokenBalance(USDT.contract, "USDT", 6, "3"),)
    assert used.addresses == (EvmAddress(1, second, "7", 0, 16, usdt),)
    assert used.tokens == usdt


def test_each_legacy_layout_is_read_whatever_the_account_gap(abandon: str) -> None:
    """Each is a layout of its own: one unused does not end the next.

    With an account gap of 1, the unused first layout is no reason to
    leave MyEtherWallet's unread.
    """
    mew = eth_address(abandon, "m/44h/60h", 0, legacy=True)
    fake = Ethereum({mew: 1})
    evm = scan(abandon, None, node=node(fake), account_gap=1).evm
    assert evm is not None
    assert [(u.path, u.account) for u in evm.used] == [("m/44h/60h", 1)]
    assert evm.searched[-1] == EvmSearched(0, "ethereum", None, 2, cut_short=False)


@pytest.fixture(scope="module")
def few_keys() -> str:
    """Return the bundle of BIP84's mnemonic with 25 of MyEtherWallet's keys.

    One account of each purpose, so that a test reads few addresses.

    :returns: its text.
    """
    return dumps(identify(ABANDON, [""], no_share, accounts=1, keys=25))


@pytest.mark.parametrize("used, short", [(None, False), (4, False), (5, True)])
def test_mews_layout_is_cut_short_where_its_keys_end_first(
    few_keys: str, used: int | None, short: bool
) -> None:
    """Read no further than its keys: cut short where the gap would pass them.

    Of 25 keys, a gap limit of 20 after index 4 ends at the last key, and
    after index 5 would pass it, where child 25 may be used.

    :param few_keys: the bundle.
    :param used: the index of the one address used, or None.
    :param short: whether the layout is cut short.
    """
    balances = (
        {}
        if used is None
        else {eth_address(few_keys, "m/44h/60h", used, legacy=True): 1}
    )
    fake = Ethereum(balances)
    evm = scan(few_keys, None, node=node(fake)).evm
    assert evm is not None
    assert evm.searched[-1] == EvmSearched(0, "ethereum", None, 2, cut_short=short)
    assert [a.index for u in evm.used for a in u.addresses] == (
        [] if used is None else [used]
    )
    read = 20 if used is None else min(used + 21, 25)
    tokens = len(EVM_CHAINS["ethereum"].tokens)
    assert len(fake.asked) == 2 + (2 + tokens) * (20 + 20 + read)


def test_the_summary_says_a_layout_is_cut_short() -> None:
    """Three keys, fewer than the gap limit: the summary says they end first."""
    bundle = dumps(identify(ABANDON, [""], no_share, accounts=1, keys=3))
    result = scan(bundle, None, node=node(Ethereum()))
    assert (
        "reading 0, ethereum legacy: accounts read: 2, cut short: a layout's keys"
        " in the bundle end before the gap limit"
    ) in cli._scan_summary(result).splitlines()


def test_a_key_of_mews_layout_that_does_not_decode_is_refused(few_keys: str) -> None:
    """No point of the curve: refused as an xpub is, the node not asked."""
    (mew,) = [a for r in loads(few_keys).readings for a in r.accounts if a.keys]
    text = edited(few_keys, "m/44h/60h", keys=[*mew.keys[:-1], "02" + "ff" * 32])
    loads(text)
    fake = Ethereum()
    with pytest.raises(SeedScanValueError) as caught:
        scan(text, None, node=node(fake))
    assert (
        str(caught.value) == "bundle: reading 0, account 6: a key that does not decode"
    )
    assert caught.value.__context__ is None
    assert not fake.asked


def test_without_a_server_bitcoin_is_not_checked(abandon: str) -> None:
    """The node alone: Bitcoin is listed, with the reason."""
    result = scan(abandon, None, node=node(Ethereum()))
    assert result.not_checked[0] == NotRead(
        0, "bitcoin", "no Electrum server was named"
    )
    assert "ethereum" not in [n.coin for n in result.not_checked]
    document = json.loads(scan_module.dumps(result))
    assert document["server"] is None
    assert list(document)[-1] == "evm"
    assert list(document["evm"]) == [
        "node",
        "chain",
        "chain_id",
        "block",
        "tokens",
        "searched",
        "used",
    ]
    assert document["evm"]["tokens"][0] == {
        "contract": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
        "symbol": "USDT",
        "decimals": 6,
    }


def test_a_server_and_a_node_are_both_read(abandon: str) -> None:
    """Bitcoin's accounts by the reader, then Ethereum's by the node."""
    receive = script(abandon, "m/84h/0h/0h", 0, 0)
    chain = Chain(HistoryTx(pay(1, (receive, 1)), BLOCK))
    first = eth_address(abandon, "m/44h/60h/0h", 0)
    result = scan(abandon, chain, server="s:1", node=node(Ethereum({first: 2})))
    assert [u.path for u in result.used] == ["m/84h/0h/0h"]
    assert result.evm is not None
    assert [u.path for u in result.evm.used] == ["m/44h/60h/0h"]
    assert {(n.coin, n.reason) for n in result.not_checked} == {
        *((coin, OTHER_CHAIN[coin]) for coin in ("ethereum-classic", "bnb")),
        *(
            (coin, NOT_READ)
            for coin in (
                "bitcoin-cash",
                "bitcoin-sv",
                "ecash",
                "ecash-tokens",
                "slp-tokens",
                "litecoin",
                "dogecoin",
            )
        ),
    }


def test_nothing_the_ethereum_scan_writes_holds_a_secret(abandon: str) -> None:
    """No piece of the mnemonic's secrets is in the result's ``evm``."""
    first = eth_address(abandon, "m/44h/60h/0h", 0)
    text = scan_module.dumps(scan(abandon, None, node=node(Ethereum({first: 1}))))
    assert first in text
    secrets = Secrets()
    secrets.sentence(ABANDON)
    paths = sorted({a.path for r in loads(abandon).readings for a in r.accounts})
    secrets.seed(bip39.seed_from_mnemonic(ABANDON, ""), paths)
    assert_json_secret_free(text, secrets.every())


def test_a_clean_ethereum_classic_scan_holds_no_secret() -> None:
    """Shares holding ``class``: no secret in the result, report or summary.

    The format's names hold that word, as ``ethereum-classic`` and
    ``Ethereum Classic`` do, and its member names others, as ``cut_short``
    holds ``short``: each is the format's, not the mnemonic's. The node's
    URL holds a double quote, which the result writes escaped and the
    report and the summary as it is, on the line that names the chain.
    """
    bundle = dumps(identify(SHARES[0], [""], Prompt(SHARES[1]), accounts=5))
    classic = eth_address(bundle, "m/44h/61h/0h", 0)
    fake = Ethereum({classic: 3}, chain_id=61)
    quoted = Node('https://node".example/rpc', transport=fake)
    result = scan(bundle, None, node=quoted, evm_chain="ethereum-classic")
    text = scan_module.dumps(result)
    secrets = Secrets()
    for share in SHARES:
        secrets.sentence(share)
    assert '"node": "https://node\\".example"' in text
    assert_json_secret_free(text, secrets.every())
    for written in (report(bundle, text), cli._scan_summary(result)):
        assert 'node: https://node".example, Ethereum Classic, chain id 61' in written
        assert_lines_secret_free(written, secrets.every())


def off_curve(xpub: str) -> str:
    """Return an extended public key whose key is no point of the curve.

    :param xpub: the key whose other fields are kept.
    :returns: the same fields, with a key whose x is past the field.
    """
    data = BIP32KeyData.b58decode(xpub)
    forged = BIP32KeyData(
        data.version,
        data.depth,
        data.parent_fingerprint,
        data.index,
        data.chain_code,
        b"\x02" + b"\xff" * 32,
        check_validity=False,
    )
    return forged.b58encode(check_validity=False)


def test_an_ethereum_xpub_that_does_not_decode_is_refused(abandon: str) -> None:
    """`loads` reads its form; decoding finds no point. Nothing is asked."""
    (account,) = [
        a
        for r in loads(abandon).readings
        for a in r.accounts
        if a.path == "m/44h/60h/1h"
    ]
    text = edited(abandon, "m/44h/60h/1h", xpub=off_curve(account.xpub))
    loads(text)
    fake = Ethereum()
    with pytest.raises(SeedScanValueError) as caught:
        scan(text, None, node=node(fake))
    assert (
        str(caught.value)
        == "bundle: reading 0, account 21: an xpub that does not decode"
    )
    assert caught.value.__context__ is None
    assert not fake.asked


@pytest.mark.parametrize(
    "path, number", [("m/44h/60h/1h", 3), ("m/44h/60h", 0), ("m/44h/60h", 2)]
)
def test_ethereum_accounts_not_numbered_from_0_are_refused(
    abandon: str, path: str, number: int
) -> None:
    """The same rule as Bitcoin's, before the node is asked.

    A coin's legacy layouts are numbered from 0 too, apart from its
    accounts of a purpose.

    :param abandon: the bundle.
    :param path: the account renumbered.
    :param number: its number.
    """
    fake = Ethereum()
    text = edited(abandon, path, account=number)
    with pytest.raises(SeedScanValueError, match="accounts not numbered from 0"):
        scan(text, None, node=node(fake))
    assert not fake.asked


def test_a_server_that_is_not_host_and_port_is_refused(abandon: str) -> None:
    """`parse_server`'s rule, before the reader is asked."""
    with pytest.raises(SeedScanValueError, match="^server is not host:port$"):
        scan(abandon, NEVER, server="no port")


@pytest.mark.parametrize(
    "text, name, said",
    [
        ("s:1", None, "invalid name type: NoneType"),
        (None, "server", "invalid server type: NoneType"),
    ],
)
def test_parse_server_refuses_a_text_or_a_name_of_a_wrong_type(
    text: Any, name: Any, said: str
) -> None:
    """Each argument on its own, the other valid."""
    with pytest.raises(SeedScanTypeError) as caught:
        parse_server(text, name)
    assert str(caught.value) == said


@pytest.mark.parametrize(
    "server, said",
    [
        ("s:1", "a server is named, and no reader asks it"),
        (None, "neither a reader nor a node is given"),
    ],
)
def test_a_scan_of_nothing_is_refused(
    abandon: str, server: str | None, said: str
) -> None:
    """No reader: a server named is refused, and so is no node.

    :param abandon: the bundle.
    :param server: the server named.
    :param said: what the refusal says.
    """
    with pytest.raises(SeedScanValueError, match=said):
        scan(abandon, None, server=server)


def test_a_node_of_another_chain_is_refused_before_any_address(abandon: str) -> None:
    """An Ethereum Classic node, for Ethereum: its chain id alone is asked."""
    fake = Ethereum(chain_id=61)
    with pytest.raises(SeedScanValueError) as caught:
        scan(abandon, None, node=node(fake))
    assert str(caught.value) == "the node does not serve Ethereum"
    assert "61" not in str(caught.value)
    assert fake.asked == ["eth_chainId"]


@pytest.mark.parametrize("name", sorted(EVM_CHAINS))
def test_each_chain_reads_the_coins_it_lists(abandon: str, name: str) -> None:
    """Ethereum's accounts on every chain; two chains read their own coin too.

    Each coin's purpose 44 and its legacy layout, whose key's own
    children are its addresses, or BNB's address alone; the result names
    the chain, and a coin
    not read on it is listed with the chain that reads it.

    :param abandon: the bundle.
    :param name: the chain.
    """
    chain = EVM_CHAINS[name]
    paths = {
        ("ethereum", 44): ("m/44h/60h/0h", 0, "5"),
        ("ethereum", None): ("m/44h/60h/0h", 7, "6"),
        ("ethereum-classic", 44): ("m/44h/61h/1h", 2, "7"),
        ("ethereum-classic", None): ("m/44h/60h/160720h/0h", 3, "8"),
        ("bnb", 44): ("m/44h/714h/1h", 4, "9"),
        ("bnb", None): ("m/44h/60h/9172h/3604", 9999, "10"),
    }
    balances = {
        eth_address(abandon, path, index, legacy=purpose is None): int(balance)
        for (_, purpose), (path, index, balance) in paths.items()
    }
    fake = Ethereum(balances, chain_id=chain.chain_id)
    result = scan(abandon, None, node=node(fake), evm_chain=name)
    evm = result.evm
    assert evm is not None
    assert (evm.chain, evm.chain_id) == (name, chain.chain_id)
    read = [key for key in paths if key[0] in chain.coins]
    assert [(s.coin, s.purpose) for s in evm.searched] == read
    assert [
        (u.coin, u.purpose, u.path, [a.index for a in u.addresses], u.balance)
        for u in evm.used
    ] == [(*key, paths[key][0], [paths[key][1]], paths[key][2]) for key in read]
    own = ("ethereum-classic", "bnb")
    assert [(n.coin, n.reason) for n in result.not_checked if n.coin in own] == [
        (coin, OTHER_CHAIN[coin]) for coin in own if coin not in chain.coins
    ]


def test_the_stable_account_is_one_address_read_on_bnb_smart_chain(
    abandon: str,
) -> None:
    """Trust Wallet's m/44h/60h/9172h/3604/9999, and no other index below it.

    Derived here from the seed by BIP32 alone. Index 0 below the same
    key holds wei too, and is never asked: the account reads one address,
    beside the twenty of each other account read. Its tokens are read as
    an account's of a purpose are.
    """
    master = BIP32KeyData.from_seed(bip39.seed_from_mnemonic(ABANDON, ""))
    stable = address_from_pub_key(master.derive("m/44h/60h/9172h/3604/9999").sec)
    first = address_from_pub_key(master.derive("m/44h/60h/9172h/3604/0").sec)
    chain = EVM_CHAINS["bnb-smart-chain"]
    usdt = chain.tokens[0]
    fake = Ethereum(
        {stable: 11, first: 12},
        {stable: 1},
        chain_id=56,
        tokens={(usdt.contract, stable): 4},
    )
    evm = scan(abandon, None, node=node(fake), evm_chain="bnb-smart-chain").evm
    assert evm is not None
    (used,) = evm.used
    assert (used.coin, used.purpose, used.account, used.path, used.balance) == (
        "bnb",
        None,
        0,
        "m/44h/60h/9172h/3604",
        "11",
    )
    held = (EvmTokenBalance(usdt.contract, "USDT", 18, "4"),)
    assert used.addresses == (EvmAddress(9999, stable, "11", 1, 16, held),)
    assert used.tokens == held
    assert evm.searched[-1] == EvmSearched(0, "bnb", None, 1, cut_short=False)
    # two requests ahead, then per address its balance and nonce and one
    # per token: twenty per account of Ethereum's three, its two legacy
    # layouts and BNB's three, and the Stable Account's one address
    read = 20 * (3 + 2 + 3) + 1
    assert len(fake.asked) == 2 + (2 + len(chain.tokens)) * read
    assert fake.asked.count("eth_getBalance") == read


def test_ethereum_classic_accounts_need_a_node(abandon: str) -> None:
    """Without a node, both coins are listed with the same reason."""
    result = scan(abandon, Chain(), server="s:1", evm_chain="ethereum-classic")
    evm_coins = [n for n in result.not_checked if n.coin.startswith("ethereum")]
    assert evm_coins == [
        NotRead(0, "ethereum", NO_NODE),
        NotRead(0, "ethereum-classic", NO_NODE),
    ]


@pytest.mark.parametrize(
    "evm_chain, error, said",
    [
        ("ethereum-mainnet", SeedScanValueError, "invalid evm_chain: not one scan"),
        (1, SeedScanTypeError, "invalid evm_chain type: int"),
    ],
)
def test_a_chain_scan_does_not_read_is_refused(
    abandon: str, evm_chain: object, error: type[Exception], said: str
) -> None:
    """Before the node is asked, and without quoting the name.

    :param abandon: the bundle.
    :param evm_chain: the chain named.
    :param error: what is raised.
    :param said: what the refusal opens with.
    """
    fake = Ethereum()
    with pytest.raises(error) as caught:
        scan(abandon, None, node=node(fake), evm_chain=evm_chain)  # type: ignore[arg-type]
    assert str(caught.value).startswith(said)
    assert "ethereum-mainnet" not in str(caught.value)
    assert not fake.asked


#: Ethereum's USDT and DAI, as `seed_scan.evm.EVM_CHAINS` lists them.
USDT, DAI = EVM_CHAINS["ethereum"].tokens[0], EVM_CHAINS["ethereum"].tokens[2]


def test_an_address_holding_a_listed_token_alone_is_used(abandon: str) -> None:
    """No nonce, no ether: a token balance is use, and finds its account.

    Account 1's only use is two tokens at index 7, past unused indexes:
    it reads as used, so discovery reads three accounts past it, where
    it would stop at account 3 had account 1 read as unused.
    """
    first = eth_address(abandon, "m/44h/60h/0h", 0)
    late = eth_address(abandon, "m/44h/60h/1h", 7)
    fake = Ethereum(
        {first: 1},
        tokens={(DAI.contract, late): 5 * 10**18, (USDT.contract, late): 7},
    )
    evm = scan(abandon, None, node=node(fake), account_gap=3).evm
    assert evm is not None
    zeroth, one = evm.used
    assert zeroth.tokens == ()
    assert one.addresses == (
        EvmAddress(
            7,
            late,
            "0",
            0,
            16,
            (
                EvmTokenBalance(USDT.contract, "USDT", 6, "7"),
                EvmTokenBalance(DAI.contract, "DAI", 18, str(5 * 10**18)),
            ),
        ),
    )
    assert one.balance == "0"
    assert one.tokens == one.addresses[0].tokens
    legacy = EvmSearched(0, "ethereum", None, 2, cut_short=False)
    assert evm.searched == (EvmSearched(0, "ethereum", 44, 5, cut_short=False), legacy)
    assert evm.tokens == EVM_CHAINS["ethereum"].tokens
    evm = scan(abandon, None, node=node(Ethereum({first: 1})), account_gap=3).evm
    assert evm is not None
    assert evm.searched == (EvmSearched(0, "ethereum", 44, 4, cut_short=False), legacy)


def test_an_accounts_token_balances_are_summed(abandon: str) -> None:
    """Over its addresses, in the order the chain lists its tokens."""
    first = eth_address(abandon, "m/44h/60h/0h", 0)
    second = eth_address(abandon, "m/44h/60h/0h", 1)
    fake = Ethereum(
        tokens={
            (DAI.contract, first): 2,
            (USDT.contract, second): 3,
            (DAI.contract, second): 4,
        },
    )
    evm = scan(abandon, None, node=node(fake)).evm
    assert evm is not None
    (account,) = evm.used
    assert account.tokens == (
        EvmTokenBalance(USDT.contract, "USDT", 6, "3"),
        EvmTokenBalance(DAI.contract, "DAI", 18, "6"),
    )


def test_each_address_is_read_at_the_scans_block(abandon: str) -> None:
    """Its balance, nonce and tokens at the block asked before the first.

    The node's block would move on between addresses, as a chain's head
    does, were it asked again. The legacy layouts' first addresses are
    read last.
    """
    first = eth_address(abandon, "m/44h/60h/0h", 0)
    second = eth_address(abandon, "m/44h/60h/0h", 1)
    fake = Ethereum({first: 1, second: 2})
    fake.step = 1
    evm = scan(abandon, None, node=node(fake), gap_limit=1, account_gap=1).evm
    assert evm is not None
    assert evm.block == 16
    (account,) = evm.used
    assert [(a.index, a.block) for a in account.addresses] == [(0, 16), (1, 16)]
    per_address = 2 + len(EVM_CHAINS["ethereum"].tokens)
    assert fake.blocks == ["0x10"] * 6 * per_address
    assert fake.asked.count("eth_blockNumber") == 1


def lagging(fake: Ethereum, *, lacks: bool) -> Node:
    """Return a node behind which a backend one block behind `fake` answers.

    A load balancer's: the first ``eth_blockNumber`` is `fake`'s, and
    every later request goes to the backend behind it. That backend
    answers ``eth_blockNumber`` with the block below `fake`'s. Where it
    `lacks` `fake`'s block, it answers a state read at a block past its
    own with a JSON-RPC error; it answers every other request as `fake`
    does.

    :param fake: the backend ahead, whose block is not moved.
    :param lacks: whether the backend behind refuses a block past its own.
    :returns: the node.
    """
    first = True

    def transport(request: Request, timeout: float) -> tuple[int, bytes]:
        nonlocal first
        assert isinstance(request.data, bytes)
        asked = json.loads(request.data)
        method, params = asked["method"], asked["params"]
        behind = fake.block - 1
        if method == "eth_blockNumber" and first:
            first = False
            return fake(request, timeout)
        answer = None
        if method == "eth_blockNumber":
            answer = response(id=asked["id"], result=hex(behind))
        elif lacks and method != "eth_chainId" and quantity(params[-1]) > behind:
            error = {"code": -32000, "message": "no such block"}
            answer = response(id=asked["id"], result=..., error=error)
        if answer is None:
            return fake(request, timeout)
        fake.asked.append(method)
        return 200, json.dumps(answer).encode()

    return Node("https://node.example/rpc", transport=transport)


def test_a_backend_a_block_behind_leaves_each_address_at_the_scans_block(
    abandon: str,
) -> None:
    """Block 16 is asked once, and every address is read at it.

    The backend behind answers block 15 to a later ``eth_blockNumber``,
    which `loads` and `report` would refuse as an address read before the
    scan. The result reads back.
    """
    first = eth_address(abandon, "m/44h/60h/0h", 0)
    third = eth_address(abandon, "m/44h/60h/2h", 0)
    fake = Ethereum({first: 1, third: 2})
    lagged = lagging(fake, lacks=False)
    result = scan(abandon, None, node=lagged)
    text = scan_module.dumps(result)
    assert scan_module.dumps(scan_module.loads(text, abandon)) == text
    written = report(abandon, text)
    assert f" {first}: 1 wei, nonce 0, block 16\n" in written
    assert f" {third}: 2 wei, nonce 0, block 16\n" in written
    assert result.evm is not None
    assert result.evm.block == 16
    assert {a.block for u in result.evm.used for a in u.addresses} == {16}
    assert fake.asked.count("eth_blockNumber") == 1
    assert set(fake.blocks) == {"0x10"}
    assert lagged.block_number() == 15


def test_a_backend_that_lacks_the_scans_block_fails_the_scan(abandon: str) -> None:
    """Its error for the first read at block 16 ends the scan, unwritten."""
    fake = Ethereum()
    with pytest.raises(RpcError) as caught:
        scan(abandon, None, node=lagging(fake, lacks=True))
    assert caught.value.code == -32000
    assert fake.asked == ["eth_chainId", "eth_blockNumber", "eth_getBalance"]


def test_a_chain_with_no_token_asks_no_call(abandon: str) -> None:
    """Ethereum Classic's list is empty: balances and nonces alone."""
    fake = Ethereum(chain_id=61)
    evm = scan(abandon, None, node=node(fake), evm_chain="ethereum-classic").evm
    assert evm is not None
    assert evm.tokens == ()
    assert "eth_call" not in fake.asked


def test_a_token_answer_that_is_no_word_fails_the_scan(abandon: str) -> None:
    """Not counted: the node's failure ends the scan, as any other does."""
    fake = Ethereum()

    def transport(request: Request, timeout: float) -> tuple[int, bytes]:
        assert isinstance(request.data, bytes)
        asked = json.loads(request.data)
        if asked["method"] != "eth_call":
            return fake(request, timeout)
        return 200, json.dumps(response(id=asked["id"], result="0x07")).encode()

    with pytest.raises(FetchError, match="eth_call answered no 32-byte word$"):
        scan(abandon, None, node=Node("https://node.example", transport=transport))
