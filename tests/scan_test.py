# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `seed_scan.scan`, over a chain kept in memory.

The bundles are `identify`'s, on the vectors `tests/identify_test.py`
names, and the addresses the scan reports are checked against the ones
BIP84 and BIP86 publish for them.
"""

from __future__ import annotations

import json
from hashlib import sha256
from typing import TYPE_CHECKING

import pytest
from bip32_descriptors.bip32 import BIP32KeyData, xpub_from_xprv
from bip39_slip39 import bip39
from btclib.script import ScriptPubKey
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from btclib_wallet.bip44 import discover_account
from btclib_wallet.descriptors import add_checksum, parse
from btclib_wallet.fetch.history import (
    BlockRef,
    HistoryTx,
    ScriptHistory,
    history_scripts,
)

from seed_scan import scan as scan_module
from seed_scan.bundle import dumps, loads
from seed_scan.exceptions import SeedScanTypeError, SeedScanValueError
from seed_scan.identify import identify
from seed_scan.scan import FORMAT, VERSION, Address, NotRead, Searched, Tip, scan

from .identify_test import (
    ABANDON,
    BIP84_CHANGE,
    BIP86_RECEIVE,
    SEGWIT,
    SEGWIT_CHANGE,
    no_share,
)
from .no_secret_test import Secrets, assert_text_secret_free

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Sequence

    from btclib.alias import Octets
    from btclib_wallet.bip44 import AccountUse
    from btclib_wallet.descriptors import Descriptor
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
        Address(0, 3, receive.address),
        Address(1, 0, BIP84_CHANGE),
    )
    assert [t.height for t in used.transactions] == [1, 1, None, None]
    assert used.transactions[0].tx_id == paid.id.hex()
    assert (used.confirmed, used.unconfirmed) == (4_000, 2_000 - 4_000)
    assert used.tip == Tip(2, TIP.block_id.hex())
    assert Searched(0, 84, 4, cut_short=False) in result.searched
    assert Searched(0, 44, 3, cut_short=False) in result.searched


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
        descriptors: Sequence[Descriptor], reader: HistoryReader, *, gap_limit: int
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
        descriptors: Sequence[Descriptor], reader: HistoryReader, *, gap_limit: int
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
    assert (used.purpose, used.addresses) == (None, (Address(1, 0, SEGWIT_CHANGE),))


def test_the_other_coins_are_not_checked(abandon: str) -> None:
    """Each coin but Bitcoin is listed once per reading, with the reason."""
    result = scan(abandon, Chain(), server="s:1")
    reason = "scan reads Bitcoin alone in this version"
    assert result.not_checked == tuple(
        NotRead(0, coin, reason)
        for coin in ("ethereum", "bitcoin-cash", "litecoin", "dogecoin")
    )


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
    assert_text_secret_free(text, secrets.every())


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
