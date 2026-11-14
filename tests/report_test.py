# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `seed_scan.report`, on bundles and results of the suite.

The bundles are `identify`'s, on the vectors `tests/identify_test.py`
names, and the scan and forks results `scan`'s and `forks`'s, over the
chain `tests/scan_test.py` keeps in memory.
"""

from __future__ import annotations

import json
import re
from hashlib import sha256

import pytest
from bip32_descriptors.bip32 import BIP32KeyData
from bip39_slip39 import bip39
from btclib_wallet.descriptors import add_checksum, parse, strip_checksum
from btclib_wallet.fetch.history import HistoryTx
from coin_addresses.evm import address_from_pub_key

from seed_scan import forks as forks_module
from seed_scan import report as report_module
from seed_scan import scan as scan_module
from seed_scan.bundle import dumps, loads
from seed_scan.exceptions import SeedScanTypeError, SeedScanValueError
from seed_scan.identify import identify
from seed_scan.report import (
    NO_CASHTOKENS,
    NO_SCAN,
    NO_TOKENS,
    NOT_IN_FORKS,
    NOT_IN_SCAN,
    VERSION,
    report,
)
from seed_scan.scan import NO_NODE, NO_SERVER, NOT_READ

from .evm_test import Ethereum
from .forks_test import NO_WITNESS, OWN, SHARED, p2pkh
from .identify_test import ABANDON, BIP84_CHANGE, OLD, SEGWIT, STANDARD, no_share
from .no_secret_test import Secrets, assert_text_secret_free
from .scan_test import BLOCK, ELSEWHERE, Chain, eth_address, node, pay, script

#: A bundle whose search does not find the address: one index past it.
MISSED = dumps(
    identify(
        ABANDON,
        [""],
        no_share,
        accounts=1,
        address="bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
        indexes=1,
    )
)


def digest(text: str) -> str:
    """Return the SHA-256 of a text, as the report spells it.

    :param text: the text.
    :returns: its hex digest.
    """
    return sha256(text.encode("utf-8")).hexdigest()


@pytest.fixture(scope="module")
def abandon() -> str:
    """Return the bundle of BIP84's mnemonic, five accounts of each purpose.

    The address searched is BIP84's first change address.

    :returns: its text.
    """
    return dumps(identify(ABANDON, [""], no_share, accounts=5, address=BIP84_CHANGE))


@pytest.fixture(scope="module")
def result(abandon: str) -> str:
    """Return the scan result of a payment to BIP84's account 0, then a spend.

    :param abandon: the bundle.
    :returns: its text.
    """
    receive = script(abandon, "m/84h/0h/0h", 0, 3)
    change = script(abandon, "m/84h/0h/0h", 1, 0)
    paid = pay(1, (receive, 10_000))
    spent = pay(2, (change, 4_000), (ELSEWHERE, 5_000), spends=paid)
    incoming = pay(3, (receive, 2_000))
    chain = Chain(
        HistoryTx(paid, BLOCK), HistoryTx(spent, BLOCK), HistoryTx(incoming, None)
    )
    return scan_module.dumps(scan_module.scan(abandon, chain, server="node.local:1"))


@pytest.fixture(scope="module")
def evm_result(abandon: str) -> str:
    """Return the result of a node alone: ether at one address, a nonce at one.

    :param abandon: the bundle.
    :returns: its text.
    """
    first = eth_address(abandon, "m/44h/60h/0h", 0)
    sixth = eth_address(abandon, "m/44h/60h/0h", 5)
    fake = Ethereum({first: 10**18}, {sixth: 4})
    return scan_module.dumps(scan_module.scan(abandon, None, node=node(fake)))


def forked_of(text: str, *entries: HistoryTx, chain: str = "bitcoin-cash") -> str:
    """Return the forks result of a bundle on a chain.

    :param text: the bundle.
    :param entries: the chain's transactions and their blocks.
    :param chain: the chain read.
    :returns: the result's text.
    """
    result = forks_module.forks(text, Chain(*entries), chain=chain, server="h:1")
    return forks_module.dumps(result)


@pytest.fixture(scope="module")
def forked(abandon: str) -> str:
    """Return the forks result of coins held at the fork, and received since.

    Bitcoin's account 0 of purpose 44 held 10000 sat at the fork, and
    spent 6000 since; the chain's own account 0 received 7000 sat since,
    on its change branch, and 5 sat in the mempool.

    :param abandon: the bundle.
    :returns: its text.
    """
    bitcoin = p2pkh("m/44h/0h/0h/0/0")
    own = p2pkh("m/44h/145h/0h/1/2")
    held = pay(1, (bitcoin, 10_000))
    spent = pay(2, (bitcoin, 4_000), (ELSEWHERE, 5_000), spends=held)
    return forked_of(
        abandon,
        HistoryTx(held, SHARED),
        HistoryTx(spent, OWN),
        HistoryTx(pay(3, (own, 7_000)), OWN),
        HistoryTx(pay(4, (own, 5)), None),
    )


def test_the_report_of_a_scanned_bundle(abandon: str, result: str) -> None:
    """Each line, from the digests to the total, for one used account."""
    receive = script(abandon, "m/84h/0h/0h", 0, 3).address
    other = (
        f"  {coin}, purpose {purpose}: not checked: {NOT_READ}"
        for coin, purpose in [
            ("bitcoin-cash", 44),
            ("bitcoin-sv", 44),
            ("litecoin", 44),
            ("litecoin", 49),
            ("litecoin", 84),
            ("dogecoin", 44),
        ]
    )
    lines = [
        f"seed-scan report {VERSION}",
        f"bundle: sha256 {digest(abandon)}",
        f"scan: sha256 {digest(result)}",
        "server: node.local:1",
        "node: none",
        "bounds: account gap 3, gap limit 20",
        "forks: none",
        "claims: bip39",
        (
            f"address search: {BIP84_CHANGE}, 800 positions, accounts 0 to 4,"
            " indexes 0 to 19"
        ),
        "found: reading 0, m/84h/0h/0h/1/0",
        "reading 0: bip39, languages en, passphrase 0, master fingerprint 73c5da0a",
        "  bitcoin, purpose 44: accounts 0 to 2 read, 0 used",
        "  bitcoin, purpose 49: accounts 0 to 2 read, 0 used",
        "  bitcoin, purpose 84: accounts 0 to 3 read, 1 used",
        (
            "    account 0, m/84h/0h/0h: 4000 sat confirmed, 2000 sat unconfirmed,"
            " 3 transactions, read up to height 2"
        ),
        (
            f"      receive m/84h/0h/0h/0/3 {receive}: 0 sat confirmed,"
            " 2000 sat unconfirmed"
        ),
        (
            f"      change m/84h/0h/0h/1/0 {BIP84_CHANGE}: 4000 sat confirmed,"
            " 0 sat unconfirmed"
        ),
        "  bitcoin, purpose 86: accounts 0 to 2 read, 0 used",
        f"  ethereum, purpose 44: not checked: {NO_NODE}",
        *other,
        (
            "total: bitcoin, 4000 sat confirmed, 2000 sat unconfirmed,"
            " 1 used accounts, each account key once"
        ),
    ]
    text = "".join(f"{line}\n" for line in lines)
    assert report(abandon, result) == f"{text}digest: sha256 {digest(text)}\n"


def test_the_report_of_a_forks_result(abandon: str, forked: str) -> None:
    """Its digest and what it asked, its accounts by reading, its total."""
    lines = report(abandon, None, [forked]).splitlines()
    assert lines[2:9] == [
        "scan: none",
        f"forks: sha256 {digest(forked)}",
        "chain: Bitcoin Cash, forked from Bitcoin at height 478559",
        "server: h:1",
        "bounds: account gap 3, gap limit 20",
        f"cashtokens: not checked: {NO_CASHTOKENS}",
        "claims: bip39",
    ]
    bitcoin = script(abandon, "m/44h/0h/0h", 0, 0).address
    own = p2pkh("m/44h/145h/0h/1/2").address
    opening = next(n for n, line in enumerate(lines) if "on Bitcoin Cash" in line)
    assert lines[opening:-1] == [
        "  bitcoin, purpose 44, on Bitcoin Cash: accounts 0 to 3 read, 1 used",
        (
            "    account 0, m/44h/0h/0h: 4000 sat confirmed, 0 sat unconfirmed,"
            " 10000 sat at the fork, 2 transactions, read up to height 2"
        ),
        (
            f"      receive m/44h/0h/0h/0/0 {bitcoin}: 4000 sat confirmed,"
            " 0 sat unconfirmed"
        ),
        *(
            f"  bitcoin, purpose {purpose}, on Bitcoin Cash: not checked: {NO_WITNESS}"
            for purpose in (49, 84, 86)
        ),
        "  bitcoin-cash, purpose 44, on Bitcoin Cash: accounts 0 to 3 read, 1 used",
        (
            "    account 0, m/44h/145h/0h: 7000 sat confirmed, 5 sat unconfirmed,"
            " 0 sat at the fork, 2 transactions, read up to height 2"
        ),
        (
            f"      change m/44h/145h/0h/1/2 {own}: 7000 sat confirmed,"
            " 5 sat unconfirmed"
        ),
        "  bitcoin-sv, purpose 44, on Bitcoin Cash: accounts 0 to 2 read, 0 used",
        (
            "total: bitcoin-cash, 11000 sat confirmed, 5 sat unconfirmed,"
            " 10000 sat at the fork, 2 used accounts, each account key once"
        ),
    ]


def test_a_forks_result_follows_the_scan_s_lines(
    abandon: str, result: str, forked: str
) -> None:
    """Its block after scan's, its accounts after scan's, its total last."""
    lines = report(abandon, result, [forked]).splitlines()
    assert lines[5:7] == [
        "bounds: account gap 3, gap limit 20",
        f"forks: sha256 {digest(forked)}",
    ]
    last = lines.index(f"  dogecoin, purpose 44: not checked: {NOT_READ}")
    assert lines[last + 1].startswith("  bitcoin, purpose 44, on Bitcoin Cash: ")
    assert lines[-3].startswith("total: bitcoin, ")
    assert lines[-2].startswith("total: bitcoin-cash, ")


@pytest.mark.parametrize("forks", [None, {}, "text", 1.5])
def test_forks_other_than_a_list_or_a_tuple_is_refused(
    abandon: str, forks: object
) -> None:
    """A dictionary, a lone text, None: a type error before any text is read."""
    with pytest.raises(SeedScanTypeError, match="^invalid forks type: "):
        report(abandon, None, forks)  # type: ignore[arg-type]


def test_two_forks_results_of_one_chain_are_refused(abandon: str, forked: str) -> None:
    """One per chain: a second would list each account twice."""
    with pytest.raises(SeedScanValueError, match="^forks results: two of one chain$"):
        report(abandon, None, [forked, forked])


def test_a_forks_result_of_another_bundle_is_refused(forked: str) -> None:
    """Read by `seed_scan.forks.loads`, against the bundle given."""
    other = dumps(identify(SEGWIT, [""], no_share, accounts=1))
    with pytest.raises(SeedScanValueError, match="^forks result: made from another"):
        report(other, None, [forked])


def test_what_the_forks_result_leaves_out_is_not_checked(
    abandon: str, forked: str
) -> None:
    """A purpose it did not search, and one it does not list as not checked."""
    document = json.loads(forked)
    document["searched"] = [s for s in document["searched"] if s["coin"] == "bitcoin"]
    document["used"] = [u for u in document["used"] if u["coin"] == "bitcoin"]
    document["not_checked"] = [n for n in document["not_checked"] if n["purpose"] != 86]
    text = report(abandon, None, [json.dumps(document)])
    assert (
        f"  bitcoin-cash, purpose 44, on Bitcoin Cash: not checked: {NOT_IN_FORKS}\n"
    ) in text
    assert (
        f"  bitcoin, purpose 86, on Bitcoin Cash: not checked: {NOT_IN_FORKS}\n"
    ) in text
    assert "\ntotal: bitcoin-cash, 4000 sat confirmed, 0 sat unconfirmed," in text


def test_a_forks_purpose_cut_short_names_the_rerun() -> None:
    """One account in the bundle, used on the chain: forks is to run again."""
    text = dumps(identify(ABANDON, [""], no_share, accounts=1))
    forked = forked_of(text, HistoryTx(pay(1, (p2pkh("m/44h/145h/0h/0/0"), 5)), OWN))
    assert (
        "  bitcoin-cash, purpose 44, on Bitcoin Cash: accounts 0 to 0 read, 1 used,"
        " cut short: run identify with --accounts above 1, then forks\n"
    ) in report(text, None, [forked])


def test_a_bitcoin_sv_result_lists_bitcoin_cash_s_accounts(abandon: str) -> None:
    """Each coin forks reads is listed on the result's chain, and totalled.

    7000 sat paid since the fork at Bitcoin Cash's coin type, read on
    Bitcoin SV. The CashTokens line is a Bitcoin Cash result's alone.
    """
    own = p2pkh("m/44h/145h/0h/0/0")
    forked = forked_of(
        abandon, HistoryTx(pay(1, (own, 7_000)), OWN), chain="bitcoin-sv"
    )
    lines = report(abandon, None, [forked]).splitlines()
    assert lines[3:8] == [
        f"forks: sha256 {digest(forked)}",
        "chain: Bitcoin SV, forked from Bitcoin at height 478559",
        "server: h:1",
        "bounds: account gap 3, gap limit 20",
        "claims: bip39",
    ]
    read = "  bitcoin-cash, purpose 44, on Bitcoin SV: accounts 0 to 3 read, 1 used"
    opening = lines.index(read)
    assert lines[opening:] == [
        read,
        (
            "    account 0, m/44h/145h/0h: 7000 sat confirmed, 0 sat unconfirmed,"
            " 0 sat at the fork, 1 transactions, read up to height 2"
        ),
        (
            f"      receive m/44h/145h/0h/0/0 {own.address}: 7000 sat confirmed,"
            " 0 sat unconfirmed"
        ),
        "  bitcoin-sv, purpose 44, on Bitcoin SV: accounts 0 to 2 read, 0 used",
        (
            "total: bitcoin-sv, 7000 sat confirmed, 0 sat unconfirmed, 0 sat at"
            " the fork, 1 used accounts, each account key once"
        ),
        lines[-1],
    ]


def test_no_total_adds_two_chains(abandon: str, result: str, forked: str) -> None:
    """Bitcoin's, Bitcoin Cash's and Bitcoin SV's amounts each in its own total.

    The same accounts are read on each chain, and each chain's satoshis
    are its own coin.
    """
    bitcoin = p2pkh("m/44h/0h/0h/0/0")
    sv = forked_of(
        abandon,
        HistoryTx(pay(1, (bitcoin, 300)), SHARED),
        HistoryTx(pay(2, (p2pkh("m/44h/236h/0h/0/0"), 20)), OWN),
        chain="bitcoin-sv",
    )
    lines = report(abandon, result, [forked, sv]).splitlines()
    assert lines[-4:-1] == [
        (
            "total: bitcoin, 4000 sat confirmed, 2000 sat unconfirmed,"
            " 1 used accounts, each account key once"
        ),
        (
            "total: bitcoin-cash, 11000 sat confirmed, 5 sat unconfirmed,"
            " 10000 sat at the fork, 2 used accounts, each account key once"
        ),
        (
            "total: bitcoin-sv, 320 sat confirmed, 0 sat unconfirmed,"
            " 300 sat at the fork, 2 used accounts, each account key once"
        ),
    ]


def shared(text: str, path: str, other: str, *, descriptors: bool) -> str:
    """Return a bundle whose account at `other` holds the key at `path`.

    :param text: the bundle's text.
    :param path: the account whose key is shared.
    :param other: the account given that key.
    :param descriptors: whether `other` takes the descriptors too, with
        its own path as their key origin.
    :returns: the edited bundle's text.
    """
    document = json.loads(text)
    accounts = {a["path"]: a for a in document["readings"][0]["accounts"]}
    accounts[other]["xpub"] = accounts[path]["xpub"]
    if descriptors:
        origin = f"{path[1:]}]", f"{other[1:]}]"
        accounts[other]["descriptors"] = [
            add_checksum(strip_checksum(d).replace(*origin))
            for d in accounts[path]["descriptors"]
        ]
    edited = json.dumps(document)
    loads(edited)
    return edited


def test_a_forks_total_counts_an_output_once_across_coins() -> None:
    """A Bitcoin and a Bitcoin Cash account of one key: one payment, once."""
    one = dumps(identify(ABANDON, [""], no_share, accounts=1))
    text = shared(one, "m/44h/0h/0h", "m/44h/145h/0h", descriptors=False)
    paid = HistoryTx(pay(1, (p2pkh("m/44h/0h/0h/0/0"), 123)), SHARED)
    lines = report(text, None, [forked_of(text, paid)]).splitlines()
    assert len([line for line in lines if line.startswith("    account 0, ")]) == 2
    assert lines[-2] == (
        "total: bitcoin-cash, 123 sat confirmed, 0 sat unconfirmed, 123 sat at"
        " the fork, 1 used accounts, each account key once"
    )


def test_a_scan_total_counts_an_output_once_whatever_the_origin() -> None:
    """Two accounts of one key and script type, their origins apart: once.

    Each lists the payment; the total counts it once.
    """
    two = dumps(identify(ABANDON, [""], no_share, accounts=2))
    text = shared(two, "m/44h/0h/0h", "m/44h/0h/1h", descriptors=True)
    chain = Chain(HistoryTx(pay(1, (p2pkh("m/44h/0h/0h/0/0"), 123)), BLOCK))
    result = scan_module.dumps(scan_module.scan(text, chain, server="s:1"))
    lines = report(text, result).splitlines()
    assert len([line for line in lines if line.startswith("    account ")]) == 2
    assert lines[-2] == (
        "total: bitcoin, 123 sat confirmed, 0 sat unconfirmed, 1 used accounts,"
        " each account key once"
    )


def test_a_forks_total_counts_a_key_once() -> None:
    """A passphrase typed twice: its accounts listed twice, its funds once."""
    text = dumps(identify(ABANDON, ["", "x", "x"], no_share, accounts=1))
    (own,) = [a for a in loads(text).readings[1].accounts if a.path == "m/44h/145h/0h"]
    receive = parse(f"pkh({own.xpub}/0/*)").script_pub_keys(0)[0]
    forked = forked_of(text, HistoryTx(pay(1, (receive, 9)), SHARED))
    lines = report(text, None, [forked]).splitlines()
    used = [line for line in lines if line.startswith("    account 0, m/44h/145h")]
    assert len(used) == 2
    assert lines[-2] == (
        "total: bitcoin-cash, 9 sat confirmed, 0 sat unconfirmed, 9 sat at the"
        " fork, 1 used accounts, each account key once"
    )


def test_the_report_of_an_ethereum_scan(abandon: str, evm_result: str) -> None:
    """The node, the tokens not asked, each used address, the total."""
    first = eth_address(abandon, "m/44h/60h/0h", 0)
    sixth = eth_address(abandon, "m/44h/60h/0h", 5)
    lines = report(abandon, evm_result).splitlines()
    assert lines[3:7] == [
        "server: none",
        (
            "node: https://node.example, chain id 1, latest block 16 before"
            " the first address was read"
        ),
        f"ethereum tokens: not checked: {NO_TOKENS}",
        "bounds: account gap 3, gap limit 20",
    ]
    (opening,) = [n for n, line in enumerate(lines) if line.startswith("reading")]
    assert lines[opening + 1 : opening + 10] == [
        *(
            f"  bitcoin, purpose {purpose}: not checked: {NO_SERVER}"
            for purpose in (44, 49, 84, 86)
        ),
        "  ethereum, purpose 44: accounts 0 to 3 read, 1 used",
        f"    account 0, m/44h/60h/0h: {10**18} wei at latest",
        f"      receive m/44h/60h/0h/0/0 {first}: {10**18} wei, nonce 0",
        f"      receive m/44h/60h/0h/0/5 {sixth}: 0 wei, nonce 4",
        f"  bitcoin-cash, purpose 44: not checked: {NOT_READ}",
    ]
    assert lines[-2] == (
        f"total: ethereum, {10**18} wei, 1 used accounts, each account key once"
    )
    assert not [line for line in lines if line.startswith("total: bitcoin")]


def test_a_report_of_both_coins_totals_each(abandon: str) -> None:
    """A server and a node: a total per coin, and no coin left for either."""
    chain = Chain(HistoryTx(pay(1, (script(abandon, "m/49h/0h/0h", 0, 0), 5)), BLOCK))
    fake = Ethereum({eth_address(abandon, "m/44h/60h/0h", 0): 3})
    text = report(
        abandon,
        scan_module.dumps(
            scan_module.scan(abandon, chain, server="s:1", node=node(fake))
        ),
    )
    assert (
        "\ntotal: bitcoin, 5 sat confirmed, 0 sat unconfirmed, 1 used accounts,"
        " each account key once\n"
    ) in text
    assert (
        "\ntotal: ethereum, 3 wei, 1 used accounts, each account key once\ndigest: "
    ) in text
    assert NO_SERVER not in text
    assert NO_NODE not in text


def test_a_passphrase_typed_twice_is_counted_once() -> None:
    """Its two readings hold the same keys: both listed, the funds once."""
    text = dumps(identify(ABANDON, ["", "x", "x"], no_share, accounts=1))
    readings = loads(text).readings
    assert readings[1].accounts == readings[2].accounts
    (bitcoin,) = [a for a in readings[1].accounts if a.path == "m/84h/0h/0h"]
    receive = parse(bitcoin.descriptors[0]).script_pub_keys(0)[0]
    (ethereum,) = [a for a in readings[1].accounts if a.path == "m/44h/60h/0h"]
    key = BIP32KeyData.b58decode(ethereum.xpub).derive("m/0/0")
    chain = Chain(HistoryTx(pay(1, (receive, 9)), BLOCK))
    fake = Ethereum({address_from_pub_key(key.sec): 5})
    lines = report(
        text,
        scan_module.dumps(scan_module.scan(text, chain, server="s:1", node=node(fake))),
    ).splitlines()
    used = [line for line in lines if line.startswith("    account 0, ")]
    assert len(used) == 4
    assert lines[-3:-1] == [
        (
            "total: bitcoin, 9 sat confirmed, 0 sat unconfirmed, 1 used accounts,"
            " each account key once"
        ),
        "total: ethereum, 5 wei, 1 used accounts, each account key once",
    ]


def test_without_a_scan_result_nothing_is_checked(abandon: str) -> None:
    """Every coin and purpose is not checked, and no total is written."""
    lines = report(abandon).splitlines()
    assert lines[2] == "scan: none"
    groups = [line for line in lines if line.startswith("  ")]
    assert len(groups) == len(
        {(a.coin, a.purpose) for a in loads(abandon).readings[0].accounts}
    )
    assert all(line.endswith(f": not checked: {NO_SCAN}") for line in groups)
    assert not [line for line in lines if line.startswith(("server", "node", "total"))]


def test_what_the_scan_result_leaves_out_is_not_checked(
    abandon: str, result: str
) -> None:
    """A purpose it did not search and a coin it does not list."""
    document = json.loads(result)
    document["searched"] = [s for s in document["searched"] if s["purpose"] != 44]
    document["not_checked"] = [
        n for n in document["not_checked"] if n["coin"] != "dogecoin"
    ]
    text = report(abandon, json.dumps(document))
    assert f"  bitcoin, purpose 44: not checked: {NOT_IN_SCAN}\n" in text
    assert f"  dogecoin, purpose 44: not checked: {NOT_IN_SCAN}\n" in text
    assert "  bitcoin, purpose 49: accounts 0 to 2 read, 0 used\n" in text


def test_a_purpose_cut_short_names_the_rerun() -> None:
    """One account in the bundle, used: identify is to write more."""
    text = dumps(identify(ABANDON, [""], no_share, accounts=1))
    chain = Chain(HistoryTx(pay(1, (script(text, "m/86h/0h/0h", 0, 0), 5)), BLOCK))
    result = scan_module.dumps(scan_module.scan(text, chain, server="s:1"))
    assert (
        "  bitcoin, purpose 86: accounts 0 to 0 read, 1 used, cut short:"
        " run identify with --accounts above 1, then scan\n"
    ) in report(text, result)


def test_an_electrum_reading_has_its_account() -> None:
    """An Electrum reading names no languages and no purpose."""
    text = dumps(identify(SEGWIT, [""], no_share, accounts=1))
    result = scan_module.dumps(scan_module.scan(text, Chain(), server="s:1"))
    lines = report(text, result).splitlines()
    (opening,) = [n for n, line in enumerate(lines) if line.startswith("reading")]
    assert lines[opening].startswith("reading 0: electrum_segwit, passphrase 0,")
    assert lines[opening + 1] == (
        "  bitcoin, Electrum account: accounts 0 to 0 read, 0 used"
    )


def test_what_identify_did_not_derive_or_search_is_said() -> None:
    """A scheme not derived, a search not run, and one that found nothing."""
    old = report(dumps(identify(OLD, [""], no_share, address="not an address")))
    assert "\nnot derived: electrum_old: pre-2.0 Electrum seed:" in old
    assert "\naddress search: not run: not a Bitcoin address:" in old
    assert "\nclaims: electrum_old\n" in old
    nothing = report(dumps(identify("qzx qzx", [""], no_share)))
    assert "\nclaims: none\naddress search: none\ndigest: " in nothing
    assert "\nfound: none\n" in report(MISSED)


def test_the_digest_is_of_every_line_above_it(abandon: str, result: str) -> None:
    """Dropping the last line, as ``sed '$d'`` does, gives the text hashed."""
    text = report(abandon, result)
    body, last = text[:-1].rsplit("\n", 1)
    assert last == f"digest: sha256 {digest(body + chr(10))}"


#: The fragments of the module docstring that are no line of a report.
NOT_LINES = ("<...>", "...", "sed '$d' report.txt | shasum -a 256")


def test_every_documented_line_is_one_a_report_writes(
    abandon: str, result: str, evm_result: str, forked: str
) -> None:
    """Each literal of the layout matches a line of the reports above.

    ``<...>`` and ``...`` in a literal stand for any value.
    """
    doc = report_module.__doc__
    assert doc is not None
    literals = [
        " ".join(text.split()) for text in re.findall(r"``(.+?)``", doc, re.DOTALL)
    ]
    one = dumps(identify(ABANDON, [""], no_share, accounts=1))
    chain = Chain(HistoryTx(pay(1, (script(one, "m/86h/0h/0h", 0, 0), 5)), BLOCK))
    own = HistoryTx(pay(1, (p2pkh("m/44h/145h/0h/0/0"), 5)), OWN)
    standard = dumps(identify(STANDARD, [""], no_share, accounts=1))
    reports = "".join(
        [
            report(abandon, result, [forked]),
            report(one, None, [forked_of(one, own)]),
            report(standard, None, [forked_of(standard)]),
            report(abandon, result),
            report(abandon, evm_result),
            report(abandon),
            report(one, scan_module.dumps(scan_module.scan(one, chain, server="s:1"))),
            report(dumps(identify(SEGWIT, [""], no_share, accounts=1))),
            report(dumps(identify(OLD, [""], no_share, address="not an address"))),
            report(dumps(identify("qzx qzx", [""], no_share))),
            report(MISSED),
        ]
    )
    unmatched = [
        literal
        for literal in literals
        if literal not in NOT_LINES
        and not re.search(
            ".+?".join(
                re.escape(part) for part in re.split(r"<[^>]+>|\.\.\.", literal)
            ),
            reports,
        )
    ]
    assert len(literals) > len(NOT_LINES)
    assert not unmatched


def test_nothing_report_writes_holds_a_secret(
    abandon: str, result: str, evm_result: str, forked: str
) -> None:
    """No piece of the mnemonic's secrets is in the reports."""
    text = report(abandon, result, [forked]) + report(abandon, evm_result)
    secrets = Secrets()
    secrets.sentence(ABANDON)
    paths = sorted({a.path for r in loads(abandon).readings for a in r.accounts})
    secrets.seed(bip39.seed_from_mnemonic(ABANDON, ""), paths)
    assert_text_secret_free(text, secrets.every())


def test_a_result_that_is_no_text_is_refused(abandon: str) -> None:
    """Its type is named, as `seed_scan.scan.loads` names it."""
    with pytest.raises(SeedScanTypeError, match="scan result: text of type bytes"):
        report(abandon, b"{}")  # type: ignore[arg-type]
