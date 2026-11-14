# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `seed_scan.report`, on bundles and scan results of the suite.

The bundles are `identify`'s, on the vectors `tests/identify_test.py`
names, and the scan results `scan`'s, over the chain `tests/scan_test.py`
keeps in memory.
"""

from __future__ import annotations

import json
import re
from hashlib import sha256

import pytest
from bip32_descriptors.bip32 import BIP32KeyData
from bip39_slip39 import bip39
from btclib_wallet.descriptors import parse
from btclib_wallet.fetch.history import HistoryTx
from coin_addresses.evm import address_from_pub_key

from seed_scan import report as report_module
from seed_scan import scan as scan_module
from seed_scan.bundle import dumps, loads
from seed_scan.exceptions import SeedScanTypeError
from seed_scan.identify import identify
from seed_scan.report import NO_SCAN, NO_TOKENS, NOT_IN_SCAN, VERSION, report
from seed_scan.scan import NO_NODE, NO_SERVER, NOT_READ

from .evm_test import Ethereum
from .identify_test import ABANDON, BIP84_CHANGE, OLD, SEGWIT, no_share
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


def test_the_report_of_a_scanned_bundle(abandon: str, result: str) -> None:
    """Each line, from the digests to the total, for one used account."""
    receive = script(abandon, "m/84h/0h/0h", 0, 3).address
    other = (
        f"  {coin}, purpose {purpose}: not checked: {NOT_READ}"
        for coin, purpose in [
            ("bitcoin-cash", 44),
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
    abandon: str, result: str, evm_result: str
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
    reports = "".join(
        [
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
    abandon: str, result: str, evm_result: str
) -> None:
    """No piece of the mnemonic's secrets is in the reports."""
    text = report(abandon, result) + report(abandon, evm_result)
    secrets = Secrets()
    secrets.sentence(ABANDON)
    paths = sorted({a.path for r in loads(abandon).readings for a in r.accounts})
    secrets.seed(bip39.seed_from_mnemonic(ABANDON, ""), paths)
    assert_text_secret_free(text, secrets.every())


def test_a_result_that_is_no_text_is_refused(abandon: str) -> None:
    """Its type is named, as `seed_scan.scan.loads` names it."""
    with pytest.raises(SeedScanTypeError, match="scan result: text of type bytes"):
        report(abandon, b"{}")  # type: ignore[arg-type]
