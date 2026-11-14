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
from btclib_wallet.descriptors import add_checksum, parse
from btclib_wallet.fetch.history import HistoryTx
from coin_addresses.evm import address_from_pub_key

from seed_scan import cli
from seed_scan import report as report_module
from seed_scan import scan as scan_module
from seed_scan.bundle import dumps, loads
from seed_scan.exceptions import SeedScanTypeError
from seed_scan.identify import identify
from seed_scan.report import NO_SCAN, NO_TOKENS, NOT_IN_SCAN, VERSION, report
from seed_scan.scan import NO_NODE, NO_SERVER, NOT_READ, OTHER_CHAIN

from .evm_test import Ethereum
from .identify_test import (
    ABANDON,
    BIP84_CHANGE,
    OLD,
    SEGWIT,
    SHARES,
    Prompt,
    no_share,
)
from .no_secret_test import Secrets, assert_lines_secret_free, unshaped
from .scan_test import (
    BLOCK,
    ELSEWHERE,
    Chain,
    edited,
    eth_address,
    node,
    pay,
    script,
)

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

    The first legacy layout's third address, below account 0's key, holds
    wei too, and so does the second address of MyEtherWallet's, below
    m/44h/60h.

    :param abandon: the bundle.
    :returns: its text.
    """
    first = eth_address(abandon, "m/44h/60h/0h", 0)
    sixth = eth_address(abandon, "m/44h/60h/0h", 5)
    legacy = eth_address(abandon, "m/44h/60h/0h", 2, legacy=True)
    mew = eth_address(abandon, "m/44h/60h", 1, legacy=True)
    fake = Ethereum({first: 10**18, legacy: 3, mew: 5}, {sixth: 4})
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
        f"  ethereum, legacy account: not checked: {NO_NODE}",
        f"  ethereum-classic, purpose 44: not checked: {NO_NODE}",
        f"  ethereum-classic, legacy account: not checked: {NO_NODE}",
        f"  bnb, purpose 44: not checked: {NO_NODE}",
        f"  bnb, legacy account: not checked: {NO_NODE}",
        *other,
        (
            "total: bitcoin, 4000 sat confirmed, 2000 sat unconfirmed,"
            " 1 used accounts, each account key once"
        ),
    ]
    text = "".join(f"{line}\n" for line in lines)
    assert report(abandon, result) == f"{text}digest: sha256 {digest(text)}\n"


def test_the_report_of_an_ethereum_scan(abandon: str, evm_result: str) -> None:
    """The node, the tokens not asked, each used address, the total.

    The first legacy account shares account 0's key, and not its
    addresses: the total counts both, and the second legacy account.
    """
    first = eth_address(abandon, "m/44h/60h/0h", 0)
    sixth = eth_address(abandon, "m/44h/60h/0h", 5)
    legacy = eth_address(abandon, "m/44h/60h/0h", 2, legacy=True)
    mew = eth_address(abandon, "m/44h/60h", 1, legacy=True)
    lines = report(abandon, evm_result).splitlines()
    assert lines[3:7] == [
        "server: none",
        (
            "node: https://node.example, Ethereum, chain id 1, latest block 16"
            " before the first address was read"
        ),
        f"Ethereum tokens: not checked: {NO_TOKENS}",
        "bounds: account gap 3, gap limit 20",
    ]
    (opening,) = [n for n, line in enumerate(lines) if line.startswith("reading")]
    classic = OTHER_CHAIN["ethereum-classic"]
    assert lines[opening + 1 : opening + 19] == [
        *(
            f"  bitcoin, purpose {purpose}: not checked: {NO_SERVER}"
            for purpose in (44, 49, 84, 86)
        ),
        "  ethereum, purpose 44, on Ethereum: accounts 0 to 3 read, 1 used",
        f"    account 0, m/44h/60h/0h: {10**18} wei at latest",
        f"      receive m/44h/60h/0h/0/0 {first}: {10**18} wei, nonce 0",
        f"      receive m/44h/60h/0h/0/5 {sixth}: 0 wei, nonce 4",
        "  ethereum, legacy account, on Ethereum: accounts 0 to 1 read, 2 used",
        "    account 0, m/44h/60h/0h: 3 wei at latest",
        f"      address m/44h/60h/0h/2 {legacy}: 3 wei, nonce 0",
        "    account 1, m/44h/60h: 5 wei at latest",
        f"      address m/44h/60h/1 {mew}: 5 wei, nonce 0",
        f"  ethereum-classic, purpose 44: not checked: {classic}",
        f"  ethereum-classic, legacy account: not checked: {classic}",
        f"  bnb, purpose 44: not checked: {OTHER_CHAIN['bnb']}",
        f"  bnb, legacy account: not checked: {OTHER_CHAIN['bnb']}",
        f"  bitcoin-cash, purpose 44: not checked: {NOT_READ}",
    ]
    assert lines[-2] == (
        f"total: ethereum, {10**18 + 8} wei of ETH, 3 used accounts, each account"
        " key once"
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
        "\ntotal: ethereum, 3 wei of ETH, 1 used accounts, each account key once"
        "\ndigest: "
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
    (ethereum,) = [
        a for a in readings[1].accounts if a.path == "m/44h/60h/0h" and a.purpose
    ]
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
        "total: ethereum, 5 wei of ETH, 1 used accounts, each account key once",
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
    assert_lines_secret_free(text, secrets.every())


#: BIP173's testnet P2WSH vector, an address `identify` does not search.
TESTNET = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"


def test_every_line_naming_a_defined_word_has_a_shape(
    abandon: str, result: str, evm_result: str
) -> None:
    """The reports and summaries of many runs: no such line is searched whole.

    Each line of a report, or of a summary of ``identify`` or ``scan``,
    that names a coin, a chain or a reason is of a shape
    `tests.no_secret_test.LINE_SHAPES` holds. The runs pay, spend before
    a block confirms it, cut a purpose short, read Ethereum's accounts on
    other chains and BNB's on BNB Smart Chain, find a legacy account used,
    and refuse a passphrase, an address and a scheme.
    """
    one = dumps(identify(ABANDON, [""], no_share, accounts=1))
    paid = pay(1, (script(one, "m/84h/0h/0h", 0, 0), 10_000))
    spent = pay(2, (ELSEWHERE, 9_000), spends=paid)
    pending = Chain(HistoryTx(paid, BLOCK), HistoryTx(spent, None))
    short = Chain(HistoryTx(pay(1, (script(one, "m/86h/0h/0h", 0, 0), 5)), BLOCK))
    btc = Chain(HistoryTx(pay(1, (script(abandon, "m/49h/0h/0h", 0, 0), 5)), BLOCK))
    eth = eth_address(abandon, "m/44h/60h/0h", 0)
    bnb = eth_address(abandon, "m/44h/714h/0h", 0)
    classic = OTHER_CHAIN["ethereum-classic"]
    segwit = dumps(identify(SEGWIT, [""], no_share, accounts=1))
    refused = ["", "\N{LATIN SMALL LETTER E WITH ACUTE}"]
    runs = [
        (abandon, scan_module.loads(result, abandon)),
        (abandon, scan_module.loads(evm_result, abandon)),
        (abandon, None),
        (one, scan_module.scan(one, pending, server="s:1")),
        (one, scan_module.scan(one, short, server="s:1")),
        (segwit, scan_module.scan(segwit, Chain(), server="s:1")),
        (
            abandon,
            scan_module.scan(abandon, btc, server="s:1", node=node(Ethereum({eth: 3}))),
        ),
        (
            abandon,
            scan_module.scan(
                abandon,
                None,
                node=node(Ethereum({eth: 2}, chain_id=61)),
                evm_chain="ethereum-classic",
            ),
        ),
        (
            abandon,
            scan_module.scan(
                abandon,
                None,
                node=node(Ethereum({eth: 2}, chain_id=137)),
                evm_chain="polygon-pos",
            ),
        ),
        (
            abandon,
            scan_module.scan(
                abandon,
                None,
                node=node(Ethereum({bnb: 2}, chain_id=56)),
                evm_chain="bnb-smart-chain",
            ),
        ),
        (dumps(identify(OLD, [""], no_share, address="not an address")), None),
        (dumps(identify(ABANDON, [""], no_share, accounts=1, address=TESTNET)), None),
        (dumps(identify(SHARES[0], refused, Prompt(SHARES[1]), accounts=1)), None),
        (dumps(identify(SHARES[0], [""], no_share)), None),
        (dumps(identify("qzx qzx", [""], no_share)), None),
        (MISSED, None),
    ]
    texts = []
    for bundle, scanned in runs:
        texts.append(cli._summary(loads(bundle)))
        if scanned is None:
            texts.append(report(bundle))
        else:
            texts += [
                report(bundle, scan_module.dumps(scanned)),
                cli._scan_summary(scanned),
            ]
    written = "".join(texts)
    for line in (
        "\ntotal: bitcoin, 10000 sat confirmed, -10000 sat unconfirmed,",
        "\nnot derived: slip39: passphrase 1: not one SLIP-0039 accepts\n",
        f"\n  ethereum-classic, purpose 44: not checked: {classic}\n",
        "\nreading 0, purpose 86: accounts read: 1, cut short: ",
        ", of Bitcoin Cash's for a base58 address, ",
        "\n  ethereum, legacy account, on Ethereum: accounts 0 to 1 read, 2 used\n",
        "\nreading 0, ethereum legacy: accounts read: 2\n",
        "\n  ethereum-classic, legacy account, on Ethereum Classic: accounts 0 to ",
        f"\n  bnb, purpose 44: not checked: {OTHER_CHAIN['bnb']}\n",
        "\n  bnb, purpose 44, on BNB Smart Chain: accounts 0 to ",
        "\n  bnb, legacy account, on BNB Smart Chain: accounts 0 to 0 read, 0 used\n",
        "\nreading 0, bnb purpose 44: accounts read: ",
    ):
        assert line in written
    assert not unshaped(written)
    assert_lines_secret_free(written, ["coin"])


def test_a_result_that_is_no_text_is_refused(abandon: str) -> None:
    """Its type is named, as `seed_scan.scan.loads` names it."""
    with pytest.raises(SeedScanTypeError, match="scan result: text of type bytes"):
        report(abandon, b"{}")  # type: ignore[arg-type]


def test_the_report_of_an_ethereum_classic_scan(abandon: str) -> None:
    """The chain is named on the node's line, each coin's and the total.

    Each coin's accounts are counted, an account key of each once, its
    legacy layout's included.
    """
    ethereum = eth_address(abandon, "m/44h/60h/0h", 0)
    classic = eth_address(abandon, "m/44h/61h/0h", 1)
    legacy = eth_address(abandon, "m/44h/60h/160720h/0h", 4, legacy=True)
    fake = Ethereum({ethereum: 2, classic: 3, legacy: 4}, chain_id=61)
    result = scan_module.scan(
        abandon, None, node=node(fake), evm_chain="ethereum-classic"
    )
    lines = report(abandon, scan_module.dumps(result)).splitlines()
    assert lines[4:6] == [
        (
            "node: https://node.example, Ethereum Classic, chain id 61, latest"
            " block 16 before the first address was read"
        ),
        f"Ethereum Classic tokens: not checked: {NO_TOKENS}",
    ]
    read = [line for line in lines if line.startswith("  ethereum")]
    assert read == [
        "  ethereum, purpose 44, on Ethereum Classic: accounts 0 to 3 read, 1 used",
        (
            "  ethereum, legacy account, on Ethereum Classic: accounts 0 to 1 read,"
            " 0 used"
        ),
        (
            "  ethereum-classic, purpose 44, on Ethereum Classic: accounts 0 to 3"
            " read, 1 used"
        ),
        (
            "  ethereum-classic, legacy account, on Ethereum Classic: accounts 0"
            " to 0 read, 1 used"
        ),
    ]
    assert lines[-2] == (
        "total: ethereum-classic, 9 wei of ETC, 3 used accounts, each account key once"
    )


def test_the_report_of_the_stable_account(abandon: str) -> None:
    """On BNB Smart Chain, its one address is listed with its full path."""
    stable = eth_address(abandon, "m/44h/60h/9172h/3604", 9999, legacy=True)
    fake = Ethereum({stable: 6}, chain_id=56)
    result = scan_module.scan(
        abandon, None, node=node(fake), evm_chain="bnb-smart-chain"
    )
    lines = report(abandon, scan_module.dumps(result)).splitlines()
    (opening,) = [n for n, line in enumerate(lines) if line.startswith("  bnb, legacy")]
    assert lines[opening : opening + 3] == [
        "  bnb, legacy account, on BNB Smart Chain: accounts 0 to 0 read, 1 used",
        "    account 0, m/44h/60h/9172h/3604: 6 wei at latest",
        f"      address m/44h/60h/9172h/3604/9999 {stable}: 6 wei, nonce 0",
    ]
    assert lines[-2] == (
        "total: bnb-smart-chain, 6 wei of BNB, 1 used accounts, each account key once"
    )


def test_an_address_alone_is_counted_apart_from_its_keys_children(
    abandon: str,
) -> None:
    """The Stable Account's key edited to be MyEtherWallet's: two addresses.

    One key, read below at index 0 for Ethereum's legacy layout and at
    index 9999 alone for the Stable Account, gives two addresses whose
    funds the total counts each once.
    """
    document = json.loads(abandon)
    accounts = document["readings"][0]["accounts"]
    (mew,) = [a for a in accounts if a["path"] == "m/44h/60h"]
    (stable,) = [a for a in accounts if a["index"] is not None]
    stable["xpub"] = mew["xpub"]
    text = json.dumps(document)
    low = eth_address(text, "m/44h/60h", 0, legacy=True)
    high = eth_address(text, "m/44h/60h", 9999, legacy=True)
    fake = Ethereum({low: 2, high: 3}, chain_id=56)
    result = scan_module.scan(text, None, node=node(fake), evm_chain="bnb-smart-chain")
    lines = report(text, scan_module.dumps(result)).splitlines()
    assert lines[-2] == (
        "total: bnb-smart-chain, 5 wei of BNB, 2 used accounts, each account key once"
    )


def test_an_address_two_keys_list_is_counted_once(abandon: str) -> None:
    """The Stable Account edited to MyEtherWallet's key at index 0.

    Two accounts of two keys, "legacy" and "index 0", each list the one
    address that holds wei: the total counts its balance once.
    """
    document = json.loads(abandon)
    accounts = document["readings"][0]["accounts"]
    (mew,) = [a for a in accounts if a["path"] == "m/44h/60h"]
    (stable,) = [a for a in accounts if a["index"] is not None]
    stable.update(xpub=mew["xpub"], index=0)
    text = json.dumps(document)
    first = eth_address(text, "m/44h/60h", 0, legacy=True)
    fake = Ethereum({first: 7}, chain_id=56)
    result = scan_module.scan(text, None, node=node(fake), evm_chain="bnb-smart-chain")
    assert result.evm is not None
    assert [(u.path, u.balance) for u in result.evm.used] == [
        ("m/44h/60h", "7"),
        ("m/44h/60h/9172h/3604", "7"),
    ]
    lines = report(text, scan_module.dumps(result)).splitlines()
    assert lines[-2] == (
        "total: bnb-smart-chain, 7 wei of BNB, 2 used accounts, each account key once"
    )


def test_a_bitcoin_address_two_keys_list_is_counted_once(abandon: str) -> None:
    """Account 1's key edited to account 0's, at another depth.

    The two xpubs differ as text and give the same scripts, so both
    accounts list the address paid: the total counts its balance once.
    """
    document = json.loads(abandon)
    accounts = document["readings"][0]["accounts"]
    (zero,) = [a for a in accounts if a["path"] == "m/84h/0h/0h"]
    (one,) = [a for a in accounts if a["path"] == "m/84h/0h/1h"]
    key = BIP32KeyData.b58decode(zero["xpub"])
    deeper = BIP32KeyData(
        key.version,
        key.depth + 1,
        key.parent_fingerprint,
        key.index,
        key.chain_code,
        key.key,
    ).b58encode()
    one["descriptors"] = [
        add_checksum(d.split("#")[0].replace(zero["xpub"], deeper))
        for d in zero["descriptors"]
    ]
    one["xpub"] = deeper
    text = json.dumps(document)
    paid = script(text, "m/84h/0h/0h", 0, 0)
    chain = Chain(HistoryTx(pay(1, (paid, 9)), BLOCK))
    result = scan_module.scan(text, chain, server="s:1")
    assert [(u.path, u.confirmed) for u in result.used] == [
        ("m/84h/0h/0h", 9),
        ("m/84h/0h/1h", 9),
    ]
    lines = report(text, scan_module.dumps(result)).splitlines()
    assert lines[-2] == (
        "total: bitcoin, 9 sat confirmed, 0 sat unconfirmed, 2 used accounts,"
        " each account key once"
    )


def test_a_key_read_as_both_coins_is_counted_once(abandon: str) -> None:
    """Ethereum's and Ethereum Classic's account 0 under one xpub: one total.

    The bundle is edited so that both hold the same key, as `loads` and
    `scan` accept: the same address is read for each coin, and its funds
    are counted once.
    """
    (ethereum,) = [
        a
        for r in loads(abandon).readings
        for a in r.accounts
        if a.path == "m/44h/60h/0h" and a.purpose
    ]
    text = edited(abandon, "m/44h/61h/0h", xpub=ethereum.xpub)
    fake = Ethereum({eth_address(text, "m/44h/60h/0h", 0): 7}, chain_id=61)
    result = scan_module.scan(text, None, node=node(fake), evm_chain="ethereum-classic")
    assert result.evm is not None
    assert [u.coin for u in result.evm.used] == ["ethereum", "ethereum-classic"]
    lines = report(text, scan_module.dumps(result)).splitlines()
    assert lines[-2] == (
        "total: ethereum-classic, 7 wei of ETC, 1 used accounts, each account key once"
    )
