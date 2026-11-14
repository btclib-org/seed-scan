# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `seed_scan.scan.loads`: a scan result read back against its bundle.

Each refusal edits one member of a result `scan` wrote, and checks that
the message names the member and quotes no value.
"""

from __future__ import annotations

import json
from hashlib import sha256
from typing import TYPE_CHECKING, Any

import pytest
from btclib_wallet.fetch.history import HistoryTx

from seed_scan.bundle import dumps
from seed_scan.exceptions import SeedScanTypeError, SeedScanValueError
from seed_scan.identify import identify
from seed_scan.scan import NO_NODE, NO_SERVER, NOT_READ, OTHER_CHAIN, loads, scan
from seed_scan.scan import dumps as scan_dumps

from .evm_test import Ethereum
from .identify_test import ABANDON, SEGWIT, no_share
from .scan_test import BLOCK, Chain, eth_address, node, pay, script

if TYPE_CHECKING:
    from collections.abc import Callable

#: A value no message may quote.
PLANTED = "xprv-planted"


@pytest.fixture(scope="module")
def bundle() -> str:
    """Return the bundle of BIP84's mnemonic, two accounts of each purpose.

    :returns: its text.
    """
    return dumps(identify(ABANDON, [""], no_share, accounts=2))


@pytest.fixture(scope="module")
def result(bundle: str) -> str:
    """Return a scan result with one used account, confirmed and not.

    :param bundle: the bundle.
    :returns: its text.
    """
    receive = script(bundle, "m/84h/0h/0h", 0, 1)
    chain = Chain(
        HistoryTx(pay(1, (receive, 3)), BLOCK), HistoryTx(pay(2, (receive, 4)), None)
    )
    return scan_dumps(scan(bundle, chain, server="[::1]:50002"))


@pytest.fixture(scope="module")
def evm_result(bundle: str) -> str:
    """Return the result of a node alone: one used account, two addresses.

    The node serves Polygon PoS, which reads Ethereum's accounts alone.

    :param bundle: the bundle.
    :returns: its text.
    """
    first = eth_address(bundle, "m/44h/60h/0h", 0)
    sixth = eth_address(bundle, "m/44h/60h/0h", 5)
    fake = Ethereum({first: 10**18}, {sixth: 4}, chain_id=137)
    return scan_dumps(scan(bundle, None, node=node(fake), evm_chain="polygon-pos"))


def test_a_result_reads_back_as_scan_wrote_it(bundle: str, result: str) -> None:
    """`loads` answers what `dumps` was given."""
    read = loads(result, bundle)
    assert scan_dumps(read) == result
    (used,) = read.used
    assert [t.height for t in used.transactions] == [1, None]
    assert read.evm is None


def test_an_ethereum_result_reads_back(bundle: str, evm_result: str) -> None:
    """A null server, and the node's scan, as `dumps` was given them."""
    read = loads(evm_result, bundle)
    assert scan_dumps(read) == evm_result
    assert read.server is None
    assert read.evm is not None
    assert (read.evm.node, read.evm.chain, read.evm.chain_id) == (
        "https://node.example",
        "polygon-pos",
        137,
    )
    (used,) = read.evm.used
    assert [(a.index, a.balance, a.nonce) for a in used.addresses] == [
        (0, str(10**18), 0),
        (5, "0", 4),
    ]


def test_a_result_of_both_reads_back(bundle: str) -> None:
    """A server and a node, each coin read."""
    receive = script(bundle, "m/84h/0h/0h", 0, 0)
    first = eth_address(bundle, "m/44h/60h/1h", 0)
    chain = Chain(HistoryTx(pay(1, (receive, 5)), BLOCK))
    fake = Ethereum({first: 7})
    text = scan_dumps(scan(bundle, chain, server="s:1", node=node(fake)))
    read = loads(text, bundle)
    assert scan_dumps(read) == text
    assert {n.reason for n in read.not_checked} == {NOT_READ, *OTHER_CHAIN.values()}


def test_an_ethereum_classic_result_reads_back(bundle: str) -> None:
    """Account 0 of each coin used: one key each, neither listed twice."""
    ethereum = eth_address(bundle, "m/44h/60h/0h", 0)
    classic = eth_address(bundle, "m/44h/61h/0h", 0)
    fake = Ethereum({ethereum: 1, classic: 2}, chain_id=61)
    text = scan_dumps(scan(bundle, None, node=node(fake), evm_chain="ethereum-classic"))
    read = loads(text, bundle)
    assert scan_dumps(read) == text
    assert read.evm is not None
    assert [(u.coin, u.account) for u in read.evm.used] == [
        ("ethereum", 0),
        ("ethereum-classic", 0),
    ]
    document = json.loads(text)
    document["evm"]["chain"], document["evm"]["chain_id"] = "ethereum", 1
    with pytest.raises(SeedScanValueError, match="a coin the chain does not read"):
        loads(json.dumps(document), bundle)
    document = json.loads(text)
    document["evm"]["chain"] = 61
    with pytest.raises(SeedScanTypeError, match="member 'chain' of type int"):
        loads(json.dumps(document), bundle)


def test_a_bnb_smart_chain_result_reads_back(bundle: str) -> None:
    """A BNB account used on BNB Smart Chain, and refused on another chain."""
    address = eth_address(bundle, "m/44h/714h/1h", 2)
    fake = Ethereum({address: 3}, chain_id=56)
    text = scan_dumps(scan(bundle, None, node=node(fake), evm_chain="bnb-smart-chain"))
    read = loads(text, bundle)
    assert scan_dumps(read) == text
    assert read.evm is not None
    assert [(u.coin, u.path, u.balance) for u in read.evm.used] == [
        ("bnb", "m/44h/714h/1h", "3")
    ]
    document = json.loads(text)
    document["evm"]["chain"], document["evm"]["chain_id"] = "base", 8453
    with pytest.raises(SeedScanValueError, match="a coin the chain does not read"):
        loads(json.dumps(document), bundle)


def test_a_legacy_layout_result_reads_back(bundle: str) -> None:
    """Each coin's legacy account, its addresses below its key itself.

    Ethereum's first shares the key of its account 0, whose receive
    branch gives other addresses: one of them listed for the legacy
    account is refused. Ethereum's two are each read, so a search that
    reads one alone is refused too.
    """
    ethereum = eth_address(bundle, "m/44h/60h/0h", 3, legacy=True)
    mew = eth_address(bundle, "m/44h/60h", 4, legacy=True)
    classic = eth_address(bundle, "m/44h/60h/160720h/0h", 0, legacy=True)
    fake = Ethereum({ethereum: 1, mew: 5, classic: 2}, chain_id=61)
    text = scan_dumps(scan(bundle, None, node=node(fake), evm_chain="ethereum-classic"))
    read = loads(text, bundle)
    assert scan_dumps(read) == text
    assert read.evm is not None
    assert [(u.coin, u.purpose, u.account, u.path) for u in read.evm.used] == [
        ("ethereum", None, 0, "m/44h/60h/0h"),
        ("ethereum", None, 1, "m/44h/60h"),
        ("ethereum-classic", None, 0, "m/44h/60h/160720h/0h"),
    ]
    document = json.loads(text)
    document["evm"]["used"][0]["addresses"][0]["address"] = eth_address(
        bundle, "m/44h/60h/0h", 3
    )
    with pytest.raises(SeedScanValueError, match="not the bundle's at its position"):
        loads(json.dumps(document), bundle)
    document = json.loads(text)
    (legacy,) = [
        s
        for s in document["evm"]["searched"]
        if (s["coin"], s["purpose"]) == ("ethereum", None)
    ]
    legacy["accounts"] = 1
    document["evm"]["used"] = [
        u for u in document["evm"]["used"] if u["path"] != "m/44h/60h"
    ]
    with pytest.raises(SeedScanValueError, match=DISAGREE):
        loads(json.dumps(document), bundle)


def test_an_electrum_result_reads_back() -> None:
    """Its search and its account have no purpose."""
    text = dumps(identify(SEGWIT, [""], no_share, accounts=1))
    result = scan_dumps(scan(text, Chain(), server="s:1"))
    assert scan_dumps(loads(result, text)) == result


def first(key: str, edit: Callable[[dict[str, Any]], None]) -> Callable[..., None]:
    """Return an edit of the first item of a list member.

    :param key: the member.
    :param edit: what is done to its first item.
    :returns: the edit of the whole document.
    """

    def apply(document: dict[str, Any]) -> None:
        edit(document[key][0])

    return apply


def setter(key: str, value: object) -> Callable[[dict[str, Any]], None]:
    """Return the edit that sets one member of an object.

    :param key: the member.
    :param value: its new value.
    :returns: the edit.
    """
    return lambda document: document.__setitem__(key, value)


def deleter(key: str) -> Callable[[dict[str, Any]], None]:
    """Return the edit that removes one member of an object.

    :param key: the member.
    :returns: the edit.
    """
    return lambda document: document.__delitem__(key)


def in_address(key: str, value: object) -> Callable[[dict[str, Any]], None]:
    """Return the edit of a member of the first used address.

    :param key: the member.
    :param value: its new value.
    :returns: the edit.
    """
    return first("used", lambda used: used["addresses"][0].__setitem__(key, value))


def twice(document: dict[str, Any]) -> None:
    """Search the first purpose twice.

    :param document: the result.
    """
    document["searched"].append(document["searched"][0])


def past_the_search(document: dict[str, Any]) -> None:
    """Make the used account one past those its search read.

    :param document: the result.
    """
    used = document["used"][0]
    (done,) = [
        s
        for s in document["searched"]
        if (s["reading"], s["purpose"]) == (used["reading"], used["purpose"])
    ]
    done["accounts"] = 1
    used["account"] = 1


def used_twice(document: dict[str, Any]) -> None:
    """List the used account twice, which would double its balance.

    :param document: the result.
    """
    document["used"].append(document["used"][0])


def address_twice(document: dict[str, Any]) -> None:
    """List the used account's first address twice.

    :param document: the result.
    """
    addresses = document["used"][0]["addresses"]
    addresses.append(addresses[0])


def in_evm(edit: Callable[[dict[str, Any]], None]) -> Callable[..., None]:
    """Return an edit of the ``evm`` member.

    :param edit: what is done to it.
    :returns: the edit of the whole document.
    """
    return lambda document: edit(document["evm"])


def in_evm_address(key: str, value: object) -> Callable[[dict[str, Any]], None]:
    """Return the edit of a member of the first used Ethereum address.

    :param key: the member.
    :param value: its new value.
    :returns: the edit.
    """
    return in_evm(first("used", lambda u: u["addresses"][0].__setitem__(key, value)))


def evm_address_twice(document: dict[str, Any]) -> None:
    """List the used Ethereum account's first address twice.

    :param document: the result.
    """
    addresses = document["evm"]["used"][0]["addresses"]
    addresses.append(addresses[0])


def evm_searched_twice(document: dict[str, Any]) -> None:
    """List the search of Ethereum's purpose 44 twice.

    :param document: the result.
    """
    document["evm"]["searched"].append(document["evm"]["searched"][0])


def evm_used_twice(document: dict[str, Any]) -> None:
    """List the used Ethereum account twice.

    :param document: the result.
    """
    document["evm"]["used"].append(document["evm"]["used"][0])


def unused_address(document: dict[str, Any]) -> None:
    """List an address with no balance and no nonce, the account's sum kept.

    :param document: the result.
    """
    used = document["evm"]["used"][0]
    used["addresses"][1]["nonce"] = 0


def no_address(document: dict[str, Any]) -> None:
    """List the used Ethereum account with no address and no balance.

    :param document: the result.
    """
    used = document["evm"]["used"][0]
    used["addresses"] = []
    used["balance"] = "0"


def both_spend_more(confirmed: int, unconfirmed: int) -> Callable[..., None]:
    """Return the edit giving the used account and its address one balance.

    The sums agree, so what refuses it is the balance itself.

    :param confirmed: the confirmed balance of both.
    :param unconfirmed: the mempool's change to both.
    :returns: the edit.
    """

    def apply(document: dict[str, Any]) -> None:
        used = document["used"][0]
        (address,) = used["addresses"]
        for item in (used, address):
            item["confirmed"], item["unconfirmed"] = confirmed, unconfirmed

    return apply


def in_used(edit: Callable[[dict[str, Any]], None]) -> Callable[..., None]:
    """Return an edit of the first used account.

    :param edit: what is done to it.
    :returns: the edit of the whole document.
    """
    return first("used", edit)


def heights(*values: int | None) -> Callable[[dict[str, Any]], None]:
    """Return the edit that sets the heights of the used account's history.

    :param values: a height, or None for the mempool, per transaction.
    :returns: the edit.
    """

    def apply(used: dict[str, Any]) -> None:
        for transaction, height in zip(used["transactions"], values, strict=True):
            transaction["height"] = height

    return in_used(apply)


def searched_of(purpose: int, key: str, value: object) -> Callable[..., None]:
    """Return the edit of a member of the search of one purpose.

    :param purpose: the purpose.
    :param key: the member.
    :param value: its new value.
    :returns: the edit.
    """

    def apply(document: dict[str, Any]) -> None:
        (done,) = [s for s in document["searched"] if s["purpose"] == purpose]
        done[key] = value

    return apply


#: What a search's flags refuse with.
DISAGREE = "a search's accounts and 'cut_short' do not agree"

VALUE_ERRORS = [
    (setter("format", PLANTED), "format is not 'seed-scan-scan'"),
    (setter("version", 2), "version is not 1"),
    (deleter("server"), "missing member 'server'"),
    (setter("bundle", PLANTED), "made from another bundle"),
    (setter("server", f"{PLANTED} :1"), "member 'server' is not host:port"),
    (setter("server", f"{PLANTED}\x1b:1"), "member 'server' is not host:port"),
    (setter("server", "h:0"), "member 'server': the port is not 1 to 65535"),
    (setter("server", f"h:{'9' * 5000}"), "member 'server': the port is not 1"),
    (setter("gap_limit", 0), "member 'gap_limit' is below 1"),
    (first("searched", setter("reading", 1)), "a search reads no account"),
    (first("searched", setter("accounts", 3)), "a search reads no account"),
    (first("searched", setter("purpose", 45)), "a search reads no account"),
    (twice, "a purpose searched twice"),
    (first("used", setter("reading", 1)), "a used account was not searched"),
    (first("used", setter("purpose", None)), "a used account was not searched"),
    (first("used", setter("account", 2)), "a used account was not searched"),
    (past_the_search, "a used account was not searched"),
    (used_twice, "a used account listed twice"),
    (address_twice, "an address listed twice"),
    # two accounts in the bundle and a gap of 3: the gap cannot be reached
    (searched_of(84, "cut_short", False), DISAGREE),
    (searched_of(44, "cut_short", False), DISAGREE),
    # one account of two read, and none used: the search went on
    (searched_of(44, "accounts", 1), DISAGREE),
    # with a gap of 1, purpose 44 stops after account 0, and 84 is not
    # cut short
    (setter("account_gap", 1), DISAGREE),
    (in_address("confirmed", 4), "the addresses' balances are not the account's"),
    (in_address("unconfirmed", 3), "the addresses' balances are not the account's"),
    (in_address("confirmed", -1), "member 'confirmed' is below 0"),
    (both_spend_more(9, -10), "a balance outside 0 to 21 million bitcoin"),
    (both_spend_more(21 * 10**14 + 1, 0), "a balance outside 0 to 21 million"),
    (first("used", setter("path", PLANTED)), "member 'path' is not the account's"),
    (in_address("address", PLANTED), "an address is not the bundle's"),
    (in_address("branch", 2), "an address is not the bundle's"),
    (in_address("index", 2), "an address is not the bundle's"),
    (in_address("index", 2**31), "an address is not the bundle's"),
    (in_address("index", -1), "member 'index' is below 0"),
    (
        first("used", lambda u: u["transactions"][0].__setitem__("tx_id", PLANTED)),
        "member 'tx_id' is not an id",
    ),
    (
        first("used", lambda u: u["transactions"][0].__setitem__("height", -1)),
        "member 'height' is below 0",
    ),
    (
        first("used", lambda u: u["tip"].__setitem__("block_id", PLANTED)),
        "member 'block_id' is not an id",
    ),
    # 3 sat confirmed, 4 unconfirmed: the mempool cannot spend more than
    # the account holds, nor can it hold past the supply
    (in_used(setter("unconfirmed", -4)), "a balance outside 0 to 21 million"),
    (in_used(setter("confirmed", 21 * 10**14 + 1)), "a balance outside 0 to 21"),
    (in_used(setter("confirmed", 10**4299)), "a balance outside 0 to 21 million"),
    (in_used(setter("transactions", [])), "a balance or a use no transaction"),
    (heights(None, None), "a balance or a use no transaction listed gives"),
    (heights(1, 1), "a balance or a use no transaction listed gives"),
    (in_used(setter("addresses", [])), "a used account lists no address"),
    # the used address is at index 1 of the receive branch
    (setter("gap_limit", 1), "an address past the gap limit"),
    (first("not_checked", setter("coin", "bitcoin")), "a coin read is listed"),
    (first("not_checked", setter("coin", PLANTED)), "is not the bundle's"),
    (first("not_checked", setter("reading", 1)), "is not the bundle's"),
    (
        first("not_checked", setter("reason", PLANTED)),
        "member 'reason' is not the format's for that coin",
    ),
    (
        first("not_checked", setter("reason", NOT_READ)),
        "member 'reason' is not the format's for that coin",
    ),
    (setter("server", None), "a Bitcoin search with no server"),
]


@pytest.mark.parametrize("edit, said", VALUE_ERRORS)
def test_a_result_the_format_does_not_define_is_refused(
    bundle: str, result: str, edit: Callable[[dict[str, Any]], None], said: str
) -> None:
    """Each refusal names the member, quoting nothing.

    :param bundle: the bundle.
    :param result: the result edited.
    :param edit: the edit.
    :param said: what the message holds.
    """
    document = json.loads(result)
    edit(document)
    with pytest.raises(SeedScanValueError) as caught:
        loads(json.dumps(document), bundle)
    message = str(caught.value)
    assert message.startswith("scan result: ")
    assert said in message
    assert PLANTED not in message


#: The refusals of a result whose ``evm`` is the node's scan.
EVM_VALUE_ERRORS = [
    (setter("evm", None), "it names neither a server nor a node"),
    (deleter("evm"), "missing member 'evm'"),
    (in_evm(setter("node", PLANTED)), "member 'node' is not a scheme, host"),
    (
        in_evm(setter("node", "https://node.example/rpc")),
        "member 'node' is not a scheme, host",
    ),
    (
        in_evm(setter("node", "http://node.example")),
        "member 'node' is not a scheme, host",
    ),
    (in_evm(setter("chain_id", -1)), "member 'chain_id' is below 0"),
    (in_evm(setter("chain_id", 1)), "member 'chain_id' is not the chain's"),
    (in_evm(setter("chain", PLANTED)), "member 'chain' is not one scan reads"),
    (
        in_evm(first("searched", setter("coin", "ethereum-classic"))),
        "a coin the chain does not read",
    ),
    (in_evm(first("used", setter("coin", PLANTED))), "a coin the chain does not read"),
    (
        in_evm(first("used", setter("coin", "bitcoin"))),
        "a coin the chain does not read",
    ),
    (in_evm(first("searched", setter("purpose", 84))), "a search reads no account"),
    (in_evm(first("used", setter("account", 2))), "a used account was not searched"),
    (
        in_evm(first("used", setter("path", PLANTED))),
        "member 'path' is not the account's",
    ),
    (in_evm(first("searched", setter("cut_short", False))), DISAGREE),
    (evm_searched_twice, "a purpose searched twice"),
    (evm_used_twice, "a used account listed twice"),
    (evm_address_twice, "an address listed twice"),
    (in_evm_address("address", PLANTED), "an address is not the bundle's"),
    (in_evm_address("index", 1), "an address is not the bundle's"),
    (in_evm_address("index", 2**31), "an address is not the bundle's"),
    (in_evm_address("balance", PLANTED), "member 'balance' is not a wei balance"),
    (in_evm_address("balance", "01"), "member 'balance' is not a wei balance"),
    (in_evm_address("balance", str(2**256)), "member 'balance' is not a wei"),
    (in_evm_address("nonce", -1), "member 'nonce' is below 0"),
    # the used addresses are at indexes 0 and 5
    (setter("gap_limit", 4), "an address past the gap limit"),
    (unused_address, "an unused address listed as used"),
    (no_address, "a used account lists no address"),
    (
        in_evm(first("used", setter("balance", "1"))),
        "the addresses' balances are not the account's",
    ),
    (first("not_checked", setter("reason", NO_NODE)), "member 'reason' is not"),
    (first("not_checked", setter("coin", "ethereum")), "a coin read is listed"),
]


@pytest.mark.parametrize("edit, said", EVM_VALUE_ERRORS)
def test_an_ethereum_result_the_format_does_not_define_is_refused(
    bundle: str, evm_result: str, edit: Callable[[dict[str, Any]], None], said: str
) -> None:
    """Each refusal names the member, quoting nothing.

    :param bundle: the bundle.
    :param evm_result: the result edited.
    :param edit: the edit.
    :param said: what the message holds.
    """
    document = json.loads(evm_result)
    edit(document)
    with pytest.raises(SeedScanValueError) as caught:
        loads(json.dumps(document), bundle)
    message = str(caught.value)
    assert message.startswith("scan result: ")
    assert said in message
    assert PLANTED not in message
    assert caught.value.__context__ is None


def test_offsetting_mempool_changes_need_a_mempool_transaction(bundle: str) -> None:
    """A transfer in the mempool between two owned addresses nets to 0.

    The account's unconfirmed change is 0, but each address's is not:
    without the mempool's transaction, nothing listed gives them.
    """
    receive = script(bundle, "m/84h/0h/0h", 0, 0)
    change = script(bundle, "m/84h/0h/0h", 1, 0)
    paid = pay(1, (receive, 9))
    chain = Chain(
        HistoryTx(paid, BLOCK), HistoryTx(pay(2, (change, 9), spends=paid), None)
    )
    text = scan_dumps(scan(bundle, chain, server="s:1"))
    document = json.loads(text)
    (used,) = document["used"]
    assert (used["confirmed"], used["unconfirmed"]) == (9, 0)
    balances = [(a["confirmed"], a["unconfirmed"]) for a in used["addresses"]]
    assert balances == [(9, -9), (0, 9)]
    assert loads(text, bundle).used[0].unconfirmed == 0
    used["transactions"] = [t for t in used["transactions"] if t["height"] is not None]
    err_msg = "a balance or a use no transaction listed gives"
    with pytest.raises(SeedScanValueError, match=err_msg):
        loads(json.dumps(document), bundle)


@pytest.mark.parametrize(
    "server", ["host.example:050002", "bücher.example:50002", f"{'a' * 300}:1"]
)
def test_a_server_scan_takes_reads_back(bundle: str, server: str) -> None:
    """Leading zeros, a host that is not ASCII, a long host: as `scan` wrote it.

    :param bundle: the bundle.
    :param server: the server named.
    """
    text = scan_dumps(scan(bundle, Chain(), server=server))
    assert loads(text, bundle).server == server


def test_a_bitcoin_address_past_the_gap_limit_is_refused(
    bundle: str, result: str
) -> None:
    """The bundle's own address at index 1000 is one discovery never reads."""
    document = json.loads(result)
    position = document["used"][0]["addresses"][0]
    position["index"] = 1000
    position["address"] = script(bundle, "m/84h/0h/0h", 0, 1000).address
    with pytest.raises(SeedScanValueError, match="an address past the gap limit"):
        loads(json.dumps(document), bundle)
    document["gap_limit"] = 1001
    assert loads(json.dumps(document), bundle).gap_limit == 1001


def test_an_ethereum_address_past_the_gap_limit_is_refused(
    bundle: str, evm_result: str
) -> None:
    """Index 1000 after index 0: past a gap of 20, not past one of 1000."""
    document = json.loads(evm_result)
    position = document["evm"]["used"][0]["addresses"][1]
    position["index"] = 1000
    position["address"] = eth_address(bundle, "m/44h/60h/0h", 1000)
    with pytest.raises(SeedScanValueError, match="an address past the gap limit"):
        loads(json.dumps(document), bundle)
    document["gap_limit"] = 1000
    assert loads(json.dumps(document), bundle).gap_limit == 1000
    document["gap_limit"] = 999
    with pytest.raises(SeedScanValueError, match="an address past the gap limit"):
        loads(json.dumps(document), bundle)


def test_a_bundle_scan_refuses_is_refused(bundle: str) -> None:
    """A purpose whose account 0 is gone: no search may claim it was read.

    The result is made to agree with the edited bundle: its digest, two
    accounts read of each purpose, a gap of 2 reached, none used.
    """
    document = json.loads(bundle)
    accounts = document["readings"][0]["accounts"]
    (gone,) = [
        a
        for a in accounts
        if (a["coin"], a["purpose"], a["account"]) == ("bitcoin", 84, 0)
    ]
    accounts.remove(gone)
    edited = json.dumps(document)
    result = json.loads(scan_dumps(scan(bundle, Chain(), server="s:1", account_gap=2)))
    result["bundle"] = sha256(edited.encode("utf-8")).hexdigest()
    with pytest.raises(SeedScanValueError, match="accounts not numbered from 0"):
        loads(json.dumps(result), edited)


TYPE_ERRORS = [
    (setter("version", True), "member 'version' of type bool"),
    (setter("used", {}), "member 'used' of type dict"),
    (setter("searched", [PLANTED]), "an item of 'searched' of type str"),
    (first("searched", setter("cut_short", 0)), "member 'cut_short' of type int"),
    (first("used", setter("unconfirmed", "1")), "member 'unconfirmed' of type str"),
    (setter("server", 1), "member 'server' of type int"),
    (setter("evm", []), "member 'evm' of type list"),
    (in_address("unconfirmed", 1.0), "member 'unconfirmed' of type float"),
]


@pytest.mark.parametrize("edit, said", TYPE_ERRORS)
def test_a_member_of_a_wrong_type_is_refused(
    bundle: str, result: str, edit: Callable[[dict[str, Any]], None], said: str
) -> None:
    """A `SeedScanTypeError`, naming the member and its type.

    :param bundle: the bundle.
    :param result: the result edited.
    :param edit: the edit.
    :param said: the message, after its prefix.
    """
    document = json.loads(result)
    edit(document)
    with pytest.raises(SeedScanTypeError) as caught:
        loads(json.dumps(document), bundle)
    assert str(caught.value) == f"scan result: {said}"


@pytest.mark.parametrize(
    "text, error, said",
    [
        (f"{{{PLANTED}", SeedScanValueError, "not JSON, at line 1 column 2"),
        (f"[{'1' * 5000}]", SeedScanValueError, "a number too long to read"),
        ("[]", SeedScanTypeError, "a JSON list"),
        (b"{}", SeedScanTypeError, "text of type bytes"),
    ],
)
def test_a_text_that_is_no_result_is_refused(
    bundle: str, text: object, error: type[Exception], said: str
) -> None:
    """Neither the text nor the decoding error is kept.

    :param bundle: the bundle.
    :param text: what is read.
    :param error: what is raised.
    :param said: the message, after its prefix.
    """
    with pytest.raises(error) as caught:
        loads(text, bundle)  # type: ignore[arg-type]
    assert str(caught.value) == f"scan result: {said}"
    assert caught.value.__context__ is None


def test_an_electrum_search_is_never_cut_short() -> None:
    """Its one account is read alone, whatever the account gap."""
    text = dumps(identify(SEGWIT, [""], no_share, accounts=1))
    document = json.loads(scan_dumps(scan(text, Chain(), server="s:1")))
    document["searched"][0]["cut_short"] = True
    with pytest.raises(SeedScanValueError, match=DISAGREE):
        loads(json.dumps(document), text)


def test_a_search_that_reached_the_gap_reads_back() -> None:
    """Five accounts, none used: three read, not cut short."""
    text = dumps(identify(ABANDON, [""], no_share, accounts=5))
    result = scan_dumps(scan(text, Chain(), server="s:1"))
    read = loads(result, text)
    assert {(s.accounts, s.cut_short) for s in read.searched} == {(3, False)}


def test_the_reason_a_coin_is_not_checked_is_the_one_scan_gives(
    bundle: str, result: str, evm_result: str
) -> None:
    """A coin whose backend was not named says so; every other, `NOT_READ`."""
    reasons = {(n.coin, n.reason) for n in loads(result, bundle).not_checked}
    evm_coins = {"ethereum", "ethereum-classic", "bnb"}
    assert {(c, r) for c, r in reasons if c in evm_coins} == {
        ("ethereum", NO_NODE),
        ("ethereum-classic", NO_NODE),
        ("bnb", NO_NODE),
    }
    assert {r for c, r in reasons if c not in evm_coins} == {NOT_READ}
    assert "bitcoin" not in {c for c, _ in reasons}
    reasons = {(n.coin, n.reason) for n in loads(evm_result, bundle).not_checked}
    assert ("bitcoin", NO_SERVER) in reasons
    assert ("ethereum-classic", OTHER_CHAIN["ethereum-classic"]) in reasons
    assert ("bnb", OTHER_CHAIN["bnb"]) in reasons
    assert "ethereum" not in {c for c, _ in reasons}
