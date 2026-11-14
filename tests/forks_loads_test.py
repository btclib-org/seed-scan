# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `seed_scan.forks.loads`: a forks result read against its bundle.

Each refusal edits one member of a result `forks` wrote, and checks that
the message opens as a forks result's, names the member and quotes no
value. `tests/scan_loads_test.py` holds the refusals the two readers
share to every case; here each kind is tried once, and what is the
forks result's own.
"""

from __future__ import annotations

import json
from hashlib import sha256
from typing import TYPE_CHECKING, Any

import pytest
from btclib_wallet.fetch.history import HistoryTx

from seed_scan.bundle import dumps
from seed_scan.exceptions import SeedScanTypeError, SeedScanValueError
from seed_scan.forks import CHAINS, forks, loads
from seed_scan.forks import dumps as forks_dumps
from seed_scan.identify import identify

from .forks_test import OWN, SHARED, p2pkh
from .identify_test import ABANDON, STANDARD, no_share
from .scan_loads_test import (
    DISAGREE,
    PLANTED,
    deleter,
    first,
    in_address,
    in_used,
    setter,
    twice,
    used_twice,
)
from .scan_test import ELSEWHERE, Chain, edited, pay

if TYPE_CHECKING:
    from collections.abc import Callable


@pytest.fixture(scope="module")
def bundle() -> str:
    """Return the bundle of BIP84's mnemonic, two accounts of each purpose.

    :returns: its text.
    """
    return dumps(identify(ABANDON, [""], no_share, accounts=2))


@pytest.fixture(scope="module")
def result(bundle: str) -> str:
    """Return a forks result with a used account of each coin.

    Bitcoin's account 0 held 10000 sat at the fork, at its receive index
    1, and spent 6000 since; the chain's own account 0 received 7000 sat
    since, at its receive index 0, and 2 sat in the mempool.

    :param bundle: the bundle.
    :returns: its text.
    """
    bitcoin = p2pkh("m/44h/0h/0h/0/1")
    own = p2pkh("m/44h/145h/0h/0/0")
    held = pay(1, (bitcoin, 10_000))
    spent = pay(2, (bitcoin, 4_000), (ELSEWHERE, 5_000), spends=held)
    chain = Chain(
        HistoryTx(held, SHARED),
        HistoryTx(spent, OWN),
        HistoryTx(pay(3, (own, 7_000)), OWN),
        HistoryTx(pay(4, (own, 2)), None),
    )
    return forks_dumps(forks(bundle, chain, chain="bitcoin-cash", server="[::1]:1"))


def test_a_result_reads_back_as_forks_wrote_it(bundle: str, result: str) -> None:
    """`loads` answers what `dumps` was given, each coin's account."""
    read = loads(result, bundle)
    assert forks_dumps(read) == result
    first_used, second = read.used
    assert (first_used.coin, first_used.at_fork, first_used.confirmed) == (
        "bitcoin",
        10_000,
        4_000,
    )
    assert (second.coin, second.at_fork, second.unconfirmed) == ("bitcoin-cash", 0, 2)
    assert {(s.coin, s.purpose) for s in read.not_checked} == {
        ("bitcoin", 49),
        ("bitcoin", 84),
        ("bitcoin", 86),
    }


@pytest.mark.parametrize("chain", list(CHAINS))
def test_a_result_of_each_chain_reads_back_each_coin(bundle: str, chain: str) -> None:
    """A used account of each coin forks reads, on each chain.

    :param bundle: the bundle.
    :param chain: the chain read.
    """
    paths = (
        "m/44h/0h/0h",
        "m/44h/145h/0h",
        "m/44h/236h/0h",
        "m/44h/899h/0h",
        "m/44h/1899h/0h",
        "m/44h/245h/0h",
    )
    paid = pay(1, *((p2pkh(f"{path}/0/0"), 1) for path in paths))
    result = forks_dumps(
        forks(bundle, Chain(HistoryTx(paid, SHARED)), chain=chain, server="h:1")
    )
    read = loads(result, bundle)
    assert forks_dumps(read) == result
    assert [(u.coin, u.path) for u in read.used] == [
        ("bitcoin", "m/44h/0h/0h"),
        ("bitcoin-cash", "m/44h/145h/0h"),
        ("bitcoin-sv", "m/44h/236h/0h"),
        ("ecash", "m/44h/899h/0h"),
        ("ecash-tokens", "m/44h/1899h/0h"),
        ("slp-tokens", "m/44h/245h/0h"),
    ]


def test_an_electrum_result_reads_back() -> None:
    """Electrum's standard reading: its search and account have no purpose."""
    text = dumps(identify(STANDARD, [""], no_share, accounts=1))
    result = forks_dumps(forks(text, Chain(), chain="bitcoin-cash", server="h:1"))
    assert forks_dumps(loads(result, text)) == result


def at_fork_of(n: int, value: object) -> Callable[[dict[str, Any]], None]:
    """Return the edit of the ``at_fork`` member of a used account.

    :param n: the account's position in ``used``.
    :param value: its new value.
    :returns: the edit.
    """
    return lambda document: document["used"][n].__setitem__("at_fork", value)


def in_own_address(key: str, value: object) -> Callable[[dict[str, Any]], None]:
    """Return the edit of a member of the chain's own account's address.

    :param key: the member.
    :param value: its new value.
    :returns: the edit.
    """
    return lambda document: document["used"][1]["addresses"][0].__setitem__(key, value)


VALUE_ERRORS = [
    (setter("format", PLANTED), "format is not 'seed-scan-forks'"),
    (setter("version", 2), "version is not 1"),
    (deleter("chain"), "missing member 'chain'"),
    (setter("bundle", PLANTED), "made from another bundle"),
    (setter("chain", PLANTED), "member 'chain' is not one forks reads"),
    (setter("fork_height", 1), "member 'fork_height' is not the chain's"),
    (setter("server", f"{PLANTED} :1"), "member 'server' is not host:port"),
    (setter("gap_limit", 0), "member 'gap_limit' is below 1"),
    (first("searched", setter("coin", PLANTED)), "member 'coin' is not one forks"),
    (first("searched", setter("coin", "ethereum")), "member 'coin' is not one"),
    # Bitcoin's purpose 84 is a segwit script, which forks does not read
    (first("searched", setter("purpose", 84)), "a search of accounts not read"),
    (first("searched", setter("accounts", 3)), "a search reads no account"),
    (twice, "a purpose searched twice"),
    (first("used", setter("coin", PLANTED)), "member 'coin' is not one forks"),
    # Bitcoin's account read as the chain's own: not that account's path
    (first("used", setter("coin", "bitcoin-cash")), "member 'path' is not"),
    (first("used", setter("account", 2)), "a used account was not searched"),
    (used_twice, "a used account listed twice"),
    (in_address("address", PLANTED), "an address is not the bundle's"),
    (in_own_address("address", PLANTED), "an address is not the bundle's"),
    (in_own_address("index", 1), "an address is not the bundle's"),
    (in_used(setter("confirmed", 21 * 10**14 + 1)), "a balance outside 0 to 21"),
    (in_used(deleter("at_fork")), "missing member 'at_fork'"),
    (at_fork_of(0, -1), "member 'at_fork' is below 0"),
    (at_fork_of(0, 21 * 10**14 + 1), "a balance outside 0 to 21 million bitcoin"),
    # the chain's own account was paid after the fork alone
    (at_fork_of(1, 1), "a balance at the fork no transaction listed gives"),
    # two accounts in the bundle and a gap of 3: the gap cannot be reached
    (first("searched", setter("cut_short", False)), DISAGREE),
    (
        first("not_checked", setter("reason", PLANTED)),
        "an item of 'not_checked' is not one forks writes",
    ),
    (
        first("not_checked", setter("purpose", 44)),
        "an item of 'not_checked' is not one forks writes",
    ),
]


@pytest.mark.parametrize("edit, said", VALUE_ERRORS)
def test_a_result_the_format_does_not_define_is_refused(
    bundle: str, result: str, edit: Callable[[dict[str, Any]], None], said: str
) -> None:
    """Each refusal opens as a forks result's and names the member, unquoted.

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
    assert message.startswith("forks result: ")
    assert said in message
    assert PLANTED not in message
    assert caught.value.__context__ is None


def test_the_bitcoin_address_is_not_the_chain_s_own(bundle: str, result: str) -> None:
    """Bitcoin's address at the position of the chain's own: refused."""
    document = json.loads(result)
    position = document["used"][1]["addresses"][0]
    position["address"] = str(p2pkh("m/44h/0h/0h/0/0").address)
    with pytest.raises(SeedScanValueError, match="an address is not the bundle's"):
        loads(json.dumps(document), bundle)


TYPE_ERRORS = [
    (setter("chain", 1), "member 'chain' of type int"),
    (setter("not_checked", {}), "member 'not_checked' of type dict"),
    (first("searched", setter("coin", None)), "member 'coin' of type NoneType"),
    (at_fork_of(0, 1.0), "member 'at_fork' of type float"),
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
    assert str(caught.value) == f"forks result: {said}"


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
    assert str(caught.value) == f"forks result: {said}"
    assert caught.value.__context__ is None


def test_a_bundle_forks_refuses_is_refused_as_a_bundle(
    bundle: str, result: str
) -> None:
    """A chain's account renumbered: the result agrees with it, the plan not.

    The refusal is the bundle's, as `forks` gives it.
    """
    text = edited(bundle, "m/44h/145h/1h", account=2)
    document = json.loads(result)
    document["bundle"] = sha256(text.encode("utf-8")).hexdigest()
    with pytest.raises(SeedScanValueError) as caught:
        loads(json.dumps(document), text)
    assert str(caught.value) == "bundle: reading 0: accounts not numbered from 0"
