# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `seed_scan.forks`, over a chain kept in memory.

The bundles are `identify`'s, on the vectors `tests/identify_test.py`
names, and each address the result reports is checked against the one
`tests.identify_test.legacy_address` derives by BIP32 alone.
"""

from __future__ import annotations

import json
from hashlib import sha256
from typing import TYPE_CHECKING

import pytest
from bip32_descriptors.bip32 import BIP32KeyData
from bip39_slip39 import bip39
from btclib.script import ScriptPubKey
from btclib_wallet.descriptors import parse
from btclib_wallet.fetch.history import BlockRef, HistoryTx, ScriptHistory

from seed_scan import forks as forks_module
from seed_scan.bundle import dumps, loads
from seed_scan.exceptions import SeedScanTypeError, SeedScanValueError
from seed_scan.forks import (
    BITCOIN_CASH,
    BITCOIN_SV,
    CHAINS,
    ECASH,
    FORMAT,
    VERSION,
    ForkSearched,
    Skipped,
    forks,
)
from seed_scan.identify import identify
from seed_scan.scan import Address

from .identify_test import ABANDON, SEGWIT, STANDARD, legacy_address, no_share
from .no_secret_test import Secrets, assert_text_secret_free
from .scan_test import ELSEWHERE, Chain, edited, pay

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator

    from btclib.alias import Octets

#: The last block Bitcoin and Bitcoin Cash share, and the first that is
#: Bitcoin Cash's alone.
SHARED = BlockRef(BITCOIN_CASH.fork_height - 1, b"\x01" * 32)
OWN = BlockRef(BITCOIN_CASH.fork_height, b"\x02" * 32)

#: Why a Bitcoin account of a segwit script is not read on Bitcoin Cash.
NO_WITNESS = (
    "a segwit script: Bitcoin Cash's transactions carry no witness, so a key"
    " does not sign for it there"
)

#: A reader no refusal may reach.
NEVER = Chain()

#: A CashTokens token prefix, one fungible token of category aa..aa: the
#: first valid prefix of the specification's vectors,
#: https://github.com/cashtokens/cashtokens/blob/41d2444c17bbfb456d4061953a3ed0e32161571b/test-vectors/token-prefix-valid.json
TOKEN_PREFIX = bytes.fromhex("ef" + "aa" * 32 + "1001")

#: A 1Sat Ordinals inscription of a BSV-20 transfer, in the envelope of
#: the specification's README,
#: https://github.com/BitcoinSchema/1sat-ordinals/blob/4f6d8d78d90acd807843cd254a9068586c793c20/README.md?plain=1#L18-L32
_TRANSFER = b'{"p":"bsv-20","op":"transfer","tick":"ordi","amt":"100"}'
INSCRIPTION = (
    bytes.fromhex("0063036f726451")
    + bytes([18])
    + b"application/bsv-20"
    + b"\x00"
    + bytes([len(_TRANSFER)])
    + _TRANSFER
    + b"\x68"
)

#: Each way a protocol of Bitcoin SV writes its tokens in the script of
#: the output holding them, as `seed_scan.forks` cites them, built from
#: the P2PKH of the owner's key: STAS's, which goes on after it; STAS 3's,
#: which starts with its key hash; and an inscription after or before it.
IN_SCRIPT: dict[str, Callable[[bytes], bytes]] = {
    "stas": lambda p2pkh: p2pkh + bytes.fromhex("6976aa607f5f7f7c"),
    "stas 3": lambda p2pkh: b"\x14" + p2pkh[3:23] + bytes.fromhex("006d827363"),
    "inscription after": lambda p2pkh: p2pkh + INSCRIPTION,
    "inscription before": lambda p2pkh: INSCRIPTION + p2pkh,
}


class Listing:
    """A reader that lists the same transactions whatever it is asked.

    As a server indexing an output carrying tokens under its script alone
    would list it.
    """

    def __init__(self, *entries: HistoryTx) -> None:
        """Keep the transactions.

        :param entries: the transactions and their blocks.
        """
        self.entries = entries

    def get_history(
        self, scripts: Iterable[Octets | ScriptPubKey], start_height: int = 0
    ) -> ScriptHistory:
        """Answer every transaction kept.

        :param scripts: unread.
        :param start_height: the height the read starts from.
        :returns: the transactions, up to a tip past them.
        """
        return ScriptHistory(BlockRef(start_height, bytes(32)), OWN, self.entries)


@pytest.fixture(autouse=True)
def never_asked() -> Iterator[None]:
    """Fail a test after which `NEVER` was asked anything.

    :yields: once the test has run.
    """
    yield
    assert NEVER.asked == 0


@pytest.fixture(scope="module")
def abandon() -> str:
    """Return the bundle of BIP84's mnemonic, five accounts of each purpose.

    :returns: its text.
    """
    return dumps(identify(ABANDON, [""], no_share, accounts=5))


def p2pkh(path: str) -> ScriptPubKey:
    """Return the P2PKH script of the key at a path of BIP84's mnemonic.

    :param path: the full derivation path.
    :returns: the script whose address `legacy_address` gives.
    """
    return ScriptPubKey.from_address(legacy_address(path))


def test_the_chain_s_own_account_and_bitcoin_s_are_read(abandon: str) -> None:
    """Coins held at the fork, spent since, and coins received since."""
    bitcoin = p2pkh("m/44h/0h/0h/0/0")
    own = p2pkh("m/44h/145h/0h/0/1")
    held = pay(1, (bitcoin, 10_000))
    spent = pay(2, (bitcoin, 4_000), (ELSEWHERE, 5_000), spends=held)
    received = pay(3, (own, 7_000))
    chain = Chain(
        HistoryTx(held, SHARED), HistoryTx(spent, OWN), HistoryTx(received, OWN)
    )
    result = forks(abandon, chain, chain="bitcoin-cash", server="h:1")
    first, second = result.used
    assert (first.coin, first.path, first.purpose) == ("bitcoin", "m/44h/0h/0h", 44)
    assert first.addresses == (
        Address(0, 0, legacy_address("m/44h/0h/0h/0/0"), 4_000, 0),
    )
    assert (first.confirmed, first.unconfirmed, first.at_fork) == (4_000, 0, 10_000)
    assert [t.height for t in first.transactions] == [SHARED.height, OWN.height]
    assert (second.coin, second.path) == ("bitcoin-cash", "m/44h/145h/0h")
    assert second.addresses == (
        Address(0, 1, legacy_address("m/44h/145h/0h/0/1"), 7_000, 0),
    )
    assert (second.confirmed, second.at_fork) == (7_000, 0)


@pytest.mark.parametrize("chain", list(CHAINS))
def test_each_chain_reads_the_accounts_of_every_chain(abandon: str, chain: str) -> None:
    """A payment at Bitcoin's path and at each chain's coin type is found.

    Bitcoin SV and eCash each hold Bitcoin Cash's blocks up to their
    split, and a base58 address spells one script on each, so each reads
    every chain's coin. Each counts at the fork from Bitcoin, Bitcoin SV's
    and eCash's included.

    :param abandon: the bundle.
    :param chain: the chain read.
    """
    paths = ["m/44h/0h/0h", "m/44h/145h/0h", "m/44h/236h/0h", "m/44h/899h/0h"]
    chain_read = Chain(
        HistoryTx(pay(1, *((p2pkh(f"{path}/0/0"), 1) for path in paths)), SHARED)
    )
    result = forks(abandon, chain_read, chain=chain, server="h:1")
    assert [(u.coin, u.path, u.at_fork) for u in result.used] == [
        ("bitcoin", "m/44h/0h/0h", 1),
        ("bitcoin-cash", "m/44h/145h/0h", 1),
        ("bitcoin-sv", "m/44h/236h/0h", 1),
        ("ecash", "m/44h/899h/0h", 1),
    ]
    assert result.fork_height == BITCOIN_CASH.fork_height


@pytest.mark.parametrize("fork", [BITCOIN_SV, ECASH])
def test_a_later_fork_s_segwit_accounts_are_not_checked(
    abandon: str, fork: forks_module.Chain
) -> None:
    """The reason names the chain read.

    :param abandon: the bundle.
    :param fork: the chain read.
    """
    result = forks(abandon, Chain(), chain=fork.name, server="h:1")
    reason = NO_WITNESS.replace("Bitcoin Cash", fork.title)
    assert result.not_checked == tuple(
        Skipped(0, "bitcoin", purpose, reason) for purpose in (49, 84, 86)
    )
    assert result.chain == fork.name


def test_the_fork_height_is_the_first_block_not_counted(abandon: str) -> None:
    """A payment in the last shared block counts at the fork; one after not.

    A payment in the mempool counts neither at the fork nor as confirmed.
    """
    script = p2pkh("m/44h/0h/0h/0/0")
    chain = Chain(
        HistoryTx(pay(1, (script, 1)), SHARED),
        HistoryTx(pay(2, (script, 20)), OWN),
        HistoryTx(pay(3, (script, 300)), None),
    )
    (used,) = forks(abandon, chain, chain="bitcoin-cash", server="h:1").used
    assert (used.at_fork, used.confirmed, used.unconfirmed) == (1, 21, 300)


def test_a_spend_before_the_fork_is_not_held_at_it(abandon: str) -> None:
    """Paid and spent in shared blocks: nothing is held at the fork."""
    script = p2pkh("m/44h/0h/0h/0/0")
    paid = pay(1, (script, 50))
    chain = Chain(
        HistoryTx(paid, SHARED), HistoryTx(pay(2, (ELSEWHERE, 50), spends=paid), SHARED)
    )
    (used,) = forks(abandon, chain, chain="bitcoin-cash", server="h:1").used
    assert (used.at_fork, used.confirmed) == (0, 0)


def test_an_output_carrying_tokens_is_not_counted(abandon: str) -> None:
    """Its prefix is part of the script it pays, which is not the account's.

    The account is used through the plain payment beside it, and neither
    its balance now nor at the fork holds the token output's satoshis.
    """
    plain = p2pkh("m/44h/145h/0h/0/0")
    token = ScriptPubKey(TOKEN_PREFIX + plain.script)
    chain = Chain(HistoryTx(pay(1, (plain, 1_000), (token, 800)), SHARED))
    (used,) = forks(abandon, chain, chain="bitcoin-cash", server="h:1").used
    assert (used.confirmed, used.at_fork) == (1_000, 1_000)
    assert used.addresses == (
        Address(0, 0, legacy_address("m/44h/145h/0h/0/0"), 1_000, 0),
    )


def test_an_account_paid_only_through_tokens_reads_as_unused(abandon: str) -> None:
    """Listed under the account's script, the payment still pays another."""
    token = ScriptPubKey(TOKEN_PREFIX + p2pkh("m/44h/145h/0h/0/0").script)
    chain = Listing(HistoryTx(pay(1, (token, 800)), SHARED))
    assert not forks(abandon, chain, chain="bitcoin-cash", server="h:1").used


@pytest.mark.parametrize("shape", IN_SCRIPT.values(), ids=IN_SCRIPT.keys())
def test_bitcoin_sv_tokens_in_the_script_leave_the_account_unused(
    abandon: str, shape: Callable[[bytes], bytes]
) -> None:
    """Listed under the account's script, the token output pays another."""
    token = ScriptPubKey(shape(p2pkh("m/44h/236h/0h/0/0").script))
    chain = Listing(HistoryTx(pay(1, (token, 1_000)), OWN))
    assert not forks(abandon, chain, chain="bitcoin-sv", server="h:1").used


def test_an_output_beside_an_op_return_is_counted(abandon: str) -> None:
    """SLP, Run and Tokenized write tokens apart from the P2PKH holding them."""
    op_return = ScriptPubKey(bytes.fromhex("006a03") + b"run")
    plain = p2pkh("m/44h/236h/0h/0/0")
    chain = Chain(HistoryTx(pay(1, (op_return, 0), (plain, 546)), OWN))
    (used,) = forks(abandon, chain, chain="bitcoin-sv", server="h:1").used
    assert (used.confirmed, used.at_fork) == (546, 0)


def test_nothing_used_reads_each_p2pkh_purpose_and_lists_the_segwit_ones(
    abandon: str,
) -> None:
    """Bitcoin's purpose 44 and the chain's own; the rest not checked.

    The bundle's other coins are not listed: they are `scan`'s.
    """
    result = forks(abandon, Chain(), chain="bitcoin-cash", server="h:1")
    assert not result.used
    assert result.searched == (
        ForkSearched(0, "bitcoin", 44, 3, cut_short=False),
        ForkSearched(0, "bitcoin-cash", 44, 3, cut_short=False),
        ForkSearched(0, "bitcoin-sv", 44, 3, cut_short=False),
        ForkSearched(0, "ecash", 44, 3, cut_short=False),
    )
    assert result.not_checked == tuple(
        Skipped(0, "bitcoin", purpose, NO_WITNESS) for purpose in (49, 84, 86)
    )


def test_a_purpose_cut_short_where_the_accounts_end(abandon: str) -> None:
    """The chain's accounts 0 and 2 used: they end before the gap."""
    first = p2pkh("m/44h/145h/0h/0/0")
    third = p2pkh("m/44h/145h/2h/1/0")
    chain = Chain(HistoryTx(pay(1, (first, 1), (third, 1)), OWN))
    result = forks(abandon, chain, chain="bitcoin-cash", server="h:1")
    assert [u.path for u in result.used] == ["m/44h/145h/0h", "m/44h/145h/2h"]
    assert ForkSearched(0, "bitcoin-cash", 44, 5, cut_short=True) in result.searched


def test_the_bounds_are_the_ones_given(abandon: str) -> None:
    """A payment at index 3 is past a gap limit of 3, and found with 4."""
    script = p2pkh("m/44h/145h/0h/0/3")
    chain = Chain(HistoryTx(pay(1, (script, 1)), OWN))
    assert not forks(
        abandon, chain, chain="bitcoin-cash", server="h:1", gap_limit=3
    ).used
    result = forks(
        abandon, chain, chain="bitcoin-cash", server="h:1", gap_limit=4, account_gap=1
    )
    assert [u.path for u in result.used] == ["m/44h/145h/0h"]
    assert ForkSearched(0, "bitcoin", 44, 1, cut_short=False) in result.searched


def test_electrum_s_standard_reading_is_read_and_its_segwit_one_is_not() -> None:
    """The standard reading's addresses are P2PKH, the segwit one's are not."""
    standard = dumps(identify(STANDARD, [""], no_share, accounts=1))
    (account,) = loads(standard).readings[0].accounts
    change = parse(account.descriptors[1]).script_pub_keys(0)[0]
    chain = Chain(HistoryTx(pay(1, (change, 5)), SHARED))
    result = forks(standard, chain, chain="bitcoin-cash", server="h:1")
    assert result.searched == (ForkSearched(0, "bitcoin", None, 1, cut_short=False),)
    (used,) = result.used
    assert (used.purpose, used.at_fork) == (None, 5)
    segwit = dumps(identify(SEGWIT, [""], no_share, accounts=1))
    result = forks(segwit, Chain(), chain="bitcoin-cash", server="h:1")
    assert (result.searched, result.used) == ((), ())
    assert result.not_checked == (Skipped(0, "bitcoin", None, NO_WITNESS),)


def test_the_result_is_versioned_json_naming_the_bundle_and_the_chain(
    abandon: str,
) -> None:
    """`dumps` writes the format, the version, the digest, the chain."""
    result = forks(abandon, Chain(), chain="bitcoin-cash", server="node.local:50002")
    document = json.loads(forks_module.dumps(result))
    assert list(document) == [
        "format",
        "version",
        "bundle",
        "chain",
        "server",
        "fork_height",
        "gap_limit",
        "account_gap",
        "searched",
        "used",
        "not_checked",
    ]
    assert (document["format"], document["version"]) == (FORMAT, VERSION)
    assert document["bundle"] == sha256(abandon.encode()).hexdigest()
    assert (document["chain"], document["server"]) == (
        "bitcoin-cash",
        "node.local:50002",
    )
    assert document["fork_height"] == BITCOIN_CASH.fork_height


def test_a_used_account_s_members_follow_scan_s(abandon: str) -> None:
    """The coin first, `scan`'s members, then what was held at the fork."""
    script = p2pkh("m/44h/145h/0h/0/0")
    chain = Chain(HistoryTx(pay(1, (script, 1)), OWN))
    result = forks(abandon, chain, chain="bitcoin-cash", server="h:1")
    (used,) = json.loads(forks_module.dumps(result))["used"]
    assert list(used) == [
        "coin",
        "reading",
        "purpose",
        "account",
        "path",
        "addresses",
        "transactions",
        "confirmed",
        "unconfirmed",
        "tip",
        "at_fork",
    ]


def test_nothing_forks_writes_holds_a_secret(abandon: str) -> None:
    """No piece of the mnemonic's secrets is in the forks result."""
    chain = Chain(HistoryTx(pay(1, (p2pkh("m/44h/145h/0h/0/0"), 1)), OWN))
    text = forks_module.dumps(forks(abandon, chain, chain="bitcoin-cash", server="h:1"))
    assert '"used": [\n    {' in text
    secrets = Secrets()
    secrets.sentence(ABANDON)
    paths = sorted({a.path for r in loads(abandon).readings for a in r.accounts})
    secrets.seed(bip39.seed_from_mnemonic(ABANDON, ""), paths)
    assert_text_secret_free(text, secrets.every())


def test_a_double_spend_in_both_reads_is_refused(abandon: str) -> None:
    """Read again once, as `scan` reads it, and refused the second time.

    :param abandon: the bundle.
    """
    paid = pay(1, (p2pkh("m/44h/145h/0h/0/0"), 10_000))
    change = p2pkh("m/44h/145h/0h/1/0")
    chain = Chain(
        HistoryTx(paid, OWN),
        HistoryTx(pay(0, (change, 9_000), spends=paid), None),
        HistoryTx(pay(0, (change, 8_000), spends=paid), None),
    )
    err_msg = (
        "^reading 0, account m/44h/145h/0h: "
        "two transactions spend one output, in both reads of it$"
    )
    with pytest.raises(SeedScanValueError, match=err_msg):
        forks(abandon, chain, chain="bitcoin-cash", server="h:1")


#: 15 million bitcoin, in satoshis: two of them pass 21 million.
FIFTEEN_MILLION = 15 * 10**14


def past_the_bound(abandon: str, case: str) -> tuple[Chain, str]:
    """Return a history whose balance, or holding at the fork, passes the bound.

    :param abandon: the bundle.
    :param case: ``"balance"``, two payments in the chain's own blocks to
        its own account; ``"at_fork"``, two in shared blocks to Bitcoin's,
        one spent since, so that the balance is within the bound.
    :returns: the history, and the path of the account refused.
    """
    path = "m/44h/145h/0h" if case == "balance" else "m/44h/0h/0h"
    block = OWN if case == "balance" else SHARED
    script = p2pkh(f"{path}/0/0")
    first, second = (pay(n, (script, FIFTEEN_MILLION)) for n in (1, 2))
    entries = [HistoryTx(first, block), HistoryTx(second, block)]
    if case == "at_fork":
        spend = pay(3, (ELSEWHERE, FIFTEEN_MILLION), spends=first)
        entries.append(HistoryTx(spend, OWN))
    return Chain(*entries), path


@pytest.mark.parametrize("case", ["balance", "at_fork"])
def test_a_balance_past_21_million_bitcoin_is_refused(abandon: str, case: str) -> None:
    """Refused as `seed_scan.scan` refuses one, naming the account alone.

    :param abandon: the bundle.
    :param case: which of the two passes the bound.
    """
    chain, path = past_the_bound(abandon, case)
    err_msg = f"^reading 0, account {path}: a balance outside 0 to 21 million bitcoin$"
    with pytest.raises(SeedScanValueError, match=err_msg):
        forks(abandon, chain, chain="bitcoin-cash", server="h:1")


def test_a_chain_s_xpub_off_the_curve_is_refused(abandon: str) -> None:
    """Its descriptors are built here, and `parse` refuses its key, unquoted.

    Its x is 5, and 5**3 + 7 is no square modulo secp256k1's prime, so no
    point has it: the xpub's version, length, checksum and prefix are
    valid, and `loads` reads it.
    """
    (xpub,) = [
        a.xpub for a in loads(abandon).readings[0].accounts if a.path == "m/44h/145h/1h"
    ]
    data = BIP32KeyData.b58decode(xpub, check_validity=False)
    off_curve = BIP32KeyData(
        data.version,
        data.depth,
        data.parent_fingerprint,
        data.index,
        data.chain_code,
        b"\x02" + (5).to_bytes(32, "big"),
        check_validity=False,
    ).b58encode(check_validity=False)
    text = edited(abandon, "m/44h/145h/1h", xpub=off_curve)
    loads(text)
    with pytest.raises(SeedScanValueError) as caught:
        forks(text, NEVER, chain="bitcoin-cash", server="h:1")
    assert str(caught.value).endswith(": a descriptor that does not parse")
    assert off_curve not in str(caught.value)
    assert caught.value.__context__ is None


@pytest.mark.parametrize(
    "path", ["m/44h/145h/1h", "m/44h/236h/1h", "m/44h/899h/1h", "m/44h/0h/1h"]
)
def test_accounts_not_numbered_from_0_are_refused(abandon: str, path: str) -> None:
    """A coin and purpose's accounts are 0 to n - 1, in order.

    :param abandon: the bundle.
    :param path: the account renumbered.
    """
    text = edited(abandon, path, account=2)
    with pytest.raises(SeedScanValueError, match="accounts not numbered from 0"):
        forks(text, NEVER, chain="bitcoin-cash", server="h:1")


def test_an_electrum_reading_with_two_accounts_is_refused() -> None:
    """Electrum's layout has one account."""
    document = json.loads(dumps(identify(STANDARD, [""], no_share, accounts=1)))
    accounts = document["readings"][0]["accounts"]
    accounts.append(dict(accounts[0], account=1))
    with pytest.raises(SeedScanValueError, match="accounts not numbered from 0"):
        forks(json.dumps(document), NEVER, chain="bitcoin-cash", server="h:1")


def test_a_text_that_is_no_bundle_is_refused() -> None:
    """`seed_scan.bundle.loads` refuses it, quoting nothing of it."""
    with pytest.raises(SeedScanValueError) as caught:
        forks(ABANDON, NEVER, chain="bitcoin-cash", server="h:1")
    assert ABANDON.split()[0] not in str(caught.value)


def test_a_chain_forks_does_not_read_is_refused_unquoted(abandon: str) -> None:
    """Bitcoin is no chain forked from Bitcoin."""
    assert "bitcoin" not in CHAINS
    with pytest.raises(SeedScanValueError) as caught:
        forks(abandon, NEVER, chain=ABANDON, server="h:1")
    assert str(caught.value) == "invalid chain: not one forks reads"


@pytest.mark.parametrize(
    "arguments, error",
    [
        ({"gap_limit": 0}, SeedScanValueError),
        ({"account_gap": 0}, SeedScanValueError),
        ({"gap_limit": True}, SeedScanTypeError),
        ({"account_gap": 1.0}, SeedScanTypeError),
        ({"server": None}, SeedScanTypeError),
        ({"server": "node.local"}, SeedScanValueError),
        ({"chain": None}, SeedScanTypeError),
    ],
)
def test_the_arguments_are_checked_before_the_reader_is_asked(
    abandon: str, arguments: dict[str, object], error: type[Exception]
) -> None:
    """A bound below 1, a server not host:port, a value of a wrong type.

    :param abandon: the bundle.
    :param arguments: the arguments given beside the bundle and the reader.
    :param error: what is raised.
    """
    given: dict[str, object] = {"chain": "bitcoin-cash", "server": "h:1", **arguments}
    with pytest.raises(error):
        forks(abandon, NEVER, **given)  # type: ignore[arg-type]
