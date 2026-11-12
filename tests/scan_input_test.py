# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The bundle is what `btclib_wallet.bip44`'s account discovery reads.

`seed_scan.scan` reads a bundle with `seed_scan.bundle` alone and hands
it to `discover_account`, and `discover_accounts` reads the same keys.
These tests hand the bundle's keys to both, over a history kept in
memory, so that the format is checked against the reader it is written
for and no test reaches the network.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from btclib.script import ScriptPubKey
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from btclib_wallet.bip44 import discover_account, discover_accounts
from btclib_wallet.descriptors import parse
from btclib_wallet.fetch.history import (
    BlockRef,
    HistoryTx,
    ScriptHistory,
    history_scripts,
)

from seed_scan.bundle import Bundle, dumps, loads
from seed_scan.identify import identify

from .identify_test import ABANDON, SEGWIT, no_share

if TYPE_CHECKING:
    from collections.abc import Iterable

    from btclib.alias import Octets


class Chain:
    """A `HistoryReader` over one block of payments from outside."""

    def __init__(self, *paid: ScriptPubKey) -> None:
        """Put one payment to each script in the block.

        :param paid: the scripts paid.
        """
        self.txs = [
            Tx(
                vin=[TxIn(OutPoint(b"\xff" * 28 + n.to_bytes(4, "big"), 0))],
                vout=[TxOut(10_000, script)],
            )
            for n, script in enumerate(paid)
        ]

    def get_history(
        self, scripts: Iterable[Octets | ScriptPubKey], start_height: int = 0
    ) -> ScriptHistory:
        """Answer the payments to the scripts asked for.

        :param scripts: the scripts asked for.
        :param start_height: the height the read starts from.
        :returns: the payments, in the one block.
        """
        wanted = history_scripts(scripts)
        block = BlockRef(1, b"\x01" * 32)
        txs = tuple(
            HistoryTx(tx, block)
            for tx in self.txs
            if any(out.script_pub_key.script in wanted for out in tx.vout)
        )
        return ScriptHistory(BlockRef(min(start_height, 1), bytes(32)), block, txs)


def read_back(bundle: Bundle) -> Bundle:
    """Write a bundle and read it back, as `scan` gets it.

    :param bundle: what `identify` answered.
    :returns: the bundle `seed_scan.bundle.loads` reads from its text.
    """
    return loads(dumps(bundle))


def test_the_bitcoin_accounts_feed_discover_accounts() -> None:
    """The xpubs by purpose and account, and the fingerprint, are its input."""
    (reading,) = read_back(identify(ABANDON, [""], no_share, accounts=2)).readings
    xpubs: dict[int, list[str]] = {}
    for account in reading.accounts:
        if account.coin == "bitcoin" and account.purpose is not None:
            xpubs.setdefault(account.purpose, []).append(account.xpub)
    bip84 = next(a for a in reading.accounts if a.path == "m/84h/0h/0h")
    paid = parse(bip84.descriptors[0]).script_pub_keys(3)[0]
    found = discover_accounts(
        xpubs, Chain(paid), bytes.fromhex(reading.master_fingerprint)
    )
    assert list(found) == [(84, 0)]
    assert found[84, 0].used == ((3,), ())


def test_an_electrum_account_feeds_discover_account() -> None:
    """Electrum's descriptors, parsed, are what `discover_account` reads."""
    (reading,) = read_back(identify(SEGWIT, [""], no_share, accounts=1)).readings
    (account,) = reading.accounts
    descriptors = [parse(text) for text in account.descriptors]
    paid = descriptors[1].script_pub_keys(0)[0]
    use = discover_account(descriptors, Chain(paid))
    assert use is not None
    assert use.used == ((), (0,))
