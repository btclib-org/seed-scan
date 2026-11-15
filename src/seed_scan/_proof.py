# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Whether a server's tip is on a chain's checkpoint, by valid proof of work.

`btclib_wallet.fetch.electrum.ElectrumFetcher.get_history` proves each
confirmed transaction of a history by its merkle branch, against the
header at its height, and chains each of those headers to the tip it
answers. Each header's hash is within the target its own bits claim.
What the fetcher does not hold the bits to is the chain's rule, and its
chain starts at the server's own lowest header: a server can answer a
chain of its own, at the easiest target the network allows.

`TipProof` closes that gap. A tip is proved where the headers from the
chain's last checkpoint up to it each name the one before as their
parent, the last is the tip, and each after the checkpoint carries the
bits the chain's `Rule` gives it. The checkpoint's block, pinned by its
id, then commits to every block below it, and a block above it costs
the work the chain's rule asks there. So each confirmed transaction of
a history whose tip is proved is in a block of the checkpoint's chain,
and to answer one of its own the server mines a block at the
difficulty the chain's rule gives after the checkpoint.

General, so it goes to btclib-wallet with btclib-org/btclib-wallet#963.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING

from btclib.block.proof_of_work import (
    DIFFICULTY_ADJUSTMENT_INTERVAL,
    bits_from_target,
    block_work,
    next_bits,
    target_from_bits,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from btclib.block.block_header import BlockHeader
    from btclib_wallet.fetch.electrum import ElectrumFetcher
    from btclib_wallet.fetch.history import BlockRef

__all__ = [
    "ASERTI3_2D",
    "BELOW",
    "BITCOIN",
    "CW144",
    "MOVED",
    "OFF",
    "RULES",
    "UNRULED",
    "Rule",
    "TipProof",
]


@dataclass(frozen=True)
class Rule:
    """The bits a chain's header carries, by what the headers before it hold.

    `bits` answers for a height and a callable that returns the header at
    an earlier height, from `lookback` below it up to the one before it.
    """

    lookback: int
    bits: Callable[[int, Callable[[int], BlockHeader]], bytes]


def _seconds(header: BlockHeader) -> int:
    """Return the second a header's timestamp holds, as a node reads it."""
    return int(header.time.timestamp())


def _bitcoin_bits(height: int, header_at: Callable[[int], BlockHeader]) -> bytes:
    """Return the bits of Bitcoin's header at `height`.

    Bitcoin Core's `GetNextWorkRequired` on mainnet: the parent's, except
    at a multiple of `DIFFICULTY_ADJUSTMENT_INTERVAL`, where the period
    from the header that many blocks below to the parent is retargeted by
    `btclib.block.proof_of_work.next_bits`
    (https://github.com/bitcoin/bitcoin/blob/a527a0077a0fcae913188410214efe98021c0cca/src/pow.cpp#L14-L47).
    """
    parent = header_at(height - 1)
    if height % DIFFICULTY_ADJUSTMENT_INTERVAL:
        return parent.bits
    first = header_at(height - DIFFICULTY_ADJUSTMENT_INTERVAL)
    return next_bits(parent.bits, first.time, parent.time)


#: Bitcoin's mainnet rule.
BITCOIN = Rule(lookback=DIFFICULTY_ADJUSTMENT_INTERVAL, bits=_bitcoin_bits)

# the easiest target of Bitcoin Cash, Bitcoin SV and eCash, as their
# nodes hold it, which is Bitcoin's
_POW_LIMIT = 2**224 - 1
# the time a block aims at
_SPACING = 10 * 60

# aserti3-2d's anchor: Bitcoin Cash Node's mainnet parameters, its block
# at 661647, its bits and its parent's time, and the half-life. Bitcoin
# ABC takes the anchor from its block at that height, which eCash shares
# with Bitcoin Cash, as each chain's first block of its own is at 661648.
# https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/e13b48e37b3005dca9a316f75aea456697a5dfd6/src/chainparams.cpp#L105-L108
# https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/e13b48e37b3005dca9a316f75aea456697a5dfd6/src/chainparams.cpp#L168-L172
# https://github.com/Bitcoin-ABC/bitcoin-abc/blob/988b903deb04311b12ba067734dab3ff9f5411a7/src/pow/aserti32d.cpp#L9-L15
_ANCHOR_HEIGHT = 661647
_ANCHOR_BITS = bytes.fromhex("1804dafe")
_ANCHOR_PARENT_TIME = 1605447844
_HALF_LIFE = 2 * 24 * 60 * 60


def _aserti3_2d_bits(height: int, header_at: Callable[[int], BlockHeader]) -> bytes:
    """Return the bits of Bitcoin Cash's or eCash's header at `height`.

    aserti3-2d as Bitcoin Cash Node and Bitcoin ABC write it, from the
    parent's time and height, for a parent at the anchor or above it
    (https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/e13b48e37b3005dca9a316f75aea456697a5dfd6/src/pow.cpp#L101-L267,
    https://github.com/Bitcoin-ABC/bitcoin-abc/blob/988b903deb04311b12ba067734dab3ff9f5411a7/src/pow/aserti32d.cpp#L28-L169).
    The exponent's division truncates toward zero, as C++'s does, and its
    shift floors. A target shifted past 256 bits, which the nodes' check
    of the shift sets to the limit, is clamped to it here.
    """
    parent = header_at(height - 1)
    time_diff = _seconds(parent) - _ANCHOR_PARENT_TIME
    height_diff = height - 1 - _ANCHOR_HEIGHT
    numerator = (time_diff - _SPACING * (height_diff + 1)) * 65536
    exponent = abs(numerator) // _HALF_LIFE
    if numerator < 0:
        exponent = -exponent
    shifts = (exponent >> 16) - 16
    frac = exponent & 0xFFFF
    factor = 65536 + (
        (195766423245049 * frac + 971821376 * frac**2 + 5127 * frac**3 + 2**47) >> 48
    )
    target = int.from_bytes(target_from_bits(_ANCHOR_BITS)) * factor
    target = target << shifts if shifts > 0 else target >> -shifts
    target = min(max(target, 1), _POW_LIMIT)
    return bits_from_target(target.to_bytes(32))


#: Bitcoin Cash's and eCash's rule, aserti3-2d.
ASERTI3_2D = Rule(lookback=1, bits=_aserti3_2d_bits)


def _suitable(height: int, header_at: Callable[[int], BlockHeader]) -> int:
    """Return the height of the median by time of a header and its two parents.

    Bitcoin SV's `GetSuitableBlock`, its sorting network swap for swap.
    """
    blocks = [height - 2, height - 1, height]
    for low, high in ((0, 2), (0, 1), (1, 2)):
        if _seconds(header_at(blocks[low])) > _seconds(header_at(blocks[high])):
            blocks[low], blocks[high] = blocks[high], blocks[low]
    return blocks[1]


def _cw144_bits(height: int, header_at: Callable[[int], BlockHeader]) -> bytes:
    """Return the bits of Bitcoin SV's header at `height`.

    Bitcoin SV's `GetNextCashWorkRequired` and `ComputeTarget`: the work
    of the blocks after the first suitable block up to the last, over the
    time between them, bounded to 72 and 288 spacings, for a parent above
    the height at which Bitcoin SV took the rule up
    (https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/pow.cpp#L95-L118,
    https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/pow.cpp#L177-L297).
    """
    last = _suitable(height - 1, header_at)
    first = _suitable(height - 1 - 144, header_at)
    work = sum(block_work(header_at(h).bits) for h in range(first + 1, last + 1))
    timespan = _seconds(header_at(last)) - _seconds(header_at(first))
    timespan = min(max(timespan, 72 * _SPACING), 288 * _SPACING)
    work = work * _SPACING // timespan
    target = min((2**256 - work) // work, _POW_LIMIT)
    return bits_from_target(target.to_bytes(32))


#: Bitcoin SV's rule, the difficulty adjustment Bitcoin Cash ran from
#: November 2017 to November 2020: its first suitable block is 146
#: headers below the parent at most.
CW144 = Rule(lookback=147, bits=_cw144_bits)

#: The rule of each chain read, by name: ``bitcoin`` for `seed_scan.scan`,
#: and each key of `seed_scan.forks.CHAINS`.
RULES = MappingProxyType(
    {
        "bitcoin": BITCOIN,
        "bitcoin-cash": ASERTI3_2D,
        "bitcoin-sv": CW144,
        "ecash": ASERTI3_2D,
    }
)

#: Why a tip does not prove: below the last checkpoint.
BELOW = "its tip is below the chain's last checkpoint"
#: Why a tip does not prove: not on the last checkpoint's chain.
OFF = "its tip is not on the chain of the last checkpoint"
#: Why a tip does not prove: a header the rule does not give.
UNRULED = "a header carries bits the chain's rule does not give"
#: What a walk answers where the server's tip moved since the history.
MOVED = "the tip moved"


class TipProof:
    """Whether a tip a fetcher answered is on a checkpoint's chain.

    `checkpoint` is a height and the chain's block id there, as hex in
    display order, and `rule` the chain's. The headers come from the
    fetcher's `get_block_headers`, which checks each for the work its
    own bits claim.
    """

    def __init__(
        self, fetcher: ElectrumFetcher, checkpoint: tuple[int, str], rule: Rule
    ) -> None:
        self._fetcher = fetcher
        self._height = checkpoint[0]
        self._id = bytes.fromhex(checkpoint[1])
        self._rule = rule
        # the last tip proved, and the headers up to it the rule reads
        self._proved: BlockRef | None = None
        self._held: dict[int, BlockHeader] = {}

    def refusal(self, tip: BlockRef) -> str:
        """Return why `tip` does not prove, or ``""`` where it does.

        A tip below the checkpoint is `BELOW`, and one at its height that
        is another block `OFF`. Above it, the headers are read from the
        last tip proved, where `tip` descends from it, and otherwise from
        the `Rule.lookback` headers that end at the checkpoint's block.
        Headers that do not each follow the one before, that hold another
        block at the checkpoint, or that do not end at `tip` are `OFF`; a
        header after the checkpoint whose bits are not the rule's is
        `UNRULED`. A walk that fails where the server's tip is no longer
        `tip` is `MOVED`, as a reorganization during the read leaves it.
        """
        if tip == self._proved:
            return ""
        if tip.height <= self._height:
            if tip.height < self._height:
                return BELOW
            if tip.block_id != self._id:
                return OFF
            self._proved, self._held = tip, {}
            return ""
        proved, reason = self._proved, OFF
        if proved is not None and proved.height < tip.height and self._held:
            reason = self._walk(proved.height + 1, tip, self._held)
        if reason == OFF:
            reason = self._walk(max(0, self._height + 1 - self._rule.lookback), tip)
        if reason and self._fetcher.get_best_block_id() != tip.block_id:
            return MOVED
        return reason

    def _walk(
        self, low: int, tip: BlockRef, held: dict[int, BlockHeader] | None = None
    ) -> str:
        """Return why the headers from `low` up do not prove `tip`, or ``""``.

        `held` holds the headers below `low` the rule reads, up to the last
        tip proved, which the header at `low` names as its parent. Once the
        walk proves `tip`, it is the last tip proved, and the headers the
        rule reads up to it are held.
        """
        headers = dict(held or {})
        last = headers[low - 1].hash if held else None
        height = low
        while height <= tip.height:
            chunk = self._fetcher.get_block_headers(height, tip.height - height + 1)
            if not chunk:
                return OFF
            for header in chunk:
                if last is not None and header.previous_block_hash != last:
                    return OFF
                if height == self._height and header.hash != self._id:
                    return OFF
                if height > self._height and header.bits != self._rule.bits(
                    height, headers.__getitem__
                ):
                    return UNRULED
                headers[height] = header
                headers.pop(height - self._rule.lookback, None)
                last = header.hash
                height += 1
        if last != tip.block_id:
            return OFF
        self._proved, self._held = tip, headers
        return ""
