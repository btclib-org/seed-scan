# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `seed_scan._proof`: each chain's rule, and the proof of a tip.

Each rule is checked against real headers of its chain, each naming the
one before it, and a test checks that the vectors of Bitcoin, Bitcoin
Cash and eCash hold the last checkpoint the tree pins. The proof of a
tip is checked against a fake Electrum server of a chain mined here at
regtest's easiest target, whose proof of work a test can produce,
through an `ElectrumFetcher` on regtest, and a rule of the test's own
that reads headers below the one it answers for.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest
from btclib.block.block_header import BlockHeader
from btclib.block.proof_of_work import REGTEST_POW_LIMIT_BITS, target_from_bits
from btclib_wallet.fetch.electrum import ElectrumFetcher
from btclib_wallet.fetch.history import BlockRef

from seed_scan import cli
from seed_scan._proof import (
    ASERTI3_2D,
    BELOW,
    BITCOIN,
    CW144,
    MOVED,
    OFF,
    RULES,
    UNRULED,
    Rule,
    TipProof,
)
from seed_scan.forks import BITCOIN_CASH, BITCOIN_SV, CHAINS, ECASH

from .forks_cli_test import BCH_661648, XEC_HEADERS
from .forks_cli_test import HEADERS as BCH_HEADERS
from .scan_cli_test import HEADERS as BTC_HEADERS

#: Bitcoin's headers, as mempool.space answers them for the id it gives
#: at each height: the command's checkpoint and the one after it, and
#: for the first retarget after it, the first and last headers of the
#: period it measures and the header it gives the bits of.
BITCOIN_HEADERS = {
    965000: BTC_HEADERS[965000],
    963648: (
        "0000ff3f331fea1f0be79c6037c580aabc7ac324e9134ce49ed2000000000000"
        "00000000901420fd0a4f3e9cab31eafeeea59d316e9d9f7e0bc77a11bbb40e71"
        "2a72b9ea6f438a6ac13c0217f3f95d66"
    ),
    965001: (
        "0000f032a97db9900bc3cc313e07b4c9f52961e50c00e6775959010000000000"
        "00000000b99d7a866bd294075f980c71248a3c954d24c9f80aca363e34a7c040"
        "452c1cd54875966ac13c021726e5b874"
    ),
    965663: (
        "00e0ff3f1f794b41e367a663f9d1a625c7f90bf0ab4f5ca52731000000000000"
        "00000000c0aeecb56b60788c4f9d0180ac82eeed79751ede9729db9f2ffb4046"
        "8eb9cd5f847b9c6ac13c0217c23bddeb"
    ),
    965664: (
        "0020f4228a1af9368ebe5ed1fd29c4715449c63d429303e4c835000000000000"
        "000000006d04326138d4832a5bdcc1ec8cf510b8feb9fd538f5cd7d2666e5a20"
        "7bc0dce66f7c9c6a5e3502179d9b6e7c"
    ),
}

#: Bitcoin Cash's block 661647, the anchor of aserti3-2d, with the block
#: before it and the one after, and its checkpoint and the block after
#: it, as Fulcrum servers of that chain answer them.
CASH_HEADERS = {
    661646: (
        "00000020ac1d4c0fdf21cfcba41d0bb00802ed3020befbedb8bbd70000000000"
        "0000000008979c37cc3ff63198dc807c3b710f9df37fdc843b0db9de41bc78db"
        "e5279f14a430b15f3ec00418d1623dd0"
    ),
    661647: (
        "000000202df7a2e0562ebbbd8dc95ca6669c4f1ba888484c2cc7e40300000000"
        "0000000067418c23d8901e49555725fb2e37adfb9ed29a05833eb4774d53b63b"
        "44ba457e8937b15ffeda04183c2b1978"
    ),
    661648: BCH_661648,
    970892: BCH_HEADERS[970892],
    970893: (
        "0060aa24d88ca6c0265193845969a146db82b2d2bb4e7fe57062e70000000000"
        "00000000e5559d72690fbf382b2d9b47dd97aac37a5f18da641b11529c87bf3a"
        "c429ec430655bd6a042602183b547ba5"
    ),
}

#: eCash's block after its checkpoint, as a server of Electrum ABC's list
#: answers it.
ECASH_HEADERS = {
    949200: XEC_HEADERS[949200],
    949201: (
        "00000032a2cb86483cdf3738c2a7086cf0e2bba8db9051816045699800000000"
        "000000004ad986baf11157484407d0e3148c0c40ef35a83bebacce5c1960e9d2"
        "a6bd8373ea1c076a5b9f0019468c18b1"
    ),
}

#: The time and the bits of Bitcoin SV's headers from 772893 up to its
#: checkpoint, four bytes each, as hex in display order, header after
#: header: WhatsOnChain answered each header's fields walking back from
#: 773041, and each rebuilt header hashed to the id asked.
SV_TIMES_AND_BITS = (
    "63b26ce5180cb2bd63b26e4d180ca76b63b26f3d180cddfd63b274dd180ce82d"
    "63b27681180ce10363b27735180d096763b27ac2180d143d63b27be5180d01d3"
    "63b27e3d180cffa563b2801d180ce1b763b28455180ce5f163b28581180cee3a"
    "63b28671180cc4bf63b28851180cc5da63b28db5180cbc2163b29445180cbaa5"
    "63b294bd180ce59063b29742180d130c63b29841180d0abf63b2996d180d10b7"
    "63b299e5180d181e63b29a21180d1cd163b29ac7180d1f4563b29b14180cc559"
    "63b29c3d180cc6aa63b29c61180cb13963b29ca0180c9c4563b2a039180c7afc"
    "63b2a1a1180c710363b2a1dd180c8c3e63b2a1fc180c914563b2a200180c8e06"
    "63b2a219180c87b063b2a95d180c6c3063b2a999180c669663b2aca5180c9fe8"
    "63b2aefd180c6ca963b2b0a1180c636b63b2b191180c661363b2b209180c6f1e"
    "63b2b2bd180c2a9763b2b551180c082963b2b605180c06b163b2b641180bf764"
    "63b2b989180bcf8263b2b9c5180bb4d063b2bb69180bcd3863b2bdc1180ba589"
    "63b2bdfd180b86e663b2bf29180b947163b2bfaf180b83ac63b2c022180b83ad"
    "63b2c5f5180b82e763b2c8b8180b787d63b2ca69180ba2fa63b2d009180b9fef"
    "63b2d0bd180b9b4563b2d29d180bc82263b2d531180bc5e163b2d6d5180bd1e4"
    "63b2d8b5180be5da63b2da95180beed863b2db49180be84863b2dd65180bf373"
    "63b2dddd180bf5a563b2df81180c036b63b2eb75180bf46d63b2ed55180bfff5"
    "63b2f205180c46dc63b2f769180c4dfc63b2f7a5180c4ca063b2f81d180c7307"
    "63b2fa39180c602763b2fb29180c5d1063b2fccd180c578b63b3008d180c5e29"
    "63b30579180c690e63b305f1180c5af063b30975180c81b363b30b19180c6f96"
    "63b30cf9180c6adc63b30e9d180c618a63b30ed9180c632963b310f5180c5540"
    "63b314b5180c52f663b317c1180c5e9463b31b45180c621563b31b64180c6162"
    "63b31dd9180c7f2863b31e51180c722963b32211180c5cbc63b32919180c2c3d"
    "63b32a81180c480a63b32e41180c81c763b32e7d180c5df763b33099180c551e"
    "63b33369180c382d63b334d1180c407063b33549180c441363b33675180c47dc"
    "63b33d41180c316063b3431d180c397063b34449180c6aad63b34575180c6a0c"
    "63b348bd180c602563b34b15180c5a6063b34bc9180bf6b563b34cb9180c0488"
    "63b35079180bd6b963b350f1180bdd7263b35169180beee863b3530d180bcc49"
    "63b35a51180babed63b3611d180b84a263b363b1180bbf5063b36735180bfcc0"
    "63b36a41180bf31763b36d11180bbec463b36d3c180bce5263b36e79180bdf12"
    "63b36fe1180bc5db63b37d79180bca6363b37f1d180bcc2b63b383cd180c418a"
    "63b38535180c3aea63b38841180c23b263b388b9180c305463b3896d180c3ead"
    "63b38b11180bffd363b39469180beec363b3977d180bee6a63b397f5180c3c14"
    "63b39f39180c4fb363b3a1cd180c4bd663b3a209180c830363b3a245180c9518"
    "63b3a2f9180c4be463b3a515180c04f663b3a731180c051863b3a911180bf0be"
    "63b3aa79180bf00363b3ad0d180bfc0963b3ae75180bfd2b63b3ae94180c0b72"
    "63b3ae9b180be57b63b3b2ad180be4a163b3b2e9180bac0963b3b84d180bc37c"
)

#: The bits of Bitcoin SV's header at 773041, the one after its checkpoint.
SV_773041_BITS = bytes.fromhex("180bbaed")


def parsed(headers: dict[int, str]) -> dict[int, BlockHeader]:
    """Return headers given as hex, parsed.

    :param headers: the headers by height.
    :returns: the same, parsed.
    """
    return {h: BlockHeader.parse(bytes.fromhex(x)) for h, x in headers.items()}


def bare(time: int, bits: bytes) -> BlockHeader:
    """Return a header holding a time and bits, its other fields zero.

    :param time: the seconds.
    :param bits: the bits.
    :returns: the header.
    """
    return BlockHeader(
        version=1,
        previous_block_hash=bytes(32),
        merkle_root=bytes(32),
        time=datetime.fromtimestamp(time, UTC),
        bits=bits,
        nonce=0,
    )


def sv_headers() -> dict[int, BlockHeader]:
    """Return `SV_TIMES_AND_BITS` as headers holding them, by height.

    :returns: the headers.
    """
    raw = bytes.fromhex("".join(SV_TIMES_AND_BITS))
    return {
        772893 + k: bare(
            int.from_bytes(raw[8 * k : 8 * k + 4]), raw[8 * k + 4 : 8 * k + 8]
        )
        for k in range(len(raw) // 8)
    }


def test_every_chain_read_has_a_rule() -> None:
    """Bitcoin's, for scan, and each chain of forks."""
    assert set(RULES) == {"bitcoin", *CHAINS}
    assert RULES["bitcoin"] is BITCOIN
    assert RULES[BITCOIN_CASH.name] is RULES[ECASH.name] is ASERTI3_2D
    assert RULES[BITCOIN_SV.name] is CW144


def test_each_vector_names_its_parent() -> None:
    """Each header of a vector, after its first, names the one before."""
    for headers in (
        parsed(BITCOIN_HEADERS),
        parsed(CASH_HEADERS),
        parsed(ECASH_HEADERS),
    ):
        for height, header in headers.items():
            if height - 1 in headers:
                assert header.previous_block_hash == headers[height - 1].hash


def test_the_vectors_start_at_the_checkpoints() -> None:
    """Each holds the block of the chain's last checkpoint."""
    assert (
        parsed(BITCOIN_HEADERS)[965000].hash.hex() == max(cli._BITCOIN_CHECKPOINTS)[1]
    )
    assert parsed(CASH_HEADERS)[970892].hash.hex() == max(BITCOIN_CASH.checkpoints)[1]
    assert parsed(ECASH_HEADERS)[949200].hash.hex() == max(ECASH.checkpoints)[1]


def test_bitcoin_keeps_its_bits_inside_a_period() -> None:
    """The header after the checkpoint carries its parent's bits."""
    headers = parsed(BITCOIN_HEADERS)
    assert BITCOIN.bits(965001, headers.__getitem__) == headers[965001].bits


def test_bitcoin_retargets_at_a_period_s_end() -> None:
    """965664 retargets the period from 963648 to 965663."""
    headers = parsed(BITCOIN_HEADERS)
    assert headers[965664].bits != headers[965663].bits
    assert BITCOIN.bits(965664, headers.__getitem__) == headers[965664].bits


@pytest.mark.parametrize(
    "headers, height",
    [(CASH_HEADERS, 661648), (CASH_HEADERS, 970893), (ECASH_HEADERS, 949201)],
)
def test_aserti3_2d_gives_the_chain_s_bits(
    headers: dict[int, str], height: int
) -> None:
    """The block after the anchor, and after each chain's checkpoint.

    :param headers: the chain's headers.
    :param height: the height of the header whose bits are given.
    """
    chain = parsed(headers)
    assert ASERTI3_2D.bits(height, chain.__getitem__) == chain[height].bits


def test_aserti3_2d_s_anchor_is_bitcoin_cash_s_block() -> None:
    """661647 holds the anchor's bits, and its parent the anchor's time.

    A parent at the anchor's height, timed on the schedule from that
    time, keeps the anchor's bits.
    """
    cash = parsed(CASH_HEADERS)
    assert cash[661647].bits == bytes.fromhex("1804dafe")
    assert int(cash[661646].time.timestamp()) == 1605447844
    on_schedule = {661647: bare(1605447844 + 600, cash[661647].bits)}
    assert ASERTI3_2D.bits(661648, on_schedule.__getitem__) == cash[661647].bits


@pytest.mark.parametrize(
    "seconds, bits",
    [(3_500_000_000, "1d00ffff"), (1_231_006_505, "01010000")],
)
def test_aserti3_2d_is_bounded(seconds: int, bits: str) -> None:
    """A parent far behind the schedule is at the limit; far ahead, at 1.

    :param seconds: the parent's time.
    :param bits: the bits given.
    """
    parent = {970892: bare(seconds, bytes.fromhex("1802260a"))}
    assert ASERTI3_2D.bits(970893, parent.__getitem__).hex() == bits


@pytest.mark.parametrize("height", [773040, 773041])
def test_cw_144_gives_bitcoin_sv_s_bits(height: int) -> None:
    """The checkpoint's bits and the next, from the 147 headers below each.

    :param height: the height of the header whose bits are given.
    """
    headers = sv_headers()
    expected = headers[773040].bits if height == 773040 else SV_773041_BITS
    assert CW144.bits(height, headers.__getitem__) == expected


def steady(
    spacing: int, bits: bytes = bytes.fromhex("180bbaed")
) -> dict[int, BlockHeader]:
    """Return 147 headers at one target, `spacing` seconds apart.

    :param spacing: the seconds between two headers.
    :param bits: their bits.
    :returns: the headers, from height 1000.
    """
    return {1000 + k: bare(1_600_000_000 + spacing * k, bits) for k in range(147)}


def test_cw_144_keeps_a_target_mined_on_schedule() -> None:
    """Blocks ten minutes apart at one target keep it."""
    headers = steady(600)
    assert CW144.bits(1147, headers.__getitem__) == headers[1000].bits


@pytest.mark.parametrize("spacing, factor", [(6000, 2), (60, 0.5)])
def test_cw_144_moves_a_target_by_two_at_most(spacing: int, factor: float) -> None:
    """Blocks ten times too slow or too fast move it by a factor of two.

    :param spacing: the seconds between two headers.
    :param factor: how far the target moves.
    """
    headers = steady(spacing)
    old = int.from_bytes(target_from_bits(headers[1000].bits))
    new = int.from_bytes(target_from_bits(CW144.bits(1147, headers.__getitem__)))
    assert abs(new / old - factor) < 0.001


@pytest.mark.parametrize(
    "parent, skew",
    [(1146, 10**6), (1146, -(10**5)), (1145, -(10**5)), (1002, -(10**5))],
)
def test_cw_144_measures_to_the_median_of_three_times(parent: int, skew: int) -> None:
    """A header timed far from its neighbours is not the one measured to.

    The median of the three is one of its neighbours, so the window keeps
    blocks ten minutes apart, and the target.

    :param parent: the header whose time is moved.
    :param skew: the seconds it is moved by.
    """
    headers = steady(600)
    skewed = dict(headers)
    moved = headers[parent]
    skewed[parent] = bare(int(moved.time.timestamp()) + skew, moved.bits)
    assert CW144.bits(1147, skewed.__getitem__) == headers[1000].bits


#: The bits the chains here are mined at, and another a header can carry.
EASY = REGTEST_POW_LIMIT_BITS
EASIER = bytes.fromhex("207ffffe")

#: The rule of the chains here: the bits of the header two below.
TWO_BELOW = Rule(lookback=2, bits=lambda height, at: at(height - 2).bits)

#: The checkpoint's height on the chains here.
CHECKPOINT = 4


def mine(parent: BlockHeader | None, time: int, bits: bytes = EASY) -> BlockHeader:
    """Return a header on `parent` whose hash is within its bits.

    :param parent: the header below it, or None for the first.
    :param time: its seconds.
    :param bits: its bits, regtest's easiest by default.
    :returns: the header.
    """
    target = int.from_bytes(target_from_bits(bits))
    nonce = 0
    while True:
        header = BlockHeader(
            version=0x20000000,
            previous_block_hash=bytes(32) if parent is None else parent.hash,
            merkle_root=bytes(32),
            time=datetime.fromtimestamp(1_700_000_000 + time, UTC),
            bits=bits,
            nonce=nonce,
        )
        if int.from_bytes(header.hash) <= target:
            return header
        nonce += 1


def chain(
    length: int, below: list[BlockHeader] | None = None, *, at: int = 0, **bits: bytes
) -> list[BlockHeader]:
    """Return a chain of headers, by height, from `below` up to `length`.

    :param length: how many headers the chain holds.
    :param below: the headers it extends, those up to `at` kept.
    :param at: the height above which it parts from `below`.
    :param bits: the bits of a header other than `EASY`, keyed by
        ``h`` and its height.
    :returns: the headers.
    """
    headers = list(below[: at + 1]) if below else []
    while len(headers) < length:
        height = len(headers)
        parent = headers[-1] if headers else None
        headers.append(
            mine(parent, 600 * height + 7 * at, bits.get(f"h{height}", EASY))
        )
    return headers


@dataclass
class Served:
    """An Electrum server of a chain: its tip, and the headers it answers.

    `walked` answers `blockchain.block.headers` where given, in place of
    `headers`, and `most` is the most headers one answer holds.
    """

    headers: list[BlockHeader]
    walked: list[BlockHeader] | None = None
    most: int = 3
    asked: list[tuple[int, int]] = field(default_factory=list)

    def tip(self) -> BlockRef:
        """Return the tip the server answers.

        :returns: its height and id.
        """
        return BlockRef(len(self.headers) - 1, self.headers[-1].hash)

    def __call__(self, request: bytes, timeout: float) -> bytes:
        """Answer one request line, as a `LineTransport` does.

        :param request: the request.
        :param timeout: unread.
        :returns: the answering line.
        """
        parsed_request = json.loads(request)
        result: object
        if parsed_request["method"] == "blockchain.headers.subscribe":
            tip = self.headers[-1]
            result = {"height": len(self.headers) - 1, "hex": tip.serialize().hex()}
        else:
            start, count = parsed_request["params"]
            self.asked.append((start, count))
            walked = self.headers if self.walked is None else self.walked
            chunk = walked[start : start + min(count, self.most)]
            hex_ = "".join(header.serialize().hex() for header in chunk)
            result = {"count": len(chunk), "hex": hex_, "max": self.most}
        answer = {"jsonrpc": "2.0", "id": parsed_request["id"], "result": result}
        return json.dumps(answer).encode()


def proof(served: Served, headers: list[BlockHeader] | None = None) -> TipProof:
    """Return the proof of tips the server answers, on a chain's checkpoint.

    :param served: the server.
    :param headers: the chain whose block at `CHECKPOINT` is pinned, the
        server's by default.
    :returns: the proof.
    """
    pinned = (served.headers if headers is None else headers)[CHECKPOINT]
    fetcher = ElectrumFetcher("regtest", transport=served, verify_network=False)
    return TipProof(fetcher, (CHECKPOINT, pinned.hash.hex()), TWO_BELOW)


@pytest.fixture(scope="module")
def main_chain() -> list[BlockHeader]:
    """Return a chain of twelve headers.

    :returns: the headers, by height.
    """
    return chain(12)


def test_a_tip_at_the_checkpoint_proves_unasked(main_chain: list[BlockHeader]) -> None:
    """The checkpoint's own block: no header is asked."""
    served = Served(main_chain[: CHECKPOINT + 1])
    assert proof(served).refusal(served.tip()) == ""
    assert served.asked == []


def test_a_tip_below_the_checkpoint_does_not_prove(
    main_chain: list[BlockHeader],
) -> None:
    """A tip under the checkpoint's height: no header is asked."""
    served = Served(main_chain[:CHECKPOINT])
    assert proof(served, main_chain).refusal(served.tip()) == BELOW
    assert served.asked == []


def test_another_block_at_the_checkpoint_s_height_does_not_prove(
    main_chain: list[BlockHeader],
) -> None:
    """A tip at the checkpoint's height that is not its block."""
    other = chain(CHECKPOINT + 1, main_chain, at=2)
    served = Served(other)
    assert proof(served, main_chain).refusal(served.tip()) == OFF
    assert served.asked == []


def test_a_tip_above_is_walked_from_below_the_checkpoint(
    main_chain: list[BlockHeader],
) -> None:
    """From the lookback below the checkpoint, a chunk at a time, once a tip."""
    served = Served(main_chain[:10])
    proved = proof(served)
    assert proved.refusal(served.tip()) == ""
    assert served.asked == [(3, 7), (6, 4), (9, 1)]
    assert proved.refusal(served.tip()) == ""
    assert served.asked == [(3, 7), (6, 4), (9, 1)]


def test_a_tip_after_the_checkpoint_s_is_walked_from_below_it(
    main_chain: list[BlockHeader],
) -> None:
    """A tip proved at the checkpoint holds no header the rule reads."""
    served = Served(main_chain[: CHECKPOINT + 1])
    proved = proof(served)
    assert proved.refusal(served.tip()) == ""
    served.headers = main_chain[:7]
    assert proved.refusal(served.tip()) == ""
    assert served.asked[0] == (3, 4)


def test_a_tip_on_the_last_proved_is_walked_from_it(
    main_chain: list[BlockHeader],
) -> None:
    """The headers above the last tip proved, and no more."""
    served = Served(main_chain[:8])
    proved = proof(served)
    assert proved.refusal(served.tip()) == ""
    served.headers, served.asked = main_chain, []
    assert proved.refusal(served.tip()) == ""
    assert served.asked == [(8, 4), (11, 1)]


@pytest.mark.parametrize("at, length", [(6, 12), (6, 8), (8, 9)])
def test_a_tip_off_the_last_proved_is_walked_from_the_checkpoint(
    main_chain: list[BlockHeader], at: int, length: int
) -> None:
    """A reorganization above the checkpoint, to a longer chain or not.

    :param main_chain: the chain first proved.
    :param at: the height above which the new chain parts from it.
    :param length: how many headers the new chain holds.
    """
    served = Served(main_chain[:10])
    proved = proof(served)
    assert proved.refusal(served.tip()) == ""
    served.headers, served.asked = chain(length, main_chain, at=at), []
    assert proved.refusal(served.tip()) == ""
    assert served.asked[-1][0] + min(served.asked[-1][1], 3) == length
    assert (3, length - 3) in served.asked


def test_bits_the_rule_does_not_give_do_not_prove(
    main_chain: list[BlockHeader],
) -> None:
    """A header above the checkpoint at other bits, within its own work."""
    served = Served(chain(10, main_chain, at=5, h6=EASIER))
    assert proof(served).refusal(served.tip()) == UNRULED


def test_bits_the_rule_does_not_give_above_the_last_proved_do_not_prove(
    main_chain: list[BlockHeader],
) -> None:
    """The same, on a tip that extends the last one proved."""
    served = Served(main_chain[:8])
    proved = proof(served)
    assert proved.refusal(served.tip()) == ""
    served.headers = chain(11, main_chain, at=7, h9=EASIER)
    assert proved.refusal(served.tip()) == UNRULED


def test_bits_below_the_checkpoint_are_not_the_rule_s() -> None:
    """The headers the rule reads below the checkpoint are its chain's alone."""
    read = Served(chain(10, None, h3=EASIER))
    assert proof(read).refusal(read.tip()) == UNRULED
    served = Served(chain(10, None, h3=EASIER, h5=EASIER, h7=EASIER, h9=EASIER))
    assert proof(served).refusal(served.tip()) == ""


def test_another_block_at_the_checkpoint_in_the_walk_does_not_prove(
    main_chain: list[BlockHeader],
) -> None:
    """A chain above the checkpoint's height that parts below it."""
    served = Served(chain(10, main_chain, at=2))
    assert proof(served, main_chain).refusal(served.tip()) == OFF


def test_a_chunk_that_does_not_follow_the_last_does_not_prove(
    main_chain: list[BlockHeader],
) -> None:
    """The second chunk is another chain's, which parts at the first."""
    walked = main_chain[:6] + chain(10, main_chain, at=4)[6:]
    served = Served(main_chain[:10], walked)
    assert proof(served).refusal(served.tip()) == OFF


def test_a_walk_that_ends_short_does_not_prove(main_chain: list[BlockHeader]) -> None:
    """No header answered past height 7, for a tip at 9."""
    served = Served(main_chain[:10], main_chain[:8])
    assert proof(served).refusal(served.tip()) == OFF


@pytest.mark.parametrize("moved, reason", [(False, OFF), (True, MOVED)])
def test_a_walk_that_does_not_end_at_the_tip(
    main_chain: list[BlockHeader], moved: bool, reason: str
) -> None:
    """Off where the server still answers that tip, moved where it does not.

    :param main_chain: the chain whose tip is asked.
    :param moved: whether the server's tip is the chain it walks.
    :param reason: the answer.
    """
    walked = chain(10, main_chain, at=7)
    served = Served(walked if moved else main_chain[:10], walked)
    tip = BlockRef(9, main_chain[9].hash)
    assert proof(served).refusal(tip) == reason
