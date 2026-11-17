# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing what `seed_scan.evm.Node` reads off an answer.

The node is one the user names, which may be a host on the internet, so
its answers are bytes a stranger can choose. `data` is the body of an
answer with HTTP status 200, which a transport kept in memory hands to a
new `Node` for each of `ASKS`, so that each read is its node's first
request, the one an answer of id ``1`` responds to.

A crash on hostile input is a defect in the node's reader, never in this
harness. A `btclib_wallet.exceptions.FetchError` is how a node refuses an
answer, its `HttpError` and `RpcError` included, so it is caught as the
expected outcome; any other exception propagates to atheris as the
finding it is. **What a node reads is an integer from 0 to ``2**256 - 1``**,
the bound `seed_scan.evm.quantity` and a 32-byte word give, and any other
value raises `AssertionError`.

The seed corpus is an answer of each shape the node reads: a quantity, a
32-byte word, and an error object.
"""

from __future__ import annotations

import sys
from operator import methodcaller
from typing import TYPE_CHECKING

import atheris
from btclib_wallet.exceptions import FetchError

from seed_scan.evm import Node

if TYPE_CHECKING:
    from urllib.request import Request

#: The address and the token contract the node is asked about.
ADDRESS = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
CONTRACT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"

#: Each read a node makes of an answer.
ASKS = (
    methodcaller("chain_id"),
    methodcaller("block_number"),
    methodcaller("balance", ADDRESS),
    methodcaller("nonce", ADDRESS),
    methodcaller("token_balance", CONTRACT, ADDRESS),
)

# what bounds a value read: an EVM word
_WORD = 2**256


def fuzz_target(data: bytes) -> None:
    """Hand `data` to a new node as the answer to each of `ASKS`.

    The module docstring says what is refused quietly and what is a
    finding.
    """

    def transport(request: Request, timeout: float) -> tuple[int, bytes]:
        return 200, data

    for ask in ASKS:
        try:
            value = ask(Node("https://node.example", transport=transport))
        except FetchError:
            continue
        if type(value) is not int or not 0 <= value < _WORD:
            raise AssertionError("a node read an answer as no 256-bit integer")


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
