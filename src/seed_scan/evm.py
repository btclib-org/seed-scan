# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An EVM node's JSON-RPC, for the reads `seed_scan.scan` makes.

`Node` asks an execution client the user names: its chain id, its latest
block number, and the balance and the nonce of an address at the block
tag ``latest``. The methods and their types are those of the Ethereum
execution-apis specification, read at commit
``981aa66d79364be8322a9c358aaf0a571cca0873``:

- ``eth_chainId`` and ``eth_blockNumber`` in `src/eth/client.yaml`_;
- ``eth_getBalance`` and ``eth_getTransactionCount`` in
  `src/eth/state.yaml`_, each given an address and the tag ``latest`` of
  `src/schemas/block.yaml`_;
- each result a ``uint`` of `src/schemas/base-types.yaml`_, which
  `quantity` reads, bounded as that file's ``uint256`` is: an account's
  balance and nonce are words of the EVM's state, and a chain id and a
  block number are smaller;
- the framing of `docs-api/docs/tests.md`_: one JSON-RPC 2.0 request
  object, ``jsonrpc``, ``id``, ``method`` and ``params``, answered by one
  response object.

The response is read as `JSON-RPC 2.0`_'s section 5 defines it: an
object whose ``jsonrpc`` is ``"2.0"``, whose ``id`` is the request's, and
which holds either ``result`` or ``error``, the error an object with an
integer ``code`` and a string ``message`` as section 5.1 says. Anything
else, an HTTP status other than 200 included, is refused, and no refusal
quotes the answer.

The request goes through `btclib_wallet.fetch.transport.http_request`,
whose network policy is the one `btclib_wallet.fetch.transport`'s
``TlsLineTransport`` states for its own: a bounded read, refused rather
than truncated past `MAX_ANSWER` octets; a timeout over the whole
exchange, name resolution, connect, handshake, send and read; no proxy
taken from the environment; and no redirect followed. Over ``https``
the certificate is verified against the system's CA certificates, which
OpenSSL's ``SSL_CERT_FILE`` and ``SSL_CERT_DIR`` choose, and must name
the host.

The URL is ``https``, except on a loopback address, where ``http`` is
accepted too: the addresses asked tie a wallet's accounts together, and
over plain HTTP they would cross the network in the clear. The loopback
address is written as an address, ``127.0.0.1`` or ``[::1]``: a name such
as ``localhost`` is resolved by the system, and RFC 6761 asks resolvers
to answer it with the loopback address without requiring it. A URL with a
login is refused, and so is one that is not printable ASCII.

`EVM_CHAINS` holds the chains a node may serve, each with the chain id
its ``eth_chainId`` answers and the coins of a bundle whose accounts are
read on it; the comment above it cites each chain. A key gives the same
address on each, so the bundle's Ethereum accounts, at m/44h/60h and
its legacy layout, are read on every one: what such an account held on
Ethereum when Ethereum Classic parted from it is on that chain too.
Ethereum Classic's, at m/44h/61h, its SLIP-0044 coin type, and at its
legacy layout, are read on Ethereum Classic alone, where its own
wallets derive them, as `seed_scan.identify`'s comments on its
``COINS`` cite.

.. _src/eth/client.yaml: https://github.com/ethereum/execution-apis/blob/981aa66d79364be8322a9c358aaf0a571cca0873/src/eth/client.yaml
.. _src/eth/state.yaml: https://github.com/ethereum/execution-apis/blob/981aa66d79364be8322a9c358aaf0a571cca0873/src/eth/state.yaml
.. _src/schemas/block.yaml: https://github.com/ethereum/execution-apis/blob/981aa66d79364be8322a9c358aaf0a571cca0873/src/schemas/block.yaml
.. _src/schemas/base-types.yaml: https://github.com/ethereum/execution-apis/blob/981aa66d79364be8322a9c358aaf0a571cca0873/src/schemas/base-types.yaml
.. _docs-api/docs/tests.md: https://github.com/ethereum/execution-apis/blob/981aa66d79364be8322a9c358aaf0a571cca0873/docs-api/docs/tests.md
.. _JSON-RPC 2.0: https://www.jsonrpc.org/specification
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
import re
import ssl
import traceback
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from btclib_wallet.exceptions import FetchError, HttpError, RpcError
from btclib_wallet.fetch.fetcher import client_errors
from btclib_wallet.fetch.transport import (
    DEFAULT_TIMEOUT,
    http_request,
    urlopen_transport,
)

from seed_scan.exceptions import SeedScanTypeError, SeedScanValueError

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from urllib.request import Request

__all__ = [
    "EVM_CHAINS",
    "MAX_ANSWER",
    "EvmChain",
    "Node",
    "quantity",
]

#: The octets an answer may hold. A response object holding a quantity of
#: at most 64 hex digits, which `quantity` refuses past, is well under it.
MAX_ANSWER = 4096

# a `uint256` of the specification's base types: `0x`, then `0` or up to
# 64 lower-case hex digits with no leading zero
_QUANTITY = re.compile(r"0x(?:0|[1-9a-f][0-9a-f]{0,63})")

_OK = 200

# what a failure below the answer is reported as caused by: the first
# class here that anything in its chain is of. A fresh instance of the
# class, holding no message, stands for it: the original's message, and
# those of the exceptions it chains, can quote what the node sent, as a
# status line that does not parse does
_CAUSES: tuple[type[OSError], ...] = (
    ssl.SSLCertVerificationError,
    ssl.SSLError,
    TimeoutError,
    ConnectionRefusedError,
    OSError,
)


@dataclass(frozen=True)
class EvmChain:
    """An EVM chain a node serves, and the bundle's coins read on it.

    `name` is how the command and the result name it, and `title` how a
    summary and the report do. `chain_id` is what ``eth_chainId`` answers
    on it, and `symbol` names its native asset, of which a balance in wei
    counts 10**-18. `coins` are the coins of a bundle whose accounts are
    read on it.
    """

    name: str
    title: str
    chain_id: int
    symbol: str
    coins: tuple[str, ...]


# Each chain's id, its native asset's symbol, and 18 decimals of that
# asset, are those of its entry in the ethereum-lists registry, read at
# the commit linked, which takes `eip155-<chain id>.json` as its name:
#   https://github.com/ethereum-lists/chains/blob/07ae44203a27d87410e6efadf26cd00b247072cd/_data/chains/eip155-1.json#L40-L45
#   https://github.com/ethereum-lists/chains/blob/07ae44203a27d87410e6efadf26cd00b247072cd/_data/chains/eip155-61.json#L18-L23
#   https://github.com/ethereum-lists/chains/blob/07ae44203a27d87410e6efadf26cd00b247072cd/_data/chains/eip155-56.json#L30-L35
#   https://github.com/ethereum-lists/chains/blob/07ae44203a27d87410e6efadf26cd00b247072cd/_data/chains/eip155-137.json#L24-L29
#   https://github.com/ethereum-lists/chains/blob/07ae44203a27d87410e6efadf26cd00b247072cd/_data/chains/eip155-42161.json#L3-L10
#   https://github.com/ethereum-lists/chains/blob/07ae44203a27d87410e6efadf26cd00b247072cd/_data/chains/eip155-10.json#L19-L24
#   https://github.com/ethereum-lists/chains/blob/07ae44203a27d87410e6efadf26cd00b247072cd/_data/chains/eip155-8453.json#L23-L28
#   https://github.com/ethereum-lists/chains/blob/07ae44203a27d87410e6efadf26cd00b247072cd/_data/chains/eip155-43114.json#L21-L26
# Trezor Suite derives each chain's accounts at m/44h/60h, Ethereum
# Classic's at m/44h/61h, and gives each the same chain id:
#   https://github.com/trezor/trezor-suite/blob/c861929418c13919b335061d65a169de5aa869f3/networks/ethereum/network-ethereum-suite-common/src/networkConfig.ts#L43-L414

#: The chains a node may serve, by name.
EVM_CHAINS = MappingProxyType(
    {
        chain.name: chain
        for chain in (
            EvmChain("ethereum", "Ethereum", 1, "ETH", ("ethereum",)),
            EvmChain(
                "ethereum-classic",
                "Ethereum Classic",
                61,
                "ETC",
                ("ethereum", "ethereum-classic"),
            ),
            EvmChain("bnb-smart-chain", "BNB Smart Chain", 56, "BNB", ("ethereum",)),
            EvmChain("polygon-pos", "Polygon PoS", 137, "POL", ("ethereum",)),
            EvmChain("arbitrum-one", "Arbitrum One", 42161, "ETH", ("ethereum",)),
            EvmChain("op-mainnet", "OP Mainnet", 10, "ETH", ("ethereum",)),
            EvmChain("base", "Base", 8453, "ETH", ("ethereum",)),
            EvmChain(
                "avalanche-c-chain", "Avalanche C-Chain", 43114, "AVAX", ("ethereum",)
            ),
        )
    }
)


def quantity(value: object) -> int:
    """Return the integer a JSON-RPC quantity spells, of 256 bits at most.

    A quantity is a string: ``0x``, then ``0`` or up to 64 lower-case hex
    digits with no leading zero. Anything else is refused, a string as a
    `SeedScanValueError` and any other type as a `SeedScanTypeError`;
    neither quotes it.
    """
    if not isinstance(value, str):
        raise SeedScanTypeError(f"not a quantity: a {type(value).__name__}")
    if _QUANTITY.fullmatch(value) is None:
        err_msg = "not a quantity: 0x and up to 64 hex digits, no leading zero"
        raise SeedScanValueError(err_msg)
    return int(value, 0)


def _refuse_constant(name: str) -> object:
    """Refuse a NaN or an infinity in an answer, as `json.loads` meets one."""
    raise ValueError(name)


def _url(url: str) -> tuple[str, str]:
    """Return the URL, checked, and the node's name: scheme, host and port.

    The name is what the result and a refusal write: a path or a query,
    which can hold a token, is left out of it.
    """
    if not isinstance(url, str):
        raise SeedScanTypeError(f"invalid node type: {type(url).__name__}")
    if not url.isascii() or any(c.isspace() or not c.isprintable() for c in url):
        raise SeedScanValueError("node: the URL is not printable ASCII")
    parts = None
    # an IPv6 host with no closing bracket is a ValueError, raised outside
    # `suppress` so that it does not chain the one quoting the URL
    with contextlib.suppress(ValueError):
        parts = urlsplit(url)
    if parts is None:
        raise SeedScanValueError("node: the URL does not parse")
    host = parts.hostname
    # a property: a port that is no number, or past 65535, raises only
    # once asked for, and the refusal is raised outside `suppress`. None
    # is a URL with no port
    port: int | None = 0
    with contextlib.suppress(ValueError):
        port = parts.port
    if port == 0:
        raise SeedScanValueError("node: the URL's port is not 1 to 65535")
    if parts.scheme not in {"http", "https"}:
        raise SeedScanValueError("node: the URL is not http or https")
    if not host:
        raise SeedScanValueError("node: the URL names no host")
    if parts.username is not None or parts.password is not None:
        raise SeedScanValueError("node: the URL carries a login")
    if parts.scheme == "http" and not _is_loopback(host):
        raise SeedScanValueError(
            "node: plain http is accepted on a loopback address alone"
        )
    shown = f"[{host}]" if ":" in host else host
    return url, f"{parts.scheme}://{shown}" + ("" if port is None else f":{port}")


def _chain(error: BaseException) -> Iterator[BaseException]:
    """Yield an error and what it chains: cause, context and reason.

    urllib wraps what the socket raised as a ``URLError``'s ``reason``,
    which is neither its cause nor its context.
    """
    seen: set[int] = set()
    todo: list[object] = [error]
    while todo:
        found = todo.pop(0)
        if not isinstance(found, BaseException) or id(found) in seen:
            continue
        seen.add(id(found))
        yield found
        todo += [found.__cause__, found.__context__, getattr(found, "reason", None)]


def _stand_in(error: BaseException) -> OSError | None:
    """Return a fresh error of the class `_CAUSES` finds in a chain, or None."""
    chain = list(_chain(error))
    return next(
        (kind() for kind in _CAUSES if any(isinstance(link, kind) for link in chain)),
        None,
    )


def _release(error: BaseException) -> None:
    """Clear the frames of an error's chain, so that what they hold is freed.

    A failed exchange can leave its response open in a frame of the
    transport's: ``SessionTransport`` closes the connection and not the
    response when its bounded read raises. Held by an error in a
    reference cycle, the response and its socket wait for the garbage
    collector, which may finalize the socket first and warn that it was
    never closed. Cleared here, the response is freed at once, and closes
    its socket as it goes. A frame still running is left as it is.
    """
    for found in _chain(error):
        traceback.clear_frames(found.__traceback__)


def _is_loopback(host: str) -> bool:
    """Answer whether a host is written as a loopback address."""
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class Node:
    """An EVM node the user names, asked over JSON-RPC 2.0.

    Construction checks the URL, as the module docstring says, and opens
    nothing. `transport` is `btclib_wallet.fetch.transport.http_request`'s
    own parameter: its default opens one connection per request, and a
    ``SessionTransport`` keeps one open across requests. `timeout` bounds
    each request, in seconds.

    Each method asks one request. A failure below the answer is a
    `btclib_wallet.exceptions.FetchError` that names the node alone,
    caused by a fresh, empty error of the class that failed, of those
    `_CAUSES` lists, or by nothing; neither it nor its chain keeps what
    the transport raised, whose messages can quote the node. An HTTP
    status other than 200 is its `HttpError`, and a JSON-RPC error object
    its `RpcError`, with the code the node gave and neither the message
    nor the data. An answer that is not a JSON-RPC 2.0 response to the
    request, or whose result is not a quantity, is a `FetchError` too.
    """

    def __init__(
        self,
        url: str,
        *,
        transport: Callable[[Request, float], tuple[int, bytes]] = urlopen_transport,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._url, self._name = _url(url)
        self._transport = transport
        self._timeout = timeout
        self._id = 0

    @property
    def name(self) -> str:
        """Return the node as scheme, host and port, with no path or query."""
        return self._name

    @property
    def requests(self) -> int:
        """Return how many requests were sent, or were about to be."""
        return self._id

    def _call(self, method: str, params: list[str]) -> object:
        """Ask one method; return its result, refusing what is no answer."""
        self._id += 1
        request = {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}
        failed: FetchError | None = None
        status, body = 0, b""
        try:
            with client_errors():
                status, body = http_request(
                    self._url,
                    data=json.dumps(request).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    timeout=self._timeout,
                    max_body_size=MAX_ANSWER,
                    transport=self._transport,
                )
        except FetchError as e:
            failed = e
        if failed is not None:
            # raised outside the `except`, so that the failure caught is
            # not its context, and dropped from this frame, whose locals a
            # traceback keeps
            cause = _stand_in(failed)
            _release(failed)
            del failed
            raise FetchError(f"{self._name}: no answer") from cause
        if status != _OK:
            raise HttpError(f"{self._name}: HTTP status {status}", status)
        answer = None
        # the refusal is raised outside `suppress`, so that it chains no
        # decoding error, which quotes what it read. A body nested past
        # the interpreter's recursion limit is a RecursionError
        with contextlib.suppress(ValueError, RecursionError):
            answer = json.loads(body, parse_constant=_refuse_constant)
        if not isinstance(answer, dict) or not _is_response(answer, self._id):
            err_msg = f"{self._name}: not a JSON-RPC 2.0 response to the request"
            raise FetchError(err_msg)
        error = answer.get("error")
        if isinstance(error, dict):
            code, message = error.get("code"), error.get("message")
            if (
                isinstance(code, bool)
                or not isinstance(code, int)
                or not isinstance(message, str)
            ):
                err_msg = f"{self._name}: an error object with no integer code"
                err_msg += " or no string message"
                raise FetchError(err_msg)
            raise RpcError(f"{self._name}: the node answered an error", code)
        return answer["result"]

    def _quantity(self, method: str, params: list[str]) -> int:
        """Ask one method whose result is a quantity, and read it."""
        result = self._call(method, params)
        value = None
        # the refusal is raised outside `suppress`: a node's answer is no
        # caller's argument, so it is a failure of the node and not a
        # refusal
        with contextlib.suppress(SeedScanTypeError, SeedScanValueError):
            value = quantity(result)
        if value is None:
            raise FetchError(f"{self._name}: {method} answered no quantity")
        return value

    def chain_id(self) -> int:
        """Return the chain id, ``eth_chainId``'s."""
        return self._quantity("eth_chainId", [])

    def block_number(self) -> int:
        """Return the latest block's number, ``eth_blockNumber``'s."""
        return self._quantity("eth_blockNumber", [])

    def balance(self, address: str) -> int:
        """Return an address's balance at ``latest``, in wei."""
        return self._quantity("eth_getBalance", [address, "latest"])

    def nonce(self, address: str) -> int:
        """Return an address's nonce at ``latest``.

        ``eth_getTransactionCount``'s: the specification says why the
        name is no longer the count of the transactions the address sent.
        """
        return self._quantity("eth_getTransactionCount", [address, "latest"])


def _is_response(answer: dict[str, object], request_id: int) -> bool:
    """Answer whether an object is a JSON-RPC 2.0 response to a request.

    Section 5: ``jsonrpc`` exactly ``"2.0"``, the request's ``id``, and
    exactly one of ``result`` and ``error``, the error an object.
    """
    answer_id = answer.get("id")
    # an integer, and not the float or the bool that compare equal to it
    if type(answer_id) is not int or answer_id != request_id:
        return False
    if answer.get("jsonrpc") != "2.0" or ("result" in answer) == ("error" in answer):
        return False
    return "result" in answer or isinstance(answer["error"], dict)
