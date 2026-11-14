# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An EVM node's JSON-RPC, for the reads `seed_scan.scan` makes.

`Node` asks an execution client the user names: its chain id, its latest
block number, and an address's balance, its nonce and its balance of an
ERC-20 token, each at a block the caller numbers or at the tag
``latest``. The methods and their types are those of the Ethereum
execution-apis specification, read at commit
``981aa66d79364be8322a9c358aaf0a571cca0873``:

- ``eth_chainId`` and ``eth_blockNumber`` in `src/eth/client.yaml`_;
- ``eth_getBalance`` and ``eth_getTransactionCount`` in
  `src/eth/state.yaml`_, each given an address and a block number or the
  tag ``latest`` of `src/schemas/block.yaml`_;
- ``eth_call`` in `src/eth/execute.yaml`_, given the same block and a
  transaction of `src/schemas/transaction.yaml`_ holding ``to``, the
  token's contract, and ``input``;
- each result of the first four a ``uint`` of
  `src/schemas/base-types.yaml`_, which `quantity` reads, bounded as that
  file's ``uint256`` is: an account's balance and nonce are words of the
  EVM's state, and a chain id and a block number are smaller;
- the framing of `docs-api/docs/tests.md`_: one JSON-RPC 2.0 request
  object, ``jsonrpc``, ``id``, ``method`` and ``params``, answered by one
  response object.

The call is `EIP-20`_'s ``balanceOf(address)``, encoded as the Solidity
ABI specification says: its ``input`` is the `function selector`_, the
first four bytes of the Keccak-256 of that signature, then the address
`encoded`_ as a ``uint160``, padded on the left with zero bytes to 32;
its result, ``bytes`` of the same base types, is one ``uint256``, 32
bytes big-endian, as the specification `encodes`_ what a function
returns. A result of any other length is refused, ``0x`` included.

The response is read as `JSON-RPC 2.0`_'s section 5 defines it: an
object whose ``jsonrpc`` is ``"2.0"``, whose ``id`` is the request's, and
which holds either ``result`` or ``error``, the error an object with an
integer ``code`` and a string ``message`` as section 5.1 says. Anything
else, an HTTP status other than 200 included, is refused, and no refusal
quotes the answer.

An address is ``0x`` and 40 hex digits, in one case, lower or upper, or
in mixed case where the case is its `EIP-55`_ checksum, as
`coin_addresses.evm.assert_valid_address` reads it. `Node.balance`,
`Node.nonce` and `Node.token_balance` refuse any other address before
the node is asked, a string as a `SeedScanValueError` and any other type
as a `SeedScanTypeError`; none quotes it.

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
its ``eth_chainId`` answers, the coins of a bundle whose accounts are
read on it and the ERC-20 tokens whose balances are read; the comments
above it cite each chain and each token. A key gives the same address
on each, so the bundle's accounts at m/44h/60h are read on every one:
what such an account held on Ethereum when Ethereum Classic parted from
it is on that chain too. The accounts at m/44h/61h, Ethereum Classic's
SLIP-0044 coin type, are read on Ethereum Classic alone, where its own
wallets derive them, as `seed_scan.identify`'s comment on its ``COINS``
cites.

.. _src/eth/client.yaml: https://github.com/ethereum/execution-apis/blob/981aa66d79364be8322a9c358aaf0a571cca0873/src/eth/client.yaml
.. _src/eth/state.yaml: https://github.com/ethereum/execution-apis/blob/981aa66d79364be8322a9c358aaf0a571cca0873/src/eth/state.yaml
.. _src/eth/execute.yaml: https://github.com/ethereum/execution-apis/blob/981aa66d79364be8322a9c358aaf0a571cca0873/src/eth/execute.yaml#L1-L23
.. _src/schemas/transaction.yaml: https://github.com/ethereum/execution-apis/blob/981aa66d79364be8322a9c358aaf0a571cca0873/src/schemas/transaction.yaml#L519-L548
.. _src/schemas/block.yaml: https://github.com/ethereum/execution-apis/blob/981aa66d79364be8322a9c358aaf0a571cca0873/src/schemas/block.yaml
.. _src/schemas/base-types.yaml: https://github.com/ethereum/execution-apis/blob/981aa66d79364be8322a9c358aaf0a571cca0873/src/schemas/base-types.yaml
.. _docs-api/docs/tests.md: https://github.com/ethereum/execution-apis/blob/981aa66d79364be8322a9c358aaf0a571cca0873/docs-api/docs/tests.md
.. _JSON-RPC 2.0: https://www.jsonrpc.org/specification
.. _EIP-55: https://github.com/ethereum/ERCs/blob/8dd085d159cb123f545c272c0d871a5339550e79/ERCS/erc-55.md
.. _EIP-20: https://github.com/ethereum/ERCs/blob/ae65e89408f387ffb47d220879925c4ab384dfc2/ERCS/erc-20.md#L85-L91
.. _function selector: https://github.com/ethereum/solidity/blob/9fb16c6a9707b047181a24c471e74d10f71b65af/docs/abi-spec.rst#L24-L32
.. _encoded: https://github.com/ethereum/solidity/blob/9fb16c6a9707b047181a24c471e74d10f71b65af/docs/abi-spec.rst#L213-L215
.. _encodes: https://github.com/ethereum/solidity/blob/9fb16c6a9707b047181a24c471e74d10f71b65af/docs/abi-spec.rst#L226-L236
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
from coin_addresses.evm import is_valid_address

from seed_scan.exceptions import SeedScanTypeError, SeedScanValueError

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from urllib.request import Request

__all__ = [
    "EVM_CHAINS",
    "MAX_ANSWER",
    "EvmChain",
    "EvmToken",
    "Node",
    "quantity",
]

#: The octets an answer may hold. A response object holding a quantity of
#: at most 64 hex digits, which `quantity` refuses past, or the 32 bytes
#: of a token balance, is well under it.
MAX_ANSWER = 4096

# a `uint256` of the specification's base types: `0x`, then `0` or up to
# 64 lower-case hex digits with no leading zero
_QUANTITY = re.compile(r"0x(?:0|[1-9a-f][0-9a-f]{0,63})")

# the result of `balanceOf`: `bytes` of the specification's base types,
# lower-case hex digits, of one 32-byte word
_WORD = re.compile(r"0x[0-9a-f]{64}")

# the function selector of `balanceOf(address)`
_BALANCE_OF = "0x70a08231"

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
class EvmToken:
    """An ERC-20 token whose balances a chain's scan reads.

    `contract` is the token's address, EIP-55 encoded. A balance counts
    10**-`decimals` of the token `symbol` names. Neither is read from the
    contract: both are those of the source the comment above
    `EVM_CHAINS` cites.
    """

    contract: str
    symbol: str
    decimals: int


@dataclass(frozen=True)
class EvmChain:
    """An EVM chain a node serves, and the bundle's coins read on it.

    `name` is how the command and the result name it, and `title` how a
    summary and the report do. `chain_id` is what ``eth_chainId`` answers
    on it, and `symbol` names its native asset, of which a balance in wei
    counts 10**-18. `coins` are the coins of a bundle whose accounts are
    read on it, and `tokens` the ERC-20 tokens whose balances are read.
    """

    name: str
    title: str
    chain_id: int
    symbol: str
    coins: tuple[str, ...]
    tokens: tuple[EvmToken, ...]


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
#
# The tokens read on each chain are a short list, chosen as what a
# recovering wallet most likely holds: the stablecoins USDT, USDC and
# DAI, both of a chain's two USDC or two USDT, its wrapped native asset
# and a wrapped bitcoin. Any other token is not read. Each contract,
# symbol and decimals are those of
# `blockchains/<folder>/assets/<contract>/info.json` in Trust Wallet's
# asset registry, read at the commit linked, the folder being the
# chain's: ethereum, smartchain, polygon, arbitrum, optimism, base and
# avalanchec:
#   https://github.com/trustwallet/assets/tree/50d6fd574843da19cdd5fded102b5d6b951c72d2/blockchains
# Base's cbBTC, which that registry does not list, is Uniswap's default
# token list's:
#   https://github.com/Uniswap/default-token-list/blob/0ae664438dd43d428c5cbef2726af1ba6378a17c/src/tokens/base.json#L91-L97
# The registry lists no USDT, USDC, DAI or wrapped ETC on Ethereum
# Classic, whose list is empty:
#   https://github.com/trustwallet/assets/tree/50d6fd574843da19cdd5fded102b5d6b951c72d2/blockchains/classic/assets
_ETHEREUM_TOKENS = (
    EvmToken("0xdAC17F958D2ee523a2206206994597C13D831ec7", "USDT", 6),
    EvmToken("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "USDC", 6),
    EvmToken("0x6B175474E89094C44Da98b954EedeAC495271d0F", "DAI", 18),
    EvmToken("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "WETH", 18),
    EvmToken("0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599", "WBTC", 8),
)
_BNB_SMART_CHAIN_TOKENS = (
    EvmToken("0x55d398326f99059fF775485246999027B3197955", "USDT", 18),
    EvmToken("0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d", "USDC", 18),
    EvmToken("0x1AF3F329e8BE154074D8769D1FFa4eE058B1DBc3", "DAI", 18),
    EvmToken("0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c", "WBNB", 18),
    EvmToken("0x7130d2A12B9BCbFAe4f2634d864A1Ee1Ce3Ead9c", "BTCB", 18),
)
_POLYGON_POS_TOKENS = (
    EvmToken("0xc2132D05D31c914a87C6611C10748AEb04B58e8F", "USDT", 6),
    EvmToken("0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", "USDC", 6),
    EvmToken("0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174", "USDC.e", 6),
    EvmToken("0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063", "DAI", 18),
    EvmToken("0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270", "WMATIC", 18),
    EvmToken("0x1BFD67037B42Cf73acF2047067bd4F2C47D9BfD6", "WBTC", 8),
)
_ARBITRUM_ONE_TOKENS = (
    EvmToken("0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", "USDT", 6),
    EvmToken("0xaf88d065e77c8cC2239327C5EDb3A432268e5831", "USDC", 6),
    EvmToken("0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8", "USDC.e", 6),
    EvmToken("0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1", "DAI", 18),
    EvmToken("0x82aF49447D8a07e3bd95BD0d56f35241523fBab1", "WETH", 18),
    EvmToken("0x2f2a2543B76A4166549F7aaB2e75Bef0aefC5B0f", "WBTC", 8),
)
_OP_MAINNET_TOKENS = (
    EvmToken("0x94b008aA00579c1307B0EF2c499aD98a8ce58e58", "USDT", 6),
    EvmToken("0x01bFF41798a0BcF287b996046Ca68b395DbC1071", "USDT0", 6),
    EvmToken("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85", "USDC", 6),
    EvmToken("0x7F5c764cBc14f9669B88837ca1490cCa17c31607", "USDC.e", 6),
    EvmToken("0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1", "DAI", 18),
    EvmToken("0x4200000000000000000000000000000000000006", "WETH", 18),
)
_BASE_TOKENS = (
    EvmToken("0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2", "USDT", 6),
    EvmToken("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "USDC", 6),
    EvmToken("0xd9aAEc86B65D86f6A7B5B1b0c42FFA531710b6CA", "USDbC", 6),
    EvmToken("0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb", "DAI", 18),
    EvmToken("0x4200000000000000000000000000000000000006", "WETH", 18),
    EvmToken("0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf", "cbBTC", 8),
)
_AVALANCHE_C_CHAIN_TOKENS = (
    EvmToken("0x9702230A8Ea53601f5cD2dc00fDBc13d4dF4A8c7", "USDt", 6),
    EvmToken("0xc7198437980c041c805A1EDcbA50c1Ce5db95118", "USDT.e", 6),
    EvmToken("0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E", "USDC", 6),
    EvmToken("0xA7D7079b0FEaD91F3e65f86E8915Cb59c1a4C664", "USDC.e", 6),
    EvmToken("0xd586E7F844cEa2F87f50152665BCbc2C279D8d70", "DAI.e", 18),
    EvmToken("0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7", "WAVAX", 18),
    EvmToken("0x50b7545627a5162F82A992c33b87aDc75187B218", "WBTC.e", 8),
)

#: The chains a node may serve, by name.
EVM_CHAINS = MappingProxyType(
    {
        chain.name: chain
        for chain in (
            EvmChain("ethereum", "Ethereum", 1, "ETH", ("ethereum",), _ETHEREUM_TOKENS),
            EvmChain(
                "ethereum-classic",
                "Ethereum Classic",
                61,
                "ETC",
                ("ethereum", "ethereum-classic"),
                (),
            ),
            EvmChain(
                "bnb-smart-chain",
                "BNB Smart Chain",
                56,
                "BNB",
                ("ethereum",),
                _BNB_SMART_CHAIN_TOKENS,
            ),
            EvmChain(
                "polygon-pos",
                "Polygon PoS",
                137,
                "POL",
                ("ethereum",),
                _POLYGON_POS_TOKENS,
            ),
            EvmChain(
                "arbitrum-one",
                "Arbitrum One",
                42161,
                "ETH",
                ("ethereum",),
                _ARBITRUM_ONE_TOKENS,
            ),
            EvmChain(
                "op-mainnet", "OP Mainnet", 10, "ETH", ("ethereum",), _OP_MAINNET_TOKENS
            ),
            EvmChain("base", "Base", 8453, "ETH", ("ethereum",), _BASE_TOKENS),
            EvmChain(
                "avalanche-c-chain",
                "Avalanche C-Chain",
                43114,
                "AVAX",
                ("ethereum",),
                _AVALANCHE_C_CHAIN_TOKENS,
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


def _address(address: object) -> str:
    """Return an address, refusing it as the module docstring says."""
    if not isinstance(address, str):
        raise SeedScanTypeError(f"not an address: a {type(address).__name__}")
    if not is_valid_address(address):
        err_msg = "not an address: 0x and 40 hex digits, in one case or EIP-55's"
        raise SeedScanValueError(err_msg)
    return address


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

    `balance`, `nonce` and `token_balance` check their address first, as
    the module docstring says, and refuse it without asking anything.

    Each method asks one request. A failure below the answer is a
    `btclib_wallet.exceptions.FetchError` that names the node alone,
    caused by a fresh, empty error of the class that failed, of those
    `_CAUSES` lists, or by nothing; neither it nor its chain keeps what
    the transport raised, whose messages can quote the node. An HTTP
    status other than 200 is its `HttpError`, and a JSON-RPC error object
    its `RpcError`, with the code the node gave and neither the message
    nor the data. An answer that is not a JSON-RPC 2.0 response to the
    request, or whose result is not a quantity, or for a token balance
    not one 32-byte word, is a `FetchError` too.

    `balance`, `nonce` and `token_balance` read the state at the block
    numbered `block`, or at ``latest`` where it is None.
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

    def _call(self, method: str, params: list[object]) -> object:
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

    def _quantity(self, method: str, params: list[object]) -> int:
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

    def balance(self, address: str, block: int | None = None) -> int:
        """Return an address's balance, in wei."""
        return self._quantity("eth_getBalance", [_address(address), _block(block)])

    def nonce(self, address: str, block: int | None = None) -> int:
        """Return an address's nonce.

        ``eth_getTransactionCount``'s: the specification says why the
        name is no longer the count of the transactions the address sent.
        """
        params: list[object] = [_address(address), _block(block)]
        return self._quantity("eth_getTransactionCount", params)

    def token_balance(
        self, contract: str, address: str, block: int | None = None
    ) -> int:
        """Return an address's balance of the ERC-20 token at `contract`.

        ``eth_call`` of the token's ``balanceOf``, as the module docstring
        says, in the token's units.
        """
        word = _address(address)[2:].lower().zfill(64)
        call = {"to": contract, "input": _BALANCE_OF + word}
        result = self._call("eth_call", [call, _block(block)])
        if not isinstance(result, str) or _WORD.fullmatch(result) is None:
            raise FetchError(f"{self._name}: eth_call answered no 32-byte word")
        return int(result, 16)


def _block(block: int | None) -> str:
    """Return a block parameter: the number as a quantity, or ``latest``."""
    return "latest" if block is None else hex(block)


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
