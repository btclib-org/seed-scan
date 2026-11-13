# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `seed_scan.evm`: the URL, the framing, the quantities, the policy.

The node is `Ethereum`, a fake kept in memory that answers the four
methods `Node` asks. Some tests hand it to `Node` as its transport; the
others serve it over HTTP on the loopback interface, with `HttpServer`,
so that the network policy under test is the one the request meets.
`tests.scan_cli_test` serves it over HTTPS, where the `tls` fixture
makes the certificates.
"""

from __future__ import annotations

import contextlib
import gc
import json
import socket
import socketserver
import ssl
import threading
import time
import traceback
import warnings
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING

import pytest
from btclib_wallet.exceptions import FetchError, HttpError, RpcError
from btclib_wallet.fetch.transport import SessionTransport
from typing_extensions import override

from seed_scan.evm import MAX_ANSWER, Node, quantity
from seed_scan.exceptions import SeedScanTypeError, SeedScanValueError

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from urllib.request import Request

#: Text a node puts in an answer, which no refusal may quote.
MARK = "node-said-this"

#: What one exchange answers: the status, the body and the headers.
Exchange = tuple[int, bytes, dict[str, str]]


class Ethereum:
    """An Ethereum node kept in memory: balances and nonces by address."""

    def __init__(
        self,
        balances: dict[str, int] | None = None,
        nonces: dict[str, int] | None = None,
        chain_id: int = 1,
    ) -> None:
        """Hold the state.

        :param balances: the wei of each address, zero for any other.
        :param nonces: the nonce of each address, zero for any other.
        :param chain_id: what ``eth_chainId`` answers.
        """
        self.balances = {a.lower(): v for a, v in (balances or {}).items()}
        self.nonces = {a.lower(): v for a, v in (nonces or {}).items()}
        self.chain_id = chain_id
        self.asked: list[str] = []

    def result(self, method: str, params: list[str]) -> str:
        """Return a method's result, a quantity.

        :param method: the method asked.
        :param params: its parameters.
        :returns: the quantity.
        """
        self.asked.append(method)
        if method == "eth_chainId":
            return hex(self.chain_id)
        if method == "eth_blockNumber":
            return hex(0x10)
        address, block = params
        assert block == "latest"
        state = self.balances if method == "eth_getBalance" else self.nonces
        return hex(state.get(address.lower(), 0))

    def answer(self, body: bytes) -> bytes:
        """Answer one request body, checking its framing.

        :param body: the JSON-RPC 2.0 request object.
        :returns: the response object.
        """
        request = json.loads(body)
        assert set(request) == {"jsonrpc", "id", "method", "params"}
        assert request["jsonrpc"] == "2.0"
        result = self.result(request["method"], request["params"])
        response = {"jsonrpc": "2.0", "id": request["id"], "result": result}
        return json.dumps(response).encode()

    def __call__(self, request: Request, timeout: float) -> tuple[int, bytes]:
        """Answer as an `HttpTransport` does.

        :param request: the request, a JSON POST.
        :param timeout: unread.
        :returns: the status and the body.
        """
        assert request.get_method() == "POST"
        assert request.get_header("Content-type") == "application/json"
        assert isinstance(request.data, bytes)
        return 200, self.answer(request.data)


def answering(*bodies: object) -> Callable[[Request, float], tuple[int, bytes]]:
    """Return a transport answering each request with the next body.

    :param bodies: each a JSON value to answer, or the bytes themselves.
    :returns: the transport.
    """
    queue = list(bodies)

    def transport(request: Request, timeout: float) -> tuple[int, bytes]:
        body = queue.pop(0)
        return 200, body if isinstance(body, bytes) else json.dumps(body).encode()

    return transport


class HttpServer:
    """An HTTP server on the loopback interface, in a thread.

    Each POST is answered by `respond`, given the path and the body.
    """

    def __init__(
        self,
        respond: Callable[[str, bytes], Exchange],
        context: ssl.SSLContext | None = None,
    ) -> None:
        """Listen on a port of 127.0.0.1, and serve until stopped.

        :param respond: what answers each request.
        :param context: the TLS context, for HTTPS.
        """
        self.requests: list[str] = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            """Answer each POST with what `respond` answers."""

            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:
                """Read the body, and answer it, closing the connection.

                Closed so that no thread waits on a client after its
                test, and the answer is written where a client that
                gave up is no longer there to read it.
                """
                body = self.rfile.read(int(self.headers["Content-Length"]))
                owner.requests.append(self.path)
                status, payload, headers = respond(self.path, body)
                self.send_response(status)
                for name, value in headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Connection", "close")
                self.close_connection = True
                with contextlib.suppress(OSError):
                    self.end_headers()
                    self.wfile.write(payload)

            @override
            def log_message(self, format: str, *args: object) -> None:
                """Write nothing."""

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        if context is not None:
            self.server.socket = context.wrap_socket(
                self.server.socket, server_side=True
            )
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            kwargs={"poll_interval": 0.05},
            daemon=True,
        )
        self.thread.start()

    def url(self, scheme: str = "http", host: str = "127.0.0.1") -> str:
        """Return the URL of the server.

        :param scheme: http or https.
        :param host: how the host is written.
        :returns: the URL.
        """
        return f"{scheme}://{host}:{self.port}/"

    def stop(self) -> None:
        """Stop serving, and close the port."""
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()


def serving(node: Ethereum) -> Callable[[str, bytes], Exchange]:
    """Return what answers each request as the node does.

    :param node: the node.
    :returns: the responder.
    """
    return lambda _, body: (200, node.answer(body), {})


@contextlib.contextmanager
def serve(
    respond: Callable[[str, bytes], Exchange], context: ssl.SSLContext | None = None
) -> Iterator[HttpServer]:
    """Serve on the loopback interface for the length of a `with`.

    :param respond: what answers each request.
    :param context: the TLS context, for HTTPS.
    :yields: the server, stopped on leaving.
    """
    started = HttpServer(respond, context)
    try:
        yield started
    finally:
        started.stop()


@pytest.fixture
def server() -> Iterator[Callable[..., HttpServer]]:
    """Start servers on demand, each stopped at teardown.

    :yields: what starts one, given `serve`'s arguments.
    """
    with contextlib.ExitStack() as stack:

        def start(
            respond: Callable[[str, bytes], Exchange],
            context: ssl.SSLContext | None = None,
        ) -> HttpServer:
            return stack.enter_context(serve(respond, context))

        yield start


@pytest.mark.parametrize(
    "text, value",
    [
        ("0x0", 0),
        ("0x1", 1),
        ("0x2377", 0x2377),
        ("0x" + "f" * 64, 2**256 - 1),
        # eth_getBalance's example in the specification's state.yaml
        ("0x1cfe56f3795885980000", 0x1CFE56F3795885980000),
    ],
)
def test_a_quantity_is_read(text: str, value: int) -> None:
    """``0x``, then 0 or lower-case hex digits with no leading zero.

    :param text: the quantity.
    :param value: what it spells.
    """
    assert quantity(text) == value


@pytest.mark.parametrize(
    "text",
    [
        "0x",
        "0x00",
        "0x01",
        "0xA",
        "0X1",
        "1",
        " 0x1",
        "0x1\n",
        "0x-1",
        "0x1g",
        "0x1" + "0" * 64,
    ],
)
def test_a_malformed_quantity_is_refused(text: str) -> None:
    """A leading zero, upper case, no prefix, a space, a digit not ASCII.

    :param text: the string refused.
    """
    with pytest.raises(SeedScanValueError):
        quantity(text)


@pytest.mark.parametrize("value", [1, None, ["0x1"], b"0x1"])
def test_a_quantity_that_is_no_string_is_a_type_error(value: object) -> None:
    """A JSON number is not a quantity either.

    :param value: the value refused.
    """
    with pytest.raises(SeedScanTypeError):
        quantity(value)


@pytest.mark.parametrize(
    "url, name",
    [
        ("https://node.example", "https://node.example"),
        ("https://node.example:8545/rpc?key=secret", "https://node.example:8545"),
        ("http://127.0.0.1:8545", "http://127.0.0.1:8545"),
        ("http://127.1.2.3:8545", "http://127.1.2.3:8545"),
        ("http://[::1]:8545", "http://[::1]:8545"),
        ("HTTPS://Node.Example", "https://node.example"),
    ],
)
def test_the_node_is_named_without_path_or_query(url: str, name: str) -> None:
    """The scheme, the host and the port: a path or a query can hold a token.

    :param url: the URL given.
    :param name: the node's name.
    """
    assert Node(url).name == name


@pytest.mark.parametrize(
    "url, said",
    [
        ("http://localhost:8545", "plain http is accepted on a loopback address"),
        ("http://192.168.1.2:8545", "plain http is accepted on a loopback address"),
        ("http://node.example", "plain http is accepted on a loopback address"),
        ("ftp://127.0.0.1", "not http or https"),
        ("127.0.0.1:8545", "not http or https"),
        ("https://", "names no host"),
        ("https://:8545", "names no host"),
        ("https://user@node.example", "carries a login"),
        ("https://node.example:0", "port is not 1 to 65535"),
        ("https://node.example:65536", "port is not 1 to 65535"),
        ("https://node.example:port", "port is not 1 to 65535"),
        ("https://[::1", "does not parse"),
        ("https://nöde.example", "not printable ASCII"),
        ("https://node.example/a b", "not printable ASCII"),
        ("https://node.example/\x00", "not printable ASCII"),
    ],
)
def test_a_url_that_is_not_one_the_node_takes_is_refused(url: str, said: str) -> None:
    """Plain http off loopback, another scheme, no host, a login, a port.

    :param url: the URL given.
    :param said: what the refusal says.
    """
    with pytest.raises(SeedScanValueError, match=said) as caught:
        Node(url)
    assert "user" not in str(caught.value)


def test_a_url_that_is_no_string_is_a_type_error() -> None:
    """A URL is a string."""
    with pytest.raises(SeedScanTypeError):
        Node(b"https://node.example")  # type: ignore[arg-type]


def test_each_method_asks_its_quantity() -> None:
    """The chain id, the block number, a balance and a nonce."""
    address = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
    fake = Ethereum({address: 10**18}, {address: 3}, chain_id=11155111)
    node = Node("https://node.example", transport=fake)
    assert node.chain_id() == 11155111
    assert node.block_number() == 0x10
    assert node.balance(address) == 10**18
    assert node.nonce(address) == 3
    assert node.nonce("0x" + "00" * 20) == 0
    assert fake.asked == [
        "eth_chainId",
        "eth_blockNumber",
        "eth_getBalance",
        "eth_getTransactionCount",
        "eth_getTransactionCount",
    ]
    assert node.requests == len(fake.asked)


def response(**members: object) -> dict[str, object]:
    """Return a response object to the first request, with members replaced.

    :param members: the members replaced, or removed where ``...``.
    :returns: the response.
    """
    document = {"jsonrpc": "2.0", "id": 1, "result": "0x1", **members}
    return {k: v for k, v in document.items() if v is not ...}


@pytest.mark.parametrize(
    "body",
    [
        f"not json {MARK}".encode(),
        b"\xff" + MARK.encode(),
        b"NaN",
        b'{"jsonrpc": "2.0", "id": 1, "result": NaN}',
        b"[" * (MAX_ANSWER - 1),
        [response()],
        response(jsonrpc=...),
        response(jsonrpc="1.0"),
        response(id=2),
        response(id=1.0),
        response(id=True),
        response(id=...),
        response(result=...),
        response(error={"code": 1, "message": MARK}),
        response(result=..., error=MARK),
        response(result=..., error={"code": True, "message": MARK}),
        response(result=..., error={"code": "1", "message": MARK}),
        response(result="0x01"),
        response(result=1),
        response(result=None),
        response(result=MARK),
        response(result="0x" + "f" * 3600),
        response(result=..., error={"code": -1}),
        response(result=..., error={"code": -1, "message": []}),
    ],
)
def test_an_answer_that_is_no_response_is_refused_unquoted(body: object) -> None:
    """Not JSON, not an object, not 2.0, another id, no single member.

    And an error object with no integer code, a result that is no
    quantity, a NaN, and a body nested past the recursion limit, which is
    under the size bound.

    :param body: what the node answers.
    """
    node = Node("https://node.example", transport=answering(body))
    with pytest.raises(FetchError) as caught:
        node.chain_id()
    assert not isinstance(caught.value, (HttpError, RpcError))
    assert MARK not in str(caught.value)
    assert str(caught.value).startswith("https://node.example: ")


def test_an_error_object_is_an_rpc_error_with_its_code() -> None:
    """The code is kept; the message and the data are not."""
    error = {"code": -32601, "message": MARK, "data": MARK}
    node = Node(
        "https://node.example", transport=answering(response(result=..., error=error))
    )
    with pytest.raises(RpcError) as caught:
        node.balance("0x" + "00" * 20)
    assert caught.value.code == -32601
    assert caught.value.data is None
    assert MARK not in str(caught.value)


def test_the_request_ids_are_matched_in_turn() -> None:
    """The second request is answered by id 2, and id 1 is refused for it."""
    node = Node("https://node.example", transport=answering(response(), response(id=1)))
    assert node.chain_id() == 1
    with pytest.raises(FetchError):
        node.chain_id()


def test_a_node_over_http_on_loopback_is_asked(
    server: Callable[..., HttpServer],
) -> None:
    """A JSON POST to the URL as given, path included."""
    address = "0x" + "11" * 20
    served = server(serving(Ethereum({address: 7})))
    node = Node(f"{served.url()}rpc/path")
    assert node.balance(address) == 7
    assert served.requests == ["/rpc/path"]


def test_a_status_other_than_200_is_an_http_error(
    server: Callable[..., HttpServer],
) -> None:
    """The status is kept, and the body is not read as an answer."""
    served = server(lambda _, __: (503, json.dumps(response()).encode(), {}))
    with pytest.raises(HttpError) as caught:
        Node(served.url()).chain_id()
    assert caught.value.status == 503


def test_a_redirect_is_not_followed(server: Callable[..., HttpServer]) -> None:
    """A 307 is its status, and the place it names is asked nothing."""
    target = server(serving(Ethereum()))
    moved = server(lambda _, __: (307, b"", {"Location": target.url()}))
    with pytest.raises(HttpError) as caught:
        Node(moved.url()).chain_id()
    assert caught.value.status == 307
    with SessionTransport() as session, pytest.raises(HttpError) as caught:
        Node(moved.url(), transport=session).chain_id()
    assert caught.value.status == 307
    assert not target.requests


def test_an_answer_past_the_bound_is_refused(
    server: Callable[..., HttpServer],
) -> None:
    """Refused rather than truncated, however well formed."""
    padded = response(padding="x" * MAX_ANSWER)
    served = server(lambda _, __: (200, json.dumps(padded).encode(), {}))
    with SessionTransport() as session, pytest.raises(FetchError) as caught:
        Node(served.url(), transport=session).chain_id()
    assert str(caught.value) == f"http://127.0.0.1:{served.port}: no answer"
    assert caught.value.__cause__ is None


def test_the_timeout_bounds_the_whole_exchange(
    server: Callable[..., HttpServer],
) -> None:
    """A node slower than the timeout is a failure caused by the timeout.

    The node answers once the client has given up, and the test waits for
    that answer, so that the handler ends before the test does.
    """
    gave_up = threading.Event()
    answered = threading.Event()

    def slow(_: str, body: bytes) -> Exchange:
        gave_up.wait(5)
        try:
            return 200, Ethereum().answer(body), {}
        finally:
            answered.set()

    served = server(slow)
    started = time.monotonic()
    with pytest.raises(FetchError) as caught:
        Node(served.url(), timeout=0.1).chain_id()
    elapsed = time.monotonic() - started
    gave_up.set()
    assert answered.wait(5)
    assert elapsed < 0.5
    assert isinstance(cause(caught.value, TimeoutError), TimeoutError)


def cause(error: BaseException, kind: type[BaseException]) -> BaseException | None:
    """Return the first error of a kind in the chain of causes.

    :param error: where the chain starts.
    :param kind: the class looked for.
    :returns: the first cause of that class, or None.
    """
    found: BaseException | None = error
    while found is not None and not isinstance(found, kind):
        found = found.__cause__
    return found


def test_no_proxy_is_taken_from_the_environment(
    server: Callable[..., HttpServer], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The variables name a proxy that would answer; the node is asked."""
    proxy = server(lambda _, __: (200, json.dumps(response(result="0x5")).encode(), {}))
    served = server(serving(Ethereum()))
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(name, proxy.url())
    assert Node(served.url()).chain_id() == 1
    with SessionTransport() as session:
        assert Node(served.url(), transport=session).chain_id() == 1
    assert not proxy.requests
    assert len(served.requests) == 2


def test_a_closed_port_is_no_connection() -> None:
    """Nothing listens: a failure caused by the refused connection."""
    with socket.create_server(("127.0.0.1", 0)) as listening:
        port = listening.getsockname()[1]
    with SessionTransport() as session, pytest.raises(FetchError) as caught:
        Node(f"http://127.0.0.1:{port}", transport=session).chain_id()
    assert cause(caught.value, ConnectionRefusedError) is not None


class _Reply(socketserver.StreamRequestHandler):
    """Read one HTTP request whole, and answer the server's bytes."""

    @override
    def handle(self) -> None:
        """Read the head and the body, then write the reply and close."""
        length = 0
        while line := self.rfile.readline().strip():
            name, _, value = line.partition(b":")
            if name.lower() == b"content-length":
                length = int(value)
        self.rfile.read(length)
        self.wfile.write(self.server.reply)  # type: ignore[attr-defined]


@contextlib.contextmanager
def replying(reply: bytes) -> Iterator[int]:
    """Answer every request on a loopback port with the same bytes.

    :param reply: what is written back, whether HTTP or not.
    :yields: the port.
    """
    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Reply) as raw:
        raw.daemon_threads = True
        raw.reply = reply  # type: ignore[attr-defined]
        thread = threading.Thread(
            target=raw.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )
        thread.start()
        try:
            yield raw.server_address[1]
        finally:
            raw.shutdown()
            thread.join()


def everything_said(error: BaseException) -> str:
    """Return the text of an error, its chain and its traceback.

    :param error: the error.
    :returns: what printing it, with every cause and context, shows.
    """
    return "".join(traceback.format_exception(error))


@pytest.mark.parametrize(
    "reply",
    [
        f"HTTP/1.1 2OO {MARK}\r\n\r\n".encode(),
        f"{MARK}\r\n\r\n".encode(),
        f"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n{MARK}".encode(),
    ],
)
def test_a_reply_that_is_no_http_is_not_quoted(reply: bytes) -> None:
    """A status line that does not parse, and a body cut short.

    `http.client` quotes the line it refused, and `http_request` the
    error: neither the failure nor anything it chains says it, whether
    it is a failure below the answer or an answer refused.

    :param reply: what the node writes back.
    """
    with replying(reply) as port:
        url = f"http://127.0.0.1:{port}"
        with pytest.raises(FetchError) as plain:
            Node(url).chain_id()
        with SessionTransport() as session, pytest.raises(FetchError) as kept:
            Node(url, transport=session).chain_id()
    for caught in (plain, kept):
        assert str(caught.value).startswith(f"{url}: ")
        assert MARK not in everything_said(caught.value)
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None


def test_a_failure_keeps_its_class_and_drops_its_message() -> None:
    """The refused connection is a fresh, empty error of its class."""
    with socket.create_server(("127.0.0.1", 0)) as listening:
        port = listening.getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    with pytest.raises(FetchError) as caught:
        Node(url).chain_id()
    cause_ = caught.value.__cause__
    assert type(cause_) is ConnectionRefusedError
    assert cause_.args == ()
    assert cause_.__cause__ is None
    assert cause_.__context__ is None


def test_a_failed_exchange_leaves_no_socket_to_the_collector(
    server: Callable[..., HttpServer],
) -> None:
    """Everything the failed exchange held is freed when the call returns.

    `SessionTransport` leaves its response in its frame where its bounded
    read raises. Left to the collector, the socket under it can be
    finalized first, and warns that it was never closed. Without the
    release of those frames, this test fails on 3.12.
    """
    padded = response(padding="x" * MAX_ANSWER)
    served = server(lambda _, __: (200, json.dumps(padded).encode(), {}))
    assert gc.isenabled()
    gc.collect()
    gc.disable()
    try:
        with SessionTransport() as session, pytest.raises(FetchError):
            Node(served.url(), transport=session).chain_id()
        with warnings.catch_warnings(record=True) as seen:
            warnings.simplefilter("always", ResourceWarning)
            gc.collect()
    finally:
        gc.enable()
    assert not [str(w.message) for w in seen]
