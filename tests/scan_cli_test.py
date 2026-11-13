# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for ``seed-scan scan``: the server, the TLS check, the refusals.

The Electrum server is `Electrum`, a fake kept in memory that answers the
methods `ElectrumFetcher` asks over a chain that is mainnet's genesis
block alone, and lists each payment as a mempool transaction: no header
past the genesis is needed, whose proof of work no test could produce.
Most tests hand it to the command in place of the TLS transport. The
others serve it over TLS on the loopback interface, with the certificates
of ``tests/tls``, so that the handshake the command makes is the one
under test. Those were made with OpenSSL, valid until 2126:
``ca.pem`` a self-signed CA certificate, and ``server.pem`` a certificate
it signed for ``IP:127.0.0.1``, with its key, which only these tests use.
"""

from __future__ import annotations

import json
import socket
import ssl
import threading
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from bitcoin_core_rpc import FetchError as RpcFetchError
from btclib.block.block_header import BlockHeader
from btclib.network import NETWORKS
from btclib.script import ScriptPubKey
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from btclib_wallet.descriptors import parse

from seed_scan import cli
from seed_scan.bundle import dumps, loads
from seed_scan.identify import identify

from .identify_test import ABANDON, no_share

if TYPE_CHECKING:
    from collections.abc import Iterator

    from btclib_wallet.fetch.transport import LineTransport

#: The certificates the loopback server presents and the client trusts.
TLS = Path(__file__).parent / "tls"

#: A script that is none of the bundle's.
ELSEWHERE = ScriptPubKey(b"\x00\x14" + bytes(20))

#: Mainnet's genesis block header: `CreateGenesisBlock` in Bitcoin Core's
#: `src/kernel/chainparams.cpp`, its time, nonce, bits and merkle root.
GENESIS = BlockHeader(
    version=1,
    previous_block_hash=bytes(32),
    merkle_root=bytes.fromhex(
        "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    ),
    time=datetime.fromtimestamp(1231006505, UTC),
    bits=bytes.fromhex("1d00ffff"),
    nonce=2083236893,
)


def scripthash(script: ScriptPubKey) -> str:
    """Return a script's hash as the Electrum protocol spells it.

    :param script: the script.
    :returns: its sha256, reversed, as hex.
    """
    return sha256(script.script).digest()[::-1].hex()


class Electrum:
    """An Electrum server over the genesis block and a mempool."""

    def __init__(self, *payments: Tx, genesis: BlockHeader = GENESIS) -> None:
        """Hold the payments, each in the mempool, and the genesis block.

        :param payments: the transactions the mempool holds.
        :param genesis: the header the server answers at height 0.
        """
        self.genesis = genesis.serialize().hex()
        self.txs = {tx.id.hex(): tx for tx in payments}
        self.history: dict[str, list[str]] = {}
        for tx in payments:
            for out in tx.vout:
                self.history.setdefault(scripthash(out.script_pub_key), []).append(
                    tx.id.hex()
                )
        self.asked: list[str] = []
        self.unrelated: list[str] = []
        self.moves = 0
        self.subscribed = 0
        self.listed_unrelated = 0

    def list_everywhere(self, tx: Tx, *served: Tx) -> None:
        """List a transaction under every script asked, touching none.

        :param tx: the transaction listed.
        :param served: what else the server serves: what `tx` spends.
        """
        self.unrelated.append(tx.id.hex())
        self.txs.update({t.id.hex(): t for t in (tx, *served)})

    def answer(self, request: bytes) -> bytes:
        """Answer one request line.

        :param request: the JSON-RPC request.
        :returns: the answering line, without its newline.
        """
        parsed = json.loads(request)
        method, params = parsed["method"], parsed["params"]
        self.asked.append(method)
        result: object = self.genesis
        if method == "blockchain.headers.subscribe":
            # the second of the two a history read asks: a tip at another
            # height is a tip that moved, while `moves` lasts
            self.subscribed += 1
            moved = self.subscribed % 2 == 0 and self.moves > 0
            self.moves -= moved
            result = {"height": int(moved), "hex": self.genesis}
        elif method == "blockchain.scripthash.get_history":
            ids = self.history.get(params[0], []) + self.unrelated
            self.listed_unrelated += len(self.unrelated)
            result = [{"tx_hash": tx_id, "height": 0} for tx_id in ids]
        elif method == "blockchain.transaction.get":
            result = self.txs[params[0]].serialize(include_witness=True).hex()
        answer = {"jsonrpc": "2.0", "id": parsed["id"], "result": result}
        return json.dumps(answer).encode()

    def __call__(self, request: bytes, timeout: float) -> bytes:
        """Answer as a `LineTransport` does.

        :param request: the request line.
        :param timeout: unread.
        :returns: the answering line.
        """
        return self.answer(request)


class Connections:
    """A `connect` for the command that hands it a fake server."""

    def __init__(self, server: LineTransport) -> None:
        """Hold the server.

        :param server: what every connection reaches.
        """
        self.server = server
        self.made: list[tuple[str, int, ssl.SSLContext]] = []

    def __call__(self, host: str, port: int, context: ssl.SSLContext) -> LineTransport:
        """Record the connection asked for, and answer the server.

        :param host: the host.
        :param port: the port.
        :param context: the TLS context.
        :returns: the server.
        """
        self.made.append((host, port, context))
        return self.server


def pay(script: ScriptPubKey, value: int) -> Tx:
    """Return a payment from outside to a script.

    :param script: the script paid.
    :param value: the satoshis.
    :returns: the transaction.
    """
    return Tx(vin=[TxIn(OutPoint(b"\xff" * 32, 0))], vout=[TxOut(value, script)])


@pytest.fixture(scope="module")
def bundle_text() -> str:
    """Return the bundle of BIP84's mnemonic, one account of each purpose.

    :returns: its text.
    """
    return dumps(identify(ABANDON, [""], no_share, accounts=1))


@pytest.fixture
def bundle(bundle_text: str, tmp_path: Path) -> str:
    """Write the bundle to a file.

    :param bundle_text: the bundle.
    :param tmp_path: pytest's directory for the test.
    :returns: the file's path.
    """
    path = tmp_path / "bundle.json"
    path.write_text(bundle_text, encoding="utf-8")
    return str(path)


def receive_script(text: str, path: str) -> ScriptPubKey:
    """Return the first receiving script of an account of a bundle.

    :param text: the bundle's text.
    :param path: the account's path.
    :returns: the script at index 0 of its receive branch.
    """
    (account,) = [a for r in loads(text).readings for a in r.accounts if a.path == path]
    return parse(account.descriptors[0]).script_pub_keys(0)[0]


def run(
    capsys: pytest.CaptureFixture[str], argv: list[str], connect: Connections
) -> tuple[int, str, str]:
    """Run the command; answer its status and output.

    :param capsys: pytest's capture of the standard streams.
    :param argv: the arguments after ``scan``.
    :param connect: what makes the connection.
    :returns: the exit status, standard output and standard error.
    """
    status = cli.main(["scan", *argv], connect=connect)
    out, err = capsys.readouterr()
    return status, out, err


def test_the_genesis_header_is_mainnets() -> None:
    """The fake serves the block Bitcoin's mainnet starts from."""
    assert GENESIS.hash == NETWORKS["mainnet"].genesis_block


def test_scan_writes_the_result_and_a_summary(
    capsys: pytest.CaptureFixture[str], bundle: str, bundle_text: str
) -> None:
    """A payment in the mempool is a used account, with its balance."""
    paid = receive_script(bundle_text, "m/84h/0h/0h")
    connect = Connections(Electrum(pay(paid, 2_500)))
    argv = [bundle, "--server", "node.local:50002"]
    status, out, err = run(capsys, argv, connect)
    assert status == 0
    document = json.loads(out)
    (used,) = document["used"]
    assert used["path"] == "m/84h/0h/0h"
    assert used["addresses"] == [{"branch": 0, "index": 0, "address": paid.address}]
    assert (used["confirmed"], used["unconfirmed"]) == (0, 2_500)
    assert document["server"] == "node.local:50002"
    assert (document["gap_limit"], document["account_gap"]) == (20, 3)
    bounds = "bounds: account gap 3, gap limit 20"
    assert err.startswith(f"server: node.local:50002\n{bounds}\n")
    assert "used: reading 0, m/84h/0h/0h: 1 addresses, 1 transactions" in err
    assert "not checked: reading 0, ethereum:" in err
    ((host, port, _),) = connect.made
    assert (host, port) == ("node.local", 50002)


def test_the_summary_says_nothing_was_used_and_what_was_cut_short(
    capsys: pytest.CaptureFixture[str], bundle: str, bundle_text: str
) -> None:
    """One account per purpose, used: the purpose is cut short."""
    paid = receive_script(bundle_text, "m/44h/0h/0h")
    connect = Connections(Electrum(pay(paid, 1)))
    status, _, err = run(capsys, [bundle, "--server", "h:1"], connect)
    assert status == 0
    assert "reading 0, purpose 44: accounts read: 1, cut short" in err
    status, _, err = run(capsys, [bundle, "--server", "h:1"], Connections(Electrum()))
    assert status == 0
    assert "no account used within that bound" in err


def test_the_bounds_are_the_options_given(
    capsys: pytest.CaptureFixture[str], bundle: str
) -> None:
    """The bound options reach the result and the summary.

    A gap of 1 is reached inside a bundle of one account per purpose, so
    no purpose is cut short.
    """
    argv = [bundle, "--server", "h:1", "--account-gap", "1", "--gap-limit", "7"]
    status, out, err = run(capsys, argv, Connections(Electrum()))
    assert status == 0
    document = json.loads(out)
    assert (document["gap_limit"], document["account_gap"]) == (7, 1)
    assert "\nbounds: account gap 1, gap limit 7\n" in err
    assert "\nreading 0, purpose 44: accounts read: 1\n" in err


def test_the_context_verifies_the_certificate_and_the_host(
    capsys: pytest.CaptureFixture[str], bundle: str
) -> None:
    """The system's CA certificates by default, the file's with --cafile."""
    connect = Connections(Electrum())
    run(capsys, [bundle, "--server", "h:1"], connect)
    run(capsys, [bundle, "--server", "h:1", "--cafile", str(TLS / "ca.pem")], connect)
    for _, _, context in connect.made:
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname
        assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    (ca,) = connect.made[1][2].get_ca_certs()
    assert ca["subject"] == ((("commonName", "seed-scan test CA"),),)


def test_a_server_on_another_chain_is_asked_for_no_address(
    capsys: pytest.CaptureFixture[str], bundle: str
) -> None:
    """Its genesis block is not mainnet's: refused before any history."""
    other = BlockHeader(
        version=1,
        previous_block_hash=bytes(32),
        merkle_root=GENESIS.merkle_root,
        time=GENESIS.time,
        bits=bytes.fromhex("207fffff"),
        nonce=2,
    )
    server = Electrum(genesis=other)
    status, out, err = run(capsys, [bundle, "--server", "h:1"], Connections(server))
    assert (status, out) == (1, "")
    assert err == "seed-scan scan: the server does not serve Bitcoin's mainnet\n"
    assert server.asked == ["blockchain.block.header"]


class Failing:
    """A server whose every answer is one failure."""

    def __init__(self, failure: Exception) -> None:
        """Hold the failure.

        :param failure: what each call raises.
        """
        self.failure = failure

    def __call__(self, request: bytes, timeout: float) -> bytes:
        """Raise the failure.

        :param request: unread.
        :param timeout: unread.
        :raises Exception: the failure.
        """
        raise self.failure


def caused(cause: BaseException) -> RpcFetchError:
    """Return the transport's failure, caused by `cause`.

    :param cause: what the socket raised.
    :returns: the failure, quoting what a server could make it quote.
    """
    failure = RpcFetchError(f"no answer from h:1: {ABANDON}")
    failure.__cause__ = cause
    return failure


@pytest.mark.parametrize(
    "failure, said",
    [
        (
            caused(ssl.SSLCertVerificationError()),
            "the server's certificate did not verify",
        ),
        (caused(ssl.SSLError()), "the TLS handshake with the server failed"),
        (caused(ConnectionRefusedError()), "no connection to the server"),
        (caused(TimeoutError()), "the server did not answer in time"),
        (
            RpcFetchError(f"h:1: line too long {ABANDON}"),
            "no usable answer from the server",
        ),
        (ValueError(ABANDON), "refused by a dependency: ValueError"),
        (KeyboardInterrupt(), "interrupted"),
    ],
)
def test_a_failure_is_one_line_of_fixed_text(
    capsys: pytest.CaptureFixture[str], bundle: str, failure: Exception, said: str
) -> None:
    """The class of the failure decides the line, never its message.

    :param capsys: pytest's capture of the standard streams.
    :param bundle: the bundle's file.
    :param failure: what the transport raises.
    :param said: the line written.
    """
    connect = Connections(Failing(failure))
    status, out, err = run(capsys, [bundle, "--server", "h:1"], connect)
    assert (status, out) == (1, "")
    assert err == f"seed-scan scan: {said}\n"


def test_an_error_the_server_answers_is_a_refusal(
    capsys: pytest.CaptureFixture[str], bundle: str
) -> None:
    """A JSON-RPC error object: the server refused, whatever it said."""

    def refusing(request: bytes, timeout: float) -> bytes:
        parsed = json.loads(request)
        error = {"code": 1, "message": ABANDON}
        return json.dumps(
            {"jsonrpc": "2.0", "id": parsed["id"], "error": error}
        ).encode()

    status, _, err = run(capsys, [bundle, "--server", "h:1"], Connections(refusing))
    assert status == 1
    assert err == "seed-scan scan: the server refused a request\n"


@pytest.mark.parametrize(
    "server, said",
    [
        ("node.local", "--server is not host:port"),
        (":50002", "--server is not host:port"),
        ("h:port", "--server is not host:port"),
        ("h:", "--server is not host:port"),
        ("h:0", "--server: the port is not 1 to 65535"),
        ("h:65536", "--server: the port is not 1 to 65535"),
    ],
)
def test_a_server_that_is_not_host_and_port_is_refused(
    capsys: pytest.CaptureFixture[str], bundle: str, server: str, said: str
) -> None:
    """Refused before any connection.

    :param capsys: pytest's capture of the standard streams.
    :param bundle: the bundle's file.
    :param server: what --server names.
    :param said: the line written.
    """
    connect = Connections(Electrum())
    status, _, err = run(capsys, [bundle, "--server", server], connect)
    assert (status, err) == (1, f"seed-scan scan: {said}\n")
    assert not connect.made


def test_an_ipv6_host_is_in_brackets(
    capsys: pytest.CaptureFixture[str], bundle: str
) -> None:
    """The brackets are not part of the host."""
    connect = Connections(Electrum())
    run(capsys, [bundle, "--server", "[::1]:50002"], connect)
    ((host, port, _),) = connect.made
    assert (host, port) == ("::1", 50002)


def test_a_host_the_transport_refuses_is_not_quoted(
    capsys: pytest.CaptureFixture[str], bundle: str
) -> None:
    """An empty label: the TLS transport refuses it, and opens nothing."""
    assert cli.main(["scan", bundle, "--server", "a..b:1"]) == 1
    assert (
        capsys.readouterr().err
        == "seed-scan scan: --server names no host a connection can use\n"
    )


def test_a_cafile_with_no_certificate_is_refused(
    capsys: pytest.CaptureFixture[str], bundle: str, tmp_path: Path
) -> None:
    """A missing file, and a file holding none."""
    for cafile in (str(tmp_path / "missing.pem"), bundle):
        argv = [bundle, "--server", "h:1", "--cafile", cafile]
        status, _, err = run(capsys, argv, Connections(Electrum()))
        assert status == 1
        assert (
            err == "seed-scan scan: --cafile: no certificate could be loaded from it\n"
        )


def test_a_file_that_is_no_bundle_is_refused_unquoted(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A missing file, bytes that are not UTF-8, and a mnemonic."""
    missing = tmp_path / "missing.json"
    binary = tmp_path / "binary"
    binary.write_bytes(b"\xff" + ABANDON.encode())
    words = tmp_path / "words.txt"
    words.write_text(ABANDON, encoding="utf-8")
    unreadable = "seed-scan scan: the bundle file cannot be read as UTF-8 text\n"
    for path, said in (
        (missing, unreadable),
        (binary, unreadable),
        (words, "seed-scan scan: bundle: not JSON, at line 1 column 1\n"),
    ):
        server = Electrum()
        argv = [str(path), "--server", "h:1"]
        status, out, err = run(capsys, argv, Connections(server))
        assert (status, out, err) == (1, "", said)
        assert server.asked == []


class TlsServer:
    """`Electrum` over TLS on the loopback interface, in a thread."""

    def __init__(self, electrum: Electrum) -> None:
        """Listen on a port of 127.0.0.1, and serve until stopped.

        :param electrum: what answers each request.
        """
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(TLS / "server.pem")
        self.electrum = electrum
        self.listening = socket.create_server(("127.0.0.1", 0))
        self.listening.settimeout(0.05)
        self.port = self.listening.getsockname()[1]
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self) -> None:
        """Answer one request per connection, until stopped."""
        while not self.stopped.is_set():
            try:
                connection, _ = self.listening.accept()
            except TimeoutError:
                continue
            connection.settimeout(5)
            try:
                with self.context.wrap_socket(connection, server_side=True) as tls:
                    line = tls.makefile("rb").readline()
                    tls.sendall(self.electrum.answer(line) + b"\n")
            except OSError:
                # the client refused the certificate, and closed
                connection.close()

    def stop(self) -> None:
        """Stop serving, and close the port."""
        self.stopped.set()
        self.thread.join()
        self.listening.close()


@pytest.fixture
def tls_server(bundle_text: str) -> Iterator[TlsServer]:
    """Serve a payment to the first BIP84 address over TLS.

    :param bundle_text: the bundle.
    :yields: the server, stopped at teardown.
    """
    server = TlsServer(Electrum(pay(receive_script(bundle_text, "m/84h/0h/0h"), 9)))
    yield server
    server.stop()


def test_a_server_whose_certificate_the_cafile_names_is_scanned(
    capsys: pytest.CaptureFixture[str], bundle: str, tls_server: TlsServer
) -> None:
    """The certificate chains to the file's CA, and names the host."""
    argv = ["scan", bundle, "--server", f"127.0.0.1:{tls_server.port}"]
    argv += ["--cafile", str(TLS / "ca.pem"), "--gap-limit", "2"]
    assert cli.main(argv) == 0
    (used,) = json.loads(capsys.readouterr().out)["used"]
    assert used["unconfirmed"] == 9


@pytest.mark.parametrize(
    "host, cafile",
    [
        # the CA is in no system store
        ("127.0.0.1", None),
        # the certificate names 127.0.0.1, not localhost
        ("localhost", TLS / "ca.pem"),
    ],
)
def test_a_certificate_that_does_not_verify_is_refused(
    capsys: pytest.CaptureFixture[str],
    bundle: str,
    tls_server: TlsServer,
    host: str,
    cafile: Path | None,
) -> None:
    """An untrusted certificate, and a trusted one naming another host.

    :param capsys: pytest's capture of the standard streams.
    :param bundle: the bundle's file.
    :param tls_server: the server.
    :param host: the host the command is given.
    :param cafile: the file --cafile names, if any.
    """
    argv = ["scan", bundle, "--server", f"{host}:{tls_server.port}"]
    argv += [] if cafile is None else ["--cafile", str(cafile)]
    assert cli.main(argv) == 1
    err = capsys.readouterr().err
    assert err == "seed-scan scan: the server's certificate did not verify\n"
    assert tls_server.electrum.asked == []


def test_a_closed_port_is_no_connection(
    capsys: pytest.CaptureFixture[str], bundle: str
) -> None:
    """Nothing listens: the connection is refused."""
    with socket.create_server(("127.0.0.1", 0)) as listening:
        port = listening.getsockname()[1]
    assert cli.main(["scan", bundle, "--server", f"127.0.0.1:{port}"]) == 1
    assert capsys.readouterr().err == "seed-scan scan: no connection to the server\n"


def test_a_transaction_touching_no_script_is_left_out(
    capsys: pytest.CaptureFixture[str], bundle: str, bundle_text: str
) -> None:
    """A server listing one under every script: it is not the account's."""
    paid = receive_script(bundle_text, "m/84h/0h/0h")
    server = Electrum(pay(paid, 3))
    funding = Tx(vin=[TxIn(OutPoint(b"\xee" * 32, 0))], vout=[TxOut(5, ELSEWHERE)])
    unrelated = Tx(vin=[TxIn(OutPoint(funding.id, 0))], vout=[TxOut(4, ELSEWHERE)])
    server.list_everywhere(unrelated, funding)
    status, out, _ = run(capsys, [bundle, "--server", "h:1"], Connections(server))
    assert status == 0
    (used,) = json.loads(out)["used"]
    listed = [t["tx_id"] for t in used["transactions"]]
    assert listed == [pay(paid, 3).id.hex()]
    assert server.listed_unrelated > 0


@pytest.mark.parametrize("moves, status", [(2, 0), (3, 1)])
def test_a_read_whose_tip_moved_is_read_again(
    capsys: pytest.CaptureFixture[str], bundle: str, moves: int, status: int
) -> None:
    """Up to three reads of one history, then a line of fixed text.

    :param capsys: pytest's capture of the standard streams.
    :param bundle: the bundle's file.
    :param moves: how many reads in a row see the tip move.
    :param status: the exit status.
    """
    server = Electrum()
    server.moves = moves
    result = run(capsys, [bundle, "--server", "h:1"], Connections(server))
    assert result[0] == status
    assert server.moves == 0
    if status:
        said = "the server's tip moved during every read of a history"
        assert result[2] == f"seed-scan scan: {said}\n"


def test_another_failure_of_a_read_is_not_read_again(
    capsys: pytest.CaptureFixture[str], bundle: str
) -> None:
    """A server refusing a history: refused at the first read."""
    server = Electrum()

    def refusing_history(request: bytes, timeout: float) -> bytes:
        parsed = json.loads(request)
        if parsed["method"] != "blockchain.scripthash.get_history":
            return server.answer(request)
        error = {"code": 1, "message": "history too large"}
        return json.dumps(
            {"jsonrpc": "2.0", "id": parsed["id"], "error": error}
        ).encode()

    connect = Connections(refusing_history)
    status, _, err = run(capsys, [bundle, "--server", "h:1"], connect)
    assert (status, err) == (1, "seed-scan scan: the server refused a request\n")
    assert server.asked.count("blockchain.headers.subscribe") == 1
