# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for ``seed-scan scan``: the server, the node, TLS, the refusals.

The Electrum server is `Electrum`, a fake kept in memory that answers the
methods `ElectrumFetcher` asks over mainnet's genesis block and Bitcoin's
block at the command's checkpoint, and lists each payment as a mempool
transaction: no other header is needed, whose proof of work no test could
produce. The checkpoint's header is a real one, which a test checks
hashes to the id the command compares. Most tests hand it to the command
in place of the transport. The others serve it on the loopback
interface, over TLS with the certificates the `tls` fixture makes or
over plain TCP, so that the connections the command makes are the ones
under test.

The Ethereum node is `tests.evm_test`'s `Ethereum`, served over HTTP, or
HTTPS with the same certificates, on the loopback interface, so that the
command and `Node` reach it through the transport they open themselves.
"""

from __future__ import annotations

import json
import socket
import ssl
import subprocess
import sys
import threading
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from ipaddress import IPv4Address
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from bitcoin_core_rpc import FetchError as RpcFetchError
from btclib.block.block_header import BlockHeader
from btclib.network import NETWORKS
from btclib.script import ScriptPubKey
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from btclib_wallet.descriptors import parse
from btclib_wallet.exceptions import FetchError
from btclib_wallet.fetch.transport import (
    PersistentTlsLineTransport,
    SessionTransport,
)

from seed_scan import cli
from seed_scan.bundle import dumps, loads
from seed_scan.evm import Node
from seed_scan.identify import identify

from .evm_test import Ethereum, cause, replying, serve, serving
from .identify_test import ABANDON, no_share
from .scan_test import eth_address

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from btclib_wallet.fetch.transport import LineTransport

    from .evm_test import Exchange

#: Why a test serving TLS is skipped where the certificates cannot be made.
NO_CRYPTOGRAPHY = (
    "cryptography is not installed: btclib-wallet leaves it out on Windows on"
    " ARM64, where it has no wheel, and the test certificates are made with it"
)

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

#: Bitcoin's header at the height of `seed_scan.cli`'s checkpoint, as
#: mempool.space and blockstream.info answer it for that block's id.
HEADERS = {
    965000: (
        "00400220ebdea44198f5b353606b02ed21c5a5e6f75ae648ec6000000000000000000000"
        "9df7486fca4bc7c3a52a83baf35137fa37a5e88b183157ec62ca35259e36189ee77196"
        "6ac13c02177e7e50b2"
    ),
}

#: Bitcoin Cash's header at that height, as Fulcrum servers of that chain
#: answered `blockchain.block.header`.
FORKED = (
    "00006922c09c495552b27e68aa3667050ab145be4513c074918f06000000000000000000"
    "482e3b88861c21eece6ad6843bc0cbea9d9f6729e71aac37f12f7eb37473c34231f6876a"
    "64810218827d3529"
)


def scripthash(script: ScriptPubKey) -> str:
    """Return a script's hash as the Electrum protocol spells it.

    :param script: the script.
    :returns: its sha256, reversed, as hex.
    """
    return sha256(script.script).digest()[::-1].hex()


class Electrum:
    """An Electrum server over the genesis block, some headers and a mempool."""

    def __init__(
        self,
        *payments: Tx,
        genesis: BlockHeader = GENESIS,
        headers: dict[int, str] = HEADERS,
    ) -> None:
        """Hold the payments, each in the mempool, and the headers.

        :param payments: the transactions the mempool holds.
        :param genesis: the header the server answers at height 0, and at
            every height `headers` does not name.
        :param headers: the header answered at each height, as hex.
        """
        self.genesis = genesis.serialize().hex()
        self.headers = headers
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
        result: object
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
        else:
            # blockchain.block.header, the one other method asked
            result = self.headers.get(params[0], self.genesis)
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
        self.made: list[tuple[str, int, ssl.SSLContext | None]] = []

    def __call__(
        self, host: str, port: int, context: ssl.SSLContext | None
    ) -> LineTransport:
        """Record the connection asked for, and answer the server.

        :param host: the host.
        :param port: the port.
        :param context: the TLS context, or None for plain TCP.
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


def test_the_headers_are_bitcoin_s_checkpoints() -> None:
    """Each header hashes to the block id the command's checkpoint names."""
    assert dict(cli._BITCOIN_CHECKPOINTS) == {
        height: BlockHeader.parse(bytes.fromhex(header)).hash.hex()
        for height, header in HEADERS.items()
    }


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
    assert used["addresses"] == [
        {
            "branch": 0,
            "index": 0,
            "address": paid.address,
            "confirmed": 0,
            "unconfirmed": 2_500,
        }
    ]
    assert (used["confirmed"], used["unconfirmed"]) == (0, 2_500)
    assert document["server"] == "node.local:50002"
    assert (document["gap_limit"], document["account_gap"]) == (20, 3)
    bounds = "bounds: account gap 3, gap limit 20"
    assert err.startswith(f"server: node.local:50002\n{bounds}\n")
    assert "used: reading 0, m/84h/0h/0h: 1 addresses, 1 transactions" in err
    assert "not checked: reading 0, ethereum:" in err
    ((host, port, _),) = connect.made
    assert (host, port) == ("node.local", 50002)


#: A whole `scan` in an interpreter of its own, against a server that
#: answers Bitcoin's headers and no history, then its exit status and
#: whether `seed_scan.identify` was loaded. The bundle file, the genesis
#: header and the checkpoint's, as JSON, are its arguments
_SCAN_ALONE = """
import contextlib, io, json, sys
from seed_scan import cli
bundle, genesis, headers = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
def server(request, timeout):
    parsed = json.loads(request)
    result = {
        "blockchain.headers.subscribe": {"height": 0, "hex": genesis},
        "blockchain.scripthash.get_history": [],
    }.get(parsed["method"], genesis)
    if parsed["method"] == "blockchain.block.header":
        result = headers.get(str(parsed["params"][0]), genesis)
    return json.dumps({"jsonrpc": "2.0", "id": parsed["id"], "result": result}).encode()
with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
    status = cli.main(["scan", bundle, "--server", "h:1"], connect=lambda *_: server)
print(json.dumps([status, "seed_scan.identify" in sys.modules]))
"""


def test_scan_loads_no_identify(bundle: str) -> None:
    """A whole `scan`, in a fresh interpreter, never loads `seed_scan.identify`.

    The module that handles the secret stays out of a command that reads
    a bundle. A subprocess, because this module imports `identify` to
    write the bundle.
    """
    stdout = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-c",
            _SCAN_ALONE,
            bundle,
            GENESIS.serialize().hex(),
            json.dumps(HEADERS),
        ],
        check=True,
        capture_output=True,
        encoding="utf-8",
    ).stdout
    assert json.loads(stdout) == [0, False]


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
    capsys: pytest.CaptureFixture[str], bundle: str, tls: Path
) -> None:
    """The system's CA certificates by default, the file's with --cafile."""
    connect = Connections(Electrum())
    run(capsys, [bundle, "--server", "h:1"], connect)
    run(capsys, [bundle, "--server", "h:1", "--cafile", str(tls / "ca.pem")], connect)
    for _, _, context in connect.made:
        assert context is not None
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname
        assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    context = connect.made[1][2]
    assert context is not None
    (ca,) = context.get_ca_certs()
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


@pytest.mark.parametrize("header", [FORKED, GENESIS.serialize().hex()])
def test_a_server_of_a_fork_is_asked_for_no_address(
    capsys: pytest.CaptureFixture[str], bundle: str, header: str
) -> None:
    """Bitcoin's genesis, and another block at the checkpoint: refused.

    :param capsys: pytest's capture of the standard streams.
    :param bundle: the bundle's file.
    :param header: the header the server answers at the checkpoint:
        Bitcoin Cash's, and one of Bitcoin's at another height.
    """
    ((height, _),) = cli._BITCOIN_CHECKPOINTS
    server = Electrum(headers={height: header})
    status, out, err = run(capsys, [bundle, "--server", "h:1"], Connections(server))
    assert (status, out) == (1, "")
    assert err == "seed-scan scan: the server does not serve Bitcoin's mainnet\n"
    assert server.asked == ["blockchain.block.header"] * 2


def test_a_balance_past_21_million_bitcoin_is_refused(
    capsys: pytest.CaptureFixture[str], bundle: str, bundle_text: str
) -> None:
    """Two payments of 15 million bitcoin: refused, and nothing written.

    The line names the account, from the bundle, and nothing the server
    answered.
    """
    paid = receive_script(bundle_text, "m/84h/0h/0h")
    payments = [
        Tx(vin=[TxIn(OutPoint(bytes([n]) * 32, 0))], vout=[TxOut(15 * 10**14, paid)])
        for n in (1, 2)
    ]
    server = Electrum(*payments)
    status, out, err = run(capsys, [bundle, "--server", "h:1"], Connections(server))
    assert (status, out) == (1, "")
    assert err == (
        "seed-scan scan: reading 0, account m/84h/0h/0h:"
        " a balance outside 0 to 21 million bitcoin\n"
    )


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
        ("h:0065536", "--server: the port is not 1 to 65535"),
        (f"h:{'9' * 5000}", "--server: the port is not 1 to 65535"),
        ("two words:1", "--server is not host:port"),
        ("h\x1b:1", "--server is not host:port"),
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


def test_a_port_with_leading_zeros_is_its_number(
    capsys: pytest.CaptureFixture[str], bundle: str
) -> None:
    """The result names the server as typed; the connection, the port."""
    connect = Connections(Electrum())
    run(capsys, [bundle, "--server", "bücher.example:050002"], connect)
    ((host, port, _),) = connect.made
    assert (host, port) == ("bücher.example", 50002)


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


@pytest.fixture(scope="module")
def tls(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Return a folder holding a test CA's certificate and a server's.

    Made at each run, so that the repository holds no private key for its
    key scanner to pass over. ``ca.pem`` is a self-signed CA certificate,
    and ``server.pem`` a certificate it signs for ``IP:127.0.0.1``, with
    its key; both are EC P-256, valid from a day before the run to a day
    after it. Skipped where cryptography is not installed.

    :param tmp_path_factory: pytest's temporary folders.
    :returns: the folder.
    """
    pytest.importorskip("cryptography", reason=NO_CRYPTOGRAPHY)
    # imported after the skip above, which a module-level import would beat
    from cryptography import x509  # noqa: PLC0415
    from cryptography.hazmat.primitives import hashes, serialization  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: PLC0415

    def usage(*granted: str) -> x509.KeyUsage:
        names = (
            "digital_signature",
            "content_commitment",
            "key_encipherment",
            "data_encipherment",
            "key_agreement",
            "key_cert_sign",
            "crl_sign",
            "encipher_only",
            "decipher_only",
        )
        return x509.KeyUsage(**{name: name in granted for name in names})

    now = datetime.now(UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "seed-scan test CA")])

    def builder(name: str, key: ec.EllipticCurvePrivateKey) -> x509.CertificateBuilder:
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
        )

    ca = (
        builder("seed-scan test CA", ca_key)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(usage("key_cert_sign", "crl_sign"), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    server_key = ec.generate_private_key(ec.SECP256R1())
    ca_id = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    server = (
        builder("seed-scan test server", server_key)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(usage("digital_signature"), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(IPv4Address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_id),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    folder = tmp_path_factory.mktemp("tls")
    pem = serialization.Encoding.PEM
    (folder / "ca.pem").write_bytes(ca.public_bytes(pem))
    key = server_key.private_bytes(
        pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    (folder / "server.pem").write_bytes(server.public_bytes(pem) + key)
    return folder


class LineServer:
    """`Electrum` on a port of 127.0.0.1, in a thread, over TLS or plain TCP."""

    def __init__(self, electrum: Electrum, tls: Path | None = None) -> None:
        """Listen on a port of 127.0.0.1, and serve until stopped.

        :param electrum: what answers each request.
        :param tls: the folder of the certificates, or None for plain TCP.
        """
        self.context = None
        if tls is not None:
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.context.load_cert_chain(tls / "server.pem")
        self.electrum = electrum
        self.connections = 0
        self.listening = socket.create_server(("127.0.0.1", 0))
        self.listening.settimeout(0.05)
        self.port = self.listening.getsockname()[1]
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self) -> None:
        """Answer each line of each connection, one connection at a time."""
        while not self.stopped.is_set():
            try:
                connection, _ = self.listening.accept()
            except TimeoutError:
                continue
            self.connections += 1
            connection.settimeout(5)
            try:
                stream = connection
                if self.context is not None:
                    stream = self.context.wrap_socket(connection, server_side=True)
                with stream:
                    lines = stream.makefile("rb")
                    while line := lines.readline():
                        stream.sendall(self.electrum.answer(line) + b"\n")
            except OSError:
                # the client refused the certificate, and closed
                connection.close()

    def stop(self) -> None:
        """Stop serving, and close the port."""
        self.stopped.set()
        self.thread.join()
        self.listening.close()


@pytest.fixture
def paid_electrum(bundle_text: str) -> Electrum:
    """Return a server holding a payment to the first BIP84 address.

    :param bundle_text: the bundle.
    :returns: the server.
    """
    return Electrum(pay(receive_script(bundle_text, "m/84h/0h/0h"), 9))


@pytest.fixture
def tls_server(paid_electrum: Electrum, tls: Path) -> Iterator[LineServer]:
    """Serve a payment to the first BIP84 address over TLS.

    :param paid_electrum: what the server answers.
    :param tls: the folder of the certificates.
    :yields: the server, stopped at teardown.
    """
    server = LineServer(paid_electrum, tls)
    yield server
    server.stop()


@pytest.fixture
def tcp_server(paid_electrum: Electrum) -> Iterator[LineServer]:
    """Serve a payment to the first BIP84 address over plain TCP.

    :param paid_electrum: what the server answers.
    :yields: the server, stopped at teardown.
    """
    server = LineServer(paid_electrum)
    yield server
    server.stop()


class Recording:
    """The command's own `connect`, keeping each transport it makes."""

    def __init__(self) -> None:
        """Hold no transport yet."""
        self.made: list[tuple[str, LineTransport]] = []

    def __call__(
        self, host: str, port: int, context: ssl.SSLContext | None
    ) -> LineTransport:
        """Make the command's transport, and keep it with its host.

        :param host: the host.
        :param port: the port.
        :param context: the TLS context, or None for plain TCP.
        :returns: the transport.
        """
        transport = cli._connect(host, port, context)
        self.made.append((host, transport))
        return transport


def test_a_server_whose_certificate_the_cafile_names_is_scanned(
    capsys: pytest.CaptureFixture[str], bundle: str, tls_server: LineServer, tls: Path
) -> None:
    """The certificate chains to the file's CA, and names the host."""
    argv = ["scan", bundle, "--server", f"127.0.0.1:{tls_server.port}"]
    argv += ["--cafile", str(tls / "ca.pem"), "--gap-limit", "2"]
    assert cli.main(argv) == 0
    (used,) = json.loads(capsys.readouterr().out)["used"]
    assert used["unconfirmed"] == 9


@pytest.mark.parametrize(
    "host, cafile",
    [
        # the CA is in no system store
        ("127.0.0.1", None),
        # the certificate names 127.0.0.1, not localhost
        ("localhost", "ca.pem"),
    ],
)
def test_a_certificate_that_does_not_verify_is_refused(
    capsys: pytest.CaptureFixture[str],
    bundle: str,
    tls_server: LineServer,
    tls: Path,
    host: str,
    cafile: str | None,
) -> None:
    """An untrusted certificate, and a trusted one naming another host.

    :param capsys: pytest's capture of the standard streams.
    :param bundle: the bundle's file.
    :param tls_server: the server.
    :param tls: the folder of the certificates.
    :param host: the host the command is given.
    :param cafile: the file of that folder --cafile names, if any.
    """
    argv = ["scan", bundle, "--server", f"{host}:{tls_server.port}"]
    argv += [] if cafile is None else ["--cafile", str(tls / cafile)]
    assert cli.main(argv) == 1
    err = capsys.readouterr().err
    assert err == "seed-scan scan: the server's certificate did not verify\n"
    assert tls_server.electrum.asked == []


@pytest.mark.parametrize("tcp", [[], ["--tcp"]])
def test_a_closed_port_is_no_connection(
    capsys: pytest.CaptureFixture[str], bundle: str, tcp: list[str]
) -> None:
    """Nothing listens: the connection is refused, over TLS and over TCP.

    :param capsys: pytest's capture of the standard streams.
    :param bundle: the bundle's file.
    :param tcp: the option that asks for plain TCP, if given.
    """
    with socket.create_server(("127.0.0.1", 0)) as listening:
        port = listening.getsockname()[1]
    assert cli.main(["scan", bundle, "--server", f"127.0.0.1:{port}", *tcp]) == 1
    assert capsys.readouterr().err == "seed-scan scan: no connection to the server\n"


def test_one_tls_connection_serves_a_short_scan(
    capsys: pytest.CaptureFixture[str], bundle: str, tls_server: LineServer, tls: Path
) -> None:
    """Every request goes over one connection, closed once the scan is done.

    A short scan, every request answered: it meets none of the conditions
    README.md's *Scanning a bundle* gives for a new connection.
    """
    connect = Recording()
    argv = ["scan", bundle, "--server", f"127.0.0.1:{tls_server.port}"]
    argv += ["--cafile", str(tls / "ca.pem"), "--gap-limit", "2"]
    assert cli.main(argv, connect=connect) == 0
    (used,) = json.loads(capsys.readouterr().out)["used"]
    assert used["unconfirmed"] == 9
    ((_, transport),) = connect.made
    assert isinstance(transport, PersistentTlsLineTransport)
    assert not transport.is_open
    assert len(tls_server.electrum.asked) > 1
    assert tls_server.connections == 1


def test_a_failure_to_close_the_tls_connection_leaves_the_result_written(
    capsys: pytest.CaptureFixture[str],
    bundle: str,
    tls_server: LineServer,
    tls: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The client's socket fails to close once the scan is done: dropped.

    The transport raises `bitcoin_core_rpc`'s `FetchError` for it, which
    no `except` of the command's catches: unhandled, it would end the
    command with a traceback and no result.
    """
    closing = ssl.SSLSocket.close

    def failing(self: ssl.SSLSocket) -> None:
        closing(self)
        if not self.server_side:
            raise OSError(ABANDON)

    monkeypatch.setattr(ssl.SSLSocket, "close", failing)
    connect = Recording()
    argv = ["scan", bundle, "--server", f"127.0.0.1:{tls_server.port}"]
    argv += ["--cafile", str(tls / "ca.pem"), "--gap-limit", "2"]
    assert cli.main(argv, connect=connect) == 0
    # the server's own socket closes while the patch holds, not after
    tls_server.stop()
    out, err = capsys.readouterr()
    (used,) = json.loads(out)["used"]
    assert used["unconfirmed"] == 9
    assert err.startswith(f"server: 127.0.0.1:{tls_server.port}\n")
    ((_, transport),) = connect.made
    assert isinstance(transport, PersistentTlsLineTransport)
    assert not transport.is_open


def test_tcp_scans_a_server_on_a_loopback_address(
    capsys: pytest.CaptureFixture[str], bundle: str, tcp_server: LineServer
) -> None:
    """Plain TCP, one connection per request."""
    argv = ["scan", bundle, "--server", f"127.0.0.1:{tcp_server.port}", "--tcp"]
    assert cli.main([*argv, "--gap-limit", "2"]) == 0
    (used,) = json.loads(capsys.readouterr().out)["used"]
    assert used["unconfirmed"] == 9
    assert tcp_server.connections == len(tcp_server.electrum.asked)


#: A name no resolver answers, RFC 6761's ``.test``: `resolving` answers it.
NAME = "electrum.test"

#: Each answer `resolving` gives: an address with its family, an error.
Found = list[tuple[int, str]] | OSError


def resolving(monkeypatch: pytest.MonkeyPatch, *answers: Found) -> list[int]:
    """Make the resolution of `NAME` answer each of `answers` in turn.

    The last answers every later resolution too. Any other host is
    resolved as the system does.

    :param monkeypatch: what replaces `socket.getaddrinfo`.
    :param answers: what each resolution answers.
    :returns: the port of each resolution of `NAME`, in order.
    """
    asked: list[int] = []
    system = socket.getaddrinfo

    def getaddrinfo(host: str, port: int, *args: object, **kwargs: object) -> object:
        if host != NAME:
            return system(host, port, *args, **kwargs)  # type: ignore[arg-type]
        asked.append(port)
        found = answers[min(len(asked), len(answers)) - 1]
        if isinstance(found, OSError):
            raise found
        return [
            (family, socket.SOCK_STREAM, 6, "", (address, port))
            for family, address in found
        ]

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    return asked


IPV4, IPV6 = socket.AF_INET, socket.AF_INET6


def test_tcp_resolves_a_name_once(
    capsys: pytest.CaptureFixture[str],
    bundle: str,
    tcp_server: LineServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A name answering loopback, then another address: resolved once.

    Each connection goes to the loopback address the one resolution gave.
    """
    asked = resolving(monkeypatch, [(IPV4, "127.0.0.1")], [(IPV4, "192.0.2.1")])
    argv = ["scan", bundle, "--server", f"{NAME}:{tcp_server.port}", "--tcp"]
    assert cli.main([*argv, "--gap-limit", "2"]) == 0
    (used,) = json.loads(capsys.readouterr().out)["used"]
    assert used["unconfirmed"] == 9
    assert asked == [tcp_server.port]
    assert tcp_server.connections > 1


@pytest.mark.parametrize(
    "found, probes",
    [
        # nothing listens on ::1: the last address, untried
        ([(IPV6, "::1"), (IPV4, "127.0.0.1")], 0),
        # the first accepts, and its connection is closed unused
        ([(IPV4, "127.0.0.1"), (IPV6, "::1")], 1),
    ],
)
def test_tcp_takes_the_first_address_that_accepts(
    capsys: pytest.CaptureFixture[str],
    bundle: str,
    tcp_server: LineServer,
    monkeypatch: pytest.MonkeyPatch,
    found: list[tuple[int, str]],
    probes: int,
) -> None:
    """In resolution's order, as ``localhost`` resolves on some systems.

    :param capsys: pytest's capture of the standard streams.
    :param bundle: the bundle's file.
    :param tcp_server: the server, on 127.0.0.1 alone.
    :param monkeypatch: what replaces the resolution.
    :param found: what the name resolves to.
    :param probes: the connections made before the scan's own.
    """
    resolving(monkeypatch, found)
    connect = Recording()
    argv = ["scan", bundle, "--server", f"{NAME}:{tcp_server.port}", "--tcp"]
    assert cli.main([*argv, "--gap-limit", "2"], connect=connect) == 0
    assert {host for host, _ in connect.made} == {"127.0.0.1"}
    asked = len(tcp_server.electrum.asked)
    assert tcp_server.connections == asked + probes


#: Why --tcp refuses a host off loopback.
OFF_LOOPBACK = (
    "--tcp is plain TCP, accepted to a loopback address alone, 127.0.0.0/8"
    " or ::1: the host --server names resolves to another"
)

#: Why --tcp refuses a host that does not resolve.
NO_ADDRESS = "--tcp: the host --server names resolves to no address"


@pytest.mark.parametrize(
    "found, said",
    [
        ([(IPV4, "192.0.2.1")], OFF_LOOPBACK),
        ([(IPV4, "127.0.0.1"), (IPV6, "2001:db8::1")], OFF_LOOPBACK),
        ([(IPV6, "::ffff:127.0.0.1")], OFF_LOOPBACK),
        ([(socket.AF_UNSPEC, "127.0.0.1")], OFF_LOOPBACK),
        ([], NO_ADDRESS),
        (socket.gaierror(socket.EAI_NONAME, NAME), NO_ADDRESS),
    ],
)
def test_tcp_refuses_a_name_off_loopback(
    capsys: pytest.CaptureFixture[str],
    bundle: str,
    monkeypatch: pytest.MonkeyPatch,
    found: Found,
    said: str,
) -> None:
    """Refused before any connection, the name unquoted.

    :param capsys: pytest's capture of the standard streams.
    :param bundle: the bundle's file.
    :param monkeypatch: what replaces the resolution.
    :param found: what the name resolves to.
    :param said: the line written.
    """
    resolving(monkeypatch, found)
    connect = Connections(Electrum())
    argv = [bundle, "--server", f"{NAME}:50001", "--tcp"]
    assert run(capsys, argv, connect) == (1, "", f"seed-scan scan: {said}\n")
    assert not connect.made


@pytest.mark.parametrize(
    "server, said",
    [
        ("192.0.2.1:50001", OFF_LOOPBACK),
        ("[::ffff:127.0.0.1]:50001", OFF_LOOPBACK),
        # an empty label, which the codec refuses before any query
        ("a..b:50001", NO_ADDRESS),
    ],
)
def test_tcp_refuses_an_address_off_loopback(
    capsys: pytest.CaptureFixture[str], bundle: str, server: str, said: str
) -> None:
    """Written as an address, or as a name the system cannot ask for.

    :param capsys: pytest's capture of the standard streams.
    :param bundle: the bundle's file.
    :param server: what --server names.
    :param said: the line written.
    """
    connect = Connections(Electrum())
    argv = [bundle, "--server", server, "--tcp"]
    assert run(capsys, argv, connect) == (1, "", f"seed-scan scan: {said}\n")
    assert not connect.made


@pytest.mark.parametrize(
    "server", ["127.0.0.1:50001", "127.8.9.10:50001", "[::1]:50001"]
)
def test_tcp_takes_a_loopback_address(
    capsys: pytest.CaptureFixture[str], bundle: str, server: str
) -> None:
    """Of 127.0.0.0/8, or ::1: plain TCP to it, with no TLS context.

    :param capsys: pytest's capture of the standard streams.
    :param bundle: the bundle's file.
    :param server: what --server names.
    """
    connect = Connections(Electrum())
    status, out, _ = run(capsys, [bundle, "--server", server, "--tcp"], connect)
    assert status == 0
    assert json.loads(out)["server"] == server
    host = server.rpartition(":")[0].strip("[]")
    assert connect.made == [(host, 50001, None)]


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


def test_the_node_alone_is_scanned(
    capsys: pytest.CaptureFixture[str], bundle: str, bundle_text: str
) -> None:
    """The result's ``evm``, and a summary naming the node and the bound."""
    address = eth_address(bundle_text, "m/44h/60h/0h", 0)
    with serve(serving(Ethereum({address: 5}))) as node:
        argv = [bundle, "--node", node.url()]
        status, out, err = run(capsys, argv, Connections(Electrum()))
    assert status == 0
    document = json.loads(out)
    assert document["server"] is None
    evm = document["evm"]
    name = f"http://127.0.0.1:{node.port}"
    assert (evm["node"], evm["chain_id"], evm["block"]) == (name, 1, 16)
    (used,) = evm["used"]
    assert used["addresses"] == [
        {"index": 0, "address": address, "balance": "5", "nonce": 0}
    ]
    elsewhere = "scan reads Bitcoin and Ethereum alone in this version"
    assert err.splitlines() == [
        f"node: {name}, chain id 1, block 16",
        "bounds: account gap 3, gap limit 20",
        "ethereum: ether and nonces read, no token balance",
        (
            "reading 0, ethereum purpose 44: accounts read: 1, cut short:"
            " the bundle's accounts end before the account gap"
        ),
        "used: reading 0, m/44h/60h/0h: 1 addresses, 5 wei",
        "not checked: reading 0, bitcoin: no Electrum server was named",
        f"not checked: reading 0, bitcoin-cash: {elsewhere}",
        f"not checked: reading 0, bitcoin-sv: {elsewhere}",
        f"not checked: reading 0, litecoin: {elsewhere}",
        f"not checked: reading 0, dogecoin: {elsewhere}",
    ]


def test_nothing_used_on_the_node_is_said(
    capsys: pytest.CaptureFixture[str], bundle: str
) -> None:
    """No Bitcoin read, and no Ethereum account used."""
    with serve(serving(Ethereum())) as node:
        argv = [bundle, "--node", node.url()]
        status, _, err = run(capsys, argv, Connections(Electrum()))
    assert status == 0
    assert "\nno account used within that bound\n" in err


def test_the_server_and_the_node_are_both_scanned(
    capsys: pytest.CaptureFixture[str], bundle: str, bundle_text: str
) -> None:
    """Each coin by its backend, each named in the summary."""
    paid = receive_script(bundle_text, "m/84h/0h/0h")
    address = eth_address(bundle_text, "m/44h/60h/0h", 0)
    with serve(serving(Ethereum({address: 1}))) as node:
        argv = [bundle, "--server", "h:1", "--node", node.url()]
        status, out, err = run(capsys, argv, Connections(Electrum(pay(paid, 2))))
    assert status == 0
    document = json.loads(out)
    assert [u["path"] for u in document["used"]] == ["m/84h/0h/0h"]
    assert [u["path"] for u in document["evm"]["used"]] == ["m/44h/60h/0h"]
    assert err.startswith(f"server: h:1\nnode: http://127.0.0.1:{node.port},")
    assert "used: reading 0, m/84h/0h/0h: 1 addresses, 1 transactions" in err
    assert "used: reading 0, m/44h/60h/0h: 1 addresses, 1 wei" in err
    assert "no account used" not in err


@pytest.mark.parametrize(
    "argv, said",
    [
        ([], "name an Electrum --server, an Ethereum --node or both"),
        (
            ["--node", "http://127.0.0.1:1", "--cafile", "ca.pem"],
            "--cafile is for --server, and none is named",
        ),
        (
            ["--node", "http://localhost:8545"],
            "node: plain http is accepted on a loopback address alone",
        ),
        (["--node", "https://user@h"], "node: the URL carries a login"),
        (
            ["--node", "http://127.0.0.1:1", "--tcp"],
            "--tcp is for --server, and none is named",
        ),
        (
            ["--server", "127.0.0.1:1", "--tcp", "--cafile", "ca.pem"],
            "--cafile is for TLS, and --tcp is plain TCP",
        ),
    ],
)
def test_options_the_command_cannot_scan_with_are_refused(
    capsys: pytest.CaptureFixture[str], bundle: str, argv: list[str], said: str
) -> None:
    """No backend, an option no other allows, a URL `Node` refuses.

    :param capsys: pytest's capture of the standard streams.
    :param bundle: the bundle's file.
    :param argv: the options after the bundle.
    :param said: the line written.
    """
    status, out, err = run(capsys, [bundle, *argv], Connections(Electrum()))
    assert (status, out, err) == (1, "", f"seed-scan scan: {said}\n")


def error_object(_: str, body: bytes) -> Exchange:
    """Answer a request with a JSON-RPC error object.

    :param _: the path.
    :param body: the request.
    :returns: the exchange.
    """
    request = json.loads(body)
    error = {"code": -32000, "message": ABANDON}
    answer = {"jsonrpc": "2.0", "id": request["id"], "error": error}
    return 200, json.dumps(answer).encode(), {}


def status_500(_: str, __: bytes) -> Exchange:
    """Answer a request with an HTTP error.

    :returns: the exchange.
    """
    return 500, ABANDON.encode(), {}


def not_json(_: str, __: bytes) -> Exchange:
    """Answer a request with text that is not JSON.

    :returns: the exchange.
    """
    return 200, ABANDON.encode(), {}


@pytest.mark.parametrize(
    "respond, said",
    [
        (error_object, "the node refused a request"),
        (status_500, "the node answered HTTP status 500"),
        (not_json, "no usable answer from the node"),
    ],
)
def test_a_failure_of_the_node_is_one_line_of_fixed_text(
    capsys: pytest.CaptureFixture[str],
    bundle: str,
    respond: Callable[[str, bytes], Exchange],
    said: str,
) -> None:
    """The node's answer decides the line, and is never quoted.

    :param capsys: pytest's capture of the standard streams.
    :param bundle: the bundle's file.
    :param respond: how the node answers.
    :param said: the line written.
    """
    with serve(respond) as node:
        argv = [bundle, "--node", node.url()]
        status, out, err = run(capsys, argv, Connections(Electrum()))
    assert (status, out, err) == (1, "", f"seed-scan scan: {said}\n")


def test_a_closed_port_is_no_connection_to_the_node(
    capsys: pytest.CaptureFixture[str], bundle: str
) -> None:
    """Nothing listens: the connection is refused."""
    with socket.create_server(("127.0.0.1", 0)) as listening:
        port = listening.getsockname()[1]
    argv = [bundle, "--node", f"http://127.0.0.1:{port}"]
    status, _, err = run(capsys, argv, Connections(Electrum()))
    assert (status, err) == (1, "seed-scan scan: no connection to the node\n")


def node_context(tls: Path) -> ssl.SSLContext:
    """Return the context a node serves HTTPS with, the `tls` fixture's.

    :param tls: the folder of the certificates.
    :returns: the context.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(tls / "server.pem")
    return context


def test_a_node_whose_certificate_the_store_trusts_is_asked(
    tls: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``SSL_CERT_FILE`` names the store: here the test CA alone."""
    monkeypatch.setenv("SSL_CERT_FILE", str(tls / "ca.pem"))
    with (
        serve(serving(Ethereum(chain_id=5)), node_context(tls)) as served,
        SessionTransport() as session,
    ):
        node = Node(served.url("https"), transport=session)
        assert node.chain_id() == 5
        assert node.block_number() == 0x10
    assert len(served.requests) == 2


def test_a_store_set_is_no_longer_trusted_once_undone(tls: Path) -> None:
    """The test CA is trusted while the variable names it, not once undone."""
    with serve(serving(Ethereum()), node_context(tls)) as served:
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setenv("SSL_CERT_FILE", str(tls / "ca.pem"))
            with SessionTransport() as session:
                assert Node(served.url("https"), transport=session).chain_id() == 1
        with SessionTransport() as session, pytest.raises(FetchError) as caught:
            Node(served.url("https"), transport=session).chain_id()
    assert cause(caught.value, ssl.SSLCertVerificationError) is not None
    assert len(served.requests) == 1


@pytest.mark.parametrize(
    "host, cafile",
    [
        # the CA is in no system store
        ("127.0.0.1", None),
        # the certificate names 127.0.0.1, not localhost
        ("localhost", "ca.pem"),
    ],
)
def test_a_node_certificate_that_does_not_verify_is_a_failure(
    tls: Path, monkeypatch: pytest.MonkeyPatch, host: str, cafile: str | None
) -> None:
    """An untrusted certificate, and a trusted one naming another host.

    :param tls: the folder of the certificates.
    :param monkeypatch: what sets the store.
    :param host: the host the URL names.
    :param cafile: the store in the folder, if not the system's.
    """
    if cafile is not None:
        monkeypatch.setenv("SSL_CERT_FILE", str(tls / cafile))
    with (
        serve(serving(Ethereum()), node_context(tls)) as served,
        SessionTransport() as session,
        pytest.raises(FetchError) as caught,
    ):
        Node(served.url("https", host), transport=session).chain_id()
    assert cause(caught.value, ssl.SSLCertVerificationError) is not None
    assert not served.requests


def test_a_node_certificate_that_does_not_verify_is_refused(
    capsys: pytest.CaptureFixture[str], bundle: str, tls: Path
) -> None:
    """The test CA is in no system store, and ``--cafile`` is not the node's."""
    with serve(serving(Ethereum()), node_context(tls)) as node:
        argv = [bundle, "--node", node.url("https")]
        status, _, err = run(capsys, argv, Connections(Electrum()))
    assert status == 1
    assert err == "seed-scan scan: the node's certificate did not verify\n"
    assert not node.requests


def test_a_failure_of_the_server_is_the_servers_with_a_node_named(
    capsys: pytest.CaptureFixture[str], bundle: str
) -> None:
    """The server is asked first, and the node is then asked nothing."""

    def refusing(request: bytes, timeout: float) -> bytes:
        parsed = json.loads(request)
        error = {"code": 1, "message": ABANDON}
        answer = {"jsonrpc": "2.0", "id": parsed["id"], "error": error}
        return json.dumps(answer).encode()

    with serve(serving(Ethereum())) as node:
        argv = [bundle, "--server", "h:1", "--node", node.url()]
        status, _, err = run(capsys, argv, Connections(refusing))
    assert (status, err) == (1, "seed-scan scan: the server refused a request\n")
    assert not node.requests


def test_a_reply_that_is_no_http_is_not_quoted(
    capsys: pytest.CaptureFixture[str], bundle: str
) -> None:
    """A status line that does not parse: one line, quoting nothing."""
    with replying(f"HTTP/1.1 2OO {ABANDON}\r\n\r\n".encode()) as port:
        argv = [bundle, "--node", f"http://127.0.0.1:{port}"]
        status, _, err = run(capsys, argv, Connections(Electrum()))
    assert (status, err) == (1, "seed-scan scan: no usable answer from the node\n")


def test_a_quantity_past_256_bits_is_no_usable_answer(
    capsys: pytest.CaptureFixture[str], bundle: str
) -> None:
    """A chain id under the answer's bound, past a quantity's: refused."""
    with serve(serving(Ethereum(chain_id=int("f" * 3600, 16)))) as node:
        argv = [bundle, "--node", node.url()]
        status, out, err = run(capsys, argv, Connections(Electrum()))
    assert (status, out) == (1, "")
    assert err == "seed-scan scan: no usable answer from the node\n"
