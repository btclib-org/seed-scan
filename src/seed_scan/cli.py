# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The `seed-scan` command.

``seed-scan identify`` reads the mnemonic at a hidden prompt, then
passphrases at a second one until an empty answer, and writes the public
bundle `seed_scan.bundle` describes to standard output. What it found is
summarized on standard error. Its options are public: the address the
user knows, and the bounds of the accounts written and of the search.

The secret is read from the terminal alone, never from an argument, a
file, standard input or the environment: where no terminal can be
opened the command refuses rather than read standard input. Before it
reads anything it refuses every socket and every new process for the
rest of the process, and where that refusal is not in place it reads
nothing. A refusal is one line on standard error, never a traceback,
and says nothing of what was typed. An argument refused is not repeated
either, in case it is a mnemonic typed there by mistake.

``seed-scan scan`` reads a bundle from the file named, runs
`seed_scan.scan.scan` on it against the Electrum server the user names
as ``host:port``, the Ethereum node the user names by its URL, or both,
and writes the scan result to standard output and a summary to standard
error. It reads no secret. README.md's *Scanning a bundle* says why
there is no default server or node. The Electrum connection is TLS,
through `btclib_wallet.fetch.transport.TlsLineTransport`; plain TCP
waits on btclib-org/btclib-wallet#861. The server's certificate is
verified: it must chain to a certificate the context trusts and name the
host as given, with TLS 1.2 at least. The context trusts the system's CA
certificates, or, where ``--cafile`` names a file, the certificates of
that file alone, which is how a server of one's own with a self-signed
certificate is reached. The server is asked first for its genesis block,
then for its block at a height Bitcoin Core pins, and one answering
another block than Bitcoin's at either is refused. A read of a history
during which the server's tip moved is read again, a bounded number of
times. The node is a `seed_scan.evm.Node`, whose docstring says which
URLs it takes and how its certificate is verified, over one connection
kept for the whole scan: ``--cafile`` is the Electrum server's alone. A
failure of the server, the node or the connection is one line of fixed
text, which names neither the answer nor the addresses asked.

``seed-scan forks`` reads a bundle from the file named, runs
`seed_scan.forks.forks` on it against the Electrum server the user names
for the chain named, and writes the forks result and a summary as
``scan`` writes its own. It reads no secret, connects as ``scan``
connects to its server, and says a failure as ``scan`` says one. Its
server's blocks are checked as ``scan`` checks them, at the chain's
checkpoints in place of Bitcoin's.

``seed-scan report`` reads a bundle from the file named and, where
``--scan`` names one, the scan result made from it, and writes
`seed_scan.report.report`'s text to standard output. It reads no secret,
and refuses every socket and every new process before it reads a file,
as ``identify`` does. The report goes out as its UTF-8 bytes, with no
newline translation, so that the file it is redirected to is what its
last line hashes, on Windows too.

A file the user names is read as its UTF-8 bytes, with no newline
translation either, so that a digest of its text, as the bundle's in
scan's result and the report's lines naming each input, is the digest
of the file.
"""

from __future__ import annotations

import argparse
import contextlib
import getpass
import ssl
import sys
import warnings
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn

from btclib.exceptions import BTClibValueError
from btclib_wallet.exceptions import FetchError, HttpError, RpcError
from btclib_wallet.fetch.electrum import ElectrumFetcher
from btclib_wallet.fetch.transport import (
    LineTransport,
    SessionTransport,
    TlsLineTransport,
)

from seed_scan.bundle import dumps
from seed_scan.evm import Node
from seed_scan.exceptions import SeedScanException, SeedScanValueError
from seed_scan.forks import CHAINS, Chain, forks
from seed_scan.forks import dumps as forks_dumps
from seed_scan.report import report
from seed_scan.scan import ACCOUNT_GAP, GAP_LIMIT, parse_server, scan
from seed_scan.scan import dumps as scan_dumps

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Sequence

    from btclib.alias import Octets
    from btclib.script import ScriptPubKey
    from btclib_wallet.fetch.history import ScriptHistory

    from seed_scan.bundle import Bundle
    from seed_scan.forks import ForkSearched, ForksResult, Skipped
    from seed_scan.scan import ScanResult, Searched

__all__ = [
    "main",
]


# the audit events of a socket, and of a new process, which could open
# one, or read the secret out of this one, beyond this hook's reach.
# `os.startfile` is Windows', and covers its `os.startfile/2`
_REFUSED = (
    "socket.",
    "subprocess.",
    "os.system",
    "os.exec",
    "os.posix_spawn",
    "os.startfile",
)
_REFUSED_EXACTLY = ("os.fork", "os.forkpty", "os.spawn")
# an event of this package's own, raised once the hook is added, with a
# token made for that addition: an earlier hook can veto the addition, and
# `sys.addaudithook` then returns as if it had added it, so only this hook
# answering the token says it is there
_PROBE = "seed_scan.guard"


class _InPlace(Exception):  # noqa: N818 -- a signal, never a failure raised out
    """The hook's answer to the guard's own event, carrying its token back."""


# what a backend raises where its tip moved during a read, which
# `HistoryReader` says the caller asks again. A text and not a class:
# btclib-org/btclib-wallet#864 asks for a class of its own
_TIP_MOVED = "the tip moved while the history was read"

# how many times one history is read where the tip moves during each read
_READS = 3

# what a failure caused by each class says, the first class it is in,
# of the server or the node
_CAUSES: tuple[tuple[type[BaseException], str], ...] = (
    (ssl.SSLCertVerificationError, "the {}'s certificate did not verify"),
    (ssl.SSLError, "the TLS handshake with the {} failed"),
    (TimeoutError, "the {} did not answer in time"),
    (OSError, "no connection to the {}"),
)

# Bitcoin's block at a height Bitcoin Core pins, its id as hex in display
# order; SECURITY.md's "Limitations, not vulnerabilities" says which
# servers the check refuses. Bitcoin Core's assumeutxo snapshot of that
# height:
# https://github.com/bitcoin/bitcoin/blob/a527a0077a0fcae913188410214efe98021c0cca/src/kernel/chainparams.cpp#L215-L220
_BITCOIN_CHECKPOINTS = (
    (965000, "00000000000000000001595977e6000ce56129f5c9b4073e31ccc30b90b97da9"),
)


def _refuse_network(event: str, args: tuple[object, ...]) -> None:
    """Refuse every socket and every new process, as an audit hook.

    The guard's own event is answered with `_InPlace`, holding its token.
    """
    if event == _PROBE:
        raise _InPlace(*args)
    if event.startswith(_REFUSED) or event in _REFUSED_EXACTLY:
        raise SeedScanValueError(
            f"this command opens no connection and starts no process: {event} refused"
        )


def _forbid_network() -> None:
    """Refuse every socket and every new process for the rest of the process.

    An audit hook cannot be removed, so this runs once per process, in
    the command alone. Where the hook does not answer the token of this
    addition, or the addition or the probe fails in any other way, it
    refuses, with fixed text and no context: another hook's failure says
    nothing of this one's. An interrupt is raised again, for `main` to say
    "interrupted" as it does at a prompt.

    It does not hold against code already running in the process: a hook
    added before this one sees the token, and can raise `_InPlace` with
    it, as it could read the secret itself.
    """
    token = object()
    in_place = False
    try:
        sys.addaudithook(_refuse_network)
        sys.audit(_PROBE, token)
    except _InPlace as answer:
        in_place = answer.args == (token,)
    except KeyboardInterrupt:
        raise
    except BaseException:  # noqa: BLE001 -- another hook's failure, refused below
        in_place = False
    if not in_place:
        raise SeedScanValueError("the refusal of sockets and processes is not in place")


def _hidden(text: str) -> str:
    """Read one answer at a hidden prompt on the terminal.

    `getpass` falls back to standard input, echoing what is typed, where
    it cannot open the terminal: that fallback is refused. So is an answer
    that is not UTF-8 text, whose decoding error holds the bytes typed.
    Each refusal is raised after the `except`, so that the error caught,
    which may hold what was typed, is not kept as its context.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            return getpass.getpass(text)
        except getpass.GetPassWarning:
            err_msg = "no terminal: the mnemonic is read at a hidden prompt only"
        except UnicodeDecodeError:
            err_msg = "what was typed is not UTF-8 text"
    raise SeedScanValueError(err_msg)


def _passphrases(prompt: Callable[[str], str]) -> list[str]:
    """Return the empty passphrase, then each one typed until an empty one."""
    passphrases = [""]
    while passphrase := prompt(f"Passphrase {len(passphrases)} (empty when done): "):
        passphrases.append(passphrase)
    return passphrases


def _summary(bundle: Bundle) -> str:
    """Return what the bundle says, for the user, with no secret in it."""
    lines = [f"schemes claiming the words: {', '.join(bundle.claims) or 'none'}"]
    lines += [
        f"reading {n}: {r.scheme}, passphrase {r.passphrase},"
        f" master fingerprint {r.master_fingerprint}"
        for n, r in enumerate(bundle.readings)
    ]
    lines += [f"not checked: {n.scheme}: {n.reason}" for n in bundle.not_checked]
    search = bundle.search
    if search is not None and not search.checked:
        lines.append(f"address not searched: {search.reason}")
    elif search is not None:
        lines.append(
            f"address searched in {search.searched} positions: accounts 0 to"
            f" {search.accounts - 1} of each Bitcoin purpose, of Bitcoin Cash's"
            " for a base58 address, and Electrum's account, receive and change,"
            f" indexes 0 to {search.indexes - 1}"
        )
        lines += [
            f"found: reading {m.reading}, {m.coin}, {m.path}" for m in search.matches
        ]
        if not search.matches:
            lines.append("not found within that bound")
    return "\n".join(lines) + "\n"


def _purpose(purpose: int | None) -> str:
    """Return how a summary names a purpose, Electrum's layouts having none."""
    return "Electrum" if purpose is None else f"purpose {purpose}"


def _searched(done: Searched | ForkSearched, coin: str) -> str:
    """Return the line that says how many accounts of a purpose were read."""
    purpose = _purpose(done.purpose)
    line = f"reading {done.reading}, {coin}{purpose}: accounts read: {done.accounts}"
    if done.cut_short:
        line += ", cut short: the bundle's accounts end before the account gap"
    return line


def _scan_summary(result: ScanResult) -> str:
    """Return what the scan result says, for the user."""
    evm = result.evm
    lines = [] if result.server is None else [f"server: {result.server}"]
    if evm is not None:
        lines.append(f"node: {evm.node}, chain id {evm.chain_id}, block {evm.block}")
    lines.append(
        f"bounds: account gap {result.account_gap}, gap limit {result.gap_limit}"
    )
    lines += [_searched(done, "") for done in result.searched]
    lines += [
        f"used: reading {u.reading}, {u.path}: {len(u.addresses)} addresses,"
        f" {len(u.transactions)} transactions, {u.confirmed} sat confirmed,"
        f" {u.unconfirmed} sat unconfirmed"
        for u in result.used
    ]
    if evm is not None:
        lines.append("ethereum: ether and nonces read, no token balance")
        lines += [_searched(done, "ethereum ") for done in evm.searched]
        lines += [
            f"used: reading {u.reading}, {u.path}: {len(u.addresses)} addresses,"
            f" {u.balance} wei"
            for u in evm.used
        ]
    if not result.used and (evm is None or not evm.used):
        lines.append("no account used within that bound")
    lines += [
        f"not checked: reading {n.reading}, {n.coin}: {n.reason}"
        for n in result.not_checked
    ]
    return "\n".join(lines) + "\n"


def _tls_context(cafile: str | None) -> ssl.SSLContext:
    """Return the context a server's certificate is verified against.

    `ssl.create_default_context` requires a certificate chaining to the
    certificates it trusts and naming the host. It trusts the system's CA
    certificates, or those of `cafile` alone where one is named.
    """
    context = None
    # FileNotFoundError and ssl.SSLError are both an OSError; the refusal
    # is raised outside `suppress`, so that it chains neither
    with contextlib.suppress(OSError):
        context = ssl.create_default_context(cafile=cafile)
    if context is None:
        raise SeedScanValueError("--cafile: no certificate could be loaded from it")
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _connect(host: str, port: int, context: ssl.SSLContext) -> LineTransport:
    """Return the TLS transport to a server."""
    return TlsLineTransport(host, port, context=context)


class _Mainnet:
    """A reader that asks its server for Bitcoin's genesis block first.

    The server is then asked for its block at each checkpoint of the chain
    read, and refused where one is not that chain's, before any address is
    asked of it: the chain is Bitcoin, at `_BITCOIN_CHECKPOINTS`, or
    `chain` where it is given, a chain forked from Bitcoin. A read during
    which the tip moved is read again, up to `_READS` times in all, as
    `HistoryReader` asks of its caller.
    """

    def __init__(self, fetcher: ElectrumFetcher, chain: Chain | None = None) -> None:
        self._fetcher = fetcher
        self._chain = chain
        self._checked = False

    def _assert_chain(self) -> None:
        """Refuse a server whose blocks are not those of the chain read."""
        chain = self._chain
        title = "Bitcoin's mainnet" if chain is None else chain.title
        checkpoints = _BITCOIN_CHECKPOINTS if chain is None else chain.checkpoints
        other_chain = False
        try:
            self._fetcher.assert_network()
            other_chain = any(
                self._fetcher.get_block_header(height).hash.hex() != block_id
                for height, block_id in checkpoints
            )
        except BTClibValueError:
            other_chain = True
        if other_chain:
            raise SeedScanValueError(f"the server does not serve {title}")

    def get_history(
        self, scripts: Iterable[Octets | ScriptPubKey], start_height: int = 0
    ) -> ScriptHistory:
        """Return the fetcher's answer, once the chain has been checked."""
        if not self._checked:
            self._assert_chain()
            self._checked = True
        for _ in range(_READS - 1):
            try:
                return self._fetcher.get_history(scripts, start_height)
            except FetchError as e:
                if str(e) != _TIP_MOVED:
                    raise
        return self._fetcher.get_history(scripts, start_height)


def _failure(error: FetchError, who: str) -> str:
    """Return the fixed text that says how the server or the node failed.

    `who` is ``"server"`` or ``"node"``. The text is chosen by the class
    of the error and of its causes, and for a tip that moved by comparing
    the message with `_TIP_MOVED`. A message is never written: it can
    hold the answers. An HTTP status is, being a number.
    """
    if isinstance(error, RpcError):
        return f"the {who} refused a request"
    if isinstance(error, HttpError):
        return f"the {who} answered HTTP status {error.status}"
    if str(error) == _TIP_MOVED:
        return "the server's tip moved during every read of a history"
    cause = error.__cause__
    while cause is not None:
        for kind, text in _CAUSES:
            if isinstance(cause, kind):
                return text.format(who)
        cause = cause.__cause__
    return f"no usable answer from the {who}"


def _read_text(name: str, what: str = "bundle") -> str:
    """Return the text of a file the user names, refusing one it cannot read.

    `what` is the file's kind, which the refusal names.
    """
    text = None
    # the refusal is raised outside `suppress`: a decoding error holds the
    # bytes read, which a file handed in by mistake fills with a secret
    with contextlib.suppress(OSError, UnicodeDecodeError):
        text = Path(name).read_bytes().decode("utf-8")
    if text is None:
        raise SeedScanValueError(f"the {what} file cannot be read as UTF-8 text")
    return text


def _electrum(
    args: argparse.Namespace,
    connect: Callable[[str, int, ssl.SSLContext], LineTransport],
    chain: Chain | None = None,
) -> _Mainnet:
    """Return the reader of the Electrum server --server names, on `chain`."""
    host, port = parse_server(args.server, "--server")
    context = _tls_context(args.cafile)
    transport = None
    # the transport quotes a host it refuses, and the refusal says none
    with contextlib.suppress(BTClibValueError):
        transport = connect(host, port, context)
    if transport is None:
        raise SeedScanValueError("--server names no host a connection can use")
    return _Mainnet(ElectrumFetcher(transport=transport, verify_network=False), chain)


def _online(
    command: str, run: Callable[[], tuple[str, str]], who: Callable[[], str]
) -> int:
    """Run a command that asks a server; answer its exit status.

    `run` returns what goes to standard output and the summary, both made
    inside the `try`, so that what making them raises is one line too.
    `who` names what a `FetchError` came from, ``"server"`` or ``"node"``.
    """
    try:
        out, summary = run()
    except SeedScanException as e:
        err_msg = str(e)
    except FetchError as e:
        err_msg = _failure(e, who())
    except (ValueError, TypeError) as e:
        err_msg = f"refused by a dependency: {type(e).__name__}"
    except KeyboardInterrupt:
        err_msg = "interrupted"
    else:
        sys.stdout.write(out)
        sys.stderr.write(summary)
        return 0
    sys.stderr.write(f"seed-scan {command}: {err_msg}\n")
    return 1


def _scan_command(
    args: argparse.Namespace,
    connect: Callable[[str, int, ssl.SSLContext], LineTransport],
) -> int:
    """Run ``seed-scan scan``; answer its exit status.

    The node is asked once the server is done, so a failure after the
    node's first request is the node's.
    """
    nodes: list[Node] = []

    def run() -> tuple[str, str]:
        if args.server is None and args.node is None:
            err_msg = "name an Electrum --server, an Ethereum --node or both"
            raise SeedScanValueError(err_msg)
        if args.cafile is not None and args.server is None:
            raise SeedScanValueError("--cafile is for --server, and none is named")
        text = _read_text(args.bundle)
        reader = None if args.server is None else _electrum(args, connect)
        with SessionTransport() as session:
            if args.node is not None:
                nodes.append(Node(args.node, transport=session))
            result = scan(
                text,
                reader,
                server=args.server,
                node=nodes[0] if nodes else None,
                gap_limit=args.gap_limit,
                account_gap=args.account_gap,
            )
        return scan_dumps(result), _scan_summary(result)

    def who() -> str:
        return "node" if nodes and nodes[0].requests else "server"

    return _online("scan", run, who)


def _skipped(skipped: Skipped) -> str:
    """Return the line that says which accounts forks did not read, and why."""
    purpose = _purpose(skipped.purpose)
    return (
        f"not checked: reading {skipped.reading}, {skipped.coin} {purpose}:"
        f" {skipped.reason}"
    )


def _forks_summary(result: ForksResult) -> str:
    """Return what the forks result says, for the user."""
    title = CHAINS[result.chain].title
    lines = [
        f"server: {result.server}",
        f"chain: {title}, its own blocks from height {result.fork_height}",
        f"bounds: account gap {result.account_gap}, gap limit {result.gap_limit}",
    ]
    lines += [_searched(done, f"{done.coin} ") for done in result.searched]
    lines += [
        f"used: reading {u.reading}, {u.coin}, {u.path}: {len(u.addresses)}"
        f" addresses, {len(u.transactions)} transactions, {u.confirmed} sat"
        f" confirmed, {u.unconfirmed} sat unconfirmed, {u.at_fork} sat at the fork"
        for u in result.used
    ]
    if not result.used:
        lines.append("no account used within that bound")
    lines += [_skipped(skipped) for skipped in result.not_checked]
    return "\n".join(lines) + "\n"


def _forks_command(
    args: argparse.Namespace,
    connect: Callable[[str, int, ssl.SSLContext], LineTransport],
) -> int:
    """Run ``seed-scan forks``; answer its exit status."""

    def run() -> tuple[str, str]:
        text = _read_text(args.bundle)
        result = forks(
            text,
            _electrum(args, connect, CHAINS[args.chain]),
            chain=args.chain,
            server=args.server,
            gap_limit=args.gap_limit,
            account_gap=args.account_gap,
        )
        return forks_dumps(result), _forks_summary(result)

    return _online("forks", run, lambda: "server")


def _report_command(
    args: argparse.Namespace, forbid_network: Callable[[], None]
) -> int:
    """Run ``seed-scan report``; answer its exit status."""
    try:
        forbid_network()
        bundle = _read_text(args.bundle)
        result = None if args.scan is None else _read_text(args.scan, "scan result")
        text = report(bundle, result)
    except SeedScanException as e:
        err_msg = str(e)
    else:
        # the bytes, past the text layer's newline translation, after
        # anything that layer still holds
        sys.stdout.flush()
        sys.stdout.buffer.write(text.encode("utf-8"))
        sys.stdout.buffer.flush()
        return 0
    sys.stderr.write(f"seed-scan report: {err_msg}\n")
    return 1


def _identify_command(
    args: argparse.Namespace,
    prompt: Callable[[str], str],
    forbid_network: Callable[[], None],
) -> int:
    """Run ``seed-scan identify``; answer its exit status."""
    # here and not at the top: `scan` reads a bundle, and a command that
    # reads one never loads the module that handles the secret
    from seed_scan.identify import identify  # noqa: PLC0415

    try:
        forbid_network()
        mnemonic = prompt("Mnemonic: ")
        passphrases = _passphrases(prompt)
        bundle = identify(
            mnemonic,
            passphrases,
            prompt,
            accounts=args.accounts,
            address=args.address,
            indexes=args.indexes,
        )
    except (KeyboardInterrupt, EOFError):
        # first: an interrupt that is also a refusal says "interrupted",
        # never its own text
        err_msg = "interrupted"
    except SeedScanException as e:
        err_msg = str(e)
    except (ValueError, TypeError) as e:
        # a dependency's refusal: those packages print no secret either,
        # but the class alone is said, and no traceback
        err_msg = f"refused by a dependency: {type(e).__name__}"
    else:
        sys.stdout.write(dumps(bundle))
        sys.stderr.write(_summary(bundle))
        return 0
    sys.stderr.write(f"seed-scan identify: {err_msg}\n")
    return 1


class _Parser(argparse.ArgumentParser):
    """A parser whose refusal repeats no word given.

    argparse quotes a value it refuses and lists the words it does not
    take, so a mnemonic typed as arguments by mistake would reach standard
    error, and any log kept of it. Its refusal of a missing argument names
    arguments alone, and is kept; every other is replaced.
    """

    # no @override: `typing.override` is 3.12's, and the floor is 3.11
    def error(self, message: str) -> NoReturn:  # type: ignore[explicit-override]
        """Write the usage and the refusal, then exit with status 2."""
        if not message.startswith("the following arguments are required: "):
            message = (
                "an argument is refused, and not repeated in case it is a"
                f" mnemonic: {self.prog} --help lists them"
            )
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: {message}\n")


def _parser() -> argparse.ArgumentParser:
    """Return the command's parser."""
    parser = _Parser(
        prog="seed-scan", description="What a mnemonic of unknown scheme holds."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    identify_parser = commands.add_parser(
        "identify",
        help="read a mnemonic at a hidden prompt, write the public bundle",
        description=(
            "Read a mnemonic and passphrases at a hidden prompt, offline,"
            " and write the public bundle to standard output."
        ),
    )
    identify_parser.add_argument(
        "--address", help="an address the mnemonic gave, to find its path"
    )
    identify_parser.add_argument(
        "--accounts",
        type=int,
        default=5,
        help="accounts written for each coin and purpose (default: 5)",
    )
    identify_parser.add_argument(
        "--indexes",
        type=int,
        default=20,
        help="indexes of each branch the address search reads (default: 20)",
    )
    scan_parser = commands.add_parser(
        "scan",
        help="find the used accounts of a bundle on your own server or node",
        description=(
            "Read a public bundle, ask the Electrum server named which of its"
            " Bitcoin accounts were used and the Ethereum node named which of"
            " its Ethereum accounts were, and write the scan result to"
            " standard output. Each learns every address asked. Ethereum's"
            " accounts are read for ether and nonces: a token balance is not"
            " asked."
        ),
    )
    scan_parser.add_argument("bundle", help="the bundle file identify wrote")
    scan_parser.add_argument(
        "--server",
        help="the Electrum server to ask, as host:port, over TLS",
    )
    scan_parser.add_argument(
        "--cafile",
        help="trust the certificates of this file alone for the server",
    )
    scan_parser.add_argument(
        "--node",
        help=(
            "the Ethereum node to ask, as an https URL, or an http one on a"
            " loopback address such as http://127.0.0.1:8545"
        ),
    )
    _add_bounds(scan_parser)
    forks_parser = commands.add_parser(
        "forks",
        help="find what a bundle's keys hold on a chain forked from Bitcoin",
        description=(
            "Read a public bundle, ask the Electrum server named, which serves"
            " the chain named, which of the bundle's accounts were used there,"
            " and write the forks result to standard output. The server"
            " learns every address asked."
        ),
    )
    forks_parser.add_argument("bundle", help="the bundle file identify wrote")
    forks_parser.add_argument(
        "--chain",
        required=True,
        choices=sorted(CHAINS),
        help="the chain forked from Bitcoin that the server serves",
    )
    forks_parser.add_argument(
        "--server",
        required=True,
        help="the chain's Electrum server to ask, as host:port, over TLS",
    )
    forks_parser.add_argument(
        "--cafile",
        help="trust the certificates of this file alone for the server",
    )
    _add_bounds(forks_parser)
    report_parser = commands.add_parser(
        "report",
        help="summarize a bundle and its scan result, offline",
        description=(
            "Read a public bundle and the scan result made from it, offline,"
            " and write what they say to standard output: per reading, coin"
            " and purpose, the used accounts, their balance, addresses and"
            " paths, and what was not checked and why. seed_scan.report"
            " documents the layout."
        ),
    )
    report_parser.add_argument("bundle", help="the bundle file identify wrote")
    report_parser.add_argument(
        "--scan",
        help="the result scan wrote for that bundle; without it, nothing is checked",
    )
    return parser


def _add_bounds(parser: argparse.ArgumentParser) -> None:
    """Add the bounds of the search a command asking a server takes."""
    parser.add_argument(
        "--gap-limit",
        type=int,
        default=GAP_LIMIT,
        help=f"unused indexes in a row that end a branch (default: {GAP_LIMIT})",
    )
    parser.add_argument(
        "--account-gap",
        type=int,
        default=ACCOUNT_GAP,
        help=f"unused accounts in a row that end a purpose (default: {ACCOUNT_GAP})",
    )


def main(
    argv: Sequence[str] | None = None,
    *,
    prompt: Callable[[str], str] = _hidden,
    forbid_network: Callable[[], None] = _forbid_network,
    connect: Callable[[str, int, ssl.SSLContext], LineTransport] = _connect,
) -> int:
    """Run the command; answer its exit status.

    `prompt`, `forbid_network` and `connect` are what a test replaces:
    the hidden prompt, the refusal of every socket and new process that
    ``identify`` and ``report`` install, and the transport to a server.
    """
    args = _parser().parse_args(argv)
    if args.command == "scan":
        return _scan_command(args, connect)
    if args.command == "forks":
        return _forks_command(args, connect)
    if args.command == "report":
        return _report_command(args, forbid_network)
    return _identify_command(args, prompt, forbid_network)
