# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for ``seed-scan forks``: the chain check, the result, the refusals.

The Electrum server is `tests.scan_cli_test.Electrum`, which answers the
genesis block at every height but those of the headers it is given:
Bitcoin's at the checkpoint of ``scan``, by default, and for `Forked` a
chain's at its own checkpoints, Bitcoin Cash's unless told otherwise.
Those are real headers, so that the proof of work the fetcher checks
holds: the first test checks that Bitcoin Cash's and Bitcoin SV's hash
to the ids their chain names.
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import TYPE_CHECKING

import pytest
from btclib.block.block_header import BlockHeader
from btclib.script import ScriptPubKey

from seed_scan import cli
from seed_scan.bundle import dumps
from seed_scan.forks import BITCOIN_CASH, BITCOIN_SV
from seed_scan.identify import identify

from .identify_test import ABANDON, SEGWIT, STANDARD, legacy_address, no_share
from .scan_cli_test import GENESIS, Connections, Electrum, Failing, caused, pay

if TYPE_CHECKING:
    from pathlib import Path

    from btclib.tx import Tx

    from seed_scan.forks import Chain

#: Bitcoin Cash's header at each height of its checkpoints, as a Fulcrum
#: server of that chain answered `blockchain.block.header`.
HEADERS = {
    478559: (
        "00000020432d350741fbf28f2e1486eabe2c4e143bfe2241af6518010000000000000000"
        "abaa4bd8a48c1c6bc08ee39b66065e5e9484304cab8b56d5eed3e40b1ac996c899c48059"
        "3547011822ca4ae8"
    ),
    970892: (
        "0000003e58a5c98076ad886412fe95d341e3bfb706b93d78d4a2150200000000000000"
        "002242db1fb7a742e2eda70b2b0ab0a290ca59dae31bda9f4cb938a4f8c5452ce8dc51bd"
        "6afc2602180d6502c6"
    ),
}

#: Bitcoin SV's header at each height of its checkpoints, as ElectrumX
#: servers of that chain, from ElectrumSV's list, answered
#: `blockchain.block.header`. The fork block is Bitcoin Cash's, and the
#: other is the one ElectrumSV pins:
#: https://github.com/electrumsv/electrumsv/blob/7ab1c7ceaaaa0f8079da21356989d9b250e874b4/electrumsv/data/servers.json
SV_HEADERS = {
    478559: HEADERS[478559],
    773040: (
        "00e0ff37689867096945489d8f39ccb2859e31f6f0fb3894705e3b0b0000000000000000"
        "f282be97e1a80610fd44c3cd9bfa386f49e4b3bce4126600c0a98d22f18ae3314db8b363"
        "7cc30b1802cd6874"
    ),
}


class Forked(Electrum):
    """An Electrum server of Bitcoin Cash, by default."""

    def __init__(self, *payments: Tx, headers: dict[int, str] = HEADERS) -> None:
        """Hold the payments, in the mempool, and the headers by height.

        :param payments: the transactions the mempool holds.
        :param headers: the header answered at each height, as hex.
        """
        super().__init__(*payments, headers=headers)


def write(tmp_path: Path, mnemonic: str) -> str:
    """Write the bundle of a mnemonic, one account of each purpose, to a file.

    :param tmp_path: pytest's directory for the test.
    :param mnemonic: the mnemonic.
    :returns: the file's path.
    """
    path = tmp_path / "bundle.json"
    text = dumps(identify(mnemonic, [""], no_share, accounts=1))
    path.write_text(text, encoding="utf-8")
    return str(path)


@pytest.fixture
def bundle(tmp_path: Path) -> str:
    """Write the bundle of BIP84's mnemonic to a file.

    :param tmp_path: pytest's directory for the test.
    :returns: the file's path.
    """
    return write(tmp_path, ABANDON)


def run(
    capsys: pytest.CaptureFixture[str],
    argv: list[str],
    connect: Connections,
    chain: str = "bitcoin-cash",
) -> tuple[int, str, str]:
    """Run ``seed-scan forks`` on a chain; answer its status and output.

    :param capsys: pytest's capture of the standard streams.
    :param argv: the bundle and the arguments after it.
    :param connect: what makes the connection.
    :param chain: the chain named, Bitcoin Cash unless given.
    :returns: the exit status, standard output and standard error.
    """
    status = cli.main(["forks", "--chain", chain, *argv], connect=connect)
    out, err = capsys.readouterr()
    return status, out, err


@pytest.mark.parametrize(
    "chain, headers", [(BITCOIN_CASH, HEADERS), (BITCOIN_SV, SV_HEADERS)]
)
def test_the_headers_are_the_chain_s_checkpoints(
    chain: Chain, headers: dict[int, str]
) -> None:
    """Each header hashes to the block id the chain's checkpoint names.

    :param chain: the chain.
    :param headers: its header at each checkpoint, as hex.
    """
    assert dict(chain.checkpoints) == {
        height: BlockHeader.parse(bytes.fromhex(header)).hash.hex()
        for height, header in headers.items()
    }


def test_forks_writes_the_result_and_a_summary(
    capsys: pytest.CaptureFixture[str], bundle: str
) -> None:
    """The chain is checked first, then a payment found in its own account."""
    script = ScriptPubKey.from_address(legacy_address("m/44h/145h/0h/0/0"))
    server = Forked(pay(script, 2_500))
    connect = Connections(server)
    status, out, err = run(capsys, [bundle, "--server", "node.local:50002"], connect)
    assert status == 0
    document = json.loads(out)
    assert (document["format"], document["chain"]) == (
        "seed-scan-forks",
        "bitcoin-cash",
    )
    (used,) = document["used"]
    assert (used["coin"], used["path"]) == ("bitcoin-cash", "m/44h/145h/0h")
    assert (used["confirmed"], used["unconfirmed"], used["at_fork"]) == (0, 2_500, 0)
    assert err.startswith(
        "server: node.local:50002\n"
        "chain: Bitcoin Cash, forked from Bitcoin at height 478559\n"
        "bounds: account gap 3, gap limit 20\n"
        "reading 0, bitcoin purpose 44: accounts read: 1, cut short:"
    )
    assert (
        "\nused: reading 0, bitcoin-cash, m/44h/145h/0h: 1 addresses, 1 transactions,"
        " 0 sat confirmed, 2500 sat unconfirmed, 0 sat at the fork\n"
    ) in err
    assert "\nnot checked: reading 0, bitcoin purpose 84: a segwit script:" in err
    assert server.asked[:3] == ["blockchain.block.header"] * 3
    ((host, port, _),) = connect.made
    assert (host, port) == ("node.local", 50002)


@pytest.mark.parametrize(
    "headers",
    [{}, {478559: HEADERS[478559]}, {970892: HEADERS[970892]}],
)
def test_a_server_of_another_chain_is_asked_for_no_address(
    capsys: pytest.CaptureFixture[str], bundle: str, headers: dict[int, str]
) -> None:
    """Bitcoin's genesis, and another block at one checkpoint: refused.

    :param capsys: pytest's capture of the standard streams.
    :param bundle: the bundle's file.
    :param headers: the checkpoints the server answers as Bitcoin Cash does.
    """
    server = Forked(headers=headers)
    status, out, err = run(capsys, [bundle, "--server", "h:1"], Connections(server))
    assert (status, out) == (1, "")
    assert err == "seed-scan forks: the server does not serve Bitcoin Cash\n"
    assert set(server.asked) == {"blockchain.block.header"}


def test_bitcoin_sv_is_read_on_a_server_serving_its_checkpoints(
    capsys: pytest.CaptureFixture[str], bundle: str
) -> None:
    """A payment at Bitcoin SV's coin type, found once the chain is checked."""
    script = ScriptPubKey.from_address(legacy_address("m/44h/236h/0h/0/0"))
    server = Forked(pay(script, 1_500), headers=SV_HEADERS)
    argv = [bundle, "--server", "h:1"]
    status, out, err = run(capsys, argv, Connections(server), "bitcoin-sv")
    assert status == 0
    document = json.loads(out)
    assert document["chain"] == "bitcoin-sv"
    (used,) = document["used"]
    assert (used["coin"], used["path"]) == ("bitcoin-sv", "m/44h/236h/0h")
    assert "\nchain: Bitcoin SV, forked from Bitcoin at height 478559\n" in err
    assert "\nreading 0, bitcoin-sv purpose 44: accounts read: 1, cut short:" in err
    assert server.asked[:3] == ["blockchain.block.header"] * 3


@pytest.mark.parametrize(
    "chain, headers, title",
    [
        ("bitcoin-sv", HEADERS, "Bitcoin SV"),
        ("bitcoin-cash", SV_HEADERS, "Bitcoin Cash"),
    ],
)
def test_a_server_of_the_other_fork_is_refused(
    capsys: pytest.CaptureFixture[str],
    bundle: str,
    chain: str,
    headers: dict[int, str],
    title: str,
) -> None:
    """Both share the fork block, and differ at a later checkpoint.

    :param capsys: pytest's capture of the standard streams.
    :param bundle: the bundle's file.
    :param chain: the chain named.
    :param headers: the other chain's checkpoints, which the server answers.
    :param title: how the refusal names the chain named.
    """
    server = Forked(headers=headers)
    argv = [bundle, "--server", "h:1"]
    status, out, err = run(capsys, argv, Connections(server), chain)
    assert (status, out) == (1, "")
    assert err == f"seed-scan forks: the server does not serve {title}\n"
    assert set(server.asked) == {"blockchain.block.header"}


def test_a_server_whose_genesis_is_not_bitcoin_s_is_refused(
    capsys: pytest.CaptureFixture[str], bundle: str
) -> None:
    """Refused at block 0, before any checkpoint is asked."""
    other = BlockHeader(
        version=1,
        previous_block_hash=bytes(32),
        merkle_root=GENESIS.merkle_root,
        time=GENESIS.time,
        bits=bytes.fromhex("207fffff"),
        nonce=2,
    )
    server = Electrum(genesis=other)
    status, _, err = run(capsys, [bundle, "--server", "h:1"], Connections(server))
    assert status == 1
    assert err == "seed-scan forks: the server does not serve Bitcoin Cash\n"
    assert server.asked == ["blockchain.block.header"]


def test_the_summary_names_electrum_s_readings_and_says_nothing_was_used(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """The standard reading is read; the segwit one is not checked."""
    status, _, err = run(
        capsys, [write(tmp_path, STANDARD), "--server", "h:1"], Connections(Forked())
    )
    assert status == 0
    assert "\nreading 0, bitcoin Electrum: accounts read: 1\n" in err
    assert err.endswith("\nno account used within that bound\n")
    status, _, err = run(
        capsys, [write(tmp_path, SEGWIT), "--server", "h:1"], Connections(Forked())
    )
    assert status == 0
    assert err.endswith(
        "\nno account used within that bound\n"
        "not checked: reading 0, bitcoin Electrum: a segwit script: Bitcoin"
        " Cash's transactions carry no witness, so a key does not sign for it"
        " there\n"
    )


def test_the_bounds_are_the_options_given(
    capsys: pytest.CaptureFixture[str], bundle: str
) -> None:
    """The bound options reach the result and the summary."""
    argv = [bundle, "--server", "h:1", "--account-gap", "1", "--gap-limit", "7"]
    status, out, err = run(capsys, argv, Connections(Forked()))
    assert status == 0
    document = json.loads(out)
    assert (document["gap_limit"], document["account_gap"]) == (7, 1)
    assert "\nbounds: account gap 1, gap limit 7\n" in err
    assert "\nreading 0, bitcoin-cash purpose 44: accounts read: 1\n" in err


@pytest.mark.parametrize(
    "failure, said",
    [
        (caused(ConnectionRefusedError()), "no connection to the server"),
        (ValueError(ABANDON), "refused by a dependency: ValueError"),
        (KeyboardInterrupt(), "interrupted"),
    ],
)
def test_a_failure_is_one_line_of_fixed_text(
    capsys: pytest.CaptureFixture[str], bundle: str, failure: Exception, said: str
) -> None:
    """As ``scan`` says it, under the command's own name.

    :param capsys: pytest's capture of the standard streams.
    :param bundle: the bundle's file.
    :param failure: what the transport raises.
    :param said: the line written.
    """
    status, out, err = run(
        capsys, [bundle, "--server", "h:1"], Connections(Failing(failure))
    )
    assert (status, out) == (1, "")
    assert err == f"seed-scan forks: {said}\n"


def test_a_file_that_is_no_bundle_is_refused_before_any_connection(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A missing file: refused, and no server asked."""
    connect = Connections(Forked())
    argv = [str(tmp_path / "missing.json"), "--server", "h:1"]
    status, out, err = run(capsys, argv, connect)
    assert (status, out) == (1, "")
    assert err == "seed-scan forks: the bundle file cannot be read as UTF-8 text\n"
    assert not connect.made


def test_a_chain_forks_does_not_read_is_refused_unquoted(
    capsys: pytest.CaptureFixture[str], bundle: str
) -> None:
    """The parser refuses it, as it refuses any argument, unrepeated."""
    with pytest.raises(SystemExit) as caught:
        cli.main(["forks", bundle, "--chain", ABANDON, "--server", "h:1"])
    assert caught.value.code == 2
    err = capsys.readouterr().err
    assert ABANDON not in err
    assert "an argument is refused, and not repeated" in err


#: A whole `forks` in an interpreter of its own, against a server serving
#: Bitcoin Cash's headers, that prints its exit status and whether
#: `seed_scan.identify` was loaded. The bundle file, the genesis header and
#: the checkpoints, as JSON, are its arguments
_FORKS_ALONE = """
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
argv = ["forks", bundle, "--chain", "bitcoin-cash", "--server", "h:1"]
with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
    status = cli.main(argv, connect=lambda *_: server)
print(json.dumps([status, "seed_scan.identify" in sys.modules]))
"""


def test_forks_loads_no_identify(bundle: str) -> None:
    """A whole `forks`, in a fresh interpreter, does not load `identify`.

    The module that handles the secret stays out of a command that reads
    a bundle. A subprocess, because this module imports `identify` to
    write the bundle.
    """
    argv = [bundle, GENESIS.serialize().hex(), json.dumps(HEADERS)]
    stdout = subprocess.run(  # noqa: S603
        [sys.executable, "-c", _FORKS_ALONE, *argv],
        check=True,
        capture_output=True,
        encoding="utf-8",
        # a child that hangs fails this test, rather than holding the
        # run until the job's timeout-minutes; the bound is the one
        # tests/conftest_test.py gives its own child
        timeout=120,
    ).stdout
    assert json.loads(stdout) == [0, False]
