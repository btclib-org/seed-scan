# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for ``seed-scan report``: the files, the guard, the refusals."""

from __future__ import annotations

import io
import json
import pathlib
import sys
from hashlib import sha256
from typing import TYPE_CHECKING, Any

import pytest
from btclib_wallet.fetch.history import HistoryTx

from seed_scan import cli
from seed_scan.bundle import dumps
from seed_scan.exceptions import SeedScanValueError
from seed_scan.forks import dumps as forks_dumps
from seed_scan.forks import forks
from seed_scan.identify import identify
from seed_scan.report import report
from seed_scan.scan import dumps as scan_dumps
from seed_scan.scan import scan

from .cli_test import no_guard
from .identify_test import ABANDON, SEGWIT, Prompt, no_share
from .scan_cli_test import Connections, Electrum
from .scan_test import BLOCK, Chain, pay, script

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(scope="module")
def texts() -> tuple[str, str]:
    """Return a bundle and the scan result of a payment to its first account.

    :returns: the bundle's text and the result's.
    """
    bundle = dumps(identify(ABANDON, [""], no_share, accounts=1))
    paid = pay(1, (script(bundle, "m/84h/0h/0h", 0, 0), 9))
    result = scan(bundle, Chain(HistoryTx(paid, BLOCK)), server="s:1")
    return bundle, scan_dumps(result)


@pytest.fixture
def files(texts: tuple[str, str], tmp_path: Path) -> tuple[str, str]:
    """Write the bundle and the result to files, as their UTF-8 bytes.

    As bytes, and not with `pathlib.Path.write_text`, which on Windows
    writes each LF as CRLF, so that each file is the text its digest is of.

    :param texts: the bundle and the result.
    :param tmp_path: pytest's directory for the test.
    :returns: the two files' paths.
    """
    names = []
    for name, text in zip(("bundle.json", "scan.json"), texts, strict=True):
        path = tmp_path / name
        path.write_bytes(text.encode("utf-8"))
        names.append(str(path))
    return names[0], names[1]


@pytest.fixture
def forks_file(texts: tuple[str, str], tmp_path: Path) -> str:
    """Write the forks result of the bundle, on a chain that used nothing.

    :param texts: the bundle and the scan result.
    :param tmp_path: pytest's directory for the test.
    :returns: the file's path.
    """
    result = forks(texts[0], Chain(), chain="bitcoin-cash", server="h:1")
    path = tmp_path / "forks.json"
    path.write_bytes(forks_dumps(result).encode("utf-8"))
    return str(path)


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    """Run ``seed-scan report`` with the guard replaced.

    :param capsys: pytest's capture of the standard streams.
    :param argv: the arguments after ``report``.
    :returns: the exit status, standard output and standard error.
    """
    status = cli.main(["report", *argv], prompt=Prompt(), forbid_network=no_guard)
    out, err = capsys.readouterr()
    return status, out, err


def test_report_writes_the_report_of_both_files(
    capsys: pytest.CaptureFixture[str],
    texts: tuple[str, str],
    files: tuple[str, str],
) -> None:
    """The report goes to standard output, and nothing to standard error."""
    status, out, err = run(capsys, files[0], "--scan", files[1])
    assert (status, err) == (0, "")
    assert out == report(*texts)
    assert "    account 0, m/84h/0h/0h: 9 sat confirmed" in out


def test_each_forks_file_is_reported(
    capsys: pytest.CaptureFixture[str],
    texts: tuple[str, str],
    files: tuple[str, str],
    forks_file: str,
) -> None:
    """The report of the bundle, its scan result and its forks result."""
    status, out, err = run(capsys, files[0], "--scan", files[1], "--forks", forks_file)
    assert (status, err) == (0, "")
    forked = pathlib.Path(forks_file).read_bytes().decode("utf-8")
    assert out == report(*texts, [forked])
    assert "\nchain: Bitcoin Cash, its own blocks from height " in out


def test_two_forks_files_of_one_chain_are_one_line(
    capsys: pytest.CaptureFixture[str], files: tuple[str, str], forks_file: str
) -> None:
    """--forks is given once per chain."""
    status, out, err = run(
        capsys, files[0], "--forks", forks_file, "--forks", forks_file
    )
    assert (status, out) == (1, "")
    assert err == "seed-scan report: forks results: two of one chain\n"


def test_a_forks_file_that_is_no_text_is_refused_unquoted(
    capsys: pytest.CaptureFixture[str], files: tuple[str, str], tmp_path: Path
) -> None:
    """Bytes that are no UTF-8 are neither decoded nor quoted."""
    binary = tmp_path / "forks.bin"
    binary.write_bytes(b"\xff" + ABANDON.encode())
    status, out, err = run(capsys, files[0], "--forks", str(binary))
    assert (status, out) == (1, "")
    assert err == (
        "seed-scan report: the forks result file cannot be read as UTF-8 text\n"
    )


def test_without_scan_the_bundle_alone_is_reported(
    capsys: pytest.CaptureFixture[str],
    texts: tuple[str, str],
    files: tuple[str, str],
) -> None:
    """No result: every account is not checked."""
    status, out, _ = run(capsys, files[0])
    assert status == 0
    assert out == report(texts[0])


def test_the_guard_is_on_before_a_file_is_read(
    monkeypatch: pytest.MonkeyPatch, files: tuple[str, str], forks_file: str
) -> None:
    """`main` refuses sockets and processes before it reads the bundle."""
    events: list[str] = []
    read_bytes = pathlib.Path.read_bytes

    def recorded(path: pathlib.Path) -> bytes:
        events.append(path.name)
        return read_bytes(path)

    monkeypatch.setattr(pathlib.Path, "read_bytes", recorded)
    argv = ["report", files[0], "--scan", files[1], "--forks", forks_file]
    cli.main(argv, forbid_network=lambda: events.append("guard"))
    assert events == ["guard", "bundle.json", "scan.json", "forks.json"]


def test_the_report_is_written_as_its_bytes(
    monkeypatch: pytest.MonkeyPatch, texts: tuple[str, str], files: tuple[str, str]
) -> None:
    """A standard output that writes CRLF, as Windows' does, writes LF.

    The bytes are those the last line hashes.
    """
    windows = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", newline="\r\n")
    monkeypatch.setattr(sys, "stdout", windows)
    argv = ["report", files[0], "--scan", files[1]]
    assert cli.main(argv, prompt=Prompt(), forbid_network=no_guard) == 0
    windows.flush()
    out = windows.buffer.getvalue()
    assert out == report(*texts).encode("utf-8")
    body, last = out[:-1].rsplit(b"\n", 1)
    assert last == b"digest: sha256 " + sha256(body + b"\n").hexdigest().encode()


def test_a_crlf_file_is_hashed_as_its_bytes(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A bundle written with CRLF, as Windows writes identify's: its digest.

    The scan result made from it names the digest of those bytes, and the
    report reads them back as they are.
    """
    lf = dumps(identify(ABANDON, [""], no_share, accounts=1))
    crlf = lf.replace("\n", "\r\n")
    bundle = tmp_path / "bundle.json"
    bundle.write_bytes(crlf.encode("utf-8"))
    result = tmp_path / "scan.json"
    result.write_bytes(scan_dumps(scan(crlf, Chain(), server="s:1")).encode("utf-8"))
    status, out, err = run(capsys, str(bundle), "--scan", str(result))
    assert (status, err) == (0, "")
    digest = sha256(bundle.read_bytes()).hexdigest()
    assert out.splitlines()[1] == f"bundle: sha256 {digest}"


def test_what_windows_writes_reports_as_its_bytes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """identify, scan and report, each writing through a CRLF standard output.

    As on Windows: the bundle and the result are written with CRLF, and
    the report names the SHA-256 of each file as it is, and is LF itself.
    """

    def written(argv: list[str], **replaced: Any) -> bytes:
        out = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", newline="\r\n")
        monkeypatch.setattr(sys, "stdout", out)
        assert cli.main(argv, **replaced) == 0
        out.flush()
        return out.buffer.getvalue()

    bundle = tmp_path / "bundle.json"
    prompt = Prompt(ABANDON, "")
    bundle.write_bytes(
        written(["identify", "--accounts", "1"], prompt=prompt, forbid_network=no_guard)
    )
    assert b"\r\n" in bundle.read_bytes()
    result = tmp_path / "scan.json"
    connect = Connections(Electrum())
    result.write_bytes(
        written(["scan", str(bundle), "--server", "h:1"], connect=connect)
    )
    assert b"\r\n" in result.read_bytes()
    argv = ["report", str(bundle), "--scan", str(result)]
    out = written(argv, prompt=Prompt(), forbid_network=no_guard)
    assert b"\r" not in out
    lines = out.decode("utf-8").split("\n")
    assert lines[1] == f"bundle: sha256 {sha256(bundle.read_bytes()).hexdigest()}"
    assert lines[2] == f"scan: sha256 {sha256(result.read_bytes()).hexdigest()}"


def test_a_guard_not_in_place_is_one_line_and_reads_nothing(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A refused guard is a status and a line, before the bundle is read.

    The bundle named does not exist, so a read would be refused first.
    """

    def refused() -> None:
        raise SeedScanValueError("the refusal of sockets and processes is not in place")

    missing = str(tmp_path / "missing.json")
    status = cli.main(["report", missing], forbid_network=refused)
    out, err = capsys.readouterr()
    assert (status, out) == (1, "")
    assert err == (
        "seed-scan report: the refusal of sockets and processes is not in place\n"
    )


def test_a_result_of_another_bundle_is_one_line(
    capsys: pytest.CaptureFixture[str], files: tuple[str, str], tmp_path: Path
) -> None:
    """A refusal is a status and a line, and nothing on standard output."""
    other = tmp_path / "other.json"
    other.write_text(dumps(identify(SEGWIT, [""], no_share)), encoding="utf-8")
    status, out, err = run(capsys, str(other), "--scan", files[1])
    assert (status, out) == (1, "")
    assert err == "seed-scan report: scan result: made from another bundle\n"


def test_a_scan_file_that_is_no_text_is_refused_unquoted(
    capsys: pytest.CaptureFixture[str], files: tuple[str, str], tmp_path: Path
) -> None:
    """Bytes that are no UTF-8 are neither decoded nor quoted."""
    binary = tmp_path / "scan.bin"
    binary.write_bytes(b"\xff" + ABANDON.encode())
    status, out, err = run(capsys, files[0], "--scan", str(binary))
    assert (status, out) == (1, "")
    assert err == (
        "seed-scan report: the scan result file cannot be read as UTF-8 text\n"
    )


#: A JSON text Python refuses to read: an integer of 5000 digits.
LONG = f"[{'1' * 5000}]"


@pytest.mark.parametrize(
    "which, said",
    [
        (0, "bundle: a number too long to read"),
        (1, "scan result: a number too long to read"),
    ],
)
def test_a_number_too_long_to_read_is_one_line(
    capsys: pytest.CaptureFixture[str],
    files: tuple[str, str],
    which: int,
    said: str,
) -> None:
    """Python's own refusal of the conversion is neither raised nor quoted.

    :param capsys: pytest's capture of the standard streams.
    :param files: the bundle and the result.
    :param which: the file that holds the number.
    :param said: the line written, after the command's name.
    """
    pathlib.Path(files[which]).write_text(LONG, encoding="utf-8")
    status, out, err = run(capsys, files[0], "--scan", files[1])
    assert (status, out) == (1, "")
    assert err == f"seed-scan report: {said}\n"


def test_balances_too_large_to_sum_are_one_line(
    capsys: pytest.CaptureFixture[str], texts: tuple[str, str], tmp_path: Path
) -> None:
    """Two accounts of 4300 digits each: their total would not print."""
    bundle = texts[0]
    chain = Chain(
        HistoryTx(pay(1, (script(bundle, "m/84h/0h/0h", 0, 0), 9)), BLOCK),
        HistoryTx(pay(2, (script(bundle, "m/49h/0h/0h", 0, 0), 9)), BLOCK),
    )
    document = json.loads(scan_dumps(scan(bundle, chain, server="s:1")))
    for used in document["used"]:
        used["confirmed"] = 9 * 10**4299
    result = tmp_path / "large.json"
    result.write_bytes(json.dumps(document).encode("utf-8"))
    path = tmp_path / "bundle.json"
    path.write_bytes(bundle.encode("utf-8"))
    status, out, err = run(capsys, str(path), "--scan", str(result))
    assert (status, out) == (1, "")
    assert err == (
        "seed-scan report: scan result: a balance outside 0 to 21 million bitcoin\n"
    )


def test_the_help_names_the_report_and_its_options(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``seed-scan --help`` lists the command, and its own help the options."""
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    listed = " ".join(capsys.readouterr().out.split())
    assert "summarize a bundle and its scan and forks results, offline" in listed
    with pytest.raises(SystemExit):
        cli.main(["report", "--help"])
    out = " ".join(capsys.readouterr().out.split())
    assert (
        "--scan SCAN the result scan wrote for that bundle; without it, the report"
        " checks only what --forks names"
    ) in out
    assert "--forks FORKS a result forks wrote for that bundle; once per chain" in out
    assert "seed_scan.report" in out
