# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for ``seed-scan report``: the files, the guard, the refusals."""

from __future__ import annotations

import json
import pathlib
from typing import TYPE_CHECKING

import pytest
from btclib_wallet.fetch.history import HistoryTx

from seed_scan import cli
from seed_scan.bundle import dumps
from seed_scan.exceptions import SeedScanValueError
from seed_scan.identify import identify
from seed_scan.report import report
from seed_scan.scan import dumps as scan_dumps
from seed_scan.scan import scan

from .cli_test import no_guard
from .identify_test import ABANDON, SEGWIT, Prompt, no_share
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
    """Write the bundle and the result to files.

    :param texts: the bundle and the result.
    :param tmp_path: pytest's directory for the test.
    :returns: the two files' paths.
    """
    names = []
    for name, text in zip(("bundle.json", "scan.json"), texts, strict=True):
        path = tmp_path / name
        path.write_text(text, encoding="utf-8")
        names.append(str(path))
    return names[0], names[1]


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
    monkeypatch: pytest.MonkeyPatch, files: tuple[str, str]
) -> None:
    """`main` refuses sockets and processes before it reads the bundle."""
    events: list[str] = []
    read_text = pathlib.Path.read_text

    def recorded(path: pathlib.Path, encoding: str) -> str:
        events.append(path.name)
        return read_text(path, encoding=encoding)

    monkeypatch.setattr(pathlib.Path, "read_text", recorded)
    argv = ["report", files[0], "--scan", files[1]]
    cli.main(argv, forbid_network=lambda: events.append("guard"))
    assert events == ["guard", "bundle.json", "scan.json"]


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
    result.write_text(json.dumps(document), encoding="utf-8")
    path = tmp_path / "bundle.json"
    path.write_text(bundle, encoding="utf-8")
    status, out, err = run(capsys, str(path), "--scan", str(result))
    assert (status, out) == (1, "")
    assert err == (
        "seed-scan report: scan result: a balance outside 0 to 21 million bitcoin\n"
    )


def test_the_help_names_the_report_and_its_option(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``seed-scan --help`` lists the command, and its own help the option."""
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    listed = " ".join(capsys.readouterr().out.split())
    assert "summarize a bundle and its scan result, offline" in listed
    with pytest.raises(SystemExit):
        cli.main(["report", "--help"])
    out = capsys.readouterr().out
    assert "--scan SCAN" in out
    assert "seed_scan.report" in " ".join(out.split())
