# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `seed_scan.cli`: the prompts, the output, the refusals."""

from __future__ import annotations

import getpass
import importlib.metadata
import subprocess
import sys
import warnings

import pytest

from seed_scan import cli
from seed_scan.bundle import loads
from seed_scan.exceptions import SeedScanValueError

from .identify_test import ABANDON, BIP84_CHANGE, SHARES, Prompt
from .secret_free import assert_secret_free


def no_guard() -> None:
    """Stand in for the refusal of every socket, which no test may install."""


def run(
    capsys: pytest.CaptureFixture[str], argv: list[str], *typed: str
) -> tuple[int, str, str]:
    """Run the command with what the user types; answer its status and output.

    :param capsys: pytest's capture of the standard streams.
    :param argv: the command's arguments.
    :param typed: what the user types at the hidden prompts, in order.
    :returns: the exit status, standard output and standard error.
    """
    status = cli.main(argv, prompt=Prompt(*typed), forbid_network=no_guard)
    out, err = capsys.readouterr()
    return status, out, err


def test_identify_writes_the_bundle_and_a_summary(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The bundle goes to standard output, the summary to standard error."""
    argv = ["identify", "--accounts", "1", "--address", BIP84_CHANGE]
    status, out, err = run(capsys, argv, ABANDON, "TREZOR", "")
    assert status == 0
    bundle = loads(out)
    assert [r.passphrase for r in bundle.readings] == [0, 1]
    assert "schemes claiming the words: bip39" in err
    assert "reading 1: bip39, passphrase 1" in err
    assert "found: reading 0, bitcoin, m/84h/0h/0h/1/0" in err
    assert "accounts 0 to 0 of each Bitcoin purpose, of Bitcoin Cash's" in err


def test_the_summary_says_what_was_not_found_and_not_checked(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An unfound address and an incomplete set of shares are both said."""
    argv = ["identify", "--accounts", "1", "--indexes", "1", "--address", BIP84_CHANGE]
    status, _, err = run(capsys, argv, SHARES[0], "", "")
    assert status == 0
    assert "not checked: slip39: the shares typed do not complete a set" in err
    assert "not found within that bound" in err


def test_without_an_address_the_summary_says_no_search(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """With no address given, the summary says nothing of a search."""
    status, out, err = run(capsys, ["identify", "--accounts", "1"], ABANDON, "")
    assert status == 0
    assert loads(out).search is None
    assert "address" not in err


def test_the_summary_says_an_address_was_not_searched(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An address of another kind is said not searched; no scheme is "none"."""
    status, _, err = run(capsys, ["identify", "--address", "0x00"], "qzx", "")
    assert status == 0
    assert "schemes claiming the words: none" in err
    assert "address not searched: not a Bitcoin address" in err


def test_a_refusal_is_a_status_and_a_line(capsys: pytest.CaptureFixture[str]) -> None:
    """A bound below one is refused with status 1 and nothing on stdout."""
    status, out, err = run(capsys, ["identify", "--accounts", "0"], ABANDON, "")
    assert status == 1
    assert not out
    assert err == "seed-scan identify: invalid accounts: 0 is below 1\n"


def test_the_guard_is_on_before_the_first_prompt() -> None:
    """`main` refuses sockets and processes before anything is typed."""
    events: list[str] = []

    def prompt(text: str) -> str:
        events.append(text)
        return ""

    cli.main(["identify"], prompt=prompt, forbid_network=lambda: events.append("guard"))
    assert events[:2] == ["guard", "Mnemonic: "]


class _QuotingError(ValueError):
    """A dependency's refusal whose text quotes what it was given."""


@pytest.mark.parametrize(
    "raised, said",
    [
        (_QuotingError(SHARES[1]), "refused by a dependency: _QuotingError"),
        (KeyboardInterrupt(), "interrupted"),
        (EOFError(), "interrupted"),
    ],
)
def test_a_refusal_or_an_interruption_is_one_fixed_line(
    capsys: pytest.CaptureFixture[str], raised: BaseException, said: str
) -> None:
    """Neither a traceback nor what was typed reaches standard error.

    :param capsys: pytest's capture of the standard streams.
    :param raised: what the prompt raises, after the mnemonic was typed.
    :param said: the line written.
    """
    typed = [SHARES[0]]

    def prompt(text: str) -> str:
        if typed:
            return typed.pop()
        raise raised

    status = cli.main(["identify"], prompt=prompt, forbid_network=no_guard)
    out, err = capsys.readouterr()
    assert status == 1
    assert not out
    assert err == f"seed-scan identify: {said}\n"


def test_a_command_is_required(capsys: pytest.CaptureFixture[str]) -> None:
    """No command is argparse's refusal, before any prompt."""
    with pytest.raises(SystemExit) as caught:
        cli.main([], prompt=Prompt(), forbid_network=no_guard)
    assert caught.value.code == 2
    assert "required" in capsys.readouterr().err


def test_the_prompts_ask_passphrases_until_an_empty_one() -> None:
    """Each passphrase prompt is numbered, and an empty answer ends them."""
    prompt = Prompt("one", "two", "")
    assert cli._passphrases(prompt) == ["", "one", "two"]
    assert prompt.shown == [
        "Passphrase 1 (empty when done): ",
        "Passphrase 2 (empty when done): ",
        "Passphrase 3 (empty when done): ",
    ]


def test_the_hidden_prompt_is_getpass(monkeypatch: pytest.MonkeyPatch) -> None:
    """What `getpass` answers is what the prompt answers."""
    monkeypatch.setattr(getpass, "getpass", lambda text: f"typed at {text}")
    assert cli._hidden("Mnemonic: ") == "typed at Mnemonic: "


def test_the_echoing_fallback_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """Where `getpass` would read standard input instead, the prompt refuses."""

    def no_terminal(text: str) -> str:
        """Warn as `getpass` does where it falls back to standard input.

        :param text: the prompt.
        :returns: what the user typed, echoed, once the warning passes.
        """
        warnings.warn(text, getpass.GetPassWarning, stacklevel=2)
        return "echoed"  # pragma: no cover -- the warning is an error here

    monkeypatch.setattr(getpass, "getpass", no_terminal)
    with pytest.raises(SeedScanValueError, match="no terminal") as caught:
        cli._hidden("Mnemonic: ")
    assert caught.value.__context__ is None


def test_an_answer_that_is_no_utf8_is_refused_without_its_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A byte that is no UTF-8 is refused in fixed text, its error unchained.

    `getpass` decodes what the terminal sends, and the decoding error holds
    every byte of the answer.
    """
    typed = SHARES[0].encode() + b"\xe9"

    def undecodable(text: str) -> str:
        """Decode what was typed, as `getpass` does.

        :param text: the prompt.
        :returns: never: the bytes are not UTF-8.
        """
        return typed.decode()

    monkeypatch.setattr(getpass, "getpass", undecodable)
    with pytest.raises(SeedScanValueError, match="not UTF-8 text") as caught:
        cli._hidden("Passphrase 1 (empty when done): ")
    assert_secret_free(caught.value, [typed, SHARES[0], *SHARES[0].split()])


@pytest.mark.parametrize(
    "event",
    [
        "socket.connect",
        "socket.__new__",
        "subprocess.Popen",
        "os.system",
        "os.exec",
        "os.posix_spawn",
        "os.fork",
        "os.forkpty",
        "os.spawn",
    ],
)
def test_a_socket_or_process_event_is_refused(event: str) -> None:
    """The audit hook refuses a socket and a new process.

    :param event: the audit event.
    """
    with pytest.raises(SeedScanValueError, match=f"{event} refused"):
        cli._refuse_network(event, ())


@pytest.mark.parametrize("event", ["open", "import", "os.listdir", "os.forkless"])
def test_other_events_pass(event: str) -> None:
    """The audit hook lets every other event through.

    :param event: the audit event.
    """
    cli._refuse_network(event, ())


def test_the_guard_installs_the_hook(monkeypatch: pytest.MonkeyPatch) -> None:
    """`_forbid_network` installs `_refuse_network`, and nothing else."""
    installed: list[object] = []
    monkeypatch.setattr(sys, "addaudithook", installed.append)
    cli._forbid_network()
    assert installed == [cli._refuse_network]


def test_a_socket_is_refused_once_the_guard_is_on() -> None:
    """In a process of its own, the guard refuses a socket being made.

    A subprocess: an audit hook cannot be removed, and this one would stay
    in the process running the suite.
    """
    probe = (
        "import socket\nfrom seed_scan.cli import _forbid_network\n"
        "_forbid_network()\nsocket.socket()\n"
    )
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-c", probe],
        capture_output=True,
        encoding="utf-8",
        check=False,
    )
    assert done.returncode != 0
    assert "socket.__new__ refused" in done.stderr


def test_a_process_is_refused_once_the_guard_is_on() -> None:
    """In a process of its own, the guard refuses a subprocess being started."""
    probe = (
        "import subprocess, sys\nfrom seed_scan.cli import _forbid_network\n"
        "_forbid_network()\nsubprocess.run([sys.executable, '-c', 'pass'])\n"
    )
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-c", probe],
        capture_output=True,
        encoding="utf-8",
        check=False,
    )
    assert done.returncode != 0
    assert "subprocess.Popen refused" in done.stderr


def test_the_command_is_installed_as_seed_scan() -> None:
    """The `seed-scan` script runs `seed_scan.cli:main`."""
    (script,) = [
        entry
        for entry in importlib.metadata.entry_points(group="console_scripts")
        if entry.name == "seed-scan"
    ]
    assert script.value == "seed_scan.cli:main"
