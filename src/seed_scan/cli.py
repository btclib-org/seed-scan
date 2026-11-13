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
"""

from __future__ import annotations

import argparse
import getpass
import sys
import warnings
from typing import TYPE_CHECKING, NoReturn

from seed_scan.bundle import dumps
from seed_scan.exceptions import SeedScanException, SeedScanValueError
from seed_scan.identify import identify

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from seed_scan.bundle import Bundle

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


def _refuse_network(event: str, args: tuple[object, ...]) -> None:
    """Refuse every socket and every new process, as an audit hook.

    The guard's own event is answered with `_InPlace`, holding its token.
    """
    if event == _PROBE:
        raise _InPlace(*args)
    if event.startswith(_REFUSED) or event in _REFUSED_EXACTLY:
        raise SeedScanValueError(
            f"identify opens no connection and starts no process: {event} refused"
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
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    prompt: Callable[[str], str] = _hidden,
    forbid_network: Callable[[], None] = _forbid_network,
) -> int:
    """Run the command; answer its exit status.

    `prompt` and `forbid_network` are what a test replaces: the hidden
    prompt and the refusal of every socket and new process.
    """
    args = _parser().parse_args(argv)
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
    except SeedScanException as e:
        err_msg = str(e)
    except (ValueError, TypeError) as e:
        # a dependency's refusal: those packages print no secret either,
        # but the class alone is said, and no traceback
        err_msg = f"refused by a dependency: {type(e).__name__}"
    except (KeyboardInterrupt, EOFError):
        err_msg = "interrupted"
    else:
        sys.stdout.write(dumps(bundle))
        sys.stderr.write(_summary(bundle))
        return 0
    sys.stderr.write(f"seed-scan identify: {err_msg}\n")
    return 1
