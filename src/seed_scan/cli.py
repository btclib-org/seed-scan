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
rest of the process. A refusal is one line on standard error, never a
traceback, and says nothing of what was typed.
"""

from __future__ import annotations

import argparse
import getpass
import sys
import warnings
from typing import TYPE_CHECKING

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
# one, or read the secret out of this one, beyond this hook's reach
_REFUSED = ("socket.", "subprocess.", "os.system", "os.exec", "os.posix_spawn")
_REFUSED_EXACTLY = ("os.fork", "os.forkpty", "os.spawn")


def _refuse_network(event: str, args: tuple[object, ...]) -> None:
    """Refuse every socket and every new process, as an audit hook."""
    if event.startswith(_REFUSED) or event in _REFUSED_EXACTLY:
        raise SeedScanValueError(
            f"identify opens no connection and starts no process: {event} refused"
        )


def _forbid_network() -> None:
    """Refuse every socket and every new process for the rest of the process.

    An audit hook cannot be removed, so this runs once per process, in
    the command alone.
    """
    sys.addaudithook(_refuse_network)


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


def _parser() -> argparse.ArgumentParser:
    """Return the command's parser."""
    parser = argparse.ArgumentParser(
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
    forbid_network()
    try:
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
