# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The bundle and the summary hold no secret, in any encoding.

`identify` runs on a published vector of each scheme it reads, with a
passphrase typed, and everything it writes -- the bundle on standard
output and the summary on standard error -- is searched for every
secret it handled: each word and the whole sentence, the passphrase,
the entropy, or for SLIP-0039 each share's value and the encrypted
master secret, each seed, and the private key of the master, of every
account and of the first address of each branch. Each is looked for as
text, hex, Base58Check (xprv and WIF), base64 and the `repr` of its
bytes, in any piece of `windows` length, in any letter case, with
whitespace dropped. The search is the tree's
`assert_secret_free`, which section 14 has copied into every tree.

A planted secret is the control: the same search over a bundle holding
one finds it, for each kind of secret.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import re
from typing import TYPE_CHECKING

import pytest
from bip32_descriptors.bip32 import BIP32KeyData
from bip39_slip39 import bip39, electrum, slip39
from btclib.b58 import wif_from_prv_key

from seed_scan import bundle, cli, forks, report, scan
from seed_scan.bundle import COIN_NAMES, loads
from seed_scan.evm import EVM_CHAINS
from seed_scan.scan import OTHER_CHAIN

from .identify_test import ABANDON, SHARES, Prompt
from .secret_free import assert_secret_free

if TYPE_CHECKING:
    from collections.abc import Iterable

#: A secret as a run holds it: text, or bytes.
Secret = str | bytes

#: A passphrase of BIP39's and SLIP-0039's vectors.
TREZOR = "TREZOR"

#: Electrum's SEED_TEST_CASES `english_with_passphrase` (spesmilo/electrum
#: `tests/test_mnemonic.py`, at b991f249d): a "segwit" mnemonic and its
#: passphrase.
WILD_FATHER = (
    "wild father tree among universe such mobile favorite target dynamic "
    "credit identify"
)
PLAGUEIS = "Did you ever hear the tragedy of Darth Plagueis the Wise?"


#: The member names of the objects the commands write as JSON.
MEMBERS = frozenset(
    {"format", "version"}
    | {
        field.name
        for module in (bundle, scan, forks)
        for name in module.__all__
        if dataclasses.is_dataclass(kind := getattr(module, name))
        for field in dataclasses.fields(kind)
    }
)


def _group(*patterns: str) -> str:
    """Return a regular expression's group that matches any of the patterns."""
    return f"({'|'.join(patterns)})"


def _either(words: Iterable[str]) -> str:
    """Return a regular expression's group that matches any of the words."""
    return _group(*map(re.escape, words))


#: The reasons a scan result writes, each a fixed text.
SCAN_REASONS = (scan.NO_SERVER, scan.NO_NODE, scan.OTHER_CHAIN, scan.NOT_READ)

#: The reason `seed_scan.bundle.slip39_passphrase` writes, its number any:
#: the first ``0`` of the reason of passphrase 0 is that number.
_SLIP39_REASON = re.escape(bundle.slip39_passphrase(0)).replace("0", r"\d+", 1)

#: The reasons a bundle writes.
_BUNDLE_REASON = _group(*map(re.escape, bundle.REASONS.values()), _SLIP39_REASON)

_COIN = _either(COIN_NAMES)
_EVM_NAME = _either(EVM_CHAINS)
_CHAIN = _either((*EVM_CHAINS, *forks.CHAINS))
_EVM_TITLE = _either(chain.title for chain in EVM_CHAINS.values())
_FORK_TITLE = _either(chain.title for chain in forks.CHAINS.values())
_SCAN_REASON = _either(SCAN_REASONS)
_REPORT_REASON = _either((*SCAN_REASONS, report.NO_SCAN, report.NOT_IN_SCAN))

#: The members whose value JSON writes as a defined word, and the words
#: each may hold, whole: a coin's name, a chain's, or a reason.
DEFINED_VALUES = {
    "coin": re.compile(_COIN),
    "chain": re.compile(_CHAIN),
    "reason": re.compile(f"{_BUNDLE_REASON}|{_SCAN_REASON}"),
}


def _defined(name: str, value: object) -> bool:
    """Return whether a member's value is a word `DEFINED_VALUES` holds."""
    words = DEFINED_VALUES.get(name)
    return isinstance(value, str) and words is not None and bool(words.fullmatch(value))


def _members(pairs: list[tuple[str, object]]) -> list[tuple[str | None, object]]:
    """Return a JSON object's members without the defined words.

    `json.loads` calls this on each object, the innermost first, and the
    list it returns keeps a member whose name is written twice. A name of
    `MEMBERS` becomes ``None``, and so does a value `_defined` says is a
    defined word. Every other name and value is kept.

    :param pairs: the object's members, as names and values.
    :returns: the members kept.
    """
    return [
        (
            None if name in MEMBERS else name,
            None if _defined(name, value) else value,
        )
        for name, value in pairs
    ]


def assert_json_secret_free(text: str, secrets: list[Secret]) -> None:
    """Assert that no piece of a secret, in any spelling, is in a JSON text.

    The text is parsed, the defined words are dropped from where JSON
    writes them, as `_members` says, and the `repr` of what is left is
    handed to `assert_secret_free` as a refusal's message: one search, the
    tree's, reads the bundle and the refusals alike. A defined word can
    hold a word of a mnemonic, as ``ethereum-classic`` holds SLIP-0039's
    ``class`` and ``cut_short`` its ``short``. A number is kept as it is
    written, since a float's value can lose digits its text shows.

    :param text: a JSON document a command wrote.
    :param secrets: each secret, as text or bytes.
    """
    kept = json.loads(text, object_pairs_hook=_members, parse_float=str, parse_int=str)
    assert_secret_free(ValueError(repr(kept)), secrets)


#: A number as a line writes it, a sign allowed wherever it stands: a
#: shape matched more loosely drops no more, since only its groups are
#: dropped.
_N = r"-?\d+"

#: Lines of `seed_scan.report` and of the summaries of ``identify`` and
#: ``scan`` that hold a defined word, each whole, as the code writes it.
#: Each group is a defined word: a coin's name, a chain's name or title,
#: or a reason.
LINE_SHAPES = tuple(
    re.compile(shape)
    for shape in (
        # seed_scan.report
        (
            rf"node: .*, {_EVM_TITLE}, chain id {_N}, latest block {_N} before"
            " the first address was read"
        ),
        rf"{_EVM_TITLE} tokens: not checked: {_either([report.NO_TOKENS])}",
        rf"not derived: [^:]+: {_BUNDLE_REASON}",
        rf"address search: not run: {_BUNDLE_REASON}",
        (
            rf"  {_COIN}, (?:purpose {_N}|Electrum account)(?:, on {_EVM_TITLE})?"
            rf"(?:: not checked: {_REPORT_REASON}"
            rf"|: accounts 0 to {_N} read, {_N} used"
            rf"(?:, cut short: run identify with --accounts above {_N}, then scan)?)"
        ),
        (
            rf"total: (bitcoin), {_N} sat confirmed, {_N} sat unconfirmed, {_N}"
            " used accounts, each account key once"
        ),
        (
            rf"total: {_EVM_NAME}, {_N} wei of \w+, {_N} used accounts, each"
            " account key once"
        ),
        # seed_scan.cli, the summary of identify
        rf"not checked: [^:]+: {_BUNDLE_REASON}",
        rf"address not searched: {_BUNDLE_REASON}",
        (
            rf"address searched in {_N} positions: accounts 0 to {_N} of each"
            rf" (Bitcoin) purpose, of {_FORK_TITLE}'s for a base58 address, and"
            rf" Electrum's account, receive and change, indexes 0 to {_N}"
        ),
        rf"found: reading {_N}, {_COIN}, \S+",
        # seed_scan.cli, the summary of scan
        rf"node: .*, {_EVM_TITLE}, chain id {_N}, block {_N}",
        rf"{_EVM_TITLE}: \w+ and nonces read, no token balance",
        (
            rf"reading {_N}, {_COIN} (?:purpose {_N}|Electrum): accounts read: {_N}"
            r"(?:, cut short: the bundle's accounts end before the account gap)?"
        ),
        rf"not checked: reading {_N}, {_COIN}: {_SCAN_REASON}",
    )
)

#: A coin's name, a chain's name or title, or a reason, wherever it is.
_ANY_DEFINED = re.compile(
    rf"\b(?:{_COIN}|{_CHAIN}|{_EVM_TITLE}"
    rf"|{_FORK_TITLE}|{_BUNDLE_REASON}|{_REPORT_REASON}"
    rf"|{_either([report.NO_TOKENS])})\b"
)


def unshaped(text: str) -> list[str]:
    """Return the lines of a text that hold a defined word and fit no shape.

    Such a line is searched whole, its defined words with it.

    :param text: lines a command wrote.
    :returns: those of them none of `LINE_SHAPES` matches whole.
    """
    return [
        line
        for line in text.split("\n")
        if _ANY_DEFINED.search(line)
        and not any(shape.fullmatch(line) for shape in LINE_SHAPES)
    ]


def _line_kept(line: str) -> str:
    """Return a line without the defined words its shape writes.

    A line of none of `LINE_SHAPES` is kept whole: where the code writes
    a line another way, every word of it is searched.

    :param line: a line a command wrote.
    :returns: what of it is searched.
    """
    for shape in LINE_SHAPES:
        if found := shape.fullmatch(line):
            for group in reversed(range(1, shape.groups + 1)):
                start, end = found.span(group)
                if start >= 0:
                    line = line[:start] + line[end:]
            return line
    return line


def assert_lines_secret_free(text: str, secrets: list[Secret]) -> None:
    """Assert that no piece of a secret, in any spelling, is in a text's lines.

    The text is a report or a summary. Each line loses the defined words
    its shape writes, as `_line_kept` says, and what is left is handed to
    `assert_secret_free` as a refusal's message.

    :param text: lines a command wrote.
    :param secrets: each secret, as text or bytes.
    """
    kept = "\n".join(map(_line_kept, text.split("\n")))
    assert_secret_free(ValueError(kept), secrets)


class Secrets:
    """The secrets a run handled, by kind, as text or bytes."""

    def __init__(self) -> None:
        """Start with none of any kind."""
        self.kinds: dict[str, list[Secret]] = {}

    def add(self, kind: str, *secrets: Secret) -> None:
        """Add secrets of one kind.

        :param kind: what they are.
        :param secrets: their values.
        """
        self.kinds.setdefault(kind, []).extend(secrets)

    def every(self) -> list[Secret]:
        """Return every secret, whatever its kind.

        :returns: the secrets.
        """
        return [s for values in self.kinds.values() for s in values]

    def sentence(self, mnemonic: str) -> None:
        """Add a mnemonic whole, and each of its words.

        :param mnemonic: the sentence.
        """
        self.add("sentence", mnemonic)
        self.add("word", *mnemonic.split())

    def key(self, key: BIP32KeyData) -> None:
        """Add an extended private key: Base58Check, scalar, base64, WIF.

        :param key: an extended private key.
        """
        self.add("xprv", key.b58encode())
        scalar = key.q.to_bytes(32, "big")
        self.add("scalar", scalar)
        self.add("base64", base64.b64encode(scalar).decode())
        self.add("wif", wif_from_prv_key(key.q, "mainnet", compressed=True))

    def seed(self, seed: bytes, paths: list[str]) -> None:
        """Add a seed and every private key the bundle's paths derive from it.

        The master key, each account key, and the first key of each branch.

        :param seed: the BIP32 seed.
        :param paths: the paths of the account keys the bundle holds.
        """
        self.add("seed", seed)
        self.add("base64", base64.b64encode(seed).decode())
        root = BIP32KeyData.from_seed(seed)
        self.key(root)
        for path in paths:
            account = root.derive(path)
            self.key(account)
            for branch in (0, 1):
                self.key(account.derive([branch, 0]))


#: What `identify` writes: the bundle, as JSON, and the summary's lines.
Written = tuple[str, str]


def run(capsys: pytest.CaptureFixture[str], *typed: str) -> tuple[Written, list[str]]:
    """Run `identify` on what the user types; answer its output and paths.

    :param capsys: pytest's capture of the standard streams.
    :param typed: what the user types at the hidden prompts, in order.
    :returns: what it wrote on standard output and on standard error, and
        the path of every account key in its bundle.
    """
    argv = ["identify", "--accounts", "1", "--address", "bc1qx", "--indexes", "1"]
    assert cli.main(argv, prompt=Prompt(*typed), forbid_network=lambda: None) == 0
    out, err = capsys.readouterr()
    paths = sorted({a.path for r in loads(out).readings for a in r.accounts})
    return (out, err), paths


def bip39_case(capsys: pytest.CaptureFixture[str]) -> tuple[Written, Secrets]:
    """BIP39: the mnemonic of BIP84's vector, with "TREZOR" typed.

    :param capsys: pytest's capture of the standard streams.
    :returns: what the command wrote, and the secrets it handled.
    """
    written, paths = run(capsys, ABANDON, TREZOR, "")
    secrets = Secrets()
    secrets.sentence(ABANDON)
    secrets.add("passphrase", TREZOR)
    entropy = int(bip39.entropy_from_mnemonic(ABANDON), 2).to_bytes(16, "big")
    secrets.add("entropy", entropy)
    for passphrase in ("", TREZOR):
        secrets.seed(bip39.seed_from_mnemonic(ABANDON, passphrase), paths)
    return written, secrets


def slip39_case(capsys: pytest.CaptureFixture[str]) -> tuple[Written, Secrets]:
    """SLIP-0039: two shares of vector 4, with "TREZOR" typed.

    :param capsys: pytest's capture of the standard streams.
    :returns: what the command wrote, and the secrets it handled.
    """
    written, paths = run(capsys, SHARES[0], TREZOR, "", SHARES[1])
    secrets = Secrets()
    for share in SHARES:
        secrets.sentence(share)
        secrets.add("entropy", slip39.share_from_mnemonic(share).value)
    secrets.add("passphrase", TREZOR)
    ems = slip39.encrypted_master_secret_from_mnemonics(list(SHARES))
    secrets.add("entropy", ems.value)
    for passphrase in ("", TREZOR):
        secrets.seed(ems.master_secret(passphrase), paths)
    return written, secrets


def electrum_case(capsys: pytest.CaptureFixture[str]) -> tuple[Written, Secrets]:
    """Electrum: SEED_TEST_CASES' `english_with_passphrase`.

    :param capsys: pytest's capture of the standard streams.
    :returns: what the command wrote, and the secrets it handled.
    """
    written, paths = run(capsys, WILD_FATHER, PLAGUEIS, "")
    secrets = Secrets()
    secrets.sentence(WILD_FATHER)
    secrets.add("passphrase", PLAGUEIS)
    entropy = int(electrum.entropy_from_mnemonic(WILD_FATHER), 2)
    secrets.add("entropy", entropy.to_bytes((entropy.bit_length() + 7) // 8, "big"))
    for passphrase in ("", PLAGUEIS):
        secrets.seed(electrum.seed_from_mnemonic(WILD_FATHER, passphrase), paths)
    return written, secrets


CASES = {"bip39": bip39_case, "slip39": slip39_case, "electrum": electrum_case}


@pytest.mark.parametrize("case", CASES)
def test_nothing_identify_writes_holds_a_secret(
    case: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """No piece of any secret is in the bundle or in the summary.

    :param case: the scheme, by name.
    :param capsys: pytest's capture of the standard streams.
    """
    (out, err), secrets = CASES[case](capsys)
    assert '"readings": [\n    {' in out
    assert err.startswith("schemes claiming the words: ")
    assert_json_secret_free(out, secrets.every())
    assert_lines_secret_free(err, secrets.every())


#: Each kind of secret a run handles.
KINDS = [
    "sentence",
    "word",
    "passphrase",
    "entropy",
    "seed",
    "xprv",
    "scalar",
    "base64",
    "wif",
]


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("kind", KINDS)
def test_a_planted_secret_is_found(
    case: str, kind: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Each kind of secret, swapped for an xpub's prefix, is found.

    The prefix is the bundle's, which the JSON search reads. Bytes are
    planted as upper-case hex, the spelling a leak would most likely take
    and the one furthest from what the search is fed.

    :param kind: which secret is planted.
    :param case: the scheme, by name.
    :param capsys: pytest's capture of the standard streams.
    """
    (out, _), secrets = CASES[case](capsys)
    assert sorted(secrets.kinds) == sorted(KINDS)
    secret = secrets.kinds[kind][-1]
    shown = secret if isinstance(secret, str) else secret.hex().upper()
    with pytest.raises(AssertionError):
        assert_json_secret_free(out.replace("xpub", shown, 1), secrets.every())


#: The search of each format, by name.
SEARCHES = {"json": assert_json_secret_free, "lines": assert_lines_secret_free}


@pytest.mark.parametrize(
    "form, text, secret",
    [
        ("json", '{"passphrase": "bitcoin"}', "bitcoin"),
        ("json", '{"coin": "bitcoin", "reason": "ethereum"}', "ethereum"),
        ("json", '{"coin": "ethereum-classic", "passphrase": "class"}', "class"),
        ("json", '{"passphrase": "ethereum-classic"}', "class"),
        ("json", '{"chain": "ethereum-classic", "short": 1}', "short"),
        ("json", '{"reason": "Ethereum Classic"}', "class"),
        ("json", '{"failed: ethereum-classic, try again": 1}', "class"),
        ("json", '{"reason": "failed: ethereum-classic, try again"}', "class"),
        ("json", '{"reason": "failed: bitcoin, try again"}', "bitcoin"),
        ("json", '{"note": "classic", "note": 1}', "class"),
        ("json", '{"note": 12345678901234567890.0}', bytes.fromhex("901234567890")),
        ("lines", "passphrase: bitcoin", "bitcoin"),
        ("lines", "failed: ethereum-classic, try again", "class"),
        ("lines", "total: ethereum-classic, 1 wei of ETC, class", "class"),
        ("lines", "passphrase ethereum-classic", "class"),
        ("lines", '"chain": "ethereum-classic",', "class"),
        ("lines", "node: https://h, Ethereum Classical, chain id 61, block 1", "class"),
        (
            "lines",
            "node: https://class.h, Ethereum Classic, chain id 61, block 1",
            "class",
        ),
        (
            "lines",
            "  bitcoin, purpose 44: not checked: failed: ethereum-classic, try again",
            "class",
        ),
    ],
)
def test_a_defined_word_elsewhere_is_found(
    form: str, text: str, secret: Secret
) -> None:
    """A defined word is dropped where its format writes it, and nowhere else.

    :param form: which search reads the text.
    :param text: what a command wrote.
    :param secret: a word of a mnemonic, a passphrase, or a key's bytes.
    """
    with pytest.raises(AssertionError):
        SEARCHES[form](text, [secret])


@pytest.mark.parametrize(
    "form, text, secret",
    [
        ("json", '{\n  "coin": "ethereum-classic"\n}', "class"),
        ("json", '{\n  "chain": "ethereum-classic",\n  "cut_short": true\n}', "class"),
        ("json", '{"cut_short": true}', "short"),
        ("json", f'{{"reason": "{OTHER_CHAIN}"}}', "class"),
        (
            "json",
            '{"node": "https://node\\".example", "chain": "ethereum-classic"}',
            "class",
        ),
        (
            "lines",
            (
                "total: ethereum-classic, 1 wei of ETC, 1 used accounts, each"
                " account key once"
            ),
            "class",
        ),
        (
            "lines",
            (
                "  ethereum-classic, purpose 44, on Ethereum Classic: accounts 0"
                " to 3 read, 1 used"
            ),
            "class",
        ),
        ("lines", f"Ethereum Classic tokens: not checked: {report.NO_TOKENS}", "class"),
        (
            "lines",
            (
                "total: bitcoin, 10000 sat confirmed, -10000 sat unconfirmed, 1"
                " used accounts, each account key once"
            ),
            "coin",
        ),
        (
            "json",
            '{"reason": "passphrase 1: not one SLIP-0039 accepts"}',
            "SLIP-0039 accepts",
        ),
        (
            "lines",
            "not derived: slip39: passphrase 1: not one SLIP-0039 accepts",
            "SLIP-0039 accepts",
        ),
        (
            "lines",
            'node: https://node".example, Ethereum Classic, chain id 61, block 16',
            "class",
        ),
    ],
)
def test_a_defined_word_where_the_format_writes_it_is_not_a_leak(
    form: str, text: str, secret: str
) -> None:
    """A defined word can hold a word of a mnemonic, and is not searched.

    A name holds SLIP-0039's ``class``, a member name its ``short``, and
    ``bitcoin`` BIP39's ``coin``. A reason is dropped whole.

    :param form: which search reads the text.
    :param text: what a command wrote.
    :param secret: a word of a mnemonic, or a piece of a reason.
    """
    SEARCHES[form](text, [secret])


def test_a_line_of_no_shape_naming_a_defined_word_is_listed() -> None:
    """`unshaped` lists it, and no line of a shape or naming none."""
    lines = [
        "passphrase: bitcoin",
        "seed-scan report 1",
        (
            "total: bitcoin, 1 sat confirmed, -1 sat unconfirmed, 1 used accounts,"
            " each account key once"
        ),
        "for a base58 address",
    ]
    assert unshaped("\n".join(lines)) == ["passphrase: bitcoin"]
