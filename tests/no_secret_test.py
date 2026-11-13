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

import pytest
from bip32_descriptors.bip32 import BIP32KeyData
from bip39_slip39 import bip39, electrum, slip39
from btclib.b58 import wif_from_prv_key

from seed_scan import cli
from seed_scan.bundle import loads

from .identify_test import ABANDON, SHARES, Prompt
from .secret_free import assert_secret_free

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


def assert_text_secret_free(text: str, secrets: list[Secret]) -> None:
    """Assert that no piece of a secret, in any spelling, is in a text.

    The text is handed to `assert_secret_free` as a refusal's message, so
    that one search, the tree's, reads the bundle and the refusals alike.

    :param text: what the command wrote.
    :param secrets: each secret, as text or bytes.
    """
    assert_secret_free(ValueError(text), secrets)


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


def run(capsys: pytest.CaptureFixture[str], *typed: str) -> tuple[str, list[str]]:
    """Run `identify` on what the user types; answer its output and paths.

    :param capsys: pytest's capture of the standard streams.
    :param typed: what the user types at the hidden prompts, in order.
    :returns: what it wrote on both streams, and the path of every
        account key in its bundle.
    """
    argv = ["identify", "--accounts", "1", "--address", "bc1qx", "--indexes", "1"]
    assert cli.main(argv, prompt=Prompt(*typed), forbid_network=lambda: None) == 0
    out, err = capsys.readouterr()
    paths = sorted({a.path for r in loads(out).readings for a in r.accounts})
    return out + err, paths


def bip39_case(capsys: pytest.CaptureFixture[str]) -> tuple[str, Secrets]:
    """BIP39: the mnemonic of BIP84's vector, with "TREZOR" typed.

    :param capsys: pytest's capture of the standard streams.
    :returns: what the command wrote, and the secrets it handled.
    """
    text, paths = run(capsys, ABANDON, TREZOR, "")
    secrets = Secrets()
    secrets.sentence(ABANDON)
    secrets.add("passphrase", TREZOR)
    entropy = int(bip39.entropy_from_mnemonic(ABANDON), 2).to_bytes(16, "big")
    secrets.add("entropy", entropy)
    for passphrase in ("", TREZOR):
        secrets.seed(bip39.seed_from_mnemonic(ABANDON, passphrase), paths)
    return text, secrets


def slip39_case(capsys: pytest.CaptureFixture[str]) -> tuple[str, Secrets]:
    """SLIP-0039: two shares of vector 4, with "TREZOR" typed.

    :param capsys: pytest's capture of the standard streams.
    :returns: what the command wrote, and the secrets it handled.
    """
    text, paths = run(capsys, SHARES[0], TREZOR, "", SHARES[1])
    secrets = Secrets()
    for share in SHARES:
        secrets.sentence(share)
        secrets.add("entropy", slip39.share_from_mnemonic(share).value)
    secrets.add("passphrase", TREZOR)
    ems = slip39.encrypted_master_secret_from_mnemonics(list(SHARES))
    secrets.add("entropy", ems.value)
    for passphrase in ("", TREZOR):
        secrets.seed(ems.master_secret(passphrase), paths)
    return text, secrets


def electrum_case(capsys: pytest.CaptureFixture[str]) -> tuple[str, Secrets]:
    """Electrum: SEED_TEST_CASES' `english_with_passphrase`.

    :param capsys: pytest's capture of the standard streams.
    :returns: what the command wrote, and the secrets it handled.
    """
    text, paths = run(capsys, WILD_FATHER, PLAGUEIS, "")
    secrets = Secrets()
    secrets.sentence(WILD_FATHER)
    secrets.add("passphrase", PLAGUEIS)
    entropy = int(electrum.entropy_from_mnemonic(WILD_FATHER), 2)
    secrets.add("entropy", entropy.to_bytes((entropy.bit_length() + 7) // 8, "big"))
    for passphrase in ("", PLAGUEIS):
        secrets.seed(electrum.seed_from_mnemonic(WILD_FATHER, passphrase), paths)
    return text, secrets


CASES = {"bip39": bip39_case, "slip39": slip39_case, "electrum": electrum_case}


@pytest.mark.parametrize("case", CASES)
def test_nothing_identify_writes_holds_a_secret(
    case: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """No piece of any secret is in the bundle or in the summary.

    :param case: the scheme, by name.
    :param capsys: pytest's capture of the standard streams.
    """
    text, secrets = CASES[case](capsys)
    assert '"readings": [\n    {' in text
    assert_text_secret_free(text, secrets.every())


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

    Bytes are planted as upper-case hex, the spelling a leak would most
    likely take and the one furthest from what the search is fed.

    :param kind: which secret is planted.
    :param case: the scheme, by name.
    :param capsys: pytest's capture of the standard streams.
    """
    text, secrets = CASES[case](capsys)
    assert sorted(secrets.kinds) == sorted(KINDS)
    secret = secrets.kinds[kind][-1]
    shown = secret if isinstance(secret, str) else secret.hex().upper()
    with pytest.raises(AssertionError):
        assert_text_secret_free(text.replace("xpub", shown, 1), secrets.every())
