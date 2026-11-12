# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `seed_scan.bundle`: the format written and read back."""

from __future__ import annotations

import json
from typing import Any

import pytest
from bip32_descriptors.bip32 import BIP32KeyData
from bip39_slip39 import electrum
from bip39_slip39.mnemonic import BIP39_LANGUAGE_FILES
from btclib.b58 import wif_from_prv_key
from btclib_wallet.descriptors import add_checksum

from seed_scan.bundle import (
    CLAIMS,
    FORMAT,
    LANGUAGES,
    REASONS,
    VERSION,
    Account,
    Bundle,
    Match,
    NotChecked,
    Reading,
    Search,
    dumps,
    loads,
    slip39_passphrase,
)
from seed_scan.exceptions import SeedScanTypeError, SeedScanValueError

from .identify_test import BIP84_CHANGE, BIP86_XPUB, SHARES_XPRV
from .secret_free import assert_secret_free

#: The receive and change descriptors of BIP86's account 0 key, at the
#: path an Electrum "segwit" key is written at: their shape is checked,
#: not what they derive.
DESCRIPTORS = tuple(
    add_checksum(f"wpkh([0a1b2c3d/0h]{BIP86_XPUB}/{branch}/*)") for branch in (0, 1)
)

BUNDLE = Bundle(
    claims=("electrum_segwit", "bip39_wordlist"),
    readings=(
        Reading(
            "electrum_segwit",
            (),
            0,
            "0a1b2c3d",
            (Account("bitcoin", 0, None, 0, "m/0h", BIP86_XPUB, DESCRIPTORS),),
        ),
        Reading(
            "bip39",
            ("en",),
            1,
            "0a1b2c3e",
            (Account("ethereum", 60, 44, 3, "m/44h/60h/3h", BIP86_XPUB, ()),),
        ),
    ),
    not_checked=(NotChecked("bip39_wordlist", REASONS["bip39_wordlist"]),),
    search=Search(BIP84_CHANGE, True, "", 5, 20, 400, (Match(0, "m/0h/0/3"),)),
)


def document() -> dict[str, Any]:
    """Return the bundle above as the JSON object it is written as.

    :returns: a fresh object each call, to be edited.
    """
    return json.loads(dumps(BUNDLE))  # type: ignore[no-any-return]


def test_a_bundle_reads_back_as_written() -> None:
    """`loads` answers what `dumps` was given, its search absent or not."""
    assert loads(dumps(BUNDLE)) == BUNDLE
    unsearched = Bundle(BUNDLE.claims, (), (), None)
    assert loads(dumps(unsearched)) == unsearched


def test_the_format_and_version_lead() -> None:
    """The two members a reader checks first are the first two written."""
    keys = list(document())
    assert keys[:2] == ["format", "version"]
    assert document()["format"] == FORMAT == "seed-scan-bundle"
    assert document()["version"] == VERSION == 1


def test_a_member_this_version_does_not_name_is_ignored() -> None:
    """An extra member reads back as the bundle without it."""
    extra = document()
    extra["comment"] = "public"
    assert loads(json.dumps(extra)) == BUNDLE


#: A made-up key, in the two spellings a file handed in by mistake holds:
#: an xprv-shaped Base58 text and a 78-digit scalar.
KEY_TEXT = "xprvMadeUpKeyTextHeldByNoWalletQwErTyUiOpAsDfGhJkLzXcVbNm"
KEY_NUMBER = 0x1D2F3E4D5C6B7A8998A7B6C5D4E3F20112233445566778899AABBCCDDEEFF0A1


def set_match_reading(d: dict[str, Any], reading: int) -> None:
    """Point the first match at a reading.

    :param d: the document.
    :param reading: the reading's position.
    """
    d["search"]["matches"][0]["reading"] = reading


@pytest.mark.parametrize(
    "edit, error, match",
    [
        (lambda d: d.update(format=KEY_TEXT), SeedScanValueError, "format is not"),
        (
            lambda d: d.update(version=KEY_NUMBER),
            SeedScanValueError,
            "version is not 1",
        ),
        (lambda d: d.pop("claims"), SeedScanValueError, "missing member 'claims'"),
        (lambda d: d.update(version="1"), SeedScanTypeError, "'version' of type str"),
        (lambda d: d.update(version=True), SeedScanTypeError, "of type bool"),
        (
            lambda d: d.update(claims=[KEY_NUMBER]),
            SeedScanTypeError,
            "item of 'claims'",
        ),
        (
            lambda d: d.update(readings=[KEY_TEXT]),
            SeedScanTypeError,
            "item of 'readings'",
        ),
        (lambda d: d.update(search=[]), SeedScanTypeError, "'search' of type list"),
        (
            lambda d: d["readings"][0]["accounts"][0].update(purpose=KEY_TEXT),
            SeedScanTypeError,
            "'purpose' of type str",
        ),
        (
            lambda d: d["readings"][0]["accounts"][0].update(purpose=-KEY_NUMBER),
            SeedScanValueError,
            "'purpose' is negative",
        ),
        (
            lambda d: d["readings"][0].update(passphrase=-KEY_NUMBER),
            SeedScanValueError,
            "'passphrase' is negative",
        ),
        (
            lambda d: d["readings"][0].update(master_fingerprint=KEY_TEXT),
            SeedScanValueError,
            "'master_fingerprint' is not 8 hex characters",
        ),
        (
            lambda d: d["readings"][0].update(master_fingerprint="0A1B2C3D"),
            SeedScanValueError,
            "'master_fingerprint' is not 8 hex characters",
        ),
        (
            lambda d: d["search"].update(checked=1),
            SeedScanTypeError,
            "'checked' of type int",
        ),
        (
            lambda d: d["search"].update(indexes=-KEY_NUMBER),
            SeedScanValueError,
            "'indexes' is negative",
        ),
        (
            lambda d: set_match_reading(d, KEY_NUMBER),
            SeedScanValueError,
            "a match names no reading",
        ),
    ],
)
def test_a_document_that_is_no_bundle_is_refused(
    edit: Any, error: type[Exception], match: str
) -> None:
    """Each member is checked, its type and its value, and never quoted.

    The value refused is a key in each case it can be, and the refusal
    holds no piece of it, in any spelling the tree checks for.

    :param edit: what is changed in a valid document.
    :param error: the refusal's class.
    :param match: what the refusal says.
    """
    changed = document()
    edit(changed)
    with pytest.raises(error, match=match) as caught:
        loads(json.dumps(changed))
    assert_secret_free(caught.value, [KEY_TEXT, str(KEY_NUMBER), f"{KEY_NUMBER:x}"])


@pytest.mark.parametrize(
    "text, error, match",
    [
        ('{"key": "' + KEY_TEXT + '", ', SeedScanValueError, "not JSON, at line 1"),
        ("[" + str(KEY_NUMBER) + "]", SeedScanTypeError, "a JSON list"),
        (KEY_TEXT.encode(), SeedScanTypeError, "text of type bytes"),
    ],
)
def test_text_that_is_no_bundle_is_refused(
    text: Any, error: type[Exception], match: str
) -> None:
    """Text that is not a JSON object is refused, its content not quoted.

    The JSON decoding error holds the whole text, so the refusal is raised
    outside its `except` and does not chain it.

    :param text: what is read.
    :param error: the refusal's class.
    :param match: what the refusal says.
    """
    with pytest.raises(error, match=match) as caught:
        loads(text)
    assert_secret_free(caught.value, [KEY_TEXT, str(KEY_NUMBER)])


#: The secrets planted in a member: a published xprv, the WIF of the made-up
#: scalar above, and that scalar in hex.
PLANTED = [
    SHARES_XPRV,
    wif_from_prv_key(KEY_NUMBER, "mainnet", compressed=True),
    f"{KEY_NUMBER:064x}",
]


def at(path: tuple[Any, ...]) -> Any:
    """Return an edit that puts a value at a path of the document.

    :param path: the keys and indexes leading to the member.
    :returns: the edit, taking the document and the value.
    """

    def edit(d: dict[str, Any], value: Any) -> None:
        for step in path[:-1]:
            d = d[step]
        d[path[-1]] = value

    return edit


#: Each text member a reader may echo, by where it sits.
MEMBERS = {
    "bitcoin xpub": (("readings", 0, "accounts", 0, "xpub"), "'xpub'"),
    "ethereum xpub": (("readings", 1, "accounts", 0, "xpub"), "'xpub'"),
    "path": (("readings", 1, "accounts", 0, "path"), "'path'"),
    "coin": (("readings", 1, "accounts", 0, "coin"), "'coin'"),
    "bitcoin descriptor": (
        ("readings", 0, "accounts", 0, "descriptors", 0),
        "'descriptors'",
    ),
    "ethereum descriptors": (
        ("readings", 1, "accounts", 0, "descriptors"),
        "'descriptors'",
    ),
    "scheme": (("readings", 0, "scheme"), "'scheme'"),
    "language": (("readings", 1, "languages", 0), "'languages'"),
    "claim": (("claims", 0), "'claims'"),
    "not checked scheme": (("not_checked", 0, "scheme"), "'scheme'"),
    "not checked reason": (("not_checked", 0, "reason"), "'reason'"),
    "address": (("search", "address"), "'address'"),
    "search reason": (("search", "reason"), "'reason'"),
    "match path": (("search", "matches", 0, "path"), "'path'"),
}


@pytest.mark.parametrize("secret", PLANTED)
@pytest.mark.parametrize("member", MEMBERS)
def test_a_secret_in_a_text_member_is_refused_unquoted(
    member: str, secret: str
) -> None:
    """Each text member takes only what the format defines, so no key passes.

    A reader such as `scan` echoes these members, so what `loads` accepts
    in them is what reaches its output. The refusal names the member and
    holds no piece of the secret.

    :param member: where the secret is planted, by name.
    :param secret: an xprv, a WIF or a hex scalar.
    """
    path, named = MEMBERS[member]
    changed = document()
    value: Any = [secret] if member == "ethereum descriptors" else secret
    if member == "bitcoin descriptor":
        value = changed["readings"][0]["accounts"][0]["descriptors"][0].replace(
            BIP86_XPUB, secret
        )
    at(path)(changed, value)
    with pytest.raises(SeedScanValueError, match=named) as caught:
        loads(json.dumps(changed))
    assert_secret_free(caught.value, PLANTED)


def relabelled(key: str, version: str) -> str:
    """Return an extended key with other version bytes, nothing checked.

    :param key: the extended key.
    :param version: the version bytes, in hex.
    :returns: the same depth, index, chain code and key under that version.
    """
    data = BIP32KeyData.b58decode(key, check_validity=False)
    forged = BIP32KeyData(
        bytes.fromhex(version),
        data.depth,
        data.parent_fingerprint,
        data.index,
        data.chain_code,
        data.key,
        check_validity=False,
    )
    return forged.b58encode(check_validity=False)


#: BIP32's testnet public version, and SLIP-0132's mainnet p2wpkh one.
OTHER_PUBLIC_VERSIONS = {"tpub": "043587cf", "zpub": "04b24746"}


@pytest.mark.parametrize("prefix", OTHER_PUBLIC_VERSIONS)
def test_a_public_key_of_another_version_is_refused(prefix: str) -> None:
    """A tpub or a zpub of the same key is refused: the bundle writes xpubs.

    :param prefix: the version, by the prefix its keys are written with.
    """
    other = relabelled(BIP86_XPUB, OTHER_PUBLIC_VERSIONS[prefix])
    assert other.startswith(prefix)
    changed = document()
    at(MEMBERS["ethereum xpub"][0])(changed, other)
    with pytest.raises(SeedScanValueError, match="'xpub' is not an extended public"):
        loads(json.dumps(changed))


def test_the_languages_are_bip39_slip39s() -> None:
    """`LANGUAGES` is bip39-slip39's BIP39 word-lists, so none is refused.

    A release that adds a word-list fails here, rather than `identify`
    writing a bundle `loads` refuses.
    """
    assert set(LANGUAGES) == set(BIP39_LANGUAGE_FILES)


def test_the_claims_are_those_dispatch_can_answer() -> None:
    """`CLAIMS` is every name `dispatch.all_seed_types_from_mnemonic` answers.

    Its module docstring lists them: SLIP-0039, Electrum's pre-2.0 seed
    and its versions, and BIP39's two. The Electrum versions are read from
    `electrum`'s table, which no public name exposes, so that a version
    added there fails here.
    """
    versions = {"old", *electrum._MNEMONIC_VERSIONS}
    expected = {"slip39", "bip39", "bip39_wordlist"}
    expected |= {f"electrum_{version}" for version in versions}
    assert set(CLAIMS) == expected


@pytest.mark.parametrize(
    "address",
    [
        # BIP350's invalid vectors: a version 1 program under a BIP173
        # checksum, and a version 0 one under a BIP350 checksum
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
    ],
)
def test_a_checksum_of_the_other_witness_version_is_refused(address: str) -> None:
    """Version 0 takes BIP173's checksum, every later version BIP350's.

    :param address: an address whose checksum is the other version's.
    """
    changed = document()
    changed["search"]["address"] = address
    with pytest.raises(SeedScanValueError, match="'address' is not an address"):
        loads(json.dumps(changed))


def test_an_xprv_relabelled_as_an_xpub_is_refused() -> None:
    """An xprv given an xpub's version bytes is refused by its key's prefix."""
    forged = relabelled(SHARES_XPRV, "0488b21e")
    changed = document()
    at(MEMBERS["ethereum xpub"][0])(changed, forged)
    with pytest.raises(SeedScanValueError, match="'xpub' is not an extended public"):
        loads(json.dumps(changed))


@pytest.mark.parametrize(
    "address",
    [
        "1NNkttn1YvVGdqBW4PR6zvc3Zx3H5owKRf",
        "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2",
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
        "BC1Q8C6FSHW2DLWUN7EKN9QWF37CU2RN755UPCP6EL",
        "",
    ],
)
def test_an_address_of_each_kind_reads_back(address: str) -> None:
    """A base58 and a segwit address, upper case included, and none, are read.

    :param address: the address searched.
    """
    changed = document()
    changed["search"]["address"] = address
    assert loads(json.dumps(changed)).search.address == address  # type: ignore[union-attr]


@pytest.mark.parametrize(
    "address",
    [
        "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6eL",
        "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6em",
        "xx1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el",
        "bc1qqqqqqqqq",
        "bc1qbqqqqqqqqq",
        "1NNkttn1YvVGdqBW4PR6zvc3Zx3H5owKRg",
        "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
    ],
)
def test_a_text_that_is_no_address_is_refused(address: str) -> None:
    """Mixed case, a bad checksum, another prefix, a short program, no base58.

    :param address: the text in the `address` member.
    """
    changed = document()
    changed["search"]["address"] = address
    with pytest.raises(SeedScanValueError, match="'address' is not an address"):
        loads(json.dumps(changed))


def test_a_slip39_passphrase_reason_reads_back() -> None:
    """The one reason with a number in it is read back."""
    changed = document()
    changed["not_checked"][0]["reason"] = slip39_passphrase(3)
    assert loads(json.dumps(changed)).not_checked[0].reason == slip39_passphrase(3)


@pytest.mark.parametrize("path", ["m/2147483648", "m/0h/2147483648h", "m/01", "M/0"])
def test_a_path_past_an_index_is_refused(path: str) -> None:
    """An index of 2^31 or more, a leading zero, or another root is refused.

    :param path: the text in an account's `path` member.
    """
    changed = document()
    at(MEMBERS["path"][0])(changed, path)
    with pytest.raises(SeedScanValueError, match="'path' is not a derivation path"):
        loads(json.dumps(changed))
