# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `seed_scan.bundle`: the format written and read back."""

from __future__ import annotations

import json
from typing import Any

import pytest

from seed_scan.bundle import (
    FORMAT,
    VERSION,
    Account,
    Bundle,
    Match,
    NotChecked,
    Reading,
    Search,
    dumps,
    loads,
)
from seed_scan.exceptions import SeedScanTypeError, SeedScanValueError

from .secret_free import assert_secret_free

BUNDLE = Bundle(
    claims=("electrum_segwit", "bip39_wordlist"),
    readings=(
        Reading(
            "electrum_segwit",
            (),
            0,
            "0a1b2c3d",
            (Account("bitcoin", 0, None, 0, "m/0h", "xpub", ("wpkh()", "wpkh()")),),
        ),
        Reading(
            "bip39",
            ("en",),
            1,
            "0a1b2c3e",
            (Account("ethereum", 60, 44, 3, "m/44h/60h/3h", "xpub", ()),),
        ),
    ),
    not_checked=(NotChecked("bip39_wordlist", "the checksum fails"),),
    search=Search("bc1q", True, "", 5, 20, 400, (Match(0, "m/0h/0/3"),)),
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
