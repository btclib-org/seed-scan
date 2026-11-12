# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The public bundle: what `identify` writes and the later commands read.

A bundle is one JSON object. `dumps` writes it and `loads` reads it
back, so a command that reads a bundle imports this module and never
`seed_scan.identify`. It holds no secret: no mnemonic, passphrase,
seed, entropy or private key, in any encoding. It is still not harmless,
README.md's *What touches the secret* says why.

The object's members:

- ``format``: the string ``"seed-scan-bundle"``.
- ``version``: the integer `VERSION`. A reader refuses any other value:
  a change of meaning takes a new version, never a reuse of the old one.
- ``claims``: the schemes that claim the words, best first, as
  `bip39_slip39.dispatch.all_seed_types_from_mnemonic` names them:
  ``"slip39"``, ``"electrum_old"``, ``"electrum_standard"``,
  ``"electrum_segwit"``, ``"electrum_2fa"``, ``"electrum_2fa_segwit"``,
  ``"bip39"`` and ``"bip39_wordlist"``. Empty where no scheme claims them.
- ``readings``: one object per scheme and passphrase that gave a seed:

  - ``scheme``: ``"bip39"``, ``"slip39"``, ``"electrum_standard"`` or
    ``"electrum_segwit"``. For Electrum, the single-signature wallet
    alone: the multisig layouts a versioned seed can also be a cosigner
    of are not derived;
  - ``languages``: for ``"bip39"``, the word-lists in which the words
    are a valid mnemonic; empty for the other schemes;
  - ``passphrase``: which passphrase gave the seed, never the passphrase
    itself: ``0`` is the empty one, ``n`` the n-th typed at the prompt;
  - ``master_fingerprint``: the BIP32 master key's fingerprint, as 8 hex
    characters;
  - ``accounts``: one object per account key.

- ``not_checked``: one object per scheme the words claim and no reading
  covers, with ``scheme`` and ``reason``. A user acts on "nothing found",
  so what was not searched is said, never passed over.
- ``search``: ``null``, or the search for an address the user knows:
  ``address``, empty where the text given is no Bitcoin address, so that
  a key typed by mistake is not written; ``checked``, false where the
  search did not run, and then ``reason`` says why; ``accounts`` and
  ``indexes``, the bound (accounts ``0`` to ``accounts - 1`` of each
  Bitcoin purpose and the one account of an Electrum reading, receive
  and change branches, indexes ``0`` to ``indexes - 1``); ``searched``,
  how many positions were compared; and ``matches``, each the position
  of a reading in ``readings`` and the full derivation path of the
  address.

An account object holds:

- ``coin``: ``"bitcoin"``, ``"ethereum"``, ``"bitcoin-cash"``,
  ``"litecoin"`` or ``"dogecoin"``;
- ``coin_type``: its SLIP-0044 number, from ``0``;
- ``purpose``: the BIP43 purpose, or ``null`` for Electrum's layouts,
  which have none;
- ``account``: the account number, from ``0``;
- ``path``: the derivation path of the key, hardened levels written
  with ``h``;
- ``xpub``: the extended public key at ``path``, in BIP32's mainnet
  version whatever the coin, so that each reader decodes one spelling;
- ``descriptors``: for Bitcoin, the receive and change output
  descriptors, checksum included, as Bitcoin Core imports them; empty
  for the other coins, whose addresses `scan` derives from ``xpub``.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from hashlib import sha256
from typing import Any

from seed_scan.exceptions import SeedScanTypeError, SeedScanValueError

__all__ = [
    "CLAIMS",
    "COIN_NAMES",
    "FORMAT",
    "LANGUAGES",
    "READ_SCHEMES",
    "REASONS",
    "VERSION",
    "Account",
    "Bundle",
    "Match",
    "NotChecked",
    "Reading",
    "Search",
    "dumps",
    "loads",
    "slip39_passphrase",
]

#: The value of the ``format`` member.
FORMAT = "seed-scan-bundle"

#: The value of the ``version`` member this module writes and reads.
VERSION = 1

#: The schemes a claim, or a scheme not checked, names.
CLAIMS = (
    "slip39",
    "electrum_old",
    "electrum_standard",
    "electrum_segwit",
    "electrum_2fa",
    "electrum_2fa_segwit",
    "bip39",
    "bip39_wordlist",
)

#: The schemes a reading names.
READ_SCHEMES = ("bip39", "slip39", "electrum_standard", "electrum_segwit")

#: The BIP39 word-lists a reading names, as bip39-slip39 names them.
LANGUAGES = ("cs", "en", "es", "fr", "it", "ja", "ko", "pt", "ru", "tr", "zh", "zh_tw")

#: The coins an account names.
COIN_NAMES = ("bitcoin", "ethereum", "bitcoin-cash", "litecoin", "dogecoin")

#: Each reason a scheme is not checked, or an address not searched, by
#: name. A passphrase SLIP-0039 refuses is the one reason with a number
#: in it, `slip39_passphrase` below.
REASONS = {
    "electrum_old": "pre-2.0 Electrum seed: no dependency derives its addresses",
    "electrum_2fa": "Electrum two-factor seed: its third key is TrustedCoin's",
    "bip39_wordlist": (
        "every word is in a BIP39 word-list, and the checksum or the word count fails"
    ),
    "incomplete_set": "the shares typed do not complete a set",
    "not_mainnet": "not a mainnet address: only Bitcoin mainnet ones are searched",
    "not_an_address": (
        "not a Bitcoin address: neither searched nor written, in case it is a key"
    ),
}
_SLIP39_PASSPHRASE = re.compile(
    r"passphrase (?:0|[1-9][0-9]{0,8}): not one SLIP-0039 accepts"
)

# a path as identify writes it: `m`, then indexes, hardened ones with `h`
_PATH = re.compile(r"m(?:/(?:0|[1-9][0-9]{0,9})h?)*")
_INDEX = re.compile(r"[0-9]+")
_HARDENED = 0x80000000

# the version bytes of a BIP32 mainnet extended public key, the one
# spelling the bundle writes
_XPUB_VERSION = bytes.fromhex("0488b21e")
_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
# the version bytes of a base58 address: p2pkh and p2sh, mainnet and test
_ADDRESS_VERSIONS = (0x00, 0x05, 0x6F, 0xC4)
_BECH32_HRPS = ("bc", "tb", "bcrt")
_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
# BIP173's checksum constant, which a version 0 program takes, and
# BIP350's, which every later version takes
_BECH32_CONSTANT = 1
_BECH32M_CONSTANT = 0x2BC830A3
# a descriptor's checksum, eight characters of its own alphabet
_CHECKSUM = "#[" + _BECH32 + "]{8}"


def slip39_passphrase(number: int) -> str:
    """Return the reason a passphrase SLIP-0039 refuses is not checked.

    :param number: the passphrase's number, never the passphrase.
    :returns: the reason.
    """
    return f"passphrase {number}: not one SLIP-0039 accepts"


@dataclass(frozen=True)
class Account:
    """One account key of a reading: the module docstring's account object."""

    coin: str
    coin_type: int
    purpose: int | None
    account: int
    path: str
    xpub: str
    descriptors: tuple[str, ...]


@dataclass(frozen=True)
class Reading:
    """One scheme and passphrase that gave a seed, and its account keys."""

    scheme: str
    languages: tuple[str, ...]
    passphrase: int
    master_fingerprint: str
    accounts: tuple[Account, ...]


@dataclass(frozen=True)
class NotChecked:
    """A scheme the words claim and no reading covers, and why."""

    scheme: str
    reason: str


@dataclass(frozen=True)
class Match:
    """Which reading, at which path, gives the address searched."""

    reading: int
    path: str


@dataclass(frozen=True)
class Search:
    """The search for an address the user knows, and its bound."""

    address: str
    checked: bool
    reason: str
    accounts: int
    indexes: int
    searched: int
    matches: tuple[Match, ...]


@dataclass(frozen=True)
class Bundle:
    """What `identify` found: the module docstring's top-level object."""

    claims: tuple[str, ...]
    readings: tuple[Reading, ...]
    not_checked: tuple[NotChecked, ...]
    search: Search | None


def dumps(bundle: Bundle) -> str:
    """Return the JSON text of a bundle, members in a fixed order."""
    document = {"format": FORMAT, "version": VERSION, **asdict(bundle)}
    return json.dumps(document, indent=2) + "\n"


def _member(document: dict[str, Any], key: str, kind: type | tuple[type, ...]) -> Any:
    """Return one member of an object, refusing it missing or of a wrong type.

    `bool` is an `int` to `isinstance`, so it is refused where an integer
    is asked for.
    """
    if key not in document:
        raise SeedScanValueError(f"bundle: missing member {key!r}")
    value = document[key]
    wrong_bool = isinstance(value, bool) and bool not in (
        kind if isinstance(kind, tuple) else (kind,)
    )
    if wrong_bool or not isinstance(value, kind):
        err_msg = f"bundle: member {key!r} of type {type(value).__name__}"
        raise SeedScanTypeError(err_msg)
    return value


def _count(document: dict[str, Any], key: str) -> int:
    """Return a member that is an integer from 0, refusing a negative one.

    The value is not quoted, for `loads`'s reason.
    """
    value: int = _member(document, key, int)
    if value < 0:
        raise SeedScanValueError(f"bundle: member {key!r} is negative")
    return value


def _fingerprint(document: dict[str, Any]) -> str:
    """Return the master fingerprint, 8 lower-case hex characters."""
    value: str = _member(document, "master_fingerprint", str)
    if len(value) != 8 or set(value) - set("0123456789abcdef"):
        err_msg = "bundle: member 'master_fingerprint' is not 8 hex characters"
        raise SeedScanValueError(err_msg)
    return value


def _one_of(document: dict[str, Any], key: str, allowed: tuple[str, ...]) -> str:
    """Return a member that is one of the texts the format defines."""
    value: str = _member(document, key, str)
    if value not in allowed:
        raise SeedScanValueError(
            f"bundle: member {key!r} is not one the format defines"
        )
    return value


def _path(document: dict[str, Any], key: str) -> str:
    """Return a derivation path as identify writes it, refusing another text.

    Each index is below 2^31, so that no level holds more than an index.
    """
    value: str = _member(document, key, str)
    indexes = _INDEX.findall(value)
    if not _PATH.fullmatch(value) or any(int(i) >= _HARDENED for i in indexes):
        raise SeedScanValueError(f"bundle: member {key!r} is not a derivation path")
    return value


def _base58check(text: str) -> bytes | None:
    """Return the payload of a Base58Check text, `None` where it is none."""
    if not text or len(text) > 112 or set(text) - set(_BASE58):
        return None
    number = 0
    for char in text:
        number = number * 58 + _BASE58.index(char)
    zeros = len(text) - len(text.lstrip("1"))
    raw = bytes(zeros) + number.to_bytes((number.bit_length() + 7) // 8, "big")
    payload, checksum = raw[:-4], raw[-4:]
    if len(raw) < 5 or sha256(sha256(payload).digest()).digest()[:4] != checksum:
        return None
    return payload


def _xpub(document: dict[str, Any]) -> str:
    """Return a BIP32 mainnet extended public key, refusing any other text.

    The version bytes, the length, the checksum and the prefix of the key
    are checked: an extended private key, or anything else, is refused.
    """
    value: str = _member(document, "xpub", str)
    payload = _base58check(value)
    public = (
        payload is not None
        and len(payload) == 78
        and payload[:4] == _XPUB_VERSION
        and payload[45] in (2, 3)
    )
    if not public:
        raise SeedScanValueError("bundle: member 'xpub' is not an extended public key")
    return value


def _bech32_polymod(values: list[int]) -> int:
    """Return BIP173's checksum polynomial over the values."""
    generator = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    check = 1
    for value in values:
        top = check >> 25
        check = (check & 0x1FFFFFF) << 5 ^ value
        for i, g in enumerate(generator):
            check ^= g if top >> i & 1 else 0
    return check


def _is_segwit_address(text: str) -> bool:
    """Return whether a text is a BIP173 or BIP350 address of a known chain."""
    lower = text.lower()
    hrp, _, data = lower.rpartition("1")
    if text not in (lower, text.upper()) or hrp not in _BECH32_HRPS:
        return False
    if len(text) > 90 or len(data) < 8 or set(data) - set(_BECH32):
        return False
    values = [_BECH32.index(c) for c in data]
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    version = values[0]
    constant = _BECH32_CONSTANT if version == 0 else _BECH32M_CONSTANT
    if _bech32_polymod(expanded + values) != constant:
        return False
    program_bits = 5 * (len(values) - 7)
    return version <= 16 and 2 * 8 <= program_bits <= 40 * 8 + 4


def _address(document: dict[str, Any]) -> str:
    """Return an address, or the empty text, refusing any other text."""
    value: str = _member(document, "address", str)
    payload = _base58check(value)
    base58 = payload is not None and len(payload) == 21
    if (
        value
        and not _is_segwit_address(value)
        and not (
            base58 and payload[0] in _ADDRESS_VERSIONS  # type: ignore[index]
        )
    ):
        raise SeedScanValueError("bundle: member 'address' is not an address")
    return value


def _reason(document: dict[str, Any]) -> str:
    """Return a reason the format defines, refusing any other text."""
    value: str = _member(document, "reason", str)
    if (
        value
        and value not in REASONS.values()
        and not _SLIP39_PASSPHRASE.fullmatch(value)
    ):
        raise SeedScanValueError(
            "bundle: member 'reason' is not one the format defines"
        )
    return value


def _descriptors(document: dict[str, Any], coin: str, xpub: str) -> tuple[str, ...]:
    """Return an account's descriptors, refusing any not of the account's key.

    A Bitcoin account holds its receive and change descriptors over its
    own `xpub`, with a key origin and a checksum, and no other coin holds
    any.
    """
    values = _strings(document, "descriptors")
    key = r"\[[0-9a-f]{8}(?:/(?:0|[1-9][0-9]{0,9})h?)*\]" + re.escape(xpub)

    def shape(branch: int) -> str:
        inner = rf"{key}/{branch}/\*"
        return rf"(?:(?:pkh|wpkh|tr)\({inner}\)|sh\(wpkh\({inner}\)\)){_CHECKSUM}"

    expected = 2 if coin == "bitcoin" else 0
    fits = len(values) == expected and all(
        re.fullmatch(shape(branch), value) for branch, value in enumerate(values)
    )
    if not fits:
        err_msg = "bundle: member 'descriptors' is not the account's two descriptors"
        raise SeedScanValueError(err_msg)
    return values


def _objects(document: dict[str, Any], key: str) -> list[dict[str, Any]]:
    """Return a member that is a list of objects."""
    values: list[object] = _member(document, key, list)
    objects: list[dict[str, Any]] = []
    for value in values:
        if not isinstance(value, dict):
            err_msg = f"bundle: an item of {key!r} of type {type(value).__name__}"
            raise SeedScanTypeError(err_msg)
        objects.append(value)
    return objects


def _strings(
    document: dict[str, Any], key: str, allowed: tuple[str, ...] | None = None
) -> tuple[str, ...]:
    """Return a member that is a list of strings, each `allowed` where given."""
    values = _member(document, key, list)
    for value in values:
        if not isinstance(value, str):
            err_msg = f"bundle: an item of {key!r} of type {type(value).__name__}"
            raise SeedScanTypeError(err_msg)
        if allowed is not None and value not in allowed:
            err_msg = f"bundle: an item of {key!r} is not one the format defines"
            raise SeedScanValueError(err_msg)
    return tuple(values)


def _account(document: dict[str, Any]) -> Account:
    """Read one account object."""
    purpose = _member(document, "purpose", (int, type(None)))
    coin = _one_of(document, "coin", COIN_NAMES)
    xpub = _xpub(document)
    return Account(
        coin=coin,
        coin_type=_count(document, "coin_type"),
        purpose=None if purpose is None else _count(document, "purpose"),
        account=_count(document, "account"),
        path=_path(document, "path"),
        xpub=xpub,
        descriptors=_descriptors(document, coin, xpub),
    )


def _reading(document: dict[str, Any]) -> Reading:
    """Read one reading object."""
    return Reading(
        scheme=_one_of(document, "scheme", READ_SCHEMES),
        languages=_strings(document, "languages", LANGUAGES),
        passphrase=_count(document, "passphrase"),
        master_fingerprint=_fingerprint(document),
        accounts=tuple(_account(a) for a in _objects(document, "accounts")),
    )


def _search(document: dict[str, Any], readings: int) -> Search:
    """Read the search object; a match names one of `readings` readings."""
    matches = []
    for match in _objects(document, "matches"):
        reading = _count(match, "reading")
        if reading >= readings:
            raise SeedScanValueError("bundle: a match names no reading")
        matches.append(Match(reading, _path(match, "path")))
    return Search(
        address=_address(document),
        checked=_member(document, "checked", bool),
        reason=_reason(document),
        accounts=_count(document, "accounts"),
        indexes=_count(document, "indexes"),
        searched=_count(document, "searched"),
        matches=tuple(matches),
    )


def loads(text: str) -> Bundle:
    """Read a bundle back from its JSON text.

    Refused, as a `SeedScanValueError`: text that is not JSON, another
    ``format``, another ``version``, a missing member, a negative count,
    a fingerprint that is not 8 lower-case hex characters, or a match
    naming no reading. A member of the wrong type is a
    `SeedScanTypeError`. Members this version does not name are ignored.
    A refusal names the member, never its value.

    A reader echoes the text members, so each holds only what the format
    defines, and a key put in one is refused: a scheme, a language, a
    coin or a reason among `CLAIMS`, `READ_SCHEMES`, `LANGUAGES`,
    `COIN_NAMES` and `REASONS`; a path of `m` and indexes below 2^31; an
    ``xpub`` whose Base58Check, version bytes, length and key prefix are
    a BIP32 mainnet public key's; a Bitcoin account's two descriptors
    over that ``xpub``, and none for another coin; an address that is a
    base58 or a segwit one, or empty.
    """
    if not isinstance(text, str):
        raise SeedScanTypeError(f"bundle: text of type {type(text).__name__}")
    document: object = None
    try:
        document = json.loads(text)
    except json.JSONDecodeError as e:
        where = f"line {e.lineno} column {e.colno}"
    else:
        where = ""
    # raised here and not in the `except`: the decoding error would stay
    # its context, and its `doc` holds the whole text, which a file handed
    # in by mistake fills with a secret. The position alone is said
    if where:
        raise SeedScanValueError(f"bundle: not JSON, at {where}")
    if not isinstance(document, dict):
        raise SeedScanTypeError(f"bundle: a JSON {type(document).__name__}")
    if _member(document, "format", str) != FORMAT:
        raise SeedScanValueError(f"bundle: format is not {FORMAT!r}")
    # the value is not quoted: no other version is defined, and a number
    # handed in by mistake may be a key
    if _member(document, "version", int) != VERSION:
        raise SeedScanValueError(f"bundle: version is not {VERSION}")
    search = _member(document, "search", (dict, type(None)))
    readings = tuple(_reading(r) for r in _objects(document, "readings"))
    return Bundle(
        claims=_strings(document, "claims", CLAIMS),
        readings=readings,
        not_checked=tuple(
            NotChecked(_one_of(n, "scheme", CLAIMS), _reason(n))
            for n in _objects(document, "not_checked")
        ),
        search=None if search is None else _search(search, len(readings)),
    )
