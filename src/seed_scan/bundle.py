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
from dataclasses import asdict, dataclass
from typing import Any

from seed_scan.exceptions import SeedScanTypeError, SeedScanValueError

__all__ = [
    "FORMAT",
    "VERSION",
    "Account",
    "Bundle",
    "Match",
    "NotChecked",
    "Reading",
    "Search",
    "dumps",
    "loads",
]

#: The value of the ``format`` member.
FORMAT = "seed-scan-bundle"

#: The value of the ``version`` member this module writes and reads.
VERSION = 1


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


def _strings(document: dict[str, Any], key: str) -> tuple[str, ...]:
    """Return a member that is a list of strings."""
    values = _member(document, key, list)
    for value in values:
        if not isinstance(value, str):
            err_msg = f"bundle: an item of {key!r} of type {type(value).__name__}"
            raise SeedScanTypeError(err_msg)
    return tuple(values)


def _account(document: dict[str, Any]) -> Account:
    """Read one account object."""
    purpose = _member(document, "purpose", (int, type(None)))
    return Account(
        coin=_member(document, "coin", str),
        coin_type=_count(document, "coin_type"),
        purpose=None if purpose is None else _count(document, "purpose"),
        account=_count(document, "account"),
        path=_member(document, "path", str),
        xpub=_member(document, "xpub", str),
        descriptors=_strings(document, "descriptors"),
    )


def _reading(document: dict[str, Any]) -> Reading:
    """Read one reading object."""
    return Reading(
        scheme=_member(document, "scheme", str),
        languages=_strings(document, "languages"),
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
        matches.append(Match(reading, _member(match, "path", str)))
    return Search(
        address=_member(document, "address", str),
        checked=_member(document, "checked", bool),
        reason=_member(document, "reason", str),
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
        claims=_strings(document, "claims"),
        readings=readings,
        not_checked=tuple(
            NotChecked(_member(n, "scheme", str), _member(n, "reason", str))
            for n in _objects(document, "not_checked")
        ),
        search=None if search is None else _search(search, len(readings)),
    )
