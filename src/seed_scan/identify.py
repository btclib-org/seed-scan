# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""From a mnemonic to the public bundle: the one module that holds a secret.

`identify` asks `bip39_slip39.dispatch` which schemes claim the words,
and derives a seed for each one this version reads, with the empty
passphrase and each one typed: BIP39 in every word-list, a set of
SLIP-0039 shares, and Electrum's "standard" and "segwit" seeds. From
each seed it writes the master fingerprint and the account public keys
`COINS` declares. A scheme the words claim and no reading covers is
written as not checked, with the reason: Electrum's pre-2.0 and two-factor
seeds, a BIP39 sentence whose checksum fails, an incomplete set of
shares.

Given an address the user knows, it compares the address's script with
those of every Bitcoin account it wrote, within a bound written beside
the result. An address of another network is not searched, and the
bundle says so; a text that is no Bitcoin address is not written either,
since a key typed by mistake would otherwise land in the bundle.

Nothing here opens a connection: `seed_scan.cli` refuses one for the
whole run. What leaves this module is `seed_scan.bundle`'s objects,
which hold public data only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from bip32_descriptors.bip32 import HARDENED_OFFSET, BIP32KeyData, fingerprint
from bip39_slip39 import bip39, dispatch, electrum, slip39
from btclib.script import ScriptPubKey
from btclib_wallet import bip44
from btclib_wallet.descriptors import add_checksum, parse

from seed_scan.bundle import (
    REASONS,
    Account,
    Bundle,
    Match,
    NotChecked,
    Reading,
    Search,
    slip39_passphrase,
)
from seed_scan.exceptions import SeedScanTypeError, SeedScanValueError

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from btclib_wallet.descriptors import Descriptor

__all__ = [
    "COINS",
    "Coin",
    "identify",
]


@dataclass(frozen=True)
class Coin:
    """A coin whose account keys a bundle declares, and their purposes."""

    name: str
    coin_type: int
    purposes: tuple[int, ...]


#: The coins and purposes a bundle declares, the order they are written
#: in. Bitcoin's are the four `btclib_wallet.bip44` maps to an address
#: encoding; the others are the purposes their wallets derive from.
COINS = (
    Coin("bitcoin", 0, (44, 49, 84, 86)),
    Coin("ethereum", 60, (44,)),
    Coin("bitcoin-cash", 145, (44,)),
    Coin("litecoin", 2, (44, 49, 84)),
    Coin("dogecoin", 3, (44,)),
)

# Electrum's layouts: the path of the key a wallet of each version
# derives its two branches from, and the descriptor fragment of its
# addresses. General, so it goes to btclib-wallet with
# btclib-org/btclib-wallet#849
_ELECTRUM = {
    "electrum_standard": ("m", "", "pkh"),
    "electrum_segwit": ("m/0h", "/0h", "wpkh"),
}

# what each scheme the words may claim and no reading covers is
# reported as
_NOT_READ = {
    "electrum_old": REASONS["electrum_old"],
    "electrum_2fa": REASONS["electrum_2fa"],
    "electrum_2fa_segwit": REASONS["electrum_2fa"],
    "bip39_wordlist": REASONS["bip39_wordlist"],
}


def _assert_bound(value: int, name: str) -> None:
    """Refuse a bound that is no integer or is below one."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeedScanTypeError(f"invalid {name} type: {type(value).__name__}")
    if value < 1:
        raise SeedScanValueError(f"invalid {name}: {value} is below 1")


def _accounts(
    root: BIP32KeyData, accounts: int
) -> list[tuple[Account, tuple[Descriptor, ...]]]:
    """Return the account keys `COINS` declares, Bitcoin's with descriptors."""
    master_fingerprint = fingerprint(root)
    found: list[tuple[Account, tuple[Descriptor, ...]]] = []
    for coin in COINS:
        for purpose in coin.purposes:
            parent = root.derive(f"m/{purpose}h/{coin.coin_type}h")
            for account in range(accounts):
                path = f"m/{purpose}h/{coin.coin_type}h/{account}h"
                xpub = parent.derive(HARDENED_OFFSET + account).xpub.b58encode()
                descriptors: tuple[Descriptor, ...] = (
                    bip44.account_descriptors(xpub, path, master_fingerprint)
                    if coin.coin_type == 0
                    else ()
                )
                texts = tuple(add_checksum(str(d)) for d in descriptors)
                found.append(
                    (
                        Account(
                            coin.name,
                            coin.coin_type,
                            purpose,
                            account,
                            path,
                            xpub,
                            texts,
                        ),
                        descriptors,
                    )
                )
    return found


def _electrum_account(
    root: BIP32KeyData, scheme: str
) -> tuple[Account, tuple[Descriptor, ...]]:
    """Return the one account key of an Electrum versioned seed."""
    path, origin, fragment = _ELECTRUM[scheme]
    xpub = root.derive(path).xpub.b58encode()
    key_origin = f"[{fingerprint(root).hex()}{origin}]"
    texts = tuple(
        add_checksum(f"{fragment}({key_origin}{xpub}/{branch}/*)") for branch in (0, 1)
    )
    descriptors = tuple(parse(text) for text in texts)
    return Account("bitcoin", 0, None, 0, path, xpub, texts), descriptors


@dataclass
class _Found:
    """The readings so far, their descriptors, and what was not read."""

    readings: list[Reading]
    descriptors: list[list[tuple[Account, tuple[Descriptor, ...]]]]
    not_checked: list[NotChecked]

    def add(
        self,
        scheme: str,
        languages: tuple[str, ...],
        passphrase: int,
        root: BIP32KeyData,
        accounts: list[tuple[Account, tuple[Descriptor, ...]]],
    ) -> None:
        """Add one reading and the descriptors of its accounts."""
        reading = Reading(
            scheme,
            languages,
            passphrase,
            fingerprint(root).hex(),
            tuple(account for account, _ in accounts),
        )
        self.readings.append(reading)
        self.descriptors.append(accounts)


_ASK_SHARE = "Another SLIP-0039 share (empty when done): "


def _set_of(share: slip39.Share) -> tuple[int, ...]:
    """Return the fields every share of one set holds alike."""
    return (
        share.identifier,
        share.extendable,
        share.iteration_exponent,
        share.group_threshold,
        share.group_count,
        len(share.value),
    )


def _refused(text: str, held: list[slip39.Share]) -> tuple[slip39.Share | None, str]:
    """Return a share that can join the set, or why it cannot.

    A share of another set, or one already typed, could never be part of
    the subset a master secret is recovered from, so neither joins it.
    """
    try:
        share = slip39.share_from_mnemonic(text)
    except ValueError:
        return None, "Not a SLIP-0039 share"
    group = [s for s in held if s.group_index == share.group_index]
    same_group = all(s.member_threshold == share.member_threshold for s in group)
    if _set_of(share) != _set_of(held[0]) or not same_group:
        return None, "A share of another set"
    if any(s.member_index == share.member_index for s in group):
        return None, "A share already typed"
    return share, ""


def _sufficient(held: list[slip39.Share]) -> list[int] | None:
    """Return the positions of shares a master secret is recovered from.

    SLIP-0039 combines exactly a member threshold of shares in each of
    exactly a group threshold of groups, and refuses a set with more. So
    the shares typed are a superset in any order, and the subset is taken
    from them: in each group its first member-threshold shares, and the
    first group-threshold groups so completed. `None` while there is no
    such subset. General, so it goes to bip39-slip39 with
    btclib-org/bip39-slip39#266.
    """
    groups: dict[int, list[int]] = {}
    for position, share in enumerate(held):
        groups.setdefault(share.group_index, []).append(position)
    complete = [
        positions[: held[positions[0]].member_threshold]
        for positions in groups.values()
        if len(positions) >= held[positions[0]].member_threshold
    ]
    group_threshold = held[0].group_threshold
    if len(complete) < group_threshold:
        return None
    return sorted(p for positions in complete[:group_threshold] for p in positions)


def _shares(first: str, prompt: Callable[[str], str]) -> list[str] | None:
    """Return shares a master secret is recovered from, the first included.

    Each further share is asked at the prompt until the shares typed hold
    a sufficient subset, which is what is answered. One that is not a
    share, is of another set or was already typed is asked again, the
    prompt saying which; an empty answer ends the set short, which
    answers `None`.
    """
    texts = [first]
    held = [slip39.share_from_mnemonic(first)]
    ask = _ASK_SHARE
    while (subset := _sufficient(held)) is None:
        text = prompt(ask)
        if not text.strip():
            return None
        share, problem = _refused(text, held)
        if share is None:
            ask = f"{problem}; another share (empty when done): "
        else:
            texts.append(text)
            held.append(share)
            ask = _ASK_SHARE
    return [texts[p] for p in subset]


def _read_slip39(
    found: _Found,
    mnemonic: str,
    passphrases: Sequence[str],
    prompt: Callable[[str], str],
    accounts: int,
) -> None:
    """Add a reading for each passphrase of a complete set of shares."""
    shares = _shares(mnemonic, prompt)
    if shares is None:
        reason = REASONS["incomplete_set"]
        found.not_checked.append(NotChecked("slip39", reason))
        return
    ems = slip39.encrypted_master_secret_from_mnemonics(shares)
    for number, passphrase in enumerate(passphrases):
        try:
            seed = ems.master_secret(passphrase)
        except ValueError:
            # SLIP-0039 takes printable ASCII alone; the passphrase is
            # named by its number, never quoted
            reason = slip39_passphrase(number)
            found.not_checked.append(NotChecked("slip39", reason))
            continue
        root = BIP32KeyData.from_seed(seed)
        found.add("slip39", (), number, root, _accounts(root, accounts))


def _read(
    claims: Sequence[str],
    mnemonic: str,
    passphrases: Sequence[str],
    prompt: Callable[[str], str],
    accounts: int,
) -> _Found:
    """Return the readings of every scheme that claims the words."""
    found = _Found([], [], [])
    for claim in claims:
        if claim == "slip39":
            _read_slip39(found, mnemonic, passphrases, prompt, accounts)
        elif claim in _ELECTRUM:
            for number, passphrase in enumerate(passphrases):
                root = BIP32KeyData.from_seed(
                    electrum.seed_from_mnemonic(mnemonic, passphrase)
                )
                account = _electrum_account(root, claim)
                found.add(claim, (), number, root, [account])
        elif claim == "bip39":
            languages = tuple(
                lang
                for lang in bip39.langs_from_mnemonic(mnemonic)
                if bip39.is_valid_mnemonic(mnemonic, lang)
            )
            for number, passphrase in enumerate(passphrases):
                root = BIP32KeyData.from_seed(
                    bip39.seed_from_mnemonic(mnemonic, passphrase)
                )
                found.add("bip39", languages, number, root, _accounts(root, accounts))
        else:
            found.not_checked.append(NotChecked(claim, _NOT_READ[claim]))
    return found


def _search(found: _Found, address: str, accounts: int, indexes: int) -> Search:
    """Return which reading and path give the address, within the bound."""
    try:
        target = ScriptPubKey.from_address(address)
    except ValueError:
        target = None
    if target is None:
        return Search("", False, REASONS["not_an_address"], accounts, indexes, 0, ())
    if target.network != "mainnet":
        return Search(address, False, REASONS["not_mainnet"], accounts, indexes, 0, ())
    matches = []
    searched = 0
    for reading, pairs in enumerate(found.descriptors):
        for account, descriptors in pairs:
            for branch, descriptor in enumerate(descriptors):
                for index in range(indexes):
                    searched += 1
                    scripts = descriptor.script_pub_keys(index)
                    if any(s.script == target.script for s in scripts):
                        path = f"{account.path}/{branch}/{index}"
                        matches.append(Match(reading, path))
    return Search(address, True, "", accounts, indexes, searched, tuple(matches))


def identify(
    mnemonic: str,
    passphrases: Sequence[str],
    prompt: Callable[[str], str],
    *,
    accounts: int = 5,
    address: str | None = None,
    indexes: int = 20,
) -> Bundle:
    """Return the public bundle of a mnemonic.

    `passphrases` are those to try, the empty one first; a reading names
    each by its position in them. `prompt` asks for a further SLIP-0039
    share where the words are one share of a set: it shows the text it is
    given and answers what the user typed, hidden.

    `accounts` is how many accounts of each coin and purpose are written,
    from account 0. Where `address` is given, the receive and change
    branches of each Bitcoin account written are searched for it, from
    index 0 to `indexes` - 1.

    A refusal names no secret: the words and the passphrases are never
    quoted.
    """
    if not isinstance(mnemonic, str):
        raise SeedScanTypeError(f"invalid mnemonic type: {type(mnemonic).__name__}")
    _assert_bound(accounts, "accounts")
    _assert_bound(indexes, "indexes")
    claims = tuple(dispatch.all_seed_types_from_mnemonic(mnemonic))
    found = _read(claims, mnemonic, passphrases, prompt, accounts)
    search = None if address is None else _search(found, address, accounts, indexes)
    return Bundle(claims, tuple(found.readings), tuple(found.not_checked), search)
