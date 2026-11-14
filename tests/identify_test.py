# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `seed_scan.identify`, against vectors their authors publish.

- BIP39, BIP84 and BIP86: the mnemonic of all `abandon` and `about`,
  and the account keys and addresses BIP84 and BIP86 give for it. The
  Bitcoin Cash addresses searched are derived from its seed by BIP32
  alone.
- SLIP-0039: trezor/python-shamir-mnemonic's `vectors.json`, whose
  master secrets are those of the passphrase "TREZOR"; bip39-slip39's
  `tests/_data/README.md` pins the file to its upstream commit.
- Electrum: spesmilo/electrum at b991f249d (2026-11-09):
  `tests/test_wallet_vertical.py`'s `test_electrum_seed_standard` and
  `test_electrum_seed_segwit`, a mnemonic each with its master key and
  first addresses, and `tests/test_mnemonic.py`'s `Test_seeds`, the seed
  version table.
"""

from __future__ import annotations

import dataclasses
import random
from typing import Any

import pytest
from bip32_descriptors.bip32 import BIP32KeyData, fingerprint, xpub_from_xprv
from bip39_slip39 import bip39, dispatch, slip39
from btclib import b58
from btclib.hashes import hash160

from seed_scan import identify as identify_module
from seed_scan.bundle import Match, NotChecked, dumps
from seed_scan.exceptions import SeedScanTypeError, SeedScanValueError
from seed_scan.identify import COINS, identify

from .secret_free import assert_secret_free

#: The BIP39 mnemonic BIP84's and BIP86's vectors derive from.
ABANDON = "abandon " * 11 + "about"

#: BIP84's master public key and account 0 key, zpubs, and its first change
#: address.
BIP84_ROOT = "zpub6jftahH18ngZxLmXaKw3GSZzZsszmt9WqedkyZdezFtWRFBZqsQH5hyUmb4pCEeZGmVfQuP5bedXTB8is6fTv19U1GQRyQUKQGUTzyHACMF"
BIP84_ZPUB = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"
BIP84_CHANGE = "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"

#: BIP86's account 0 key and its first receiving address.
BIP86_XPUB = "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ"
BIP86_RECEIVE = "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"

#: SLIP-0039 vector 4, "Basic sharing 2-of-3": two of its shares, and
#: the master key of its master secret under "TREZOR".
SHARES = (
    (
        "shadow pistol academic always adequate wildlife fancy gross oasis "
        "cylinder mustang wrist rescue view short owner flip making coding armed"
    ),
    (
        "shadow pistol academic acid actress prayer class unknown daughter "
        "sweater depict flip twice unkind craft early superior advocate guest "
        "smoking"
    ),
)
SHARES_XPRV = "xprv9s21ZrQH143K2nNuAbfWPHBtfiSCS14XQgb3otW4pX655q58EEZeC8zmjEUwucBu9dPnxdpbZLCn57yx45RBkwJHnwHFjZK4XPJ8SyeYjYg"

#: SLIP-0039 vector 1, "Valid mnemonic without sharing": a share of
#: another set than vector 4's.
FOREIGN_SHARE = (
    "duckling enlarge academic academic agency result length solution fridge "
    "kidney coal piece deal husband erode duke ajar critical decision keyboard"
)

#: Electrum's `test_electrum_seed_standard`: the mnemonic, its master key,
#: and the first receiving and change addresses.
STANDARD = "cycle rocket west magnet parrot shuffle foot correct salt library feed song"
STANDARD_XPRV = "xprv9s21ZrQH143K32jECVM729vWgGq4mUDJCk1ozqAStTphzQtCTuoFmFafNoG1g55iCnBTXUzz3zWnDb5CVLGiFvmaZjuazHDL8a81cPQ8KL6"
STANDARD_RECEIVE = "1NNkttn1YvVGdqBW4PR6zvc3Zx3H5owKRf"
STANDARD_CHANGE = "1KSezYMhAJMWqFbVFB2JshYg69UpmEXR4D"

#: Electrum's `test_electrum_seed_segwit`: the mnemonic, the key at m/0h,
#: a zpub, and the first receiving and change addresses.
SEGWIT = "bitter grass shiver impose acquire brush forget axis eager alone wine silver"
SEGWIT_ZPUB = "zpub6nsHdRuY92FsMKdbn9BfjBCG6X8pyhCibNP6uDvpnw2cyrVhecvHRMa3Ne8kdJZxjxgwnpbHLkcR4bfnhHy6auHPJyDTQ3kianeuVLdkCYQ"
SEGWIT_RECEIVE = "bc1q3g5tmkmlvxryhh843v4dz026avatc0zzr6h3af"
SEGWIT_CHANGE = "bc1qdy94n2q5qcp0kg7v9yzwe6wvfkhnvyzje7nx2p"

#: Electrum's seed version table: a pre-2.0 seed and a two-factor one.
OLD = "cell dumb heartbeat north boom tease ship baby bright kingdom rare squeeze"
TWO_FACTOR = "science dawn member doll dutch real can brick knife deny drive list"


def no_share(_: str) -> str:
    """Answer the share prompt with nothing, which ends a set.

    :returns: the empty string.
    """
    return ""


class Prompt:
    """A prompt that answers what a user typed, in order."""

    def __init__(self, *typed: str) -> None:
        """Keep the answers.

        :param typed: what the user types, in order.
        """
        self.typed = list(typed)
        self.shown: list[str] = []

    def __call__(self, text: str) -> str:
        """Answer the next one.

        :param text: what the prompt shows.
        :returns: what the user typed.
        """
        self.shown.append(text)
        return self.typed.pop(0)


def xpub_of(key: str) -> str:
    """Return a key's BIP32 mainnet xpub, whatever its version.

    :param key: an extended key, SLIP-0132 versions included.
    :returns: the xpub of the same key, in BIP32's version.
    """
    data = BIP32KeyData.b58decode(key)
    xpub = BIP32KeyData(
        bytes.fromhex("0488b21e"),
        data.depth,
        data.parent_fingerprint,
        data.index,
        data.chain_code,
        data.key,
    )
    return xpub.b58encode()


def test_bip39_account_keys_are_bip84s_and_bip86s() -> None:
    """BIP84's and BIP86's account 0 keys are among the bundle's."""
    bundle = identify(ABANDON, [""], no_share, accounts=1)
    assert bundle.claims == ("bip39",)
    assert not bundle.not_checked
    assert bundle.search is None
    (reading,) = bundle.readings
    assert reading.scheme == "bip39"
    assert reading.languages == ("en",)
    assert reading.passphrase == 0
    xpubs = {a.path: a.xpub for a in reading.accounts}
    assert xpubs["m/84h/0h/0h"] == xpub_of(BIP84_ZPUB)
    assert xpubs["m/86h/0h/0h"] == BIP86_XPUB


def test_the_coins_declared_are_written_in_order() -> None:
    """Each coin, purpose and account of `COINS`, Bitcoin's with descriptors.

    Each coin's legacy layouts follow its purposes, one account each.
    """
    bundle = identify(ABANDON, [""], no_share, accounts=2)
    (reading,) = bundle.readings
    expected = [
        (coin.name, coin.coin_type, purpose, account, path)
        for coin in COINS
        for purpose, account, path in [
            *(
                (p, n, f"m/{p}h/{coin.coin_type}h/{n}h")
                for p in coin.purposes
                for n in range(2)
            ),
            *((None, 0, path) for path in coin.legacy),
        ]
    ]
    assert [
        (a.coin, a.coin_type, a.purpose, a.account, a.path) for a in reading.accounts
    ] == expected
    for account in reading.accounts:
        assert len(account.descriptors) == (2 if account.coin == "bitcoin" else 0)
    assert reading.master_fingerprint == fingerprint(xpub_of(BIP84_ROOT)).hex()
    master = BIP32KeyData.from_seed(bip39.seed_from_mnemonic(ABANDON, ""))
    ethereum = next(a for a in reading.accounts if a.coin == "ethereum")
    assert ethereum.xpub == master.derive("m/44h/60h/0h").xpub.b58encode()
    classic = next(a for a in reading.accounts if a.coin == "ethereum-classic")
    assert classic.xpub == master.derive("m/44h/61h/0h").xpub.b58encode()
    legacy = [a for a in reading.accounts if a.purpose is None]
    assert [(a.coin, a.xpub) for a in legacy] == [
        ("ethereum", ethereum.xpub),
        ("ethereum-classic", master.derive("m/44h/60h/160720h/0h").xpub.b58encode()),
    ]


def test_each_coin_takes_the_purposes_its_wallets_derive_at() -> None:
    """`COINS` holds the purposes the wallets its comment cites derive at.

    A purpose added or dropped is a new reading of those wallets, so
    this pin moves with that comment.
    """
    assert {coin.name: coin.purposes for coin in COINS} == {
        "bitcoin": (44, 49, 84, 86),
        "ethereum": (44,),
        "ethereum-classic": (44,),
        "bitcoin-cash": (44,),
        "litecoin": (44, 49, 84),
        "dogecoin": (44,),
    }


def test_each_legacy_layout_is_one_its_wallets_derive_at() -> None:
    """The legacy layouts the comment above `COINS` cites, and no other.

    A layout added or dropped is a new reading of those wallets, so this
    pin moves with that comment.
    """
    assert {coin.name: coin.legacy for coin in COINS if coin.legacy} == {
        "ethereum": ("m/44h/60h/0h",),
        "ethereum-classic": ("m/44h/60h/160720h/0h",),
    }


def test_each_passphrase_is_a_reading_named_by_its_number() -> None:
    """The empty passphrase and one typed give two readings, 0 and 1."""
    bundle = identify(ABANDON, ["", "TREZOR"], no_share, accounts=1)
    assert [r.passphrase for r in bundle.readings] == [0, 1]
    # BIP39's own vector: this mnemonic and "TREZOR" give this master key
    trezor = BIP32KeyData.b58decode(
        "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs"
        "1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"
    )
    assert bundle.readings[1].master_fingerprint == fingerprint(trezor).hex()


@pytest.mark.parametrize(
    "address, path",
    [(BIP84_CHANGE, "m/84h/0h/0h/1/0"), (BIP86_RECEIVE, "m/86h/0h/0h/0/0")],
)
def test_a_known_address_is_found_with_its_path(address: str, path: str) -> None:
    """The search names the reading and path of BIP84's and BIP86's addresses.

    :param address: the address the user knows.
    :param path: the path its BIP says gives it.
    """
    bundle = identify(
        ABANDON, ["", "TREZOR"], no_share, accounts=1, address=address, indexes=2
    )
    search = bundle.search
    assert search is not None
    assert search.checked
    assert search.matches == (Match(0, "bitcoin", path),)
    # two readings, four purposes, one account, two branches, two indexes:
    # a segwit address is not searched on Bitcoin Cash's paths
    assert search.searched == 2 * 4 * 1 * 2 * 2


def legacy_address(path: str) -> str:
    """Return the p2pkh address at a path of BIP39's vector, by BIP32 alone.

    :param path: the full derivation path.
    :returns: the base58 address of the key's hash160.
    """
    root = BIP32KeyData.from_seed(bip39.seed_from_mnemonic(ABANDON, ""))
    key = root.derive(path).xpub.key
    return b58.address_from_h160("p2pkh", hash160(key), "mainnet")


@pytest.mark.parametrize(
    "coin, path",
    [
        ("bitcoin-cash", "m/44h/145h/0h/0/1"),
        ("bitcoin-cash", "m/44h/145h/0h/1/0"),
        ("bitcoin", "m/44h/0h/0h/0/1"),
    ],
)
def test_a_base58_address_is_searched_on_bitcoin_cash_paths(
    coin: str, path: str
) -> None:
    """A legacy address is found on either chain's path, which names the coin.

    :param coin: the coin of the path.
    :param path: where the address is.
    """
    address = legacy_address(path)
    bundle = identify(ABANDON, [""], no_share, accounts=1, address=address, indexes=2)
    search = bundle.search
    assert search is not None
    assert search.matches == (Match(0, coin, path),)
    # one reading, Bitcoin's four purposes and Bitcoin Cash's one, one
    # account, two branches, two indexes
    assert search.searched == 1 * (4 + 1) * 1 * 2 * 2


def test_an_address_out_of_the_bound_is_not_found() -> None:
    """An address one index past the bound is searched and not found."""
    bundle = identify(
        ABANDON,
        [""],
        no_share,
        accounts=1,
        address="bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
        indexes=1,
    )
    assert bundle.search is not None
    assert bundle.search.checked
    assert not bundle.search.matches


@pytest.mark.parametrize(
    "address",
    [
        "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
        "not an address",
        # a WIF typed by mistake: the key of an all-ones scalar, made up
        "KwFfNUhSDaASSAwtG7ssQM1uVX8RgX5GHWnnLfhfiQDigjioWXHH",
    ],
)
def test_a_text_that_is_no_bitcoin_address_is_neither_searched_nor_written(
    address: str,
) -> None:
    """The bundle says why it did not search, and holds none of the text.

    :param address: an Ethereum address, no address, and a WIF.
    """
    bundle = identify(ABANDON, [""], no_share, accounts=1, address=address)
    search = bundle.search
    assert search is not None
    assert not search.checked
    assert search.address == ""
    assert "neither searched nor written" in search.reason
    assert search.searched == 0
    assert address not in dumps(bundle)


def test_a_testnet_address_is_written_and_not_searched() -> None:
    """BIP49's testnet address is public: written, not searched."""
    address = "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2"
    bundle = identify(ABANDON, [""], no_share, accounts=1, address=address)
    search = bundle.search
    assert search is not None
    assert not search.checked
    assert search.address == address
    assert "only Bitcoin mainnet ones are searched" in search.reason


def test_a_complete_set_of_shares_is_read() -> None:
    """The second share is asked for, and "TREZOR" gives the vector's key."""
    prompt = Prompt(SHARES[1])
    bundle = identify(SHARES[0], ["", "TREZOR"], prompt, accounts=1)
    assert len(prompt.shown) == 1
    assert bundle.claims == ("slip39",)
    assert [r.scheme for r in bundle.readings] == ["slip39", "slip39"]
    master = BIP32KeyData.b58decode(SHARES_XPRV)
    assert bundle.readings[1].master_fingerprint == fingerprint(master).hex()
    assert bundle.readings[1].accounts[0].xpub == (
        master.derive("m/44h/0h/0h").xpub.b58encode()
    )


def test_a_line_that_is_no_share_is_asked_again() -> None:
    """A sentence that is no share is not added, and the prompt says so."""
    prompt = Prompt(ABANDON, SHARES[1])
    bundle = identify(SHARES[0], ["TREZOR"], prompt, accounts=1)
    assert prompt.shown[1].startswith("Not a SLIP-0039 share")
    assert len(bundle.readings) == 1


@pytest.mark.parametrize(
    "typed, problem",
    [(SHARES[0], "A share already typed"), (FOREIGN_SHARE, "A share of another set")],
)
def test_a_share_that_cannot_join_the_set_is_asked_again(
    typed: str, problem: str
) -> None:
    """A repeated share, or one of another set, is not added; the set completes.

    Either would make the set one that never completes, as SLIP-0039
    refuses a set with a member twice or with two identifiers.

    :param typed: the share typed before the one that completes the set.
    :param problem: what the prompt then says.
    """
    prompt = Prompt(typed, SHARES[1])
    bundle = identify(SHARES[0], ["TREZOR"], prompt, accounts=1)
    assert prompt.shown[1].startswith(problem)
    assert [r.scheme for r in bundle.readings] == ["slip39"]


#: A made-up master secret, as bip39-slip39's README splits one: the shares
#: of these tests are generated from it, there being no published vector
#: of more shares than a set's thresholds.
MADE_UP_SECRET = bytes(range(16))


def split(groups: list[tuple[int, int]], group_threshold: int) -> list[list[str]]:
    """Return the shares of the made-up secret, by group, the same on every run.

    The random bytes come from a generator with a fixed seed. Fresh
    shares would make the tests that expect one reading flaky: a share
    is sometimes an Electrum seed too, as `bip39_slip39.dispatch`
    explains, and identify then reads both. The assertion keeps the
    first share, which these tests type first, clear of that.

    :param groups: each group's member threshold and member count.
    :param group_threshold: how many groups recover the secret.
    :returns: the mnemonics of each group, member 0 first.
    """
    shares = slip39.mnemonics_from_master_secret(
        MADE_UP_SECRET,
        groups,
        group_threshold,
        iteration_exponent=0,
        entropy_source=random.Random(0).randbytes,
    )
    assert dispatch.all_seed_types_from_mnemonic(shares[0][0]) == ["slip39"]
    return shares


@pytest.mark.parametrize(
    "groups, group_threshold, order",
    [
        # one share of each group before a second of either: the second
        # group's share is beyond the group threshold
        ([(2, 3), (2, 3)], 1, [(0, 0), (1, 0), (0, 1)]),
        # a group typed past its member threshold before the other group
        ([(2, 3), (1, 1)], 2, [(0, 0), (0, 1), (0, 2), (1, 0)]),
    ],
)
def test_shares_beyond_the_thresholds_still_recover(
    groups: list[tuple[int, int]],
    group_threshold: int,
    order: list[tuple[int, int]],
) -> None:
    """Shares typed past a threshold are kept aside, and the secret recovers.

    :param groups: each group's member threshold and member count.
    :param group_threshold: how many groups recover the secret.
    :param order: the (group, member) of each share, in the order typed.
    """
    shares = split(groups, group_threshold)
    typed = [shares[g][m] for g, m in order]
    prompt = Prompt(*typed[1:])
    bundle = identify(typed[0], [""], prompt, accounts=1)
    assert not prompt.typed
    (reading,) = bundle.readings
    root = BIP32KeyData.from_seed(MADE_UP_SECRET)
    assert reading.master_fingerprint == fingerprint(root).hex()


@pytest.mark.parametrize(
    "groups, group_threshold",
    [
        ([(2, 3), (2, 3)], 1),
        ([(2, 3), (1, 1)], 2),
        ([(2, 3), (3, 5), (1, 1)], 2),
        ([(1, 1), (2, 2), (3, 4), (2, 3)], 3),
    ],
)
def test_every_order_of_every_share_recovers(
    groups: list[tuple[int, int]], group_threshold: int
) -> None:
    """In any order, all the shares of a set give back its master secret.

    The shares are typed until the set recovers, so a shuffled order
    stops at the first sufficient subset, wherever it falls.

    :param groups: each group's member threshold and member count.
    :param group_threshold: how many groups recover the secret.
    """
    every = [share for group in split(groups, group_threshold) for share in group]
    rng = random.Random(f"{groups}{group_threshold}")
    for _ in range(40):
        rng.shuffle(every)
        subset = identify_module._shares(every[0], Prompt(*every[1:]))
        assert subset is not None
        assert slip39.master_secret_from_mnemonics(subset) == MADE_UP_SECRET


def test_a_share_with_another_member_threshold_in_its_group_is_refused() -> None:
    """A share whose group holds another member threshold is of another set."""
    first, second, _ = split([(2, 3)], 1)[0]
    share = slip39.share_from_mnemonic(second)
    forged = slip39.mnemonic_from_share(dataclasses.replace(share, member_threshold=3))
    prompt = Prompt(forged, second)
    bundle = identify(first, [""], prompt, accounts=1)
    assert prompt.shown[1].startswith("A share of another set")
    assert len(bundle.readings) == 1


#: The share of a 1-of-1 set of the made-up secret, iteration exponent 0,
#: whose words Electrum also reads as a "standard" seed.
ELECTRUM_SHARE = (
    "election dramatic academic academic armed dress review premium imply "
    "typical dominant daisy voting random agency bike dive deadline finance survive"
)


def test_a_share_that_is_also_an_electrum_seed_is_read_as_both() -> None:
    """Both schemes claim the words, and each gives its reading."""
    bundle = identify(ELECTRUM_SHARE, [""], no_share, accounts=1)
    assert bundle.claims == ("slip39", "electrum_standard")
    assert [r.scheme for r in bundle.readings] == ["slip39", "electrum_standard"]
    root = BIP32KeyData.from_seed(MADE_UP_SECRET)
    assert bundle.readings[0].master_fingerprint == fingerprint(root).hex()


def test_an_incomplete_set_is_not_checked() -> None:
    """One share of two, then an empty answer, is said not checked."""
    bundle = identify(SHARES[0], [""], no_share, accounts=1)
    assert not bundle.readings
    assert bundle.not_checked == (
        NotChecked("slip39", "the shares typed do not complete a set"),
    )


def test_a_passphrase_slip39_refuses_is_not_checked_by_number() -> None:
    """A passphrase that is not printable ASCII is named by its number."""
    prompt = Prompt(SHARES[1])
    passphrases = [
        "",
        "\N{LATIN SMALL LETTER E WITH ACUTE}t\N{LATIN SMALL LETTER E WITH ACUTE}",
    ]
    bundle = identify(SHARES[0], passphrases, prompt, accounts=1)
    assert [r.passphrase for r in bundle.readings] == [0]
    assert bundle.not_checked == (
        NotChecked("slip39", "passphrase 1: not one SLIP-0039 accepts"),
    )


def test_an_electrum_standard_seed_is_read_at_its_master_key() -> None:
    """Electrum's "standard" key is at "m", with a p2pkh descriptor."""
    bundle = identify(STANDARD, [""], no_share, accounts=1)
    assert bundle.claims == ("electrum_standard", "bip39_wordlist")
    (reading,) = bundle.readings
    (account,) = reading.accounts
    assert account.path == "m"
    assert account.purpose is None
    assert account.xpub == xpub_from_xprv(STANDARD_XPRV)
    assert account.descriptors[0].startswith(f"pkh([{reading.master_fingerprint}]")
    assert bundle.not_checked[0].scheme == "bip39_wordlist"


def test_an_electrum_segwit_seed_is_read_at_m_0h() -> None:
    """Electrum's "segwit" key is its m/0h zpub, with a p2wpkh descriptor."""
    bundle = identify(SEGWIT, [""], no_share, accounts=1)
    (reading,) = bundle.readings
    (account,) = reading.accounts
    assert account.path == "m/0h"
    assert account.xpub == xpub_of(SEGWIT_ZPUB)
    assert account.descriptors[1].startswith(
        f"wpkh([{reading.master_fingerprint}/0h]{account.xpub}/1/*)#"
    )


@pytest.mark.parametrize(
    "mnemonic, address, path",
    [
        (STANDARD, STANDARD_RECEIVE, "m/0/0"),
        (STANDARD, STANDARD_CHANGE, "m/1/0"),
        (SEGWIT, SEGWIT_RECEIVE, "m/0h/0/0"),
        (SEGWIT, SEGWIT_CHANGE, "m/0h/1/0"),
    ],
)
def test_an_electrum_address_is_found(mnemonic: str, address: str, path: str) -> None:
    """Electrum's first addresses of each branch are found at their paths.

    :param mnemonic: the Electrum mnemonic.
    :param address: an address Electrum's test says its wallet has.
    :param path: where it is.
    """
    bundle = identify(mnemonic, [""], no_share, accounts=1, address=address, indexes=1)
    assert bundle.search is not None
    assert bundle.search.matches == (Match(0, "bitcoin", path),)


@pytest.mark.parametrize(
    "mnemonic, claims, scheme",
    [
        (OLD, ("electrum_old",), "electrum_old"),
        (TWO_FACTOR, ("electrum_2fa", "bip39_wordlist"), "electrum_2fa"),
        ("abandon " * 12, ("bip39_wordlist",), "bip39_wordlist"),
    ],
)
def test_a_scheme_no_reading_covers_is_not_checked(
    mnemonic: str, claims: tuple[str, ...], scheme: str
) -> None:
    """A pre-2.0, a two-factor and a checksum-failing sentence are not checked.

    :param mnemonic: the sentence.
    :param claims: the schemes that claim it.
    :param scheme: the one written as not checked first.
    """
    bundle = identify(mnemonic, [""], no_share, accounts=1)
    assert bundle.claims == claims
    assert not bundle.readings
    assert bundle.not_checked[0].scheme == scheme


def test_words_no_scheme_claims() -> None:
    """No scheme, no reading, nothing not checked: an empty bundle."""
    bundle = identify("qzx qzx", [""], no_share)
    assert bundle.claims == ()
    assert not bundle.readings
    assert not bundle.not_checked


@pytest.mark.parametrize("name", ["accounts", "indexes"])
def test_a_bound_is_refused(name: str) -> None:
    """A bound below one, or not an integer, is refused.

    :param name: the bound.
    """
    zero: dict[str, Any] = {name: 0}
    with pytest.raises(SeedScanValueError, match=f"invalid {name}: 0"):
        identify(ABANDON, [""], no_share, **zero)
    flag: dict[str, Any] = {name: True}
    with pytest.raises(SeedScanTypeError, match=f"invalid {name} type: bool"):
        identify(ABANDON, [""], no_share, **flag)


def test_a_mnemonic_that_is_no_str_is_refused() -> None:
    """The mnemonic's type is named, never its value, in any spelling."""
    with pytest.raises(SeedScanTypeError, match="invalid mnemonic type: bytes") as e:
        identify(ABANDON.encode(), [""], no_share)  # type: ignore[arg-type]
    assert_secret_free(e.value, [ABANDON, ABANDON.encode(), *ABANDON.split()])
