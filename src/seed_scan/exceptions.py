# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Exception classes.

These exist only to tell an exception raised by seed_scan from one
raised by any other code: each derives from the built-in that says what
kind of failure it is, and adds nothing to it.

`SeedScanException` makes that telling apart a single `except`. It is
inherited *beside* the built-in and not instead of it:
`SeedScanValueError` is a `ValueError`, so code catching the built-in
catches it, as `json.JSONDecodeError` is a `ValueError` too.

It is caught and never raised: every refusal the package raises is to be
one of the two below it, and which one says whether the value was wrong or
the type was.

The classes are this package's own rather than those of a package it
builds on: a caller catching another package's base class does not catch
these, and one catching `ValueError` catches both.
"""

from __future__ import annotations

__all__ = [
    "SeedScanException",
    "SeedScanTypeError",
    "SeedScanValueError",
]


class SeedScanException(Exception):  # noqa: N818 -- a kind, like Exception itself, not a leaf raised
    """Anything seed_scan raised, whatever kind of failure it is.

    Never raised: the two below it are, and each says which kind of
    failure it was.
    """


class SeedScanValueError(SeedScanException, ValueError):
    """A value no valid input could carry; the package's usual refusal."""


class SeedScanTypeError(SeedScanException, TypeError):
    """An input of a type no conversion accepts: a caller error."""
