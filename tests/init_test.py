# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `seed_scan` package metadata."""

import importlib
import importlib.metadata

import pytest

import seed_scan


def test_version() -> None:
    """Verify __version__ matches the installed metadata."""
    assert seed_scan.__version__ == importlib.metadata.version("seed-scan")


def test_version_without_installed_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A source tree with no metadata beside it stays importable.

    The suite cannot exercise that situation as it is, the package being
    installed in the environment running it, so the lookup is made to fail
    and the module re-executed. It is the import that is under test, not
    the string: guards against import raising PackageNotFoundError
    (issue btclib-org/btclib#150).
    """

    def raise_package_not_found(_: str) -> str:
        raise importlib.metadata.PackageNotFoundError

    # patch the attribute of the module, not the name seed_scan imported:
    # the `from importlib.metadata import version` line looks it up again on
    # reload, which is what makes this reachable at all
    monkeypatch.setattr(importlib.metadata, "version", raise_package_not_found)
    try:
        assert importlib.reload(seed_scan).__version__ == "unknown"
    finally:
        # reload once more with the lookup restored, so the module every
        # other test sees carries the real version again. monkeypatch would
        # undo the patch by itself, but not the module state it produced
        monkeypatch.undo()
        importlib.reload(seed_scan)

    assert seed_scan.__version__ == importlib.metadata.version("seed-scan")
