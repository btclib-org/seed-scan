# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Every module this package ships is documented, and nothing else is.

The pages under `docs/source/` are written by hand, which invites drift,
and re-running `sphinx-apidoc -f` is no answer: it regenerates every page
from its template, discarding the comments and the `:exclude-members:`
a page carries. What drift costs is a module absent from the
automodule directives -- and therefore from the published documentation --
with nothing anywhere to say so; this module is the thing that says so.
"""

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).parents[1]
_PACKAGE_DIR = _ROOT / "src" / "seed_scan"
_DOCS_DIR = _ROOT / "docs" / "source"
# what a documented module looks like to sphinx: ".. automodule:: name",
# whatever indentation and options follow it
_AUTOMODULE = re.compile(r"^\s*\.\.\s+automodule::\s+(\S+)\s*$", re.MULTILINE)


def _documented_in(text: str) -> set[str]:
    """Return every module one page publishes the members of.

    An automodule stanza and nothing else. A toctree line naming a package
    makes the package's *page* reachable, and says nothing about whether
    that page renders the package's own `__init__`; a page no toctree
    includes is `toc.not_included`, which `-W` already fails on.
    """
    return set(_AUTOMODULE.findall(text))


def _documented() -> set[str]:
    """Return every module the documentation sources carry a stanza for."""
    names: set[str] = set()
    for page in _DOCS_DIR.glob("*.rst"):
        names.update(_documented_in(page.read_text(encoding="utf-8")))
    return names


def _is_public(parts: tuple[str, ...]) -> bool:
    """Return whether a module path names something a caller imports.

    `__init__` is the package itself and not a private name, which is the
    only reason this is not a one-line `startswith("_")`.
    """
    return not any(part.startswith("_") for part in parts if part != "__init__")


def _dotted(parts: tuple[str, ...]) -> str:
    """Return the dotted name of a module path, a package by its own name."""
    return ".".join(("seed_scan", *parts[: -1 if parts[-1] == "__init__" else None]))


def _shipped() -> set[str]:
    """Return every dotted name a caller can import from an installed wheel.

    Read off the source tree rather than by walking the imported package,
    so that noticing a new module does not depend on it being importable.
    """
    paths = (
        p.relative_to(_PACKAGE_DIR).with_suffix("").parts
        for p in _PACKAGE_DIR.rglob("*.py")
    )
    return {_dotted(parts) for parts in paths if _is_public(parts)}


# the two directions are separate tests because they fail for opposite
# reasons and are fixed in opposite files: something undocumented is a
# missing stanza in docs/source, something documented that no longer exists
# is a stanza left behind by a rename
def test_every_module_is_documented() -> None:
    """Every shipped module has a stanza in docs/source."""
    undocumented = _shipped() - _documented()
    assert not undocumented, "not documented in docs/source: " + ", ".join(
        sorted(undocumented)
    )


def test_no_documented_module_has_gone_away() -> None:
    """No automodule stanza names a module the tree lost."""
    stale = _documented() - _shipped()
    assert not stale, "documented but not shipped: " + ", ".join(sorted(stale))


def test_the_docs_sources_were_found_at_all() -> None:
    """The two tests above do not pass because a glob found nothing.

    A wrong `_DOCS_DIR` would make `_documented()` empty, which the second
    of them reports as success.
    """
    assert (_DOCS_DIR / "seed_scan.rst").is_file()
    assert "seed_scan" in _documented()


def test_a_toctree_line_is_not_a_stanza() -> None:
    """A package page documents the package only if a stanza says so."""
    source = (
        ".. toctree::\n"
        "   :maxdepth: 4\n"
        "\n"
        "   seed_scan\n"
        "\n"
        ".. automodule:: seed_scan.slip39\n"
        "   :members:\n"
    )
    assert _documented_in(source) == {"seed_scan.slip39"}


@pytest.mark.parametrize(
    "parts, public, dotted",
    [
        (("slip39",), True, "seed_scan.slip39"),
        (("schemes", "bip39"), True, "seed_scan.schemes.bip39"),
        (("__init__",), True, "seed_scan"),
        (("schemes", "__init__"), True, "seed_scan.schemes"),
        (("_utils",), False, "seed_scan._utils"),
        (("schemes", "_helpers"), False, "seed_scan.schemes._helpers"),
        (("_internal", "bip39"), False, "seed_scan._internal.bip39"),
    ],
)
def test_is_public_and_dotted(
    parts: tuple[str, ...], public: bool, dotted: str
) -> None:
    """Both answers, and the private shapes the tree itself has none of."""
    assert _is_public(parts) is public
    assert _dotted(parts) == dotted
