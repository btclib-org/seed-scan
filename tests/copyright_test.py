# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The copyright holder is one name, and every source file says so.

Three places name the holder and each is static text a human edits:
LICENSE's copyright line, `pyproject.toml`'s `authors`, and the header
every Python file opens with. Nothing derives any of them from another,
so a change to one is silent everywhere else until something reads them
together, which is what this module does. `docs/source/conf.py` is the
fourth reader and derives its value instead, which the last test holds.

The header is read off this module's own first three lines rather than
off `COPYRIGHT`, where section 14 of the organization's standard keeps
its text: `COPYRIGHT` is not in the sdist, and the suite runs from one.
That the two agree is section 14's own comparison, made from
`btclib-org/.github`.
"""

import re
import tomllib
from pathlib import Path

import pytest

import seed_scan

_ROOT = Path(__file__).parents[1]
_HEADER = "".join(Path(__file__).read_text(encoding="utf-8").splitlines(True)[:3])
_HEADER_RE = r"^# Copyright \(c\) (.+)$"
_LICENSE_RE = r"(?m)^Copyright \([Cc]\) (.+)$"
_CONF_AUTHOR_RE = r"(?m)^author = (.+)$"
_CONF_AUTHOR_EXPECTED = 'PYPROJECT["project"]["authors"][0]["name"]'
# the trees whose Python files carry the header, each present in a
# checkout and in the sdist alike
_SOURCES = ("src", "tests", "docs")


def _match(pattern: str, text: str, what: str) -> str:
    match = re.search(pattern, text, re.MULTILINE)
    assert match, f"{what} has no line matching {pattern!r}"
    return match[1]


def _header_holder() -> str:
    return _match(_HEADER_RE, _HEADER, "the header")


def test_license_names_the_header_holder() -> None:
    """LICENSE and the header every file carries name the same holder."""
    text = (_ROOT / "LICENSE").read_text(encoding="utf-8")
    assert _match(_LICENSE_RE, text, "LICENSE") == _header_holder()


def test_the_declared_author_is_the_header_holder() -> None:
    """The wheel's `Author` metadata is the holder the header names."""
    text = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert tomllib.loads(text)["project"]["authors"][0]["name"] == _header_holder()


@pytest.mark.parametrize(
    "path",
    sorted(p for d in _SOURCES for p in (_ROOT / d).rglob("*.py")),
    ids=lambda p: p.relative_to(_ROOT).as_posix(),
)
def test_every_python_file_opens_with_the_header(path: Path) -> None:
    """A file without the header states no licence of its own."""
    text = path.read_text(encoding="utf-8")
    assert text.startswith(_HEADER), f"{path.name} does not open with the header"


def test_no_dunder_repeats_the_metadata() -> None:
    """`__author__`, `__copyright__` and `__license__` are not declared.

    Each would be a copy of a fact `pyproject.toml` or LICENSE already
    states, with nothing reading it; a caller after one reads the
    installed distribution's metadata instead.
    """
    for dunder in ("__author__", "__author_email__", "__copyright__", "__license__"):
        assert not hasattr(seed_scan, dunder), f"seed_scan.{dunder} exists"


def test_conf_py_author_reads_pyproject_rather_than_repeating_it() -> None:
    """Sphinx's `author` is `pyproject.toml`'s, read back and not retyped.

    Read as source text rather than executed: `conf.py` imports docutils
    and sphinx at its top, which the suite's own environment need not
    carry.
    """
    text = (_ROOT / "docs" / "source" / "conf.py").read_text(encoding="utf-8")
    assert _match(_CONF_AUTHOR_RE, text, "conf.py") == _CONF_AUTHOR_EXPECTED
