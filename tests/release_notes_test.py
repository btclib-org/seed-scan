# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What CHANGELOG.md and RELEASE_NOTES.md must not say about themselves.

A count of its own entries is the one fact in either file nothing
derives: prose can be reviewed, a number is right or wrong invisibly.
Checking the number against the entries would make it one more line to
edit at every release, so neither file states one, and this module fails
on a count in either.

A test rather than a reading because resolving a rebase conflict by
deleting the markers keeps a count paragraph the branch had removed.
"""

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).parents[1]
_FILES = (_ROOT / "CHANGELOG.md", _ROOT / "RELEASE_NOTES.md")

# a count of the file's own entries or of its breaking changes, spelled in
# digits or in words, `\s+` covering an 80-column wrap wherever it falls.
# Keyed on the noun the count is of, so that a number inside an entry --
# a fact about a change -- is not read as a claim about the file
_NUMBER = r"(?:\d+|(?:[a-z]+-)?(?:one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|[a-z]+teen|[a-z]+ty|hundred(?:\s+and\s+[a-z-]+)?))"
_FORBIDDEN = (
    rf"(?i)\b{_NUMBER}\s+entries\b",
    rf"(?i)\b{_NUMBER}\s+(?:source-breaking\s+)?changes\s+break\b",
    rf"(?i)\blists\s+the\s+{_NUMBER}\s+source-breaking\s+changes\b",
)

# each pattern against the shape it forbids, as a file of the organization
# once spelled it: what `test_the_patterns_still_match` compares them with
_RESURRECTED = (
    "A hundred and eighty entries, grouped.",
    "the largest: a hundred and eighty\nentries",
    "This section holds 12 entries.",
    "Twenty-nine changes break code that worked on v2023.7.12.",
    "[HISTORY.md](./HISTORY.md) lists the\ntwenty-nine source-breaking changes",
)


@pytest.mark.parametrize("path", _FILES, ids=lambda p: p.name)
def test_neither_file_states_a_count(path: Path) -> None:
    """No entry count, and no size of a breaking-changes list."""
    text = path.read_text(encoding="utf-8")
    found = [m[0] for p in _FORBIDDEN for m in re.finditer(p, text)]
    assert not found, f"{path.name} states a count: {found!r}"


def test_the_patterns_still_match() -> None:
    """The guard above passes for free if its patterns match nothing."""
    for text in _RESURRECTED:
        assert any(re.search(p, text) for p in _FORBIDDEN), text
    for pattern in _FORBIDDEN:
        assert any(re.search(pattern, t) for t in _RESURRECTED), pattern
