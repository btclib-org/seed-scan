# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Every reader of what another party writes, on input nobody wrote down.

The rest of the suite reads fixed inputs: a document `identify`, `scan`
or `forks` wrote, with the one member a test edits. This file is the
converse, section 7's property layer: hypothesis hands each harness
under `fuzz/` text it makes up, and seeds of the harness's corpus with
one member changed, removed or repeated, and the harness checks on each
what its docstring says: that the reader refuses it with the package's
own exceptions, or reads it, writes it back and reports on it. The
harnesses are loaded as `tests/fuzz_corpus_test.py` loads them.

`quantity` is read the other way too: every integer it can spell, it
reads back.

Section 12 of the organization's standard asks this file one more
question: that a release runs no fuzzing.
"""

from __future__ import annotations

import copy
import importlib
import importlib.util
import json
import re
import sys
from functools import reduce
from operator import getitem
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from seed_scan.evm import quantity

from . import module_names

if TYPE_CHECKING:
    from collections.abc import Iterator

_ROOT = Path(__file__).parents[1]
_FUZZ = _ROOT / "fuzz"

# what a made-up text is bounded to: a reader refuses most of what it is
# handed at its first check, and a text long enough to reach further is
# one the changed seeds below reach instead
MAX_INPUT = 512

#: Each harness, by the reader it fuzzes.
FUZZED = {
    "seed_scan.bundle.loads": "fuzz_bundle",
    "seed_scan.scan.loads": "fuzz_scan",
    "seed_scan.forks.loads": "fuzz_forks",
    "seed_scan.evm.Node": "fuzz_evm",
}


@pytest.fixture(scope="module")
def harnesses() -> Iterator[dict[str, ModuleType]]:
    """Load every harness, as `tests/fuzz_corpus_test.py` loads one.

    Once for the module: hypothesis runs a test once for each example, and
    refuses a fixture set up once for each test, which every example of
    the test would share without a word.

    :returns: each harness, by name.
    """
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setitem(sys.modules, "atheris", ModuleType("atheris"))
        monkeypatch.syspath_prepend(str(_FUZZ))
        loaded = {}
        for name in FUZZED.values():
            spec = importlib.util.spec_from_file_location(name, _FUZZ / f"{name}.py")
            assert spec is not None
            assert spec.loader is not None
            loaded[name] = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(loaded[name])
        yield loaded


def test_every_reader_is_fuzzed() -> None:
    """Each module of the package that defines a `loads` has a harness.

    `loads` is the name each reader of a file is published under, and a
    reader named otherwise, as `evm.Node`, rests on `FUZZED` by hand.
    """
    found = set()
    for name in module_names():
        loads = getattr(importlib.import_module(name), "loads", None)
        if getattr(loads, "__module__", None) == name:
            found.add(f"{name}.loads")
    assert found
    assert found <= set(FUZZED)
    assert set(FUZZED.values()) == {p.stem for p in _FUZZ.glob("fuzz_*.py")}


@pytest.mark.parametrize("name", ["fuzz_bundle", "fuzz_scan", "fuzz_forks"])
@given(text=st.text(max_size=MAX_INPUT))
def test_a_made_up_text_honors_the_harness(
    harnesses: dict[str, ModuleType], name: str, text: str
) -> None:
    """A text no command wrote, read as its harness reads a file."""
    harnesses[name].fuzz_target(text.encode("utf-8"))


@given(data=st.binary(max_size=MAX_INPUT))
def test_a_made_up_answer_honors_the_harness(
    harnesses: dict[str, ModuleType], data: bytes
) -> None:
    """Bytes no node sent, read as an answer by each read of a node."""
    harnesses["fuzz_evm"].fuzz_target(data)


def _paths(value: Any, path: tuple[Any, ...] = ()) -> Iterator[tuple[Any, ...]]:
    """Yield the path of every member and item below `value`, in order."""
    items: Any = ()
    if isinstance(value, dict):
        items = value.items()
    elif isinstance(value, list):
        items = enumerate(value)
    for key, item in items:
        yield (*path, key)
        yield from _paths(item, (*path, key))


def _scalars(value: Any) -> list[Any]:
    """Return every value below `value` that is neither an object nor a list."""
    if isinstance(value, dict | list):
        items = value.values() if isinstance(value, dict) else value
        return [scalar for item in items for scalar in _scalars(item)]
    return [value]


# any JSON value, nested a few levels at most: what a reader does with a
# value nested past the interpreter's recursion limit is
# btclib-org/seed-scan#116's question, not this search's
_JSON = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats() | st.text(max_size=16),
    lambda inner: (
        st.lists(inner, max_size=3)
        | st.dictionaries(st.text(max_size=8), inner, max_size=3)
    ),
    max_leaves=6,
)


@st.composite
def _changed(draw: st.DrawFn, document: Any) -> Any:
    """Return `document` with one member or item replaced, removed or repeated.

    A replacement is any JSON value, or one the document already holds
    somewhere, which is of a type and a shape a reader may take where a
    made-up one is refused at once. A repeated item is what a reader
    refuses as listed twice; a repeated member is a replaced one.
    """
    document = copy.deepcopy(document)
    *above, key = draw(st.sampled_from(list(_paths(document))))
    parent = reduce(getitem, above, document)
    change = draw(st.sampled_from(["replace", "remove", "repeat"]))
    if change == "remove":
        del parent[key]
    elif change == "repeat" and isinstance(parent, list):
        parent.insert(key, copy.deepcopy(parent[key]))
    else:
        parent[key] = draw(_JSON | st.sampled_from(_scalars(document)))
    return document


@pytest.mark.parametrize("name", sorted(FUZZED.values()))
@given(data=st.data())
def test_a_seed_with_one_member_changed_honors_the_harness(
    harnesses: dict[str, ModuleType], name: str, data: st.DataObject
) -> None:
    """A seed of the harness's corpus, one member or item changed."""
    seeds = sorted((_FUZZ / "corpus" / name).glob("*.bin"))
    seed = json.loads(data.draw(st.sampled_from(seeds)).read_bytes())
    changed = data.draw(_changed(seed))
    harnesses[name].fuzz_target(json.dumps(changed).encode("utf-8"))


@given(value=st.integers(min_value=0, max_value=2**256 - 1))
def test_a_quantity_reads_back_the_integer_it_spells(value: int) -> None:
    """Each integer of 256 bits, as a node writes it, is read as itself."""
    assert quantity(hex(value)) == value


# a comment, whole-line or after a value, which may name any workflow
_COMMENT = re.compile(r"(?:^|\s)#.*$", re.MULTILINE)


def test_a_release_runs_no_fuzzing() -> None:
    """`release.yml` calls no `fuzz` run, nor names one anywhere else.

    Section 12 of the organization's standard has the rule: a crash the
    fuzzer finds is an issue against the reader, which a release does
    nothing with. Read with a regex, as `release_digests_test.py` reads
    the file.
    """
    release = _ROOT / ".github" / "workflows" / "release.yml"
    text = _COMMENT.sub("", release.read_text(encoding="utf-8"))
    assert re.findall(r"uses: \./\.github/workflows/([\w-]+)\.yml", text)
    assert not re.search(r"\bfuzz\b", text)
