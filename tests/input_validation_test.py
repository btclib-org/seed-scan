# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Every public function refuses what it does not declare, as the package.

CONTRIBUTING.md's *The public surface* states the rule: a refusal is a
`SeedScanTypeError` or a `SeedScanValueError`. This module drives it in
two rounds:

- **a value of a type the signature does not declare** is the caller's
  mistake, and leaves as a `SeedScanTypeError`;
- **a value of a declared type that no valid input carries** is a fact
  about the input, and leaves as a `SeedScanException`: which of the two
  is the function's to decide.

## What it calls

The walk starts at `seed_scan.__all__` and descends through every
module an `__all__` publishes, at any depth, when the suite runs, so a
function published later is driven without being listed here. It takes
every function, and every class
that is neither an exception nor a dataclass, its constructor being the
call. A dataclass is a record: its constructor checks nothing, and the
readers that build one from text are what refuse.

Each call passes the required parameters only, positional and
keyword-only, and every one of them wrong at once. Whichever the
function refuses first, the rule says how it must refuse it, and the
call needs no valid value, which is what makes the walk need no list of
functions. `_WRONG_TYPE` and `_WRONG_VALUE` give the wrong values by the
annotation of the parameter, as the signature spells it.

## Where it fails loudly

A required parameter whose annotation is in neither vocabulary fails
`test_every_public_function_is_driven`, naming the function and the
annotation: the fix is a wrong type and a wrong value for it. A function
no round drives fails `test_no_public_function_escapes_both_rounds`,
unless `_NOT_DRIVEN` names it, its reason beside it. A key no public function
uses any more fails `test_the_vocabulary_is_in_use`.

## What it does not reach

A type every value of which is valid has no wrong value: a reader, a
prompt, a list of passphrases, a record `dumps` writes. A function taking
one is driven in the type round only. `object` has no wrong type, so a
function taking one is driven in the value round only.

A parameter with a default is never driven, since reaching it needs
valid arguments before it, so a function with no required parameter is
driven by neither round. A method needs
an instance the vocabulary does not build, and is not driven here
(btclib-org/seed-scan#42).
"""

from __future__ import annotations

import dataclasses
import inspect
from functools import partial
from types import ModuleType
from typing import TYPE_CHECKING, Any

import pytest

import seed_scan
from seed_scan.exceptions import SeedScanException, SeedScanTypeError

from . import published

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

# a value of no type the annotation declares: a call mypy refuses, bar the
# bool, which mypy takes for an int and this package refuses where an int
# is asked for. The tuples are read round-robin, so that a function taking
# three parameters of one type is called with three different values.
# Constants and not a strategy: a run must report what the last one did
_WRONG_TYPE: dict[str, tuple[Any, ...]] = {
    "str": (None, 1.5, b"text"),
    "int": (None, 1.5, "0", True),
    # every value is an object
    "object": (),
    "Sequence[str]": (None, 1.5),
    "Callable[[str], str]": (None, 1.5),
    "HistoryReader": (None, 1.5),
    # None is a reader's declared absence
    "HistoryReader | None": (1.5, "reader"),
    "Bundle": (None, "{}"),
    "ForksResult": (None, "{}"),
    "ScanResult": (None, "{}"),
}

# a value of the declared type that no valid input carries. Each of these
# type checks, which is what puts it here rather than above
_WRONG_VALUE: dict[str, tuple[Any, ...]] = {
    # not JSON, a URL, host:port or a chain's name
    "str": ("not one of them",),
    # below the first passphrase number, past what a reason reads back, and
    # past what `str` converts
    "int": (-1, 10**9, 10**5000),
    # a quantity is 0x and hex digits with no leading zero
    "object": ("zz", "0x01"),
    # every list of passphrases is one to try, and every prompt one to ask
    "Sequence[str]": (),
    "Callable[[str], str]": (),
    # a reader is asked, and what it answers is checked as it is read
    "HistoryReader": (),
    "HistoryReader | None": (),
    # `dumps` writes the record it is given; `loads` is what checks
    "Bundle": (),
    "ForksResult": (),
    "ScanResult": (),
}


def _is_driven(obj: object) -> bool:
    """Answer whether a published object is a call this walk drives."""
    if inspect.isfunction(obj):
        return True
    return (
        inspect.isclass(obj)
        and not issubclass(obj, BaseException)
        and not dataclasses.is_dataclass(obj)
    )


def _required(function: Callable[..., Any]) -> list[inspect.Parameter]:
    """Return a callable's parameters that carry no default."""
    return [
        parameter
        for parameter in inspect.signature(function).parameters.values()
        if parameter.default is inspect.Parameter.empty
    ]


_CALLABLES = {
    f"{module}.{name}": obj
    for module, name, obj in published(seed_scan)
    if _is_driven(obj)
}

# what neither round drives, by dotted name, with the reason. A function
# whose parameters all carry a default is the shape that lands here
_NOT_DRIVEN = {
    # the command line, whose one parameter stands for sys.argv: argparse
    # answers a wrong argument with a usage line and exit status 2
    "seed_scan.cli.main",
}


def _calls(
    dotted: str, vocabulary: dict[str, tuple[Any, ...]]
) -> Iterator[Callable[[], Any]]:
    """Yield one prepared call per round, every argument wrong at once.

    The vocabulary is what tells the two rules apart: the same walk, the
    same function, two kinds of wrong value.
    """
    function = _CALLABLES[dotted]
    parameters = _required(function)
    wrong = [vocabulary[str(p.annotation)] for p in parameters]
    for round_ in range(max(len(values) for values in wrong)):
        args = [values[round_ % len(values)] for values in wrong]
        positional = [
            arg
            for p, arg in zip(parameters, args, strict=True)
            if p.kind is not inspect.Parameter.KEYWORD_ONLY
        ]
        keywords = {
            p.name: arg
            for p, arg in zip(parameters, args, strict=True)
            if p.kind is inspect.Parameter.KEYWORD_ONLY
        }
        # partial and not a lambda, which would read the loop's variables
        # on a later round
        yield partial(function, *positional, **keywords)


def _driven_by(
    vocabulary: dict[str, tuple[Any, ...]], callables: dict[str, Any]
) -> list[str]:
    """Return the functions every required parameter of which has a value.

    A function with a parameter of an annotation the vocabulary does not
    hold is left out here and reported by the test below.
    """
    return sorted(
        dotted
        for dotted, function in callables.items()
        if (annotations := [str(p.annotation) for p in _required(function)])
        and all(vocabulary.get(annotation) for annotation in annotations)
    )


@pytest.mark.parametrize("dotted", _driven_by(_WRONG_TYPE, _CALLABLES))
def test_a_wrong_type_leaves_as_a_type_error_of_the_package(dotted: str) -> None:
    """The first rule.

    `SeedScanTypeError` and not the base: a bare `TypeError` fails here,
    as a `SeedScanValueError` does. The first is a leak from underneath
    the package, the second the package calling a caller's mistake a
    fact about the input.
    """
    for call in _calls(dotted, _WRONG_TYPE):
        with pytest.raises(SeedScanTypeError):
            call()


@pytest.mark.parametrize("dotted", _driven_by(_WRONG_VALUE, _CALLABLES))
def test_a_wrong_value_leaves_as_an_exception_of_the_package(dotted: str) -> None:
    """The second rule: the base, which is the contract a caller is given."""
    for call in _calls(dotted, _WRONG_VALUE):
        with pytest.raises(SeedScanException):
            call()


@pytest.mark.parametrize("dotted", sorted(_CALLABLES))
def test_every_public_function_is_driven(dotted: str) -> None:
    """Every published call is driven by a round, or takes nothing required.

    A parameter of an annotation in neither vocabulary is the way a
    function published later would escape both rounds, so it fails here.
    """
    annotations = [str(p.annotation) for p in _required(_CALLABLES[dotted])]
    unknown = [a for a in annotations if a not in _WRONG_TYPE]
    assert not unknown, (
        f"{dotted} takes {', '.join(unknown)}, which the vocabularies do not"
        " hold: add a wrong type and a wrong value for it"
    )


def _undriven(callables: dict[str, Any]) -> list[str]:
    """Return the callables neither round drives, `_NOT_DRIVEN` included."""
    driven = {*_driven_by(_WRONG_TYPE, callables), *_driven_by(_WRONG_VALUE, callables)}
    return sorted(set(callables) - driven)


def test_no_public_function_escapes_both_rounds() -> None:
    """What neither round calls is named, with its reason, or it fails.

    A function whose parameters all carry a default is called by neither
    round, and without this it would pass every test here untested. An
    entry `_NOT_DRIVEN` keeps for a function a round now drives, or one
    no longer published, fails too.
    """
    assert set(_undriven(_CALLABLES)) == _NOT_DRIVEN


def test_an_undriven_function_is_reported() -> None:
    """The check above, on a function with no required parameter.

    Compiled from a string, so that its body, never called, is not code
    the suite's coverage reads.
    """
    namespace: dict[str, Any] = {}
    exec(  # noqa: S102 -- a literal, compiled for its signature
        "def new_function(text: str = '') -> None: ...\n", namespace
    )
    new_function = namespace["new_function"]
    assert _undriven({"m.new_function": new_function}) == ["m.new_function"]


def test_the_vocabulary_is_in_use() -> None:
    """Both vocabularies hold the annotations the public functions take.

    Every key has a value of one kind at least, or it drives nothing, and
    a key no required parameter carries is one left behind.
    """
    used = {
        str(p.annotation)
        for function in _CALLABLES.values()
        for p in _required(function)
    }
    assert set(_WRONG_TYPE) == set(_WRONG_VALUE) == used
    assert all(_WRONG_TYPE[key] or _WRONG_VALUE[key] for key in used)


def test_the_walk_reaches_what_it_claims() -> None:
    """The shapes the walk must find, and those it must leave out.

    A walk that found nothing would pass every test above: a function,
    a constructor, a keyword-only parameter it must pass by name, and a
    parameter with a default it must leave alone. Out: a dataclass, an
    exception and a constant.
    """
    assert "seed_scan.bundle.loads" in _CALLABLES
    assert "seed_scan.evm.Node" in _CALLABLES
    assert [p.name for p in _required(_CALLABLES["seed_scan.forks.forks"])] == [
        "text",
        "reader",
        "chain",
        "server",
    ]
    assert [p.name for p in _required(_CALLABLES["seed_scan.report.report"])] == [
        "bundle"
    ]

    assert "seed_scan.bundle.Bundle" not in _CALLABLES
    assert "seed_scan.exceptions.SeedScanValueError" not in _CALLABLES
    assert "seed_scan.scan.VERSION" not in _CALLABLES
    assert "seed_scan.evm.quantity" not in _driven_by(_WRONG_TYPE, _CALLABLES)
    assert "seed_scan.forks.forks" not in _driven_by(_WRONG_VALUE, _CALLABLES)


def test_the_walk_descends_into_a_published_subpackage() -> None:
    """A function published at any depth is reached, as the lists publish it.

    Measured on modules built here: the package publishes no subpackage
    yet, and one added later is the case this guards. A module no list
    names is not reached.
    """
    root, child, grand, hidden = (
        ModuleType(name)
        for name in ("root", "root.child", "root.child.grand", "root.hidden")
    )
    root.__all__ = ["child"]  # type: ignore[attr-defined]
    child.__all__ = ["grand"]  # type: ignore[attr-defined]
    grand.__all__ = ["new_function"]  # type: ignore[attr-defined]
    hidden.__all__ = ["elsewhere"]  # type: ignore[attr-defined]
    root.child = child  # type: ignore[attr-defined]
    root.hidden = hidden  # type: ignore[attr-defined]
    child.grand = grand  # type: ignore[attr-defined]
    grand.new_function = len  # type: ignore[attr-defined]
    hidden.elsewhere = len  # type: ignore[attr-defined]
    assert list(published(root)) == [("root.child.grand", "new_function", len)]
