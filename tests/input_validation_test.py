# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Every public function refuses what it does not declare, as the package.

CONTRIBUTING.md's *The public surface* states the rule: a refusal is a
`SeedScanTypeError` or a `SeedScanValueError`. This module drives two
kinds of wrong value:

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
readers that build one from text are what refuse. A public method of
such a class that takes an argument, an inherited one included, is
called on the instance `_INSTANCES` builds.

Two rounds pass the required parameters only, positional and
keyword-only, and every one of them wrong at once. Whichever the
function refuses first, the rule says how it must refuse it, and the
call needs no valid value, which is what makes these rounds need no
list of functions. They drive only the parameter a function checks
first, so a third round makes one parameter wrong at a time, a
parameter with a default included, the others taking the valid call
`_VALID` gives.

`_WRONG_TYPE` and `_WRONG_VALUE` give the wrong values by the
annotation of the parameter, as the signature spells it. A bound of a
search has no upper limit, so the third round gives it `_WRONG_BOUND`
for its wrong values.

## Where it fails loudly

A parameter whose annotation is in neither vocabulary fails
`test_every_public_function_is_driven`, naming the function and the
annotation: the fix is a wrong type and a wrong value for it. A function
no round drives fails `test_no_public_function_escapes_the_rounds`,
unless `_NOT_DRIVEN` names it, its reason beside it, and one `_VALID`
does not hold fails `test_every_driven_function_has_a_valid_call`. A
method of a class `_INSTANCES` cannot build fails
`test_every_method_has_an_instance`. A key no public function uses any
more fails `test_the_vocabulary_is_in_use`.

`_NOT_REFUSED` names each parameter the third round finds answering,
or refusing as another package, with the issue that tracks it. An entry
fails once its parameter is refused as the rule says, so it goes with
the fix. `_ANSWERED` names a wrong value a function answers as its
docstring says, and fails once the function refuses it.

## What it does not reach

A type every value of which is valid has no wrong value: a reader, a
prompt, a list of passphrases, a record `dumps` writes. A parameter of
one is driven with wrong types only. `object` has no wrong type, so a
parameter of it is driven with wrong values only. A method taking no
argument has no input to refuse.
"""

from __future__ import annotations

import dataclasses
import inspect
import math
from functools import partial
from types import ModuleType
from typing import TYPE_CHECKING, Any, NamedTuple

import pytest

import seed_scan
from seed_scan import forks as forks_module
from seed_scan import scan as scan_module
from seed_scan.bundle import dumps as bundle_dumps
from seed_scan.bundle import loads as bundle_loads
from seed_scan.evm import Node
from seed_scan.exceptions import SeedScanException, SeedScanTypeError
from seed_scan.identify import identify

from . import published
from .evm_test import MIXED, Ethereum
from .identify_test import ABANDON, no_share
from .scan_test import Chain

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

# a value of no type the annotation declares: a call mypy refuses, bar the
# bool, which mypy takes for an int and this package refuses where an int
# is asked for, and the lone str, which mypy takes for a sequence of its
# characters. The tuples are read round-robin, so that a function taking
# three parameters of one type is called with three different values.
# Constants and not a strategy: a run must report what the last one did
_WRONG_TYPE: dict[str, tuple[Any, ...]] = {
    "str": (None, 1.5, b"text"),
    # None is the declared absence of each `| None`
    "str | None": (1.5, b"text"),
    "int": (None, 1.5, "0", True),
    "float": (None, "30"),
    # every value is an object
    "object": (),
    "Sequence[str]": (None, 1.5, "text", [None]),
    "Callable[[str], str]": (None, 1.5),
    "Callable[[Request, float], tuple[int, bytes]]": (None, 1.5),
    "HistoryReader": (None, 1.5),
    "HistoryReader | None": (1.5, "reader"),
    "Node | None": (1.5, "node"),
    "Bundle": (None, "{}"),
    "ForksResult": (None, "{}"),
    "ScanResult": (None, "{}"),
}

# a value of the declared type that no valid input carries. Each of these
# type checks, which is what puts it here rather than above
_WRONG_VALUE: dict[str, tuple[Any, ...]] = {
    # not JSON, a URL, host:port, a chain's name or an address
    "str": ("not one of them",),
    "str | None": ("not one of them",),
    # below the first passphrase number, past what a reason reads back, and
    # past what `str` converts
    "int": (-1, 10**9, 10**5000),
    # no time a request waits
    "float": (-1.0, math.nan),
    # a quantity is 0x and hex digits with no leading zero
    "object": ("zz", "0x01"),
    # every list of passphrases is one to try, and every prompt one to ask
    "Sequence[str]": (),
    "Callable[[str], str]": (),
    # a transport, a reader and a node are asked, and what they answer is
    # checked as it is read
    "Callable[[Request, float], tuple[int, bytes]]": (),
    "HistoryReader": (),
    "HistoryReader | None": (),
    "Node | None": (),
    # `dumps` writes the record it is given; `loads` is what checks
    "Bundle": (),
    "ForksResult": (),
    "ScanResult": (),
}

# the parameters that bound a search, each an int from 1 with no upper
# limit: the large ints `_WRONG_VALUE` gives are valid there, and a search
# that long would not end
_BOUNDS = frozenset({"accounts", "account_gap", "gap_limit", "indexes"})
_WRONG_BOUND = (0, -1)


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


def _methods(
    classes: dict[str, type],
) -> Iterator[tuple[str, str]]:
    """Yield each public method that takes an argument, as class and name.

    A method a class inherits is its own, whether or not its base is
    published, and the first definition along the MRO is the one it has.
    A static method takes its arguments from the first, any other method
    from the one after the instance or the class.
    """
    for dotted, cls in classes.items():
        members: dict[str, object] = {}
        for base in cls.__mro__:
            if base is not object:
                members = {**vars(base), **members}
        for attr, member in members.items():
            function = getattr(member, "__func__", member)
            if attr.startswith("_") or not inspect.isfunction(function):
                continue
            first = 0 if isinstance(member, staticmethod) else 1
            if list(inspect.signature(function).parameters)[first:]:
                yield dotted, attr


_DRIVEN = {
    f"{module}.{name}": obj
    for module, name, obj in published(seed_scan)
    if _is_driven(obj)
}

# an instance of each class whose methods are driven, by dotted name. The
# node's transport answers in memory, so no method opens a socket
_INSTANCES: dict[str, Callable[[], object]] = {
    "seed_scan.evm.Node": lambda: Node(
        "https://node.example/rpc", transport=Ethereum()
    ),
}

_CALLABLES: dict[str, Any] = {
    **_DRIVEN,
    **{
        f"{dotted}.{attr}": getattr(_INSTANCES[dotted](), attr)
        for dotted, attr in _methods(
            {d: c for d, c in _DRIVEN.items() if inspect.isclass(c)}
        )
        if dotted in _INSTANCES
    },
}

# what no round drives, by dotted name, with the reason. A function
# whose parameters all carry a default is the shape that lands here
_NOT_DRIVEN = {
    # the command line, whose one parameter stands for sys.argv: argparse
    # answers a wrong argument with a usage line and exit status 2, and an
    # argv that is no sequence is btclib-org/seed-scan#46
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


@pytest.mark.parametrize("dotted", sorted(set(_CALLABLES) - _NOT_DRIVEN))
def test_every_public_function_is_driven(dotted: str) -> None:
    """Every parameter of a driven call has wrong values to be driven with.

    A parameter of an annotation in neither vocabulary is the way a
    function published later would escape the rounds, so it fails here.
    """
    parameters = inspect.signature(_CALLABLES[dotted]).parameters.values()
    unknown = [
        str(p.annotation) for p in parameters if str(p.annotation) not in _WRONG_TYPE
    ]
    assert not unknown, (
        f"{dotted} takes {', '.join(unknown)}, which the vocabularies do not"
        " hold: add a wrong type and a wrong value for it"
    )


class _Texts(NamedTuple):
    """A bundle, and a scan result and a forks result made from it."""

    bundle: str
    scanned: str
    forked: str


@pytest.fixture(scope="module")
def texts() -> _Texts:
    """Return the texts the valid calls read, one account of each purpose.

    A fixture and not a constant: the bundle is derived from a mnemonic,
    which collecting this module does not need.
    """
    bundle = bundle_dumps(identify(ABANDON, [""], no_share, accounts=1))
    scanned = scan_module.scan(bundle, Chain(), server="h:1")
    forked = forks_module.forks(bundle, Chain(), chain="bitcoin-cash", server="h:1")
    return _Texts(bundle, scan_module.dumps(scanned), forks_module.dumps(forked))


# a call each driven function answers, by dotted name, its arguments by
# name: the third round makes one of them wrong at a time, or passes a
# parameter left out here with a wrong value in place of its default
_VALID: dict[str, Callable[[_Texts], dict[str, Any]]] = {
    "seed_scan.bundle.dumps": lambda t: {"bundle": bundle_loads(t.bundle)},
    "seed_scan.bundle.loads": lambda t: {"text": t.bundle},
    "seed_scan.bundle.slip39_passphrase": lambda _: {"number": 1},
    "seed_scan.evm.Node": lambda _: {"url": "https://node.example/rpc"},
    "seed_scan.evm.Node.balance": lambda _: {"address": MIXED},
    "seed_scan.evm.Node.nonce": lambda _: {"address": MIXED},
    "seed_scan.evm.quantity": lambda _: {"value": "0x1"},
    "seed_scan.forks.dumps": lambda t: {
        "result": forks_module.loads(t.forked, t.bundle)
    },
    "seed_scan.forks.forks": lambda t: {
        "text": t.bundle,
        "reader": Chain(),
        "chain": "bitcoin-cash",
        "server": "h:1",
    },
    "seed_scan.forks.loads": lambda t: {"text": t.forked, "bundle": t.bundle},
    "seed_scan.identify.identify": lambda _: {
        "mnemonic": ABANDON,
        "passphrases": [""],
        "prompt": no_share,
        "accounts": 1,
        "indexes": 1,
    },
    "seed_scan.report.report": lambda t: {"bundle": t.bundle},
    "seed_scan.scan.dumps": lambda t: {
        "result": scan_module.loads(t.scanned, t.bundle)
    },
    "seed_scan.scan.loads": lambda t: {"text": t.scanned, "bundle": t.bundle},
    "seed_scan.scan.parse_server": lambda _: {"text": "h:1", "name": "server"},
    "seed_scan.scan.scan": lambda t: {
        "text": t.bundle,
        "reader": Chain(),
        "server": "h:1",
    },
}

# a parameter the third round finds answering a wrong value, or refusing
# it as another package does, by dotted name, parameter and round, each
# with the issue that tracks it
_NOT_REFUSED = {
    # btclib-org/seed-scan#61
    ("seed_scan.evm.Node", "transport", "type"),
    ("seed_scan.evm.Node", "timeout", "type"),
    ("seed_scan.evm.Node", "timeout", "value"),
    # btclib-org/seed-scan#62
    ("seed_scan.forks.forks", "reader", "type"),
    ("seed_scan.scan.scan", "reader", "type"),
    ("seed_scan.scan.scan", "node", "type"),
    # btclib-org/seed-scan#63
    ("seed_scan.identify.identify", "address", "type"),
    ("seed_scan.identify.identify", "passphrases", "type"),
    ("seed_scan.identify.identify", "prompt", "type"),
}

# a wrong value a function answers, by dotted name and parameter, as its
# docstring says
_ANSWERED = {
    # a sentence no scheme claims is a bundle claiming none
    ("seed_scan.identify.identify", "mnemonic"),
    # a text that is no address is a search recording that it is none
    ("seed_scan.identify.identify", "address"),
    # what names the server in a refusal, any text
    ("seed_scan.scan.parse_server", "name"),
}


def _alone(vocabulary: dict[str, tuple[Any, ...]]) -> list[tuple[str, str]]:
    """Return each parameter of a valid call the vocabulary has values for.

    A valid call of no published function is left to
    `test_every_driven_function_has_a_valid_call`, which names it.
    """
    return sorted(
        (dotted, p.name)
        for dotted in set(_VALID) & set(_CALLABLES)
        for p in inspect.signature(_CALLABLES[dotted]).parameters.values()
        if vocabulary.get(str(p.annotation))
    )


def _outcomes(
    dotted: str, name: str, vocabulary: dict[str, tuple[Any, ...]], texts: _Texts
) -> list[type[Exception] | None]:
    """Return what each wrong value of one parameter alone ends in.

    The class of what the call raised, or None where it answered.
    """
    parameter = inspect.signature(_CALLABLES[dotted]).parameters[name]
    wrong = vocabulary[str(parameter.annotation)]
    if vocabulary is _WRONG_VALUE and name in _BOUNDS:
        wrong = _WRONG_BOUND
    outcomes: list[type[Exception] | None] = []
    for value in wrong:
        try:
            _CALLABLES[dotted](**{**_VALID[dotted](texts), name: value})
        except Exception as error:  # noqa: BLE001 -- the class is the answer
            outcomes.append(type(error))
        else:
            outcomes.append(None)
    return outcomes


def _refused(outcomes: list[type[Exception] | None], kind: type[Exception]) -> bool:
    """Answer whether every outcome is a refusal of that class."""
    return all(o is not None and issubclass(o, kind) for o in outcomes)


@pytest.mark.parametrize("dotted, name", _alone(_WRONG_TYPE))
def test_a_wrong_type_alone_leaves_as_a_type_error_of_the_package(
    dotted: str, name: str, texts: _Texts
) -> None:
    """The first rule, a parameter at a time; or its entry, while it holds."""
    refused = _refused(_outcomes(dotted, name, _WRONG_TYPE, texts), SeedScanTypeError)
    assert refused is ((dotted, name, "type") not in _NOT_REFUSED)


@pytest.mark.parametrize("dotted, name", _alone(_WRONG_VALUE))
def test_a_wrong_value_alone_leaves_as_an_exception_of_the_package(
    dotted: str, name: str, texts: _Texts
) -> None:
    """The second rule, a parameter at a time; or its entry, while it holds."""
    outcomes = _outcomes(dotted, name, _WRONG_VALUE, texts)
    if (dotted, name) in _ANSWERED:
        assert outcomes == [None] * len(outcomes)
    else:
        refused = _refused(outcomes, SeedScanException)
        assert refused is ((dotted, name, "value") not in _NOT_REFUSED)


@pytest.mark.parametrize("dotted", sorted(_VALID))
def test_each_valid_call_is_answered(dotted: str, texts: _Texts) -> None:
    """A valid call that failed would make every refusal above vacuous."""
    _CALLABLES[dotted](**_VALID[dotted](texts))


def test_every_driven_function_has_a_valid_call() -> None:
    """A function published later fails here until its valid call is written.

    An entry for a function no longer published, or one `_NOT_DRIVEN`
    names, fails too.
    """
    assert set(_VALID) == set(_CALLABLES) - _NOT_DRIVEN


def test_the_entries_name_parameters_the_third_round_drives() -> None:
    """An entry for a parameter renamed, or no longer driven, fails here."""
    driven = {
        (dotted, name, kind)
        for kind, vocabulary in (("type", _WRONG_TYPE), ("value", _WRONG_VALUE))
        for dotted, name in _alone(vocabulary)
    }
    assert driven >= _NOT_REFUSED
    assert driven >= {(dotted, name, "value") for dotted, name in _ANSWERED}


def test_every_method_has_an_instance() -> None:
    """A class whose methods take an argument is built, or they escape."""
    classes = {d: c for d, c in _DRIVEN.items() if inspect.isclass(c)}
    assert {dotted for dotted, _ in _methods(classes)} == set(_INSTANCES)


def _undriven(callables: dict[str, Any]) -> list[str]:
    """Return the callables no round drives, `_NOT_DRIVEN` included."""
    driven = {
        *_driven_by(_WRONG_TYPE, callables),
        *_driven_by(_WRONG_VALUE, callables),
        *_VALID,
    }
    return sorted(set(callables) - driven)


def test_no_public_function_escapes_the_rounds() -> None:
    """What no round calls is named, with its reason, or it fails.

    A function whose parameters all carry a default is called by neither
    of the first two rounds, and by the third only where `_VALID` holds
    it: without this it would pass every test here untested. An entry
    `_NOT_DRIVEN` keeps for a function a round now drives, or one no
    longer published, fails too.
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
    a key no driven parameter carries is one left behind. So is a bound
    no driven parameter is named by.
    """
    parameters = [
        p
        for dotted, function in _CALLABLES.items()
        if dotted not in _NOT_DRIVEN
        for p in inspect.signature(function).parameters.values()
    ]
    used = {str(p.annotation) for p in parameters}
    assert set(_WRONG_TYPE) == set(_WRONG_VALUE) == used
    assert all(_WRONG_TYPE[key] or _WRONG_VALUE[key] for key in used)
    assert {p.name for p in parameters if str(p.annotation) == "int"} >= _BOUNDS


def test_the_walk_reaches_what_it_claims() -> None:
    """The shapes the walk must find, and those it must leave out.

    A walk that found nothing would pass every test above: a function,
    a constructor, a method, a keyword-only parameter it must pass by
    name, and a parameter with a default the first two rounds must leave
    alone. Out: a dataclass, an exception, a constant, a property and a
    method taking no argument.
    """
    assert "seed_scan.bundle.loads" in _CALLABLES
    assert "seed_scan.evm.Node" in _CALLABLES
    assert "seed_scan.evm.Node.balance" in _CALLABLES
    assert "seed_scan.evm.Node.name" not in _CALLABLES
    assert "seed_scan.evm.Node.chain_id" not in _CALLABLES
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


def test_the_methods_walked_are_those_taking_an_argument() -> None:
    """Each shape of method, measured on a class compiled from a string.

    From a string, so that its bodies, never called, are not code the
    suite's coverage reads.
    """
    namespace: dict[str, Any] = {}
    exec(  # noqa: S102 -- a literal, compiled for its signatures
        "class Shapes:\n"
        "    def __init__(self, x: int) -> None: ...\n"
        "    def takes(self, x: int) -> None: ...\n"
        "    def takes_none(self) -> None: ...\n"
        "    @staticmethod\n"
        "    def static(x: int) -> None: ...\n"
        "    @staticmethod\n"
        "    def static_none() -> None: ...\n"
        "    @classmethod\n"
        "    def of(cls, x: int) -> None: ...\n"
        "    @property\n"
        "    def value(self) -> int: ...\n"
        "    def _private(self, x: int) -> None: ...\n",
        namespace,
    )
    assert list(_methods({"m.Shapes": namespace["Shapes"]})) == [
        ("m.Shapes", "takes"),
        ("m.Shapes", "static"),
        ("m.Shapes", "of"),
    ]


def test_an_inherited_method_is_walked_as_the_class_has_it() -> None:
    """A base no list publishes, and an override shadowing its base's method.

    From a string, as the test above, for the same reason.
    """
    namespace: dict[str, Any] = {}
    exec(  # noqa: S102 -- a literal, compiled for its signatures
        "class Base:\n"
        "    def inherited(self, x: int) -> None: ...\n"
        "    def overridden(self, x: int) -> None: ...\n"
        "class Child(Base):\n"
        "    def overridden(self) -> None: ...\n",
        namespace,
    )
    assert list(_methods({"m.Child": namespace["Child"]})) == [("m.Child", "inherited")]


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


def test_a_module_publishing_itself_is_walked_once() -> None:
    """A cycle of one: the walk ends, and each name is yielded once."""
    root = ModuleType("root")
    root.__all__ = ["self", "new_function"]  # type: ignore[attr-defined]
    root.self = root  # type: ignore[attr-defined]
    root.new_function = len  # type: ignore[attr-defined]
    assert list(published(root)) == [("root", "new_function", len)]


def test_two_modules_publishing_each_other_are_walked_once() -> None:
    """A cycle of two: each module is walked once, from wherever it is met."""
    first, second = ModuleType("first"), ModuleType("second")
    first.__all__ = ["second", "one"]  # type: ignore[attr-defined]
    second.__all__ = ["first", "two"]  # type: ignore[attr-defined]
    first.second = second  # type: ignore[attr-defined]
    second.first = first  # type: ignore[attr-defined]
    first.one = len  # type: ignore[attr-defined]
    second.two = abs  # type: ignore[attr-defined]
    assert list(published(first)) == [("second", "two", abs), ("first", "one", len)]
