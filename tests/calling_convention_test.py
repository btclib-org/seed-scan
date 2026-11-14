# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The calling convention: keyword-only parameters, and what a name promises.

Section 7 of the organization's standard states the convention as
rules, and this module tests these over every public callable:

- **a keyword-only parameter stays keyword-only.** `*` in a signature is
  a promise, and a mutant of `*` to `/` breaks it while every call
  already written answers the same (btclib-org/btclib#980). `KEYWORD_ONLY`
  is the walk run once and recorded: recomputed by the test, it would
  read whatever a mutation had just done. A keyword-only parameter added
  to the surface fails the test until it is recorded;
- **a name's prefix promises what the call answers**: an `assert_*`
  answers None, and an `is_*`, a `check_*` or a name holding `verify` a
  bool; and a public bool carries one of them.

The rule that a private function carries no default is not tested here:
tests/README.md says why.

The walk is `tests/__init__.py`'s `published`: it starts at
`seed_scan.__all__` and descends through every module an `__all__`
publishes, at any depth, when the suite runs, so a callable published
later is walked without being listed here. A function is walked as
itself; a class as its `__init__` and each public function it has, a
property's getter included, inherited ones too, the first definition
along its MRO winning. An inherited method is walked where it is
defined, where that class is published, and otherwise under the first
published class that inherits it, so that each is walked once. A
method is a name its class defines, so an alias is walked under its own
name.
"""

from __future__ import annotations

import inspect
from types import ModuleType
from typing import TYPE_CHECKING, Any

import seed_scan

from . import published

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

# The walk, run on the commit this file is part of: every public callable
# that takes a keyword-only parameter, and those parameters in order
KEYWORD_ONLY: dict[str, list[str]] = {
    "seed_scan.cli:main": ["prompt", "forbid_network", "connect"],
    "seed_scan.evm:Node.__init__": ["transport", "timeout"],
    "seed_scan.forks:forks": ["chain", "server", "gap_limit", "account_gap"],
    "seed_scan.identify:identify": ["accounts", "address", "indexes"],
    "seed_scan.scan:scan": ["server", "node", "gap_limit", "account_gap"],
}

# what each prefix promises the return annotation is. `verify` is matched
# anywhere in the name, a `batch_verify` being a verification too
_PROMISED = {"assert_": "None", "check_": "bool", "is_": "bool", "verify": "bool"}


def _members(cls: type) -> dict[str, tuple[type, Any]]:
    """Return what a class has, by name, with the class that defines it.

    The first definition along the MRO is the one the class has; `object`
    defines nothing a published class owes.
    """
    members: dict[str, tuple[type, Any]] = {}
    for owner in cls.__mro__:
        if owner is not object:
            for attr, member in vars(owner).items():
                members.setdefault(attr, (owner, member))
    return members


def _callables(root: ModuleType) -> Iterator[tuple[str, Any]]:
    """Yield each public function, and each class's `__init__` and methods.

        What is neither, a constant or a module-level object, is passed over.
        A method, a name its defining class gives a function, is yielded once,
    under the class the module docstring says.
    """
    walked = list(published(root))
    classes = {id(obj) for _, _, obj in walked if inspect.isclass(obj)}
    yielded: set[tuple[type, str]] = set()
    for module, name, obj in walked:
        label = f"{module}:{name}"
        if inspect.isfunction(obj):
            yield label, obj
        elif inspect.isclass(obj):
            for attr, (owner, member) in _members(obj).items():
                # a static or class method is walked as its function
                function = (
                    member.fget
                    if isinstance(member, property)
                    else getattr(member, "__func__", member)
                )
                if not inspect.isfunction(function) or (
                    attr != "__init__" and attr.startswith("_")
                ):
                    continue
                # walked under its own class, which the walk reaches too
                if owner is not obj and id(owner) in classes:
                    continue
                if (owner, attr) not in yielded:
                    yielded.add((owner, attr))
                    yield f"{label}.{attr}", function


def _keyword_only() -> dict[str, list[str]]:
    """Recompute `KEYWORD_ONLY` from the tree under test."""
    return {
        label: names
        for label, function in _callables(seed_scan)
        if (
            names := [
                p.name
                for p in inspect.signature(function).parameters.values()
                if p.kind is inspect.Parameter.KEYWORD_ONLY
            ]
        )
    }


def _broken_promises(callables: Iterable[tuple[str, Any]]) -> list[str]:
    """Return each callable whose name and return annotation disagree.

    The annotation is read as the signature spells it, which is its text
    under `from __future__ import annotations`.
    """
    broken: list[str] = []
    for label, function in callables:
        name = label.rpartition(".")[2].rpartition(":")[2]
        answer = str(inspect.signature(function).return_annotation)
        promised = next(
            (
                kind
                for prefix, kind in _PROMISED.items()
                if name.startswith(prefix) or (prefix == "verify" and prefix in name)
            ),
            None,
        )
        if promised is None and answer == "bool":
            broken.append(f"{label} answers a bool, and its name promises nothing")
        elif promised not in {None, answer}:
            broken.append(f"{label} answers {answer}, and its name promises {promised}")
    return broken


def test_the_recorded_keyword_only_parameters_are_the_whole_of_them() -> None:
    """A new site, a removed one, a renamed parameter, a `*` turned `/`."""
    assert _keyword_only() == KEYWORD_ONLY


def test_every_name_keeps_its_prefix_promise() -> None:
    """The second rule, over every public callable."""
    assert not _broken_promises(_callables(seed_scan))


def test_the_promise_check_reads_every_shape() -> None:
    """What the check above is worth, measured on functions with known answers.

    No public name of this package carries a prefix today, so the check is
    measured here, on source compiled from a string, whose functions are
    never called.
    """
    namespace: dict[str, Any] = {}
    exec(  # noqa: S102 -- a literal, compiled for its signatures
        "from __future__ import annotations\n"
        "def assert_ok() -> None: ...\n"
        "def assert_bad() -> bool: ...\n"
        "def is_ok() -> bool: ...\n"
        "def is_bad() -> int: ...\n"
        "def check_bad() -> None: ...\n"
        "def batch_verify_bad() -> str: ...\n"
        "def plain_bool() -> bool: ...\n"
        "def plain() -> int: ...\n",
        namespace,
    )
    functions = [(f"m:{n}", f) for n, f in namespace.items() if inspect.isfunction(f)]
    assert _broken_promises(functions) == [
        "m:assert_bad answers bool, and its name promises None",
        "m:is_bad answers int, and its name promises bool",
        "m:check_bad answers None, and its name promises bool",
        "m:batch_verify_bad answers str, and its name promises bool",
        "m:plain_bool answers a bool, and its name promises nothing",
    ]


def test_the_walk_reaches_what_it_claims() -> None:
    """A function, a constructor, a method and a property; private names out.

    A walk that missed one of these shapes would pass the tests above
    wherever the surface holds no site of that shape.
    """
    labels = {label for label, _ in _callables(seed_scan)}
    assert "seed_scan.bundle:loads" in labels
    assert "seed_scan.evm:Node.__init__" in labels
    assert "seed_scan.evm:Node.balance" in labels
    assert "seed_scan.evm:Node.name" in labels
    assert "seed_scan.bundle:Bundle.__init__" in labels
    assert "seed_scan.evm:Node._call" not in labels
    assert "seed_scan.exceptions:SeedScanTypeError.__init__" not in labels


def test_an_inherited_method_is_walked_once_as_the_class_has_it() -> None:
    """A base no list publishes, one a list does, and an override.

    Measured on a module built here, its classes compiled from a string,
    so that their bodies, never called, are not code the suite's coverage
    reads. `Hidden` is published by no list: its `inherited` is walked
    under `Child`, the first class that inherits it, and not again under
    `Sibling`. `Child` overrides `overridden`, so `Hidden`'s is walked
    under `Sibling`, which has it. `Base` is published: its method is
    walked there alone, not under `Derived`.
    """
    namespace: dict[str, Any] = {}
    exec(  # noqa: S102 -- a literal, compiled for its signatures
        "class Hidden:\n"
        "    def inherited(self, *, key: int) -> None: ...\n"
        "    def overridden(self, *, key: int) -> None: ...\n"
        "class Child(Hidden):\n"
        "    def overridden(self, *, other: int) -> None: ...\n"
        "class Sibling(Hidden): ...\n"
        "class Base:\n"
        "    def shared(self, *, key: int) -> None: ...\n"
        "class Derived(Base): ...\n",
        namespace,
    )
    root = ModuleType("root")
    root.__all__ = ["Child", "Sibling", "Derived", "Base"]  # type: ignore[attr-defined]
    for name in root.__all__:
        setattr(root, name, namespace[name])
    walked = {
        label: [p.name for p in inspect.signature(f).parameters.values()][1:]
        for label, f in _callables(root)
    }
    assert walked == {
        "root:Child.inherited": ["key"],
        "root:Child.overridden": ["other"],
        "root:Sibling.overridden": ["key"],
        "root:Base.shared": ["key"],
    }


def test_an_alias_is_walked_under_its_own_name() -> None:
    """Two names of one function are two methods, each held to its promise.

    `bad` is `is_ok` under a name that promises nothing. `Derived`
    inherits both from `Hidden`, which no list publishes, and each is
    walked under `Derived`, so the broken promise is reported.
    """
    namespace: dict[str, Any] = {}
    exec(  # noqa: S102 -- a literal, compiled for its signatures
        "from __future__ import annotations\n"
        "class Hidden:\n"
        "    def is_ok(self) -> bool: ...\n"
        "    bad = is_ok\n"
        "class Derived(Hidden): ...\n",
        namespace,
    )
    root = ModuleType("root")
    root.__all__ = ["Derived"]  # type: ignore[attr-defined]
    root.Derived = namespace["Derived"]  # type: ignore[attr-defined]
    assert [label for label, _ in _callables(root)] == [
        "root:Derived.is_ok",
        "root:Derived.bad",
    ]
    assert _broken_promises(_callables(root)) == [
        "root:Derived.bad answers a bool, and its name promises nothing"
    ]
