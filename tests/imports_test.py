# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the import graph of the `seed_scan` package.

Every module must be importable *first*, with no other module of this
package in sys.modules yet. Nothing else in the suite establishes that: a
test module reaches its subject through whatever the modules imported
before it have already pulled in, so a cycle that only bites the caller
who happens to arrive from the other side stays invisible.

What a module may import is the standard library, this package and the
packages `dependencies` in pyproject.toml declares: each module is asked
in an interpreter of its own at run time, where what it loads may also
be what those packages require, and each file's import statements are
read statically, which is what a module the suite never imports is
checked by.
"""

from __future__ import annotations

import ast
import importlib
import importlib.metadata
import subprocess
import sys
from functools import cache
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

import seed_scan

from . import module_names

if TYPE_CHECKING:
    from collections.abc import Iterator

_ROOT = Path(__file__).resolve().parents[1]


def _is_ours(name: str) -> bool:
    """Answer whether a dotted name is this package or one of its modules.

    `seed_scan.` and not a bare `startswith`, which would also take
    in a sibling distribution whose name merely begins the same way.
    """
    return name == "seed_scan" or name.startswith("seed_scan.")


def loaded_modules() -> list[str]:
    """Return the modules of this package in sys.modules."""
    return [name for name in sys.modules if _is_ours(name)]


@pytest.fixture
def unimported() -> Iterator[None]:
    """Hide every module of this package, then put it back.

    A subprocess per module would be the obvious way to get a virgin
    interpreter, and it costs an interpreter start-up per module for
    nothing: the import machinery decides what to execute by consulting
    sys.modules and nothing else.

    What the modules imported inside the fixture must not do is outlive
    it. They are fresh objects, so a class reimported here is not the
    class the rest of the suite already holds a reference to, and an
    isinstance check across the two would fail.
    """
    saved = {name: sys.modules[name] for name in loaded_modules()}
    for name in saved:
        del sys.modules[name]
    try:
        yield
    finally:
        for name in loaded_modules():
            del sys.modules[name]
        sys.modules.update(saved)


@pytest.mark.parametrize("module_name", module_names())
def test_import_first(module_name: str, unimported: None) -> None:
    """Import each module first, with nothing of this package loaded."""
    assert importlib.import_module(module_name).__name__ == module_name


def _loaded_after_importing(module_name: str) -> list[str]:
    """Import one module in a fresh interpreter and return sorted(sys.modules).

    A fresh subprocess rather than `unimported`: that fixture only hides
    this package's own modules from `sys.modules`, so a third-party
    package an earlier test already imported would still answer present,
    and the absence this module exists to prove would mean nothing.
    """
    probe = f"import {module_name}, sys; print(sorted(sys.modules))"
    stdout = subprocess.run(  # noqa: S603
        [sys.executable, "-c", probe],
        check=True,
        capture_output=True,
        encoding="utf-8",
        cwd=_ROOT,
    ).stdout
    return cast("list[str]", ast.literal_eval(stdout))


def test_the_tests_package_imports_no_submodule() -> None:
    """Importing the `tests` package alone reaches the root and no further.

    `tests/__init__.py` is imported by every test module before that
    module's own body runs -- before any fixture, `unimported` included,
    so this probe is a subprocess rather than that fixture. The coverage
    floor reads what the import itself reaches, so a helper built at the
    module scope of `tests/__init__.py` would be measured as reached by
    every module that asks it nothing.
    """
    loaded = _loaded_after_importing("tests")
    assert [m for m in loaded if _is_ours(m)] == ["seed_scan"]


# the modules of one interpreter that were loaded from where an installer
# puts a distribution, by name: `__file__` under a directory called
# `site-packages` or `dist-packages`, or under the purelib or the platlib
# directory. The directory name is what finds a package that `uv run --with`
# layers over the environment: it sits in a site-packages directory that
# `sysconfig` does not name. Keyed on the file and not on
# `sys.stdlib_module_names`: the standard library's directory holds
# modules the list does not name, as the `_sysconfigdata_*` module,
# named after the platform, that the probe's own `sysconfig` call loads
_INSTALLED = """
import sys, sysconfig
from pathlib import Path
roots = {Path(sysconfig.get_paths()[key]).resolve() for key in ("purelib", "platlib")}
sites = {"site-packages", "dist-packages"}
def installed(module):
    file = getattr(module, "__file__", None)
    if file is None:
        return False
    path = Path(file)
    return bool(sites.intersection(path.parts)) or any(
        root in path.resolve().parents for root in roots
    )
print(sorted(name for name, module in list(sys.modules.items()) if installed(module)))
"""


def _installed_after_importing(module_name: str) -> set[str]:
    """Import one module in a fresh interpreter; return what was installed."""
    stdout = subprocess.run(  # noqa: S603
        [sys.executable, "-c", f"import {module_name}\n{_INSTALLED}"],
        check=True,
        capture_output=True,
        encoding="utf-8",
        cwd=_ROOT,
    ).stdout
    return set(cast("list[str]", ast.literal_eval(stdout)))


def _installed_by(module_name: str) -> list[str]:
    """Return the installed modules importing one module adds, ours aside.

    The difference from an interpreter that imported nothing, rather than
    the whole of `sys.modules`: site initialization loads modules of its
    own before `-c` runs -- a virtual environment's `_virtualenv`,
    setuptools' `_distutils_hack`, a namespace package's `.pth` -- and
    none of them is something this package imported.
    """
    added = _installed_after_importing(module_name) - _installed_after_importing("sys")
    return sorted(name for name in added if not _is_ours(name))


def _required(requirement: str, extras: set[str]) -> str | None:
    """Return the distribution a requirement names, where it applies.

    :param requirement: one line of a distribution's `Requires-Dist`.
    :param extras: the extras the distribution was asked for.
    :returns: the canonical name, or `None` where the marker excludes it.
    """
    parsed = Requirement(requirement)
    marker = parsed.marker
    if marker is None or any(marker.evaluate({"extra": e}) for e in {"", *extras}):
        return canonicalize_name(parsed.name)
    return None


@cache
def _declared() -> frozenset[str]:
    """Return the distributions `dependencies` declares, canonical names."""
    names = (
        _required(r, set()) for r in importlib.metadata.requires("seed-scan") or []
    )
    return frozenset(name for name in names if name is not None)


@cache
def _closure() -> frozenset[str]:
    """Return the declared distributions and what they require, installed.

    The extras a requirement asks for are followed, so that what
    `btclib[secp256k1]` brings is in it.
    """
    found: set[str] = set()
    todo = [(r, set[str]()) for r in importlib.metadata.requires("seed-scan") or []]
    while todo:
        requirement, extras = todo.pop()
        name = _required(requirement, extras)
        if name is None or name in found:
            continue
        requires = importlib.metadata.requires(name) or []
        found.add(name)
        asked = set(Requirement(requirement).extras)
        todo += [(r, asked) for r in requires]
    return frozenset(found)


def _distributions(module: str) -> set[str]:
    """Return the canonical names of the distributions a module comes from.

    :param module: a dotted module name.
    :returns: the names `packages_distributions` gives its top level.
    """
    top = module.split(".", maxsplit=1)[0]
    return {
        canonicalize_name(d)
        for d in importlib.metadata.packages_distributions().get(top, [])
    }


def _outside(names: set[str]) -> list[str]:
    """Return the names that are neither the standard library's nor ours.

    Read off the names, which is what a file's import statements give:
    the static half below has no interpreter to ask where a module lives.
    """
    return sorted(
        name
        for name in names
        if name.split(".")[0] not in sys.stdlib_module_names and not _is_ours(name)
    )


def _undeclared(names: set[str], allowed: frozenset[str]) -> list[str]:
    """Return the names outside the standard library, ours and `allowed`.

    :param names: module names.
    :param allowed: the distributions whose modules are allowed.
    :returns: each name from no distribution `allowed` holds.
    """
    return [name for name in _outside(names) if not _distributions(name) & allowed]


@pytest.mark.parametrize("module_name", module_names())
def test_the_package_loads_only_what_it_declares(module_name: str) -> None:
    """Each module, imported alone, loads only what `dependencies` brings.

    What it loads from an installer is a module of a declared
    distribution or of one they require: anything else -- a package the
    test group installs included -- would resolve here and fail in an
    environment that installs the package alone.
    """
    assert _undeclared(set(_installed_by(module_name)), _closure()) == []


def test_the_bundle_loads_nothing_installed() -> None:
    """`seed_scan.bundle` imports the standard library alone.

    A command that reads a bundle needs no dependency of `identify`.
    """
    assert _installed_by("seed_scan.bundle") == []


def test_the_command_module_loads_no_identify() -> None:
    """`seed_scan.cli`, imported alone, does not load `seed_scan.identify`.

    `scan` reads a bundle, and a command that reads one never loads the
    module that handles the secret: the `identify` command imports it
    itself.
    """
    assert "seed_scan.identify" in _loaded_after_importing("seed_scan.identify")
    assert "seed_scan.identify" not in _loaded_after_importing("seed_scan.cli")


def test_the_runtime_check_sees_a_third_party_import() -> None:
    """The check names what an import outside the declared closure adds.

    `typing_extensions` is installed by the test group, so importing it
    here is what a module of the package importing it would add; it is
    allowed only where a declared package requires it.
    """
    assert "typing_extensions" in _installed_by("typing_extensions")
    assert _undeclared({"typing_extensions"}, frozenset()) == ["typing_extensions"]
    assert _undeclared({"pytest"}, _closure()) == ["pytest"]


def test_the_closure_follows_requirements_and_extras() -> None:
    """The closure holds what the declared packages require, not the suite's."""
    assert {"bip39-slip39", "btclib", "ecc"} <= _closure()
    assert "pytest" not in _closure()
    assert _required('x>=1; extra == "y"', set()) is None
    assert _required('x>=1; extra == "y"', {"y"}) == "x"


def _top_level_imports(source: str) -> set[str]:
    """Return the first component of every name one module's imports name.

    Relative imports name this package, so they are recorded as it.
    """
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.add("seed_scan" if node.level else (node.module or "").split(".")[0])
    return names


def test_the_import_scan_finds_a_planted_import() -> None:
    """The scan names each form, and the check refuses what is undeclared."""
    source = (
        "import hashlib\nimport btclib.utils\nfrom btclib_wallet import bip32\n"
        "from . import exceptions\nfrom typing_extensions import override\n"
    )
    names = _top_level_imports(source)
    assert names == {
        "hashlib",
        "btclib",
        "btclib_wallet",
        "seed_scan",
        "typing_extensions",
    }
    assert _outside(names) == ["btclib", "btclib_wallet", "typing_extensions"]
    assert _undeclared(names, _declared()) == ["typing_extensions"]


def test_no_module_imports_what_it_does_not_declare() -> None:
    """Every file of the package, read rather than imported.

    The static half of `test_the_package_loads_only_what_it_declares`,
    held to the declared distributions alone: an import inside a function
    or behind `TYPE_CHECKING` is one no interpreter runs at import, and
    it would still fail the day it ran.
    """
    root = Path(seed_scan.__path__[0])
    found = {
        path.relative_to(root).as_posix(): _undeclared(
            _top_level_imports(path.read_text(encoding="utf-8")), _declared()
        )
        for path in sorted(root.rglob("*.py"))
    }
    assert "identify.py" in found
    assert not {file: names for file, names in found.items() if names}
