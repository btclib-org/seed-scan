# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for what the package exports.

Every module and package of seed_scan declares an `__all__`, at every
depth: a name is public here because a list says so, not because it
happens to lack a leading underscore. A list per module is a list per
module to keep true, and the policy tests below are what keeps it, rather
than a reviewer noticing.

These tests are written against the names rather than the counts, so that a
deliberate addition is one line here and an accidental one is a failure.
Each collects what it finds and asserts the collection empty, so that a
failure names every offender at once rather than the first.
"""

from __future__ import annotations

import ast
from importlib import import_module
from pathlib import Path
from pkgutil import iter_modules
from types import ModuleType
from typing import TYPE_CHECKING

import pytest

import seed_scan

from . import module_names

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

# what a module defines without a leading underscore and deliberately does
# not export. A name added here is a decision; a name that has to be added
# here to make the suite pass is one that was about to become public by
# accident. `name` is the distribution's name and not a member of the
# tree, which the root's docstring says
UNEXPORTED = {
    "seed_scan": ["name"],
}


def public_name(dotted: str) -> bool:
    """Whether every component of a dotted module name is public."""
    return not any(part.startswith("_") for part in dotted.split("."))


def library_modules() -> list[ModuleType]:
    """Return every module and package of the library, private ones out.

    Found rather than listed: one added to seed_scan is one these
    tests ask about. Anything under a private name is out: a module whose
    name opens with an underscore is not part of the surface, so what is
    public *in* it is not reachable by any spelling a caller is offered.
    """
    return [import_module(name) for name in module_names() if public_name(name)]


def module_scope(body: Iterable[ast.stmt]) -> Iterator[ast.stmt]:
    """Yield the statements a module executes in its own namespace.

    Every statement of the body, and then inside each compound one, which
    runs at module scope too: an import in a module-level `try`, `if`,
    `with`, `for`, `while` or `match` binds a global exactly as a
    top-level one does, and `try: from dependency import PublicType` is
    how an optional import is written. A function or a class opens a scope
    of its own, so an import in either binds nothing here, and neither is
    descended into.
    """
    for node in body:
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        nested: list[ast.stmt] = []
        for field in ("body", "orelse", "finalbody"):
            statements = getattr(node, field, None)
            if isinstance(statements, list):
                nested += statements
        for clause in (*getattr(node, "handlers", ()), *getattr(node, "cases", ())):
            nested += clause.body
        yield from module_scope(nested)


def imported_names_in(source: str) -> set[str]:
    """Return the names the import statements of one module source bind."""
    return {
        alias.asname or alias.name.split(".")[0]
        for node in module_scope(ast.parse(source).body)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }


def imported_names(module: ModuleType) -> set[str]:
    """Return the names a module's own import statements bind.

    Read off the source rather than the module object, there being nothing
    in a module's namespace to say how a name got there.
    """
    return imported_names_in(Path(str(module.__file__)).read_text(encoding="utf-8"))


def defined_public_names(module: ModuleType) -> set[str]:
    """Return the public names a module defines itself.

    Everything in its namespace, minus the underscored, minus what it
    imported, minus the modules: a submodule becomes an attribute of its
    package as soon as anything imports it.
    """
    imported = imported_names(module)
    return {
        name
        for name, value in vars(module).items()
        if not name.startswith("_")
        and name not in imported
        and not isinstance(value, ModuleType)
    }


def test_every_module_declares_its_all() -> None:
    """A module with no `__all__` publishes whatever lacks an underscore."""
    undeclared = [
        module.__name__
        for module in library_modules()
        if not isinstance(getattr(module, "__all__", None), list)
    ]
    assert not undeclared, f"no __all__ list in {undeclared}"


def test_every_exported_name_exists() -> None:
    """An `__all__` entry that names nothing is a broken `import *`."""
    missing = [
        f"{module.__name__}.{name}"
        for module in library_modules()
        for name in module.__all__
        if not hasattr(module, name)
    ]
    assert not missing, f"exported and not there: {missing}"


def test_no_module_exports_a_name_it_imported() -> None:
    """A module exports what it defines, which is what packages do not.

    A package's `__all__` is re-export by design, and for a module the
    same thing is a leak: the name a caller wants is the module that
    defines it.
    """
    leaked = {
        module.__name__: sorted(set(module.__all__) & imported_names(module))
        for module in library_modules()
        if not hasattr(module, "__path__")
    }
    assert not {name: found for name, found in leaked.items() if found}


def test_nothing_becomes_public_by_accident() -> None:
    """Every public name is exported or recorded as kept out.

    This is the check the underscore convention cannot make: a helper that
    grows into a name callers depend on does so silently, where a package
    takes an edit to a list. `UNEXPORTED` is that edit.
    """
    kept_out = {
        module.__name__: sorted(defined_public_names(module) - set(module.__all__))
        for module in library_modules()
    }
    assert {name: found for name, found in kept_out.items() if found} == UNEXPORTED


def test_the_root_publishes_every_top_level_module() -> None:
    """`seed_scan.__all__` is the tree's root, missing nothing top-level.

    The list is written out rather than discovered -- a declaration is a
    list somebody edited -- and this is the other half of that: a module
    added to `src/seed_scan/` and not published there would be a name
    no walk from the root reaches.
    """
    top_level = sorted(
        name for _, name, _ in iter_modules(seed_scan.__path__) if public_name(name)
    )
    assert sorted(seed_scan.__all__) == top_level
    # and each answers on a package that imported none of them, which is
    # what the module __getattr__ is for
    for name in top_level:
        assert getattr(seed_scan, name).__name__ == f"seed_scan.{name}"


def test_the_root_answers_only_for_what_it_publishes() -> None:
    """A name outside the list raises, as an attribute of anything does.

    A private module is not asserted absent, and could not be: the import
    machinery sets a submodule as an attribute of its package, so any
    module importing a private module puts that name there. What the
    list decides is what this package imports *for* a caller.
    """
    with pytest.raises(AttributeError, match="has no attribute 'bip93'"):
        _ = seed_scan.bip93
    # dir() answers the published tree, not only what has been imported
    assert set(seed_scan.__all__) <= set(dir(seed_scan))


def test_the_import_scan_reaches_a_nested_import() -> None:
    """A module-level `try` binds a global, and a function body does not.

    The two checks above are only as good as this scan: an optional
    dependency imported in a `try` and named in `__all__` is exactly the
    re-export they refuse, and reading `tree.body` alone would have let
    it through.
    """
    source = (
        "try:\n"
        "    from dependency import PublicType\n"
        "except ImportError:\n"
        "    from fallback import PublicType\n"
        "if TYPE_CHECKING:\n"
        "    from typing import Never\n"
        "for _name in ():\n"
        "    import late\n"
        "def f():\n"
        "    import local\n"
        "class C:\n"
        "    import attribute\n"
    )
    assert imported_names_in(source) == {"PublicType", "Never", "late"}


def test_the_checks_see_a_module_that_breaks_them(tmp_path: Path) -> None:
    """A planted module fails each check above, so their green is not free.

    Every check above could pass over a walk that found nothing; this
    asks the same helpers of a module that has every defect.
    """
    planted = tmp_path / "planted.py"
    planted.write_text(
        "from os import sep\n__all__ = ['sep', 'absent']\nvisible = 1\n",
        encoding="utf-8",
    )
    module = ModuleType("planted")
    module.__file__ = str(planted)
    source = compile(planted.read_text(encoding="utf-8"), str(planted), "exec")
    exec(source, vars(module))  # noqa: S102 -- a file this test wrote
    assert imported_names(module) & set(module.__all__) == {"sep"}
    assert not hasattr(module, "absent")
    assert defined_public_names(module) - set(module.__all__) == {"visible"}
