# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The seed_scan test suite, and the code its modules share.

Here rather than in a `tests/helpers.py`: every Python file under `tests/`
is a test file except `__init__.py` and `conftest.py`, so shared test
code lives in the package `__init__`.

This package is imported by every test module, before that module's own
body runs. Whatever this file executes at import time therefore executes
inside every module's own measured reach: the suite's coverage floor
reads what the import reaches, never what a test body goes on to call. A
literal is safe to share here at module scope. Anything that calls into
the package's own code is shared as a function instead, computed only
when a caller invokes it.
"""

import pkgutil
from collections.abc import Iterator
from types import ModuleType
from typing import Any

import seed_scan


def module_names() -> list[str]:
    """Return every module of the installed seed_scan, the root included.

    Here rather than at each site that walks the package, none of which
    owns the walk. What the walk covers -- a second package root, a
    different prefix, a module it has to skip -- is settled here for all
    of them, and a copy that disagreed would be red nowhere: each site
    asserts against whatever its own walk found.
    """
    return [
        "seed_scan",
        *(
            module.name
            for module in pkgutil.walk_packages(seed_scan.__path__, "seed_scan.")
        ),
    ]


def published(module: ModuleType) -> Iterator[tuple[str, str, Any]]:
    """Yield each name a module publishes, descending into published modules.

    Each is yielded as the dotted name of the module that publishes it,
    the name and the object. A module under `__all__` is not yielded but
    walked in turn, so a subpackage at any depth is reached through the
    lists that publish it, and a module no list names is not.
    `getattr` reaches a submodule not yet imported where its package
    answers for it, as `seed_scan`'s `__getattr__` does, and
    `all_test.py` holds every name under an `__all__` to being there.
    """
    for name in module.__all__:
        obj = getattr(module, name)
        if isinstance(obj, ModuleType):
            yield from published(obj)
        else:
            yield module.__name__, name, obj
