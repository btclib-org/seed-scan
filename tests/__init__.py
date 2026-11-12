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
