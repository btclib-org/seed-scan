# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The seed_scan package: what it publishes, and the version metadata.

What a mnemonic of unknown scheme holds: its scheme, its addresses,
their coins and the forks that concern them. README.md's *What touches
the secret* says which command reads the mnemonic and which do not.

`__all__` here is the root of the package's public tree: the modules a
caller reaches from this name. Each of them declares its own `__all__`,
so a walk that starts here has a declared surface at every node -- which
is why the list is not `pkgutil.iter_modules`: discovery would answer
the file tree, and a module added to the directory would publish itself
rather than being published.

`name` is not in it, nor are the metadata dunders. `name` is the
distribution's name and not a member of the tree, `__version__` bound by
a star import would overwrite the importing module's own, and each is
still an attribute here: `seed_scan.__version__` is how a caller
reads the version and `seed_scan.name` how it reads the name.

Nothing is imported eagerly. A module is imported when it is first asked
for, through the `__getattr__` at the bottom of this file, so `import
seed_scan` is the metadata lookup below and nothing else, and the
import graph keeps its shape: importing every module here would put the
whole package in `sys.modules` before any single module of it could be
imported first, which is the situation tests/imports_test.py exists to
make impossible.

What that costs is worth stating: mypy reads a module-level `__getattr__`
as a promise that any attribute may exist, so `seed_scan.exception`
is `Any` to it and a misspelling on this package is a runtime
`AttributeError` rather than a reported error. The spellings a caller
actually writes -- `from seed_scan import exceptions`, `import
seed_scan.exceptions`, `from seed_scan.exceptions import
SeedScanValueError` -- resolve against the real modules and stay
checked.
"""

from importlib import import_module
from importlib.metadata import PackageNotFoundError, version
from types import ModuleType

name = "seed-scan"
try:
    __version__ = version("seed-scan")
except PackageNotFoundError:
    # a source tree with no metadata beside it: git clone and import, or
    # read the docs, which builds without installing this package. Any
    # number here would be a guess, and reading pyproject.toml back is not
    # the way to stop guessing: the file is not in the wheel. Importing has
    # to keep working, so the version says it does not know
    __version__ = "unknown"

__all__ = [
    "bundle",
    "cli",
    "evm",
    "exceptions",
    "identify",
    "report",
    "scan",
]


def __getattr__(published: str) -> ModuleType:
    """Import a published module the first time it is asked for.

    PEP 562: this runs only for a name the package does not already have,
    so it answers `seed_scan.exceptions` once and the import
    machinery's own attribute answers it from then on -- and it never runs
    for `import seed_scan.exceptions` or `from seed_scan import
    exceptions`, which import the submodule themselves. What it makes work
    is `getattr(seed_scan, "exceptions")` on a fresh interpreter,
    which is how a walker reading `__all__` descends, and `from
    seed_scan import *`, which asks for each name in the list.

    Anything not in `__all__` raises `AttributeError`, a private module's
    name included, which only an import of that module reaches. The
    message is the interpreter's own wording, so a typo reads as it does
    anywhere else.
    """
    if published in __all__:
        return import_module(f"{__name__}.{published}")
    raise AttributeError(f"module {__name__!r} has no attribute {published!r}")


def __dir__() -> list[str]:
    """Answer with the published tree beside what the package already has.

    `dir(seed_scan)` consults this rather than the namespace, so
    without it a module not yet imported is missing from the completion a
    caller gets at an interactive prompt -- the same names `__getattr__`
    above will answer for.
    """
    return sorted({*__all__, *globals()})
