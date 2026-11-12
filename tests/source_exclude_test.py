# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A test that reads `.github` off the tree is not in the sdist.

The directory is not in the sdist, so a test module that loads a path
under it fails when it is run from an unpacked sdist.
`[tool.uv.build-backend] source-exclude` in pyproject.toml is where such
a module is named, so that the sdist does not ship it. What no comment
there can show is that the list still names every module of that shape,
and a module added without its entry fails nothing else: check-sdist
compares the sdist with the tracked files and never asks whether a
shipped test can run.

The list is read with `tomllib`, so a comment in the array quoting a
path is never taken for an entry.
"""

from __future__ import annotations

import ast
import tomllib
from collections.abc import Iterable
from pathlib import Path

_PYPROJECT = Path(__file__).parents[1] / "pyproject.toml"
_TESTS = Path(__file__).parent


def _source_exclude() -> list[str]:
    """Return `[tool.uv.build-backend] source-exclude`, parsed."""
    text = _PYPROJECT.read_text(encoding="utf-8")
    excluded = tomllib.loads(text)["tool"]["uv"]["build-backend"]["source-exclude"]
    assert isinstance(excluded, list), "source-exclude is not an array"
    return excluded


def _reaches_outside_the_sdist(tree: ast.Module) -> bool:
    """Whether a module reads `.github` off the tree.

    A string literal that is the directory's name, or opens with it and a
    slash, is what marks the module. It is split on the slash rather than
    matched as a substring, so a name merely starting with the same
    letters (".githubbookmark") is not mistaken for the directory. It is
    walked rather than matched on the formatted text, so a reflow across
    lines is still seen, and wherever in the module the literal sits: the
    right side of a `/` join, the way `Path(__file__).parents[1] /
    ".github" / "scripts" / "<name>.py"`, `_ROOT /
    ".github/workflows/test.yml"` hold it, or anywhere else a path is
    built from it.

    Exempted is a literal that never leaves a closed membership test --
    an element of the tuple, list or set an `in` or `not in` comparison
    reads its answer from, this function's own `(".github",)` included.
    Comparing a value against a fixed set of names reads nothing off the
    tree; joining a path on the name does.
    """
    exempt = {
        id(elt)
        for node in ast.walk(tree)
        if isinstance(node, ast.Compare)
        for op, comparator in zip(node.ops, node.comparators, strict=True)
        if isinstance(op, (ast.In, ast.NotIn))  # codespell:ignore notin
        and isinstance(comparator, (ast.Tuple, ast.List, ast.Set))
        for elt in comparator.elts
    }
    return any(
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        # a membership test and not `==`, for the exemption above: this
        # module's own literals are then ones the reading passes over
        and node.value.split("/", 1)[0] in (".github",)  # noqa: FURB171 -- the exemption above
        and id(node) not in exempt
        for node in ast.walk(tree)
    )


def _missing_source_excludes(tests_dir: Path, excluded: Iterable[str]) -> list[str]:
    """Every `*.py` under `tests_dir`, recursively, reaching out and unlisted.

    Recursive, a subdirectory of `tests/` being shipped as whole as the
    top level is. The entries this is checked against are anchored paths
    from the project root, so a module is named by its path relative to
    `tests_dir` and not by its basename alone.
    """
    excluded = set(excluded)
    return [
        f"/tests/{path.relative_to(tests_dir).as_posix()}"
        for path in sorted(tests_dir.rglob("*.py"))
        if _reaches_outside_the_sdist(
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        )
        and f"/tests/{path.relative_to(tests_dir).as_posix()}" not in excluded
    ]


def test_every_test_reaching_outside_the_sdist_is_source_excluded() -> None:
    """A `tests/**/*.py` the reader above recognizes is named in the list.

    Not the other direction: `source-exclude` also names entries no test
    module could match -- `/docs/build`, the caches -- so only this
    direction is the invariant.
    """
    missing = _missing_source_excludes(_TESTS, _source_exclude())
    assert not missing, f"reaches outside the sdist, not in source-exclude: {missing}"


def test_a_subdirectory_module_is_reached_and_named_by_its_relative_path(
    tmp_path: Path,
) -> None:
    """`_missing_source_excludes` opens a subdirectory, not only the top.

    A synthetic `sub/offender_test.py`, planted under a directory this
    test builds rather than the real `tests/`, is what proves the reader
    descends into it and names the module by its relative path.
    """
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "offender_test.py").write_text('URL = ".github/scripts"\n', encoding="utf-8")

    assert _missing_source_excludes(tmp_path, []) == ["/tests/sub/offender_test.py"]
    assert _missing_source_excludes(tmp_path, ["/tests/sub/offender_test.py"]) == []


def test_a_closed_membership_test_is_not_a_reach(tmp_path: Path) -> None:
    """A name compared against, not joined on, reads nothing off the tree."""
    (tmp_path / "member_test.py").write_text(
        'OK = NAME in (".github", ".git")\n', encoding="utf-8"
    )
    (tmp_path / "prefix_test.py").write_text(
        'NAME = ".githubbookmark/x"\n', encoding="utf-8"
    )

    assert _missing_source_excludes(tmp_path, []) == []
