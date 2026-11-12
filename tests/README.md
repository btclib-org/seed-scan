# Tests and code coverage

## The suite

```shell
uv sync
uv run pytest
```

`--cov` is in `addopts`, so the bare `pytest` is the coverage gate, the
same measurement the `coverage` job makes, and it answers against
`fail_under` in `pyproject.toml`. A run that selects a subset — a path
that leaves part of the suite behind, `-k`, `-m`, `--deselect`,
`--ignore`, `--ignore-glob` or `--lf` — prints the report without the
threshold: `coverage_fail_under` in `tests/conftest.py` is where that
happens, and section 8 of [the organization's standard][std] names the
set.

```shell
uv run pytest --no-cov
```

runs the suite without measuring anything.

## Convention tests

Section 7 of [the organization's standard][std] lists conventions a
suite can turn into a red test, and a repository needs the ones its own
prose states rather than all of them. So which of them this repository
tests is declared here, in two halves that together account for every
one of them: the table below and the "Not tested here" line under it.
One row per module, so a convention answered by more than one file is
named once per file, and `conventions_test.py` asserts the declaration
is true.

| convention | tested in |
| --- | --- |
| the public surface | `all_test.py` |
| the copyright header | `copyright_test.py` |
| the documentation | `docs_test.py` |
| the import graph | `imports_test.py` |
| the changelog | `release_notes_test.py` |

Not tested here: the build system; the calling convention; input
validation; the suite opens no socket.

The calling convention and input validation have no subject yet: the
package declares no public function. Each arrives with the pull request
that adds the first function it reads.

[std]: https://github.com/btclib-org/.github/blob/main/README.md
