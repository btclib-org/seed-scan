# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing the reader of a forks result.

`report` reads whatever files it is named as the forks results, with
`seed_scan.forks.loads`, against the bundle's text: here `BUNDLE`, which
`_bundle.py` beside this file holds. `data` is decoded as UTF-8,
strictly, as `seed_scan.cli` decodes the file, and an input that does not
decode ends the run.

A crash on hostile input is a defect in the reader, never in this
harness. `SeedScanTypeError` and `SeedScanValueError` are what the reader
refuses a text with, so they are caught as the expected outcome; any
other exception propagates to atheris as the finding it is.

**What the reader accepts is then written back and reported on.** `dumps`
of the result read reads back to the same result, and
`seed_scan.report.report` takes the bundle and the text as its one forks
result, as ``seed-scan report`` does. A different read raises
`AssertionError`; an exception from either step propagates.

The seed corpus is results `forks` wrote for `BUNDLE`: on Bitcoin Cash,
with an account of Bitcoin and one of the chain's own used, and on
eCash, with none used. Each names `BUNDLE` by its SHA-256.
"""

from __future__ import annotations

import sys

import atheris
from _bundle import BUNDLE

from seed_scan import forks
from seed_scan.exceptions import SeedScanTypeError, SeedScanValueError
from seed_scan.report import report


def fuzz_target(data: bytes) -> None:
    """Read `data` as a forks result, and write back and report on it.

    The module docstring says what is refused quietly and what is a
    finding.
    """
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    try:
        read = forks.loads(text, BUNDLE)
    except (SeedScanTypeError, SeedScanValueError):
        return
    if forks.loads(forks.dumps(read), BUNDLE) != read:
        raise AssertionError("a forks result does not read back as it was written")
    report(BUNDLE, forks=[text])


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
