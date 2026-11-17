# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing the reader of a bundle.

`scan`, `forks` and `report` read whatever file they are named as the
bundle, which need not be one the user's own `identify` wrote, with
`seed_scan.bundle.loads`. `seed_scan.cli` hands a reader only a file that
decodes as UTF-8, so `data` is decoded the same way, strictly, and an
input that does not decode ends the run.

A crash on hostile input is a defect in the reader, never in this
harness. `SeedScanTypeError` and `SeedScanValueError` are what the reader
refuses a text with, so they are caught as the expected outcome; any
other exception propagates to atheris as the finding it is.

**What the reader accepts is then written back and reported on.** `dumps`
of the bundle read reads back to the same bundle, and
`seed_scan.report.report` takes the text, as ``seed-scan report`` does
with a bundle alone. A different read raises `AssertionError`; an
exception from either step propagates.

The seed corpus is bundles `identify` wrote: of a BIP39 mnemonic, of an
Electrum one, with an address found and with an address not searched.
"""

from __future__ import annotations

import sys

import atheris

from seed_scan import bundle
from seed_scan.exceptions import SeedScanTypeError, SeedScanValueError
from seed_scan.report import report


def fuzz_target(data: bytes) -> None:
    """Read `data` as a bundle, and write back and report on what is read.

    The module docstring says what is refused quietly and what is a
    finding.
    """
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    try:
        read = bundle.loads(text)
    except (SeedScanTypeError, SeedScanValueError):
        return
    if bundle.loads(bundle.dumps(read)) != read:
        raise AssertionError("a bundle does not read back as it was written")
    report(text)


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
