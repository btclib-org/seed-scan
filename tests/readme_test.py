# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Every Python block of README.md runs, and its assertions hold.

The README's example is the first code a user copies, and nothing else
reads it: a renamed function or a changed answer would leave it wrong
with every other gate green.
"""

import re
from pathlib import Path

import pytest

_README = Path(__file__).parents[1] / "README.md"
_BLOCK = re.compile(r"^```python\n(.*?)^```$", re.MULTILINE | re.DOTALL)
_BLOCKS = _BLOCK.findall(_README.read_text(encoding="utf-8"))


def test_the_readme_has_a_python_block() -> None:
    """The run below passes for free over a README with no block."""
    assert _BLOCKS


@pytest.mark.parametrize("block", _BLOCKS, ids=lambda b: b.splitlines()[0])
def test_a_readme_block_runs(block: str) -> None:
    """One block, executed in a namespace of its own."""
    exec(compile(block, str(_README), "exec"), {})  # noqa: S102
