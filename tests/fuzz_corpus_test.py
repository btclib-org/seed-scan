# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Every harness under `fuzz/` runs on its seeds, and each seed is read.

Section 7 of the organization's standard, *A fuzz harness runs on its
seeds*, asks the suite to run every harness's `fuzz_target` on every seed
of its corpus. A harness imports atheris, which no dependency group
declares, so it is loaded here under an empty stand-in `atheris`, with
`fuzz/` on the import path for the `_bundle.py` it shares.

A target returns quietly where its reader refuses the input, so a seed
the reader refuses would pass that run while seeding nothing. Each seed
is therefore also read here, by the reader its harness fuzzes, which has
to accept it.

The tests after those try each harness on what it is there to find: a
read that does not write back, and an exception outside the reader's
refusals.

What this gate keeps is the fuzzer's own starting point valid as the
readers move under it. A crash the fuzzer finds is a test of the
ordinary suite, naming the input and what the reader now does with it,
and never a seed.
"""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import replace
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock

import pytest
from btclib_wallet.exceptions import FetchError, RpcError

from seed_scan import bundle, forks, scan
from seed_scan.evm import Node

if TYPE_CHECKING:
    from collections.abc import Callable

_FUZZ = Path(__file__).parents[1] / "fuzz"
_CORPUS = _FUZZ / "corpus"


def load_harness(name: str, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load a harness under an empty stand-in for its CI-only fuzz engine.

    :param name: the harness's name, its file's stem.
    :param monkeypatch: what puts the stand-in and `fuzz/` in place, and
        takes them away after the test.
    :returns: the harness, as a module.
    """
    monkeypatch.setitem(sys.modules, "atheris", ModuleType("atheris"))
    monkeypatch.syspath_prepend(str(_FUZZ))
    spec = importlib.util.spec_from_file_location(name, _FUZZ / f"{name}.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _evm_reads(harness: ModuleType, data: bytes) -> None:
    """Refuse an answer that no read of `harness.ASKS` takes.

    A read takes it where it answers a value, or where the answer is the
    node's error object, which is the `RpcError` the error seed is.
    """
    taken = 0
    for ask in harness.ASKS:
        node = Node("https://node.example", transport=lambda *_: (200, data))
        try:
            ask(node)
        except RpcError:
            taken += 1
        except FetchError:
            continue
        else:
            taken += 1
    assert taken, "no read of the node takes the seed"


#: What each harness's reader makes of one of its seeds, given the harness.
READS: dict[str, Callable[[ModuleType, bytes], Any]] = {
    "fuzz_bundle": lambda _, data: bundle.loads(data.decode("utf-8")),
    "fuzz_evm": _evm_reads,
    "fuzz_forks": lambda h, data: forks.loads(data.decode("utf-8"), h.BUNDLE),
    "fuzz_scan": lambda h, data: scan.loads(data.decode("utf-8"), h.BUNDLE),
}

_HARNESSES = tuple(path.stem for path in sorted(_FUZZ.glob("fuzz_*.py")))
_SEEDS = tuple(
    (name, seed) for name in _HARNESSES for seed in sorted((_CORPUS / name).glob("*"))
)
_SEED_IDS = [f"{name}/{seed.name}" for name, seed in _SEEDS]


def test_the_corpus_is_not_empty() -> None:
    """Every test below quantifies over the harnesses and their seeds."""
    assert _HARNESSES, f"{_FUZZ} holds no fuzz_*.py"
    assert _SEEDS, f"{_CORPUS} holds no seed"


def test_every_harness_has_a_corpus_a_reader_and_back() -> None:
    """A harness with no seeds, or seeds with no harness, is unchecked."""
    directories = {path.name for path in _CORPUS.iterdir()}
    assert set(_HARNESSES) == directories == set(READS)
    assert all(any((_CORPUS / name).iterdir()) for name in _HARNESSES)


@pytest.mark.parametrize("name, seed", _SEEDS, ids=_SEED_IDS)
def test_a_seed_is_a_file_with_no_trailing_newline(name: str, seed: Path) -> None:
    """A seed is a `.bin` file, and holds no newline a fixer appended."""
    assert seed.suffix == ".bin", f"{name}/{seed.name} is not a .bin file"
    assert not seed.read_bytes().endswith(b"\n"), f"{seed} ends with a newline"


@pytest.mark.parametrize("name, seed", _SEEDS, ids=_SEED_IDS)
def test_a_seed_is_read_by_its_reader(
    monkeypatch: pytest.MonkeyPatch, name: str, seed: Path
) -> None:
    """The reader the harness fuzzes accepts the seed."""
    READS[name](load_harness(name, monkeypatch), seed.read_bytes())


@pytest.mark.parametrize("name, seed", _SEEDS, ids=_SEED_IDS)
def test_seed_runs_its_harness(
    monkeypatch: pytest.MonkeyPatch, name: str, seed: Path
) -> None:
    """A seed passes every check its target makes."""
    load_harness(name, monkeypatch).fuzz_target(seed.read_bytes())


def _seed(name: str, stem: str) -> bytes:
    return (_CORPUS / name / f"{stem}.bin").read_bytes()


#: Each harness that reads a text: its reader's module, a seed, and what
#: `report` is asked, given the harness and the seed's text.
TEXT_HARNESSES: dict[str, tuple[ModuleType, str, Callable[..., Any]]] = {
    "fuzz_bundle": (bundle, "bip39_accounts", lambda _, text: ((text,), {})),
    "fuzz_scan": (scan, "bitcoin", lambda h, text: ((h.BUNDLE, text), {})),
    "fuzz_forks": (
        forks,
        "bitcoin_cash",
        lambda h, text: ((h.BUNDLE,), {"forks": [text]}),
    ),
}


@pytest.mark.parametrize("name", TEXT_HARNESSES)
def test_a_text_harness_reports_on_what_it_reads(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    """`report` is asked once, as ``seed-scan report`` asks it."""
    harness = load_harness(name, monkeypatch)
    _, stem, asked = TEXT_HARNESSES[name]
    data = _seed(name, stem)
    monkeypatch.setattr(harness, "report", Mock(wraps=harness.report))
    harness.fuzz_target(data)
    args, kwargs = asked(harness, data.decode("utf-8"))
    harness.report.assert_called_once_with(*args, **kwargs)


@pytest.mark.parametrize("name", TEXT_HARNESSES)
@pytest.mark.parametrize("data", [b"\xff", b"{}"], ids=["not UTF-8", "refused"])
def test_a_text_harness_ends_quietly_where_its_reader_cannot_read(
    monkeypatch: pytest.MonkeyPatch, name: str, data: bytes
) -> None:
    """Bytes that are no UTF-8, and a text the reader refuses, end the run.

    `report` is never asked: the run ends before it.
    """
    harness = load_harness(name, monkeypatch)
    monkeypatch.setattr(harness, "report", Mock(side_effect=AssertionError))
    harness.fuzz_target(data)
    harness.report.assert_not_called()


def _written_otherwise(read: Any) -> Any:
    """Return what a reader accepts that is not `read`.

    Another server for a result, and no claim for a bundle.
    """
    if isinstance(read, bundle.Bundle):
        return replace(read, claims=())
    return replace(read, server="elsewhere.example:1")


@pytest.mark.parametrize(
    "name, message",
    [
        ("fuzz_bundle", "^a bundle does not read back as it was written$"),
        ("fuzz_scan", "^a scan result does not read back as it was written$"),
        ("fuzz_forks", "^a forks result does not read back as it was written$"),
    ],
)
def test_a_text_harness_refuses_a_read_that_writes_back_otherwise(
    monkeypatch: pytest.MonkeyPatch, name: str, message: str
) -> None:
    """A `dumps` that writes another value fails the round trip."""
    harness = load_harness(name, monkeypatch)
    module, stem, _ = TEXT_HARNESSES[name]
    dumps = module.dumps
    monkeypatch.setattr(module, "dumps", lambda read: dumps(_written_otherwise(read)))
    with pytest.raises(AssertionError, match=message):
        harness.fuzz_target(_seed(name, stem))


@pytest.mark.parametrize("step", ["loads", "report"])
@pytest.mark.parametrize("name", TEXT_HARNESSES)
def test_a_text_harness_propagates_any_other_exception(
    monkeypatch: pytest.MonkeyPatch, name: str, step: str
) -> None:
    """Only the reader's refusal leaves a run quietly."""
    harness = load_harness(name, monkeypatch)
    module, stem, _ = TEXT_HARNESSES[name]
    fail = Mock(side_effect=IndexError("read failed"))
    monkeypatch.setattr(harness if step == "report" else module, step, fail)
    with pytest.raises(IndexError, match="^read failed$"):
        harness.fuzz_target(_seed(name, stem))


@pytest.mark.parametrize("value", [-1, 2**256, True, "0x1"])
def test_the_evm_harness_refuses_a_value_outside_a_word(
    monkeypatch: pytest.MonkeyPatch, value: object
) -> None:
    """A read answering anything but an integer of 256 bits is a finding."""
    harness = load_harness("fuzz_evm", monkeypatch)
    monkeypatch.setattr(Node, "_quantity", Mock(return_value=value))
    with pytest.raises(
        AssertionError, match="^a node read an answer as no 256-bit integer$"
    ):
        harness.fuzz_target(_seed("fuzz_evm", "quantity"))


def test_the_evm_harness_propagates_any_other_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only a `FetchError` leaves a read quietly."""
    harness = load_harness("fuzz_evm", monkeypatch)
    monkeypatch.setattr(Node, "_call", Mock(side_effect=IndexError("read failed")))
    with pytest.raises(IndexError, match="^read failed$"):
        harness.fuzz_target(_seed("fuzz_evm", "quantity"))


def test_the_evm_harness_asks_a_new_node_each_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each read is a node's first request, which the seeds answer."""
    harness = load_harness("fuzz_evm", monkeypatch)
    call = Node._call
    sent: list[int] = []

    def counted(node: Node, method: str, params: list[object]) -> object:
        sent.append(node.requests)
        return call(node, method, params)

    monkeypatch.setattr(Node, "_call", counted)
    harness.fuzz_target(_seed("fuzz_evm", "word"))
    assert sent == [0] * len(harness.ASKS)
