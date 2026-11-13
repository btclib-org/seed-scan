# seed-scan

A command for somebody who holds a mnemonic and does not know what it
is: which scheme it follows, which addresses it gave, which coins those
addresses held, and whether a fork concerns them. It finds funds; the
user's own wallet moves them.

<!-- Section 2 of the organization's standard says which badges sit here. -->
[![PyPI version](https://img.shields.io/pypi/v/seed-scan.svg?logo=pypi)](https://pypi.org/project/seed-scan/)
[![GitHub release](https://img.shields.io/github/v/release/btclib-org/seed-scan.svg)](https://github.com/btclib-org/seed-scan/releases)
[![development status](https://img.shields.io/pypi/status/seed-scan.svg)](https://pypi.org/project/seed-scan/)
[![license](https://img.shields.io/github/license/btclib-org/seed-scan.svg)](https://github.com/btclib-org/seed-scan/blob/main/LICENSE)
[![downloads](https://static.pepy.tech/badge/seed-scan)](https://pepy.tech/projects/seed-scan)
[![supported Python versions](https://img.shields.io/pypi/pyversions/seed-scan.svg?logo=python)](https://pypi.org/project/seed-scan/)
[![implementation](https://img.shields.io/pypi/implementation/seed-scan.svg)](https://pypi.org/project/seed-scan/)
[![wheel](https://img.shields.io/pypi/wheel/seed-scan.svg)](https://pypi.org/project/seed-scan/)

## What is here

No release is out yet. `seed-scan identify`, `seed-scan scan` and
`seed-scan report` are the first commands, and `forks` arrives in a pull
request of its own.
[btclib-org/.github#2203](https://github.com/btclib-org/.github/issues/2203)
records the design and tracks the first release. The command is to stay
thin: what is general goes down to the packages it is to build on,
[bip39-slip39](https://github.com/btclib-org/bip39-slip39),
[bip32-descriptors](https://github.com/btclib-org/bip32-descriptors),
[btclib-wallet](https://github.com/btclib-org/btclib-wallet) and
[coin-addresses](https://github.com/btclib-org/coin-addresses). A
scheme or a coin they do not cover is to be reported as not checked,
never passed over: the costly failure is a wrong "nothing found".

## Identifying a mnemonic

```shell
seed-scan identify > bundle.json
```

It asks for the mnemonic, then for passphrases until an empty one, at
hidden prompts, and for further shares where the words are one
SLIP-0039 share. It writes the bundle to standard output and what it
found to standard error. Where you know an address the mnemonic gave,
`--address` followed by it has the command search for the address's
path. `seed_scan.bundle` documents the bundle, and
`seed-scan identify --help` the bounds of what it writes and searches.

## Scanning a bundle

```shell
seed-scan scan bundle.json --server electrum.example.org:50002 \
    --node http://127.0.0.1:8545 > scan.json
```

It asks the Electrum server named, as `host:port`, which Bitcoin
accounts of the bundle were used, and the Ethereum node named, by its
URL, which Ethereum accounts were, and writes the scan result to
standard output and what it found to standard error. Name either or
both. Each learns every address it is asked about, so name your own:
there is no default.

The Electrum connection is TLS, and the server's certificate is verified
against the system's CA certificates, or against those of the file
`--cafile` names, which is how a server with a self-signed certificate
is reached.

The node is an execution client's JSON-RPC, at an `https` URL, or an
`http` one on a loopback address such as `http://127.0.0.1:8545`.
`--cafile` is the Electrum server's alone: `seed_scan.evm` says what the
node's certificate is verified against. An Ethereum address is used
where it holds ether or has a nonce: token balances are not asked, so an
address that only ever received tokens reads as unused.

A coin with no server or node named, and every coin but Bitcoin and
Ethereum, is listed as not checked. `seed_scan.scan` documents the
result, `seed_scan.evm` the node's requests, and `seed-scan scan --help`
the bounds of the search.

## Reporting what was found

```shell
seed-scan report bundle.json --scan scan.json > report.txt
```

It reads the bundle and the scan result made from it, offline, and
writes what they say to standard output: for each reading, coin and
purpose, the used accounts with their balance, their used addresses and
the paths, and what was not checked and why. Without `--scan`, as after
a server or a node failed, every account is listed as not checked. A
result made from another bundle is refused. The last line is the SHA-256
of the lines above it. `seed_scan.report` documents the layout.

## What touches the secret

The commands are to keep to this split, so that the mnemonic stays on
one machine and everything after it reads public data:

- **`identify` touches the secret and no network.** It reads the
  mnemonic from a prompt, never from an argument. It tries each scheme,
  language and candidate passphrase, and, given an address the user
  knows, finds the reading and the path that give it. It writes a
  *public bundle*: the fingerprint and the account public keys, or the
  addresses where a coin has no extended public key.
- **`scan` and `forks` touch the network and no secret.** They read the
  bundle and what the commands before them wrote, and `scan` the CA
  certificates it verifies its server and its node against, the system's
  or, for the server, those of the file the user names; nothing else.
  *Scanning a bundle* says which server and which node `scan` asks.
  `forks` takes the balance at the height of each fork from the history,
  then checks the chains each fork created.
- **`report` touches neither.** It assembles what `scan` and `forks`
  found: what was searched, what was found, the limits of the search,
  and the digest of the report.

The bundle holds no secret, but it is not harmless: an account public
key gives every address of that account, so whoever holds the bundle can
follow its history and balance, though not spend from it. The same holds
of the report: it holds no secret, but it lets anyone follow the
wallet's history.

The package is fully annotated and ships `py.typed`. Its refusals are
`seed_scan.exceptions`'s classes: a `ValueError` or a `TypeError`,
under one base, `SeedScanException`.

```python
from seed_scan.exceptions import (
    SeedScanException,
    SeedScanTypeError,
    SeedScanValueError,
)

assert issubclass(SeedScanValueError, (SeedScanException, ValueError))
assert issubclass(SeedScanTypeError, (SeedScanException, TypeError))
```

`tests/readme_test.py` runs every Python block of this file, so the
example above is the one the suite checks.

## Security

[SECURITY.md](https://github.com/btclib-org/seed-scan/blob/main/SECURITY.md)
says what the package does to guard the mnemonic and what it cannot,
how to report a vulnerability, which versions are supported, and how a
published file is traced back to the run that built it.

## Contributing

Development is LLM-based: humans are welcome, as long as they are
comfortable with agentic development ;-). A contribution must have been
read and understood by the person who submits it.
[`CONTRIBUTING.md`](https://github.com/btclib-org/seed-scan/blob/main/CONTRIBUTING.md#working-with-an-llm)
has the rules.

[CONTRIBUTING.md](https://github.com/btclib-org/seed-scan/blob/main/CONTRIBUTING.md)
has the commands each CI job runs, verbatim. `uv sync` creates the
environment; uv is the only tool that has to be installed.
[REVIEWING.md](https://github.com/btclib-org/seed-scan/blob/main/REVIEWING.md)
is what a pull request is answered against.

How the organization decides, and who holds which role, is its
[GOVERNANCE.md](https://github.com/btclib-org/.github/blob/main/GOVERNANCE.md);
what it intends to do, and what it deliberately does not, is its
[ROADMAP.md](https://github.com/btclib-org/.github/blob/main/ROADMAP.md).

## Links

- Source: <https://github.com/btclib-org/seed-scan>
- Releases: <https://github.com/btclib-org/seed-scan/releases>
- [CHANGELOG.md](https://github.com/btclib-org/seed-scan/blob/main/CHANGELOG.md),
  and [RELEASE_NOTES.md](https://github.com/btclib-org/seed-scan/blob/main/RELEASE_NOTES.md)
  for what a release asks a user to act on

## Status

<!-- Section 2 of the organization's standard says which badges sit here. -->
[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/btclib-org/seed-scan/main.svg)](https://results.pre-commit.ci/latest/github/btclib-org/seed-scan/main)
[![lint workflow status](https://github.com/btclib-org/seed-scan/actions/workflows/lint.yml/badge.svg?branch=main)](https://github.com/btclib-org/seed-scan/actions/workflows/lint.yml?query=branch%3Amain)
[![test workflow status](https://github.com/btclib-org/seed-scan/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/btclib-org/seed-scan/actions/workflows/test.yml?query=branch%3Amain)
[![docs workflow status](https://github.com/btclib-org/seed-scan/actions/workflows/docs.yml/badge.svg?branch=main)](https://github.com/btclib-org/seed-scan/actions/workflows/docs.yml?query=branch%3Amain)
[![deps-latest workflow status](https://github.com/btclib-org/seed-scan/actions/workflows/deps-latest.yml/badge.svg?branch=main)](https://github.com/btclib-org/seed-scan/actions/workflows/deps-latest.yml?query=branch%3Amain)
[![pypi-install workflow status](https://github.com/btclib-org/seed-scan/actions/workflows/pypi-install.yml/badge.svg?branch=main)](https://github.com/btclib-org/seed-scan/actions/workflows/pypi-install.yml?query=branch%3Amain)
[![deps-oldest workflow status](https://github.com/btclib-org/seed-scan/actions/workflows/deps-oldest.yml/badge.svg?branch=main)](https://github.com/btclib-org/seed-scan/actions/workflows/deps-oldest.yml?query=branch%3Amain)
[![os-macos workflow status](https://github.com/btclib-org/seed-scan/actions/workflows/os-macos.yml/badge.svg?branch=main)](https://github.com/btclib-org/seed-scan/actions/workflows/os-macos.yml?query=branch%3Amain)
[![os-ubuntu workflow status](https://github.com/btclib-org/seed-scan/actions/workflows/os-ubuntu.yml/badge.svg?branch=main)](https://github.com/btclib-org/seed-scan/actions/workflows/os-ubuntu.yml?query=branch%3Amain)
[![os-windows workflow status](https://github.com/btclib-org/seed-scan/actions/workflows/os-windows.yml/badge.svg?branch=main)](https://github.com/btclib-org/seed-scan/actions/workflows/os-windows.yml?query=branch%3Amain)
[![links workflow status](https://github.com/btclib-org/seed-scan/actions/workflows/links.yml/badge.svg?branch=main)](https://github.com/btclib-org/seed-scan/actions/workflows/links.yml?query=branch%3Amain)
[![sdist-rebuild workflow status](https://github.com/btclib-org/seed-scan/actions/workflows/sdist-rebuild.yml/badge.svg?branch=main)](https://github.com/btclib-org/seed-scan/actions/workflows/sdist-rebuild.yml?query=branch%3Amain)
[![codeql workflow status](https://github.com/btclib-org/seed-scan/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/btclib-org/seed-scan/actions/workflows/codeql.yml?query=branch%3Amain)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/btclib-org/seed-scan/badge)](https://scorecard.dev/viewer/?uri=github.com/btclib-org/seed-scan)

---

The btclib organization and its projects are actively supported by
[DGI](https://dgi.io) and [CheckSig](https://checksig.com).
