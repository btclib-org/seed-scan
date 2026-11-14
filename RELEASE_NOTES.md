# Release notes

Notable changes are documented here.
[CHANGELOG.md](./CHANGELOG.md) is the record behind them: this file says
what a user has to act on, that one says what changed.

Versions are *[calendar versions](https://calver.org/)*, `YYYY.M.D`: the
number says when a release was cut, and promises nothing about
compatibility, so a breaking change is announced in this file — read it
before upgrading, rather than a digit.

## v2026.11.15

The first release of `seed-scan`: there is no earlier version to upgrade
from. It finds what a mnemonic of unknown scheme holds, in two steps, so
that the mnemonic is typed on one machine and every later step reads
public data alone.

- `seed-scan identify`, offline, reads the mnemonic at a hidden prompt
  and writes a public bundle of account public keys.
- `seed-scan scan` reads the bundle's Bitcoin accounts on an Electrum
  server and its Ethereum accounts on a JSON-RPC node.
- `seed-scan forks` reads them on Bitcoin Cash and Bitcoin SV.
- `seed-scan report`, offline, says what was found and what was not
  checked.

Each server and node is the user's own, named on the command line: there
is no default, since it learns every address it is asked about. The
Electrum server is trusted for what it answers, as *Limitations, not
vulnerabilities* in [SECURITY.md](./SECURITY.md) says.

The bundle, the scan result, the forks result and the report each name
their format version, `1` in this release. A refusal is a
`SeedScanValueError` or a `SeedScanTypeError`, which a caller catching
`ValueError` or `TypeError` still catches.

The release attaches the wheel, `seed_scan-2026.11.15-py3-none-any.whl`,
the sdist, `seed_scan-2026.11.15.tar.gz`, `seed_scan-2026.11.15.cdx.json`
and `v2026.11.15.intoto.jsonl`; *Supported versions* in
[SECURITY.md](./SECURITY.md) has the `gh attestation verify` command.
