# Release notes

Notable changes are documented here.
[CHANGELOG.md](./CHANGELOG.md) is the record behind them: this file says
what a user has to act on, that one says what changed.

Versions are *[calendar versions](https://calver.org/)*, `YYYY.M.D`: the
number says when a release was cut, and promises nothing about
compatibility, so a breaking change is announced in this file — read it
before upgrading, rather than a digit.

## v2026.11.16

**A bundle, a scan result or a forks result written by v2026.11.15 is
refused.** Run `seed-scan identify` on the mnemonic again, then `scan`
and `forks` on the new bundle, and delete the old bundle once it is
replaced: it holds the key at `m/44h/60h`, which with the private key of
one MyEtherWallet address gives every Ethereum account's keys. The
bundle, the scan result and the report name format version `2`.

The bundle holds no key above Ethereum's accounts
([ISS 83](https://github.com/btclib-org/seed-scan/issues/83)). For
MyEtherWallet's layout, `m/44h/60h/<n>`, it holds the public key of each
address with `n` below `identify --keys`, 100 by default, so the private
key of one leaked address gives that address alone. An address at `n` of
the bound or above is not read: where the search would pass the last
key, the report says it was cut short and names the `--keys` to run
`identify` with.

`scan` and `forks` prove each history the Electrum server answers, from
the chain's last checkpoint up to the history's tip, and refuse one whose
tip does not prove
([ISS 34](https://github.com/btclib-org/seed-scan/issues/34)). What the
server is still trusted for is in *Limitations, not vulnerabilities* in
[SECURITY.md](./SECURITY.md).

`scan` reads every EVM address at the block it asks first, so a node
behind a load balancer whose backends lag fails the scan rather than
write a result `report` refuses
([ISS 79](https://github.com/btclib-org/seed-scan/issues/79)). The
tests that search the outputs for a secret no longer exempt the text
v2026.11.15's notes name
([ISS 75](https://github.com/btclib-org/seed-scan/issues/75),
[ISS 76](https://github.com/btclib-org/seed-scan/issues/76)).

A failed exchange with an EVM node says why again: a certificate that
does not verify, a refused connection or an expired timeout
([ISS 86](https://github.com/btclib-org/seed-scan/issues/86)). seed-scan
reads it from the `failure_type` of bitcoin-core-rpc's `FetchError`, and
declares bitcoin-core-rpc a dependency, at the first release that
carries it.

For a caller of the package, beside `bundle.VERSION`, `scan.VERSION` and
`report.VERSION`:

- `identify.Coin` has a field `listed` before `alone`, so a `Coin` built
  with `alone` by position changes. `identify.COINS` lists Ethereum's
  `m/44h/60h` there, and not under `legacy`.
- `bundle.Account` has a field `keys`, after `index`.

The release's assets are named as v2026.11.15's, with this version, and
are verified the same way.

## v2026.11.15

The first release of `seed-scan`: there is no earlier version to upgrade
from. It finds what a mnemonic of unknown scheme holds, so that the
mnemonic is typed on one machine and every later step reads public data
alone.

- `seed-scan identify`, offline, reads the mnemonic at a hidden prompt
  and writes a public bundle of account public keys.
- `seed-scan scan` reads the bundle's Bitcoin accounts on an Electrum
  server, and its Ethereum accounts on a JSON-RPC node of Ethereum or of
  the EVM chain `--evm-chain` names, with the balances of the tokens it
  lists for that chain. A token the list does not name is not checked,
  and the report says so.
- `seed-scan forks` reads them on Bitcoin Cash, Bitcoin SV and eCash.
- `seed-scan report`, offline, says what was found and what was not
  checked.

Each server and node is the user's own, named on the command line: there
is no default, since it learns every address it is asked about. `--tcp`
reaches an Electrum server on the user's machine over plain TCP, and is
refused unless the host resolves to loopback addresses alone. What the
server and the node are trusted for, and what `--tcp` exposes, is in
*Limitations, not vulnerabilities* in [SECURITY.md](./SECURITY.md).

The bundle, the scan result, the forks result and the report each name
their format version, `1` in this release. A refusal is a
`SeedScanValueError` or a `SeedScanTypeError`, which a caller catching
`ValueError` or `TypeError` still catches.

Known limits, each an open issue:

- The bundle holds the key at `m/44h/60h`, for MyEtherWallet's layout,
  so the bundle and the key of one `m/44h/60h/<n>` address give every
  Ethereum account's keys, as *What touches the secret* in
  [README.md](./README.md) says. A bundle that holds no key above a
  hardened account is
  [ISS 83](https://github.com/btclib-org/seed-scan/issues/83), for a
  later release.
- Behind a load-balanced node whose backends lag, `scan` can write a
  result that `seed-scan report` refuses, an address read at an earlier
  block than the scan's; the scan is then run again
  ([ISS 79](https://github.com/btclib-org/seed-scan/issues/79)).
- With bitcoin-core-rpc 2026.11.14, which a fresh install resolves, a
  failed exchange with an EVM node no longer says why: a certificate
  that does not verify, a refused connection and an expired timeout
  each still stop the scan, with "no usable answer from the node"
  ([ISS 86](https://github.com/btclib-org/seed-scan/issues/86)).
- The tests that search seed-scan's outputs for a secret exempt more
  text than those outputs write, in a forks report's token line
  ([ISS 75](https://github.com/btclib-org/seed-scan/issues/75)) and in
  the number of a SLIP-0039 passphrase's reason
  ([ISS 76](https://github.com/btclib-org/seed-scan/issues/76)). No
  output writes such text: the gap is in the check, not in a result.

The release attaches the wheel, `seed_scan-2026.11.15-py3-none-any.whl`,
the sdist, `seed_scan-2026.11.15.tar.gz`, `seed_scan-2026.11.15.cdx.json`
and `v2026.11.15.intoto.jsonl`; *Supported versions* in
[SECURITY.md](./SECURITY.md) has the `gh attestation verify` command.
