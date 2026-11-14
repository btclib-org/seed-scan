# Changelog

The release's own pull request writes its section here, from the squash
subjects since the previous tag; a pull request adds no entry
(`CONTRIBUTING.md`'s *Pull requests*, section 9 of [the organization
standard][std]). [RELEASE_NOTES.md](./RELEASE_NOTES.md) has the release
notes, which say what a user has to act on; this file is the record
behind them.

[std]: https://github.com/btclib-org/.github

## v2026.11.15

### `seed-scan identify` writes a public bundle from a mnemonic

It reads the mnemonic and its passphrases at hidden prompts, offline, and
searches the path of an address the user knows (closes #2).

### `seed-scan scan` reads a bundle's Bitcoin accounts

Account discovery against the Electrum server the user names, over TLS,
with no default server (closes #6).

### `seed-scan scan --node` reads a bundle's Ethereum accounts

On the JSON-RPC node the user names (closes #18). `evm.Node.balance` and
`nonce` refuse an address before they send it (closes #42).

### `seed-scan forks` reads a bundle on Bitcoin Cash and Bitcoin SV

On the Electrum server the user names, refused unless its blocks at the
chain's checkpoints are that chain's (issue #24).

### `scan` checks its server past Bitcoin's forks

It refuses a Bitcoin Cash server as a Bitcoin one, and neither `scan` nor
`forks` writes a balance its own loader refuses (closes #25) (closes #30).

### `seed-scan report` says what was found, offline

Each used address with its balance and path, what was not checked, and
with `--forks` what `forks` found (closes #14) (closes #15) (closes #32).

### PyPy leaves the platform sweeps and the classifiers

(closes #26).

### `pyproject.toml` declares Development Status 4 - Beta

(#60).

### The tests: identify's shares, the EVM timeout, the wheel's modules

identify's SLIP-0039 shares are pinned clear of Electrum seeds, the EVM
timeout test is bound by its named timeout, and the wheel smoke test
imports `seed_scan.evm` (closes #23) (closes #27) (closes #47) (closes #29).

### The repository opens from the organization's scaffold

With the Read the Docs URL and section 14's shared `RootFileLinks` part
(closes #8) (closes #12) (issue btclib-org/.github#2203).

### `AGENTS.md` points at `REVIEWING.md` for code review

(issue btclib-org/.github#2009).

### prettier leaves `.pre-commit-config.yaml` to pre-commit.ci

(issue btclib-org/.github#2038).

### `CONTRIBUTING.md` no longer prescribes the contributor's checkout layout

(issue btclib-org/.github#2263).

### The locked tools move

The dev-tooling group, soupsieve past the audit's advisory, and
cryptography to a release with the Windows wheels the sweeps lacked
(closes #10) (closes #21) (#1).
