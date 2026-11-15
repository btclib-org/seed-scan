# Changelog

The release's own pull request writes its section here, from the squash
subjects since the previous tag; a pull request adds no entry
(`CONTRIBUTING.md`'s *Pull requests*, section 9 of [the organization
standard][std]). [RELEASE_NOTES.md](./RELEASE_NOTES.md) has the release
notes, which say what a user has to act on; this file is the record
behind them.

[std]: https://github.com/btclib-org/.github

## v2026.11.16

### The bundle holds MyEtherWallet's address keys, not the key above them

The public key of each `m/44h/60h/<n>` below `identify --keys`. The
bundle, the scan result and the report are format version 2; a bundle
or a scan result of version 1 is refused (closes #83) (closes #93).

### `scan` and `forks` prove each history's tip from the last checkpoint

Each header after the chain's last checkpoint is held to its difficulty
rule: Bitcoin's retarget, aserti3-2d for Bitcoin Cash and eCash, and
cw-144 for Bitcoin SV (closes #34).

### `scan` reads every EVM address at the block it asks first

A node's lagging backend fails the scan rather than have it write a
result `report` refuses (closes #79).

### A failed exchange with an EVM node says why, from `failure_type`

bitcoin-core-rpc's `FetchError.failure_type` names the class of what
failed, and bitcoin-core-rpc is a declared dependency (closes #86).

### The aserti3-2d rule is held to Bitcoin Cash Node's reference vectors

Vendored under `tests/_data/aserti3-2d/`, each file pinned (closes #96).

### The vendored aserti3-2d files are checked out byte for byte

`.gitattributes` gives them `-text`, so a checkout with `core.autocrlf`
converts nothing there (closes #99).

### The secret search shapes each token line by its protocol's reason

And searches the number of a SLIP-0039 passphrase's reason (closes #75)
(closes #76).

### The bestpractices.dev answers are measured on v2026.11.15

They name the administrator's bypass, the vulnerabilities, and what the
security mailbox received (closes #81) (#92).

### The shared files follow btclib-org/.github@7369e8a

The push runs' concurrency key, and `release-hold` in `CONTRIBUTING.md`
and `RELEASING.md` (#91).

## v2026.11.15

### `seed-scan identify` writes a public bundle from a mnemonic

It reads the mnemonic and its passphrases at hidden prompts, offline, and
searches the path of an address the user knows (closes #2).

### `seed-scan scan` reads a bundle's Bitcoin accounts

Account discovery against the Electrum server the user names, over TLS,
with no default server (closes #6).

### `scan` and `forks` keep their TLS connection, and take `--tcp`

They keep one TLS connection across requests, and `--tcp` asks a server
whose host resolves to loopback addresses alone over plain TCP (closes #7).

### `seed-scan scan --node` reads a bundle's Ethereum accounts

On the JSON-RPC node the user names (closes #18). `evm.Node.balance` and
`nonce` refuse an address before they send it (closes #42).

### `scan --evm-chain` names the EVM chain, and refuses a node of another

Ethereum, Ethereum Classic with its `m/44h/61h` accounts, BNB Smart
Chain, Polygon PoS, Arbitrum One, OP Mainnet, Base and Avalanche C-Chain,
each checked by its chain id before any address is asked (closes #43).

### `scan` reads ERC-20 token balances on each EVM chain

A pinned list of tokens per chain, OP Mainnet's WBTC among them; a token
balance counts as use, and `evm.Node` refuses a bad contract or block
before any request (closes #44).

### `scan` reads Ledger Live's and MyEtherWallet's legacy Ethereum layouts

At `m/44h/60h/0h/<n>` on every chain, and Ethereum Classic's at
`m/44h/60h/160720h/0h/<n>` on Ethereum Classic (closes #48).

### BNB Smart Chain reads Trust Wallet's legacy accounts at `m/44h/714h`

The bundle declares the coin `bnb` there (closes #49).

### `scan` reads MyEtherWallet's mnemonic layout at `m/44h/60h/<n>`

On every EVM chain, as Ethereum's accounts are (closes #55).

### BNB Smart Chain reads Trust Wallet's Stable Account

The one address at `m/44h/60h/9172h/3604/9999` (closes #56).

### `seed-scan forks` reads a bundle on Bitcoin Cash, Bitcoin SV and eCash

On the Electrum server the user names, refused unless its blocks at the
chain's checkpoints are that chain's (closes #24).

### The bundle declares `ecash-tokens` and `slp-tokens`, which `forks` reads

Coin type 1899, where Cashtab derives, and 245, where Electron Cash SLP
derives; every chain `forks` reads reads both (closes #40) (closes #66).

### A forks report names the token protocols of its chain it does not check

With whether `forks` counts the satoshis of an output holding their
tokens (closes #65).

### `scan` checks its server past Bitcoin's forks

It refuses a Bitcoin Cash server as a Bitcoin one, and neither `scan` nor
`forks` writes a balance its own loader refuses (closes #25) (closes #30).

### `seed-scan report` says what was found, offline

Each used address with its balance and path, what was not checked, and
with `--forks` what `forks` found (closes #14) (closes #15) (closes #32).

### A report's totals count each address's funds once

A Bitcoin, EVM or token total sums an address once where two accounts
list it, and a forks total counts the accounts of one public key and
chain code once (closes #68) (closes #78).

### `cli.main` refuses an `argv` that is no list or tuple of strings

With a `SeedScanTypeError`, before parsing, a lone `str` included
(closes #46). `cli` imports `Sequence` again for `_accepting` (#70).

### The tests hold every public function to the calling convention

And drive each with wrong input; `dumps`, `scan.parse_server` and
`bundle.slip39_passphrase` refuse as the package's errors (closes #3).

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

### `.bestpractices.json` holds the bestpractices.dev answers

`README.md` shows the Best Practices and Baseline badges, and every push
to `main` runs the suite (issue btclib-org/.github#2230) (#58).

### `AGENTS.md` points at `REVIEWING.md` for code review

(issue btclib-org/.github#2009).

### prettier leaves `.pre-commit-config.yaml` to pre-commit.ci

(issue btclib-org/.github#2038).

### `CONTRIBUTING.md` no longer prescribes the contributor's checkout layout

(issue btclib-org/.github#2263).

### The merge is explicit and auto-merge is off

(issue btclib-org/.github#2272).

### The locked tools move

The dev-tooling group, soupsieve past the audit's advisory, and
cryptography to a release with the Windows wheels the sweeps lacked
(closes #10) (closes #21) (#1).
