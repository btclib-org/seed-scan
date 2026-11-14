# Security policy

## Reporting a vulnerability

If you have found a security vulnerability, please do not open a GitHub
issue: an issue is public from the moment it is filed, and so is the
window between filing it and a fix being released.

Report it privately instead, by
[opening a security advisory](https://github.com/btclib-org/seed-scan/security/advisories/new).
Only the maintainers can see it, the discussion stays private until an
advisory is published, and a CVE can be requested from it if the
vulnerability warrants one.

If you have no GitHub account, or would rather not use it for this,
responsible disclosure by email to *security at btclib dot org* is
equally welcome.

A report is acknowledged within 7 days, and a fix or a published advisory
follows within 90 days.

A report triaged as easy to rediscover is fixed as soon as possible, since
anyone can find it in the meantime, and its advisory is published with the
fix.

## What belongs here

This package is run by somebody holding a secret, and its first promise
is the split
[README.md's *What touches the secret*](https://github.com/btclib-org/seed-scan/blob/main/README.md#what-touches-the-secret)
describes. Anything that breaks it is a vulnerability to report here:

- a mnemonic, a passphrase, a seed or a private key that reaches the
  bundle, the report, a log, a file, an error message or the network;
  section 7's
  [*A refusal carries no secret*](https://github.com/btclib-org/.github#a-refusal-carries-no-secret)
  says what a refusal may print;
- a command that reads one from its arguments, where the process list
  and the shell's history would show it;
- `identify` or `report` opening a connection, or `scan`, `forks` or
  `report` asking for a secret or reading a file other than the bundle,
  what the commands before it wrote and, for `scan` and `forks`, the CA
  certificates they verify their server against, and `scan` its node:
  the system's, or, for a server, those of the file the user names;
- a query sent to a server, a node or an explorer the user did not name.

So is a report that calls a scheme or a coin checked when it was not,
since a user acts on its "nothing found", and so is a flaw in the
distributions published to PyPI or in their provenance.

What is beneath the command is not here: the mnemonic schemes, the
derivation and the addresses are the business of the packages
`README.md` names. Report a flaw wherever you found it, though: routing
a report is the maintainers' job, not the reporter's, and a doubt about
which project owns a flaw is not a reason to keep it to yourself.

## Security review

No security review has been done yet.

## Supported versions

Only the latest release is supported. Versions are calendar-based
(`YYYY.M.D`), a fix is published as a new release, and nothing is
backported.

Wheels and sdist are published to PyPI with PEP 740 attestations, through
a workflow that no long-lived token can authenticate for (PyPI Trusted
Publishing), so a distribution can be traced back to the workflow run and
the commit it was built from.

The same files are attached to the GitHub release, and those copies carry
a build provenance attestation of their own, signed in the run that built
them:

```shell
signer=btclib-org/.github/.github/workflows/reusable-build.yml
id=$(gh api repos/btclib-org/seed-scan --jq .id)
cert='.[].verificationResult.signature.certificate'
```

```shell
gh attestation verify <file> --owner btclib-org \
  --signer-workflow "${signer:?}" \
  --source-ref refs/tags/v<version> --format json \
  --jq "${cert:?}.sourceRepositoryIdentifier" | grep -qx "${id:?}"
```

The exit code is `0` only where a verified attestation names this
repository. The repository is compared by its id, which a rename keeps:
`--repo` compares the current name and refuses every release signed
before a rename.

`<file>` is a distribution file from the release.

`--signer-workflow` is what makes that say which workflow signed, rather
than accepting any attestation this repository has: the signing runs in
`btclib-org/.github`'s `reusable-build.yml`, which `release.yml` calls,
and `--source-ref` is what keeps a build of a branch from passing as the
release.
A CycloneDX bill of materials is attached beside them, generated from the
built wheel and covered by the same attestation. Either distribution file
can also be rebuilt from its tag and compared, the build being
reproducible: RELEASING.md has that command.

## Limitations, not vulnerabilities

These are known and inherent. They are worth stating because the
person running `identify` holds the keys to funds:

- **The package cannot make the machine safe.** It cannot tell whether
    the machine running `identify` is offline, or whether anything else
    on it, a keylogger or a terminal that logs what is typed, records
    the mnemonic. Run it on a machine you trust, with the network off.
- **Secret material lives in Python objects**, which are immutable and
    not zeroized: a mnemonic typed at the prompt stays in the process
    memory until garbage collection, and may have been copied by the
    interpreter meanwhile.
- **Nothing here is constant-time.** The package is pure Python.
- **The Electrum server is trusted for what it answers.** `scan` and
    `forks` take each history as the server the user names answers it.
    Each confirmed transaction's merkle branch is checked against a
    header the same server answers, so a server that lies can answer a
    history of its own making. `scan` and `forks` compare the server's
    genesis block with Bitcoin's, and its blocks at checkpoints with
    those of the chain read: that refuses an honest server of a chain
    whose blocks differ at those heights, as Bitcoin Cash's for `scan`,
    and not one of a chain that parts from the one read above its last
    checkpoint. It does not prove that a history answered is that
    chain's. Proving each history against the chain is
    [btclib-org/seed-scan#34](https://github.com/btclib-org/seed-scan/issues/34).
