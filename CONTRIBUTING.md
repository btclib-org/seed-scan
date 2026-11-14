# Contributing

What this repository holds in common with the others of the organization
— the toolchain, the lint gate, the tool tables behind it, the workflow
set and the branch rules — is stated once in the
[organization's standard](https://github.com/btclib-org/.github), each
rule with the alternative it was decided against. It binds this
repository, so a change departing from it is a divergence, and one filed
as an issue in btclib-org/.github rather than here: a difference between
two repositories belongs to neither of them.

**This file is the same in every repository of the organization up to
its last section.** What is true of one tree only — the commands that
build its environment, the gates it runs, which of its workflows decide
a merge — is under that heading, and the comparison stops there.

How the organization decides, and who holds which role, is
[`GOVERNANCE.md`][governance]; what it intends to do, and what it
deliberately does not, is [`ROADMAP.md`][roadmap]. Both are the
organization's, one copy each beside the standard.

## The issue tracker

Where an issue is filed, and what an alignment finding has to name, is
[the standard's *What this repository is*][s-what]: an issue spanning
repositories, or whose subject is the standard, goes to
[btclib-org/.github](https://github.com/btclib-org/.github/issues), and
one about this tree alone stays here.

A finding noticed while doing something else goes where `REVIEWING.md`'s
*What is filed, and what is not* says, for an author as much as for a
reviewer: a pull request answering two questions cannot be accepted for
either.

An issue labelled `good first issue` is one set aside for a first
contribution: small and self-contained.
[One search][good-first] lists the open ones across the organization, so
a newcomer need not know in advance which repository to look in.

## Documentation and comments

[Section 9 of the standard][s9] is the prose style beyond *Write
plainly* below, and it governs the prose this tree ships — comments,
docstrings and markdown. It is not restated here: a second wording is
the one that goes stale, which is that section's own *One fact in one
place*.

A commit message is prose this tree ships too, though section 9 does not
say so: [the only merge method the rule accepts][s11] puts it on `main`
as the landing commit's body, so what is written in one is read there
long after the branch is gone.

## Working with an LLM

**Development here is LLM-based.** Most issues, code and reviews are
written by agentic sessions that the maintainer directs and reads.
Humans are welcome, as long as they are comfortable working that way.

**A contribution is yours, whoever wrote it.** Read every line before
you open the pull request, understand it, and be ready to answer a
review without the model. Text or code you have not read, or cannot
explain, is closed without review.

**For a pull request the agent opened, whoever approves it reads every
line and answers for it as their own**, the agent being the pull-request
agent of [`GOVERNANCE.md`][governance]'s *Roles*. The maintainer,
landing it through the bypass without an approval, reads every line and
answers for it instead, the landing being their own act; requiring an
approval even where the bypass is kept is the alternative set aside. The
agent signs off nothing, since a bot cannot certify the [Developer
Certificate of Origin][dco], so the approval, or that landing, is the
certification.

**The `agent` label hands an issue to that agent**, in a repository
that calls its implement workflow. [Section 11][s11]'s *Labels and issue types*
says who applies it, [section 10][s10] what the agent does with an issue
it admits, and the workflow's header which issues it takes, what answers
a `decision`, and the switch that turns it on.

**Write plainly**, in the tree and on the forge: the point first, plain
words, one fact per sentence. On the forge, the title and the first
sentence carry the point; a body is at most two short paragraphs before
any code block or template section; a comment is about 250 words, and
never more than 300, with no list and no heading; a review's summary
takes the shape `REVIEWING.md`'s *The verdict* gives it.

## Pull requests

What `main` accepts, and what it refuses to everyone, is [section 11 of
the standard][s11]. Run the gates locally before opening anything —
the last section of this file says which they are — because CI runs
exactly them, so a red run there is a local run that was not done.

**Every commit of a pull request carries a `Signed-off-by:` trailer
naming its author**, which certifies the [Developer Certificate of
Origin][dco]. `git commit -s` adds it, and `git rebase --signoff <base>`
adds it to commits already made. The `Sign-off` check is required, so
only an administrator can merge a pull request with a commit the check
refuses: *Landing it* says why `--admin` waits for no required check.
The check's failure prints the command that adds the trailer. [The
standard's *Signatures*][s-sigs] says why a signature does not replace
it, and which commits the `Sign-off` job skips.

What a pull request's title and description have to say about the issues
it closes, and why a manual link in the Development panel is a trap
neither of them shows, is [the standard's *What a pull request says it
is*][s-title]. Read it before opening one; it is the rule most often
found broken after the fact.

**Before it is opened, the branch's own commit subjects and bodies are
read against that same rule.** The description does not exist yet to
disagree with them, and [the standard][s-title] has the command that
scans the branch's own commit text for a verb in front of a reference.

**The two spellings are named here as well as there, against [section 9's
*One fact in one place*][s9]**, the paragraph above naming the section
and not the forms, which are the half a citation is got wrong in:
`(closes #N)` cites an issue the change closes, wherever the citation
sits — the title, the commit subject where [*Merge method*][s11] makes
that the thing that lands — and `(issue #N)`
cites, in those same places, an issue the change advances and does *not*
close. One token holds one meaning whichever file it sits in, so the
pair is chosen by what is true of the change rather than by which file
is being written, and a tree's own landed subjects are not what to copy
it from: nothing already landed is rewritten, so what a repository wrote
before the rule stays where it is.

`REVIEWING.md` is the standard a review is written against, and is this
file's other half. Read before opening a pull request, it is what the
pull request will be answered against.

A pull request adds no entry to `CHANGELOG.md` or `RELEASE_NOTES.md`, a
release's own pull request excepted ([section 9][s9], [section 12][s12]).

### One subject, opened as soon as it is written

A pull request answers one question. Issues that share a subject are one
pull request, closing each of them; issues that do not are one pull
request each, however small either of them is.

It is opened the moment it is written and verified — not held for the
previous one to be reviewed or to land, and not batched with the next. A
batch arrives as one reviewing job with several subjects, which is the
shape that costs the most to read; a finished pull request held back is
review that could have started and did not. A security advisory's fix is
the exception, held back as [section 12][s12]'s *A security advisory is
worked in this order* says.

Working this way stacks branches, which is fine and costs one rule: a
child whose base was amended is moved with the old base named,

```shell
git rebase --onto <new-base> <old-base-sha> <child>
```

because a plain rebase replays the base's old commit inside the child,
and the forge then shows the base's old text as additions with nothing
red anywhere. Read the child's diff afterwards rather than trusting the
rebase, and retarget each child onto `main` as its parent lands.

### The review

A review is given promptly and on local evidence. It does not wait for
CI, does not report a check as a finding, and does not discuss a run at
all: whether CI is green is the author's business, once, at landing time.

The exchange is anchored to a sha rather than to a branch, a branch being
free to move under a review:

- the author hands off by naming the sha pushed and the evidence run
  against it, then leaves that head alone;
- the reviewer answers with findings — where, what is wrong, how they
  know it, and whether each is blocking;
- the author accepts what is reasonable, declines the rest with a reason
  in the thread, pushes the answer without waiting for CI, and resolves
  each thread once answered;
- the reviewer reopens a thread whose finding is still blocking, and
  re-reviews the delta rather than the branch.

**What ends the loop is the ack of record.** A reading that says what
it found and delivers no verdict is a review too and ends nothing; [the
standard's *Review*][s-rev] has which is which, and `REVIEWING.md` has
how each is written. A disagreement that survives a second exchange
goes to the maintainer instead of into a third round.

**The ack of record is not the approval *Landing it* asks for**: it is
a bot's review of type COMMENT ([the standard's *Review*][s-rev] says
whose).

### Landing it

CI is read once, and this is where: on the head that lands. `main` does
not ask that head to be up to date with it, and [section 11][s-branch]
says why. So a branch is rebased only where it conflicts with `main`. A
rebase that moved nothing but the base leaves the ack standing; one that
resolved a conflict does not, that resolution being a change no reviewer
has seen.

When `main`'s CI is red after a merge, its repair takes priority over
every other pull request, because until it lands `main`'s runs cannot
tell a new failure from the one already there. A pull request armed with
`--auto` (below) stays armed, and others keep landing meanwhile. Holding
every landing for a repair costs more than the break it guards against,
so the risk of landing on a red `main` is accepted
(btclib-org/.github#1777).

A pull request whose required check is red only because `main` was red
is closed and reopened once the repair lands (`gh pr close <n>`, then
`gh pr reopen <n>`). A re-run would test the old merge commit, and the
reopen runs the checks on the merge GitHub then holds. GitHub refreshes
that merge lazily, so the reopen's runs can still test the old one. A
run's log is read before the run is relied on: its line `HEAD is now at
<sha> Merge <head> into <base>` names the merge it tested, and where
`<base>` lacks the repair, the pull request is closed and reopened
again. No push is made, so its approvals and its ack of record stand.
Closing disarms `--auto`, so it is armed again once the checks are
green. The reopen also runs the review bot again, and changes that
review requests are answered like any other review's.

Then squash, [the only method the rule accepts][s11].

**It lands once somebody other than its author has approved that
head**, through `gh pr merge` pinned to it:

```shell
gh pr merge <n> --squash --match-head-commit <the head the checks ran on>
```

With `--auto` added, GitHub runs the same merge once the approval and
the checks are in.

**Where the repository has a bypass, the maintainer may land without
that approval, through it**: [`GOVERNANCE.md`][governance]'s *How a
decision is made* says which repositories.
`--admin` turns off `gh`'s own refusal, and GitHub applies
the bypass to the merge. `enforce_admins` is off, so it waits for no
required check either:

```shell
gh pr merge <n> --squash --admin \
  --match-head-commit <the head the checks ran on>
```

Without `--admin`, `gh pr merge` refuses a head with no approval, saying
it `is not mergeable: the base branch policy prohibits the merge`.

**The pin is not optional**, in either command. Reading the ack and
merging are two calls, and the head is free to move between them — the
push that would move it comes out of the same round the verdict does.
Unpinned, the command takes whatever sits at the head when it runs;
pinned, it refuses a head that has moved, and a round lost that way is
cheaper than a tree nobody has read reaching `main`.
*The review* above anchors the exchange to a sha and [section 11][s11]
has an ack name one: the pin is that rule reaching the call that
performs the landing.

**Verify what landed rather than trusting the answer**, the signature
[the standard asks for][s-sigs] being a valid one rather than a
particular signer's:

```shell
gh api repos/{owner}/{repo}/commits/main \
  --jq '.commit.verification | {verified, reason}'
```

**What it closed is read again here too, from the landed sha rather
than from the pull request**: [the standard's *What a pull request says
it is*][s-title] has the second read, and why the first alone does not
reach a squash subject composed after it runs.

The forge deletes the head branch itself, per the setting section 11
names. What is still yours is bringing every checkout sitting on `main`
up to date,
that being where the next session starts from and a stale one being where
a branch gets built on a base that has moved. `REPOSITORY.md` carries the
settings and why they are what they are.

[s-what]: https://github.com/btclib-org/.github#what-this-repository-is
[s11]: https://github.com/btclib-org/.github#11-github-settings
[s9]: https://github.com/btclib-org/.github#9-prose-comments-and-docstrings
[s10]: https://github.com/btclib-org/.github#10-workflows
[s12]: https://github.com/btclib-org/.github#12-releasing
[s-title]: https://github.com/btclib-org/.github#what-a-pull-request-says-it-is
[s-rev]: https://github.com/btclib-org/.github#review
[s-sigs]: https://github.com/btclib-org/.github#signatures
[s-branch]: https://github.com/btclib-org/.github#branch-protection-and-rulesets
[dco]: https://developercertificate.org/
[governance]: https://github.com/btclib-org/.github/blob/main/GOVERNANCE.md
[roadmap]: https://github.com/btclib-org/.github/blob/main/ROADMAP.md
[good-first]: https://github.com/search?q=org%3Abtclib-org+label%3A%22good+first+issue%22+is%3Aopen&type=issues

## Worktrees

Run `git fetch origin` in the primary checkout, then check that
`git status --porcelain` is empty and `git branch --show-current` is
`main`. Run `git pull --ff-only` only when both checks pass, then verify
`git rev-parse HEAD origin/main` prints the same sha twice. Create a separate
worktree for each task with
`git worktree add <path> origin/main -b <branch>`. After committing,
remove it with `git worktree remove <path>`. If initialized submodules
make that fail,
check for uncommitted, untracked, and ignored files in the worktree and
its initialized submodules. Preserve anything needed before retrying with
`git worktree remove --force <path>`; it can delete those files. Keep the
primary checkout clean and on `main`; do not
switch branches or stash there. Hooks can fix files in place, and the local
`main` and `refs/stash` are shared by all worktrees.

## This repository in particular

Everything above is the same file in every repository of the
organization; everything below is this one's, and the comparison stops at
this heading.

<!-- The toolchain badges are here rather than in the README because they
report no state: each names a choice, and this is the file that says how
the choice is enforced and what the command for it is. The README keeps
the badges that can turn red. --> [![calendar versioning:
yyyy.m.d](<https://img.shields.io/badge/cal_ver-yyyy.m.d-1674b1.svg?logo=calver>)](<https://calver.org/>)
[![uv](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json)](https://github.com/astral-sh/uv)
[![format:
ruff](https://img.shields.io/badge/format-ruff-yellowgreen.svg?logo=ruff)](https://docs.astral.sh/ruff/formatter/)
[![lint:
ruff](https://img.shields.io/badge/lint-ruff-yellowgreen.svg?logo=ruff)](https://docs.astral.sh/ruff/)
[![docstrings:
ruff](https://img.shields.io/badge/docstrings-ruff-yellowgreen.svg?logo=ruff)](https://docs.astral.sh/ruff/rules/#pydocstyle-d)
[![type check:
mypy](https://img.shields.io/badge/type_check-mypy-yellowgreen.svg?logo=mypy)](https://mypy-lang.org/)
[![lint:
markdownlint-cli2](https://img.shields.io/badge/lint-markdownlint--cli2-yellowgreen.svg?logo=markdown)](https://github.com/DavidAnson/markdownlint-cli2)
[![pre-commit
enabled](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit)](https://github.com/pre-commit/pre-commit)
[![GitHub repository:
btclib-org/seed-scan](https://img.shields.io/badge/GitHub-btclib--org%2Fseed--scan-181717?logo=github)](https://github.com/btclib-org/seed-scan/)

To get an overview of the project, read the [README](./README.md).

### The public surface

**Every module and every package declares `__all__`**, at every depth of
the tree. A name is public here because a list says so, not because it
happens to lack a leading underscore. An empty list is a legitimate
answer, for a module with nothing public of its own; declaring nothing is
not. For a package the list is what the `__init__` publishes, submodules
included; for a module it is what the module itself defines, a name it
imported belonging to the module that defines it.
`seed_scan.__all__` is the root of that tree, written out rather
than discovered, so that a new module is published by somebody deciding
to. `tests/all_test.py` checks all of this and finds the modules rather
than listing them: a public name kept out of a list is recorded in its
`UNEXPORTED` table.

**The package imports the standard library and what `dependencies` in
`pyproject.toml` declares.** What it builds on is `bip39-slip39`,
`bip32-descriptors`, `btclib-wallet` and `coin-addresses`, and what is
general goes down to them rather than staying here
(btclib-org/.github#2203). `tests/imports_test.py` imports each module
alone and refuses one that loads a module of no declared package and of
nothing they require, and holds `seed_scan.bundle` to the standard
library, so that a command reading a bundle needs no dependency of
`identify`.

**The package re-exports nothing it does not own**
(btclib-org/btclib#2404): a name is published by the module that defines
it, and `tests/all_test.py` holds every `__all__` to that.

**A refusal is a `SeedScanTypeError` or a
`SeedScanValueError`**, each beside the built-in of its name so that
a caller catching `ValueError` still catches it, and both under
`SeedScanException`. `tests/exceptions_test.py` holds the classes to
that shape.

### The environment and the gates

uv is the only tool that must be installed; it fetches interpreters,
linters and packaging tools itself. `uv sync` creates the environment.

```shell
uv sync
```

No test reaches the network. [tests/README.md](./tests/README.md) is
where the suite and its switches are described.

The gate is the suite, the hooks and the documentation build:

```shell
uv run pytest
uv run pre-commit run --all-files
uv run --locked --no-default-groups --group docs \
    sphinx-build -n -W -b html docs/source docs/build/html
```

The documentation gate also runs the checks of the built pages that
*Reproducing what CI runs* gives under `docs.yml`, `check_included_links.py`
among them.

`--cov` is in `addopts`, so the bare `pytest` above is the coverage gate
and `fail_under` is what it answers against — 100%, and coverage takes
that literally: a statement or a branch no test reaches fails it. A
selective run is reported and not gated, and `tests/conftest.py`'s
`coverage_fail_under` is what makes that difference.

The documentation build is the one to remember, because no hook reads
reStructuredText: a docstring docutils cannot parse fails it with every
hook green — a name ending in an underscore is a reference to a link
target, and the fix is double backticks around it. `-n` turns an
unresolved cross-reference into a warning for `-W` to fail on, and
`conf.py`'s `intersphinx_mapping` is what resolves a reference into the
standard library.

**Every job that installs from `uv.lock` passes `--locked`.** The jobs
that do not are deliberate:

- `deps-latest.yml` runs `uv lock --upgrade` to test the newest versions,
  and `deps-oldest.yml` calls `reusable-deps-oldest.yml`, which re-locks to
  the floors; neither commits the lock.
- `pypi-install.yml` runs `pip install` to test the published release.
- `test.yml`'s `dist` job smoke-tests the wheel with `uv pip install`,
  which resolves its dependencies from the index rather than from the
  lock.
- `uv build` and `uv run --no-project` install none of the project's
  dependencies.
- The `dev-version` action re-locks after writing a rehearsal's version
  suffix; `uv lock` keeps the versions already locked.
- `public-api`, in btclib-org/.github's `reusable-public-api.yml`, runs
  griffe with `uvx`, then btclib-org/.github's `api_gaps.py` with
  `uv run --no-project --with` griffe: the version that workflow pins,
  with its own dependencies unlocked.

**Check exit codes, not filtered output.** `pre-commit run ... | grep -v
Passed` hides a failure, and `grep` finding nothing exits 1, which is not
the gate's answer to anything.

**The lint gate is not installed as a git hook.** `pre-commit install`
writes into the common git directory, which every worktree of this
repository shares: `git -C <worktree> rev-parse --git-path hooks` answers
with the primary checkout's `.git/hooks` from every one of them. So one
session installing it installs it for every other. Run the gate by hand
before committing — the `uv run pre-commit run --all-files` above.

**Prefix any `--python <version>` command with
`UV_PROJECT_ENVIRONMENT=.venv-<version>`, naming the interpreter that
command selects — `.venv-3.11` for `--python 3.11`.** Without it,
`uv run --python <version>` removes `.venv`, builds it again on that
interpreter and with that command's own group set, and leaves it there.
`uv sync` restores it.

### The editor

`.vscode/settings.json` and `.vscode/extensions.json` are tracked, and they
hold no preference: the recommended extensions are the tools
`.pre-commit-config.yaml` already runs, and the settings put the fixing ones
on save. Installing them is optional and changes nothing about what a local
run enforces.

Anything machine-local — an interpreter path, a telemetry answer, a theme —
belongs in the editor's own user settings instead, those two files being
read by every checkout of this repository.

### Reproducing what CI runs

Each command below is the one a CI job runs. Keep this section true when a
workflow changes.

`os-ubuntu.yml`, `os-macos.yml`, `os-windows.yml` and `deps-oldest.yml`,
the suite job of each — the suite, on one cell of a matrix. `--no-cov`
undoes the `--cov` addopts carries, the `coverage` job below being where
coverage is measured and gated:

```shell
uv run --locked --no-default-groups --group test pytest --no-cov
```

`test.yml`, the `coverage` job, the gate the bare `pytest` above is:

```shell
uv run --locked --no-default-groups --group test pytest
```

`test.yml`, the `dist` job — build the distribution files, check them and
install one. `release.yml`'s `test` job calls this workflow, which then
checks the files `reusable-build.yml` built and uploaded instead of
building its own. `release.yml`'s publish jobs download that `dist`
artifact, so what
the checks below judge is what an index ends up serving. `normalize_sdist.py`
is what puts the commit's own time into every member of the sdist, and
its docstring says why the backend's archive is not published as it
stands; `sha256sum` after it is the digest a rebuild from the tag is
compared against, per RELEASING.md's
[Rebuild a release from its tag](./RELEASING.md#rebuild-a-release-from-its-tag).
`generate_sbom.py` writes the CycloneDX bill of materials into `sbom/`,
which `reusable-build.yml`'s `attest` job signs beside the two files on a
release. It is
btclib-org/.github's, served from `main`, and reads this tree from the
working directory, so the commands fetch it first:

```shell
export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
uv build
uv run --no-project --python 3.15 .github/scripts/normalize_sdist.py dist/
sha256sum dist/*
served=$(mktemp -d)
git clone --depth 1 --filter=blob:none --sparse \
    https://github.com/btclib-org/.github "$served"
git -C "$served" sparse-checkout set .github/scripts
uv run --no-project --python 3.15 \
    "$served"/.github/scripts/generate_sbom.py dist/ sbom/
uv run --locked --only-group check twine check --strict dist/*
uv run --locked --only-group check check-wheel-contents dist/*.whl
uv run --locked --only-group check pyroma --min 10 dist/*.tar.gz
```

The job then installs the wheel it just built from an empty directory,
reads the version back, and imports each published module: an import
of the package alone would pass a wheel missing a module that nothing
imports eagerly:

```shell
tmp=$(mktemp -d)
set -- "$PWD"/dist/*.whl
cd "$tmp"
uv venv
uv pip install "$1"
.venv/bin/python -c "
from importlib.metadata import requires, version
import seed_scan
from seed_scan import bundle, cli, exceptions, forks, identify, report, scan

print(version('seed-scan'), requires('seed-scan'))
assert seed_scan.__version__ == version('seed-scan')
assert issubclass(exceptions.SeedScanValueError, ValueError)
assert callable(cli.main) and callable(identify.identify)
assert callable(scan.scan) and callable(report.report)
assert bundle.VERSION == 1
"
```

Last, it unpacks the sdist outside the checkout and runs the suite
there, under the coverage job's floor; from the checkout's root:

```shell
tmp=$(mktemp -d)
tar -xzf dist/*.tar.gz -C "$tmp" --strip-components=1
cd "$tmp"
uv run --locked --python 3.15 --no-default-groups --group test pytest
```

`lint.yml`, the `lint` job — this file *is* the lint gate, so there is no
second list of tools anywhere:

```shell
uv run --locked --only-group lint \
    pre-commit run --all-files --show-diff-on-failure
```

`docs.yml`, the `docs` job — the build, and then reads of the pages it
wrote:

```shell
uv run --locked --no-default-groups --group docs \
    sphinx-build -n -W -b html docs/source docs/build/html || exit $?
if grep -rn 'href="#\.\.\?/' docs/build/html --include='*.html'; then
    echo "::error::the links above resolve to no page (unresolved relative path)"
    exit 1
fi
```

What myst renders for a destination it cannot resolve is an anchor to an
id no page has. `-W` reports it because `docs/source/conf.py` resolves the
links the included root files carry and suppresses no myst warning; the
`grep` is what still finds one the day a suppression goes back in.

Last, the job runs btclib-org/.github's `check_included_links.py`, at the
commit `docs.yml` pins, over the same pages. It fails on a link to a file
the docs render that is left at the repository's `/blob/main/` address
rather than at the file's page here. Section 2 of the standard, *The
documentation*, is the rule:

```shell
found=0
pin=$(sed -n 's/.*reusable-docs\.yml@\([0-9a-f]*\).*/\1/p' .github/workflows/docs.yml)
served=$(mktemp -d) &&
git clone --quiet --filter=blob:none --sparse \
    https://github.com/btclib-org/.github "$served" &&
git -C "$served" sparse-checkout set .github/scripts &&
git -C "$served" checkout --quiet "$pin" &&
uv run --no-project --python 3.15 \
    "$served"/.github/scripts/check_included_links.py docs/build/html || found=$?
rm -rf "$served"
test "$found" -eq 0 || exit "$found"
```

`codeql.yml` has no line here: its jobs run `github/codeql-action` and no
command of this project's, so reproducing it locally means the CodeQL CLI
and a database rather than a `uv run`.

### What gates a merge, and what only reports

`lint.yml`, `test.yml`, `docs.yml` and `sourcery.yml` produce the
required checks, and `REPOSITORY.md` reads the rule back from the
endpoint rather than restating it. So a diff does not reach a review
without having passed them or passing them beside it on the same sha,
which is the reliance `REVIEWING.md` provides for.

| workflow | when | what it varies |
| --- | --- | --- |
| `test` | pull request, push | — |
| `lint`, `docs` | pull request, push | — |
| `claude-review` | pull request, and `@claude` in a comment | — |
| `claude-release` | by hand, by an administrator | — |
| `api-break` | pull request | — |
| `sourcery` | pull request | — |
| `verified-signatures` | push to main | — |
| `codeql` | pull request, push, and weekly | the languages |
| `os-ubuntu` | weekly, a release | images × interpreters |
| `os-macos` | weekly, a release | images × interpreters |
| `os-windows` | weekly, a release | images × interpreters |
| `deps-latest` | weekly | dependencies upgraded |
| `deps-oldest` | weekly | the floor interpreter, dependencies at their floors |
| `scorecard` | weekly, push to main | — |
| `links` | weekly | — |
| `pypi-install` | weekly, a release | what PyPI serves |
| `sdist-rebuild` | weekly | the latest release's sdist, rebuilt |
| `release` | a tag, and a rehearsal | the workflows it calls |

Which workflows that last row covers is
`grep -n 'uses: \./\.github/workflows/' .github/workflows/release.yml`,
not a list here. Which day each of the rest runs is section 10 of
[the organization's standard](https://github.com/btclib-org/.github), and
not this file's to restate.

The `test` row and the `lint`, `docs` row run one image on one interpreter:
`ubuntu-latest`, and the version `.python-version` names. `claude-review` gates
nothing: a review that gates a merge would make a model's judgement a branch
rule. So few checks gate a merge because the plan caps the jobs the whole
organization may run at once, and `REPOSITORY.md`'s *Plan-gated settings*
records that ceiling. `verified-signatures.yml` reports after each push to
`main` whether every commit pushed is `verified`; [the standard's
*Signatures*][s-sigs] has the rule.

### The secrets baseline

`detect-secrets` reads `.secrets.baseline` to decide which findings have
already been reviewed, and adding a finding means regenerating it. The command
preserves the plugin selection the file already carries, which is
deliberate: the two entropy plugins are off, because the vectors this
package is to carry are extended public keys and encoded addresses,
where a new high-entropy string is what a legitimate addition looks like:

```shell
uvx detect-secrets scan --baseline .secrets.baseline
uv run --locked --only-group lint pre-commit run detect-secrets --all-files
```

Read the diff before committing it: a new entry is a finding somebody has
to have looked at, which is the whole point of a baseline over an
exclusion.
