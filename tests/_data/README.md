# Vendored test data

Each other file under `tests/_data/` is a copy of an upstream file,
pinned below to the commit it was taken from. [Section 7][s7] of the
organization's standard, *Test data is vendored, never fetched*, says
what an entry holds. `tests/proof_test.py` holds each file to the
`blob` its entry gives. No workflow re-checks the pins against upstream
yet: btclib-org/.github#2319.

A vendored file takes `-text` in `.gitattributes`: a checkout with
`core.autocrlf=true` otherwise writes it with CRLF, and its bytes no
longer hash to its `blob`.

[s7]: https://github.com/btclib-org/.github#test-data-is-vendored-never-fetched

## Bitcoin Cash Node's aserti3-2d vectors

The run files of aserti3-2d, the difficulty adjustment of Bitcoin Cash
and eCash. Bitcoin Cash Node's `contrib/testgen/gen_asert_test_vectors.cpp`
writes them, its `contrib/testgen/validate_nbits_aserti3_2d.py` reads
them, and its qa-assets repository on GitLab keeps them, with the
licence that covers them. `tests/proof_test.py` holds
`seed_scan._proof`'s rule to every vector of each run file.

Every entry pins the same commit. This lists the blob of each run file
at the commit:

```shell
commit=1e153d75cdaaa21ca3988977e946a538c74751a2
```

```shell
api=https://gitlab.com/api/v4/projects/bitcoin-cash-node%2Fbchn-sw%2Fqa-assets
tree="ref=${commit:?}&path=test_vectors/aserti3-2d"
curl -fsS "${api}/repository/tree?${tree}" | jq -r '.[] | "\(.id) \(.name)"'
```

`git hash-object tests/_data/aserti3-2d/<file>` gives the blob of the
copy here.

### `tests/_data/aserti3-2d/LICENSE`

```text
repo    gitlab.com/bitcoin-cash-node/bchn-sw/qa-assets
path    LICENSE
commit  1e153d75cdaaa21ca3988977e946a538c74751a2  2020-08-13
blob    ab602974d200aa6849e6ad8220951ef9a78d9f08
pulled  2026-11-15
behind  0 revisions on 2026-11-15
```

Verdict: **identical**.

### `tests/_data/aserti3-2d/run01`

```text
repo    gitlab.com/bitcoin-cash-node/bchn-sw/qa-assets
path    test_vectors/aserti3-2d/run01
commit  1e153d75cdaaa21ca3988977e946a538c74751a2  2020-08-13
blob    70b6cbd11aef9c3b274f411beb1b6d76b58b4b83
pulled  2026-11-15
behind  0 revisions on 2026-11-15
```

Verdict: **identical**.

### `tests/_data/aserti3-2d/run02`

```text
repo    gitlab.com/bitcoin-cash-node/bchn-sw/qa-assets
path    test_vectors/aserti3-2d/run02
commit  1e153d75cdaaa21ca3988977e946a538c74751a2  2020-08-13
blob    fc190a5acfb3c769ffa50c36a4dc58849b89d718
pulled  2026-11-15
behind  0 revisions on 2026-11-15
```

Verdict: **identical**.

### `tests/_data/aserti3-2d/run03`

```text
repo    gitlab.com/bitcoin-cash-node/bchn-sw/qa-assets
path    test_vectors/aserti3-2d/run03
commit  1e153d75cdaaa21ca3988977e946a538c74751a2  2020-08-13
blob    a0658d0c59d4aad90896fbf64c15e71de33bc4c5
pulled  2026-11-15
behind  0 revisions on 2026-11-15
```

Verdict: **identical**.

### `tests/_data/aserti3-2d/run04`

```text
repo    gitlab.com/bitcoin-cash-node/bchn-sw/qa-assets
path    test_vectors/aserti3-2d/run04
commit  1e153d75cdaaa21ca3988977e946a538c74751a2  2020-08-13
blob    e649be413ad8c7aac6fc64efed6847aa65e186cb
pulled  2026-11-15
behind  0 revisions on 2026-11-15
```

Verdict: **identical**.

### `tests/_data/aserti3-2d/run05`

```text
repo    gitlab.com/bitcoin-cash-node/bchn-sw/qa-assets
path    test_vectors/aserti3-2d/run05
commit  1e153d75cdaaa21ca3988977e946a538c74751a2  2020-08-13
blob    456134c43c47f654072adf2ed864f6f260554db3
pulled  2026-11-15
behind  0 revisions on 2026-11-15
```

Verdict: **identical**.

### `tests/_data/aserti3-2d/run06`

```text
repo    gitlab.com/bitcoin-cash-node/bchn-sw/qa-assets
path    test_vectors/aserti3-2d/run06
commit  1e153d75cdaaa21ca3988977e946a538c74751a2  2020-08-13
blob    59492f729ebad5c296167b1ecb6158b94f3aa05e
pulled  2026-11-15
behind  0 revisions on 2026-11-15
```

Verdict: **identical**.

### `tests/_data/aserti3-2d/run07`

```text
repo    gitlab.com/bitcoin-cash-node/bchn-sw/qa-assets
path    test_vectors/aserti3-2d/run07
commit  1e153d75cdaaa21ca3988977e946a538c74751a2  2020-08-13
blob    058e17023ba3db578be9ec4ed2aba2dc58d21d27
pulled  2026-11-15
behind  0 revisions on 2026-11-15
```

Verdict: **identical**.

### `tests/_data/aserti3-2d/run08`

```text
repo    gitlab.com/bitcoin-cash-node/bchn-sw/qa-assets
path    test_vectors/aserti3-2d/run08
commit  1e153d75cdaaa21ca3988977e946a538c74751a2  2020-08-13
blob    7d69ef5dd5a467cedfe4f327c8a325dacf382bc9
pulled  2026-11-15
behind  0 revisions on 2026-11-15
```

Verdict: **identical**.

### `tests/_data/aserti3-2d/run09`

```text
repo    gitlab.com/bitcoin-cash-node/bchn-sw/qa-assets
path    test_vectors/aserti3-2d/run09
commit  1e153d75cdaaa21ca3988977e946a538c74751a2  2020-08-13
blob    3413f956024e9213fa63a9977723674784c07556
pulled  2026-11-15
behind  0 revisions on 2026-11-15
```

Verdict: **identical**.

### `tests/_data/aserti3-2d/run10`

```text
repo    gitlab.com/bitcoin-cash-node/bchn-sw/qa-assets
path    test_vectors/aserti3-2d/run10
commit  1e153d75cdaaa21ca3988977e946a538c74751a2  2020-08-13
blob    d0b6018b2b4e68aea121285dd165c77ad49a2198
pulled  2026-11-15
behind  0 revisions on 2026-11-15
```

Verdict: **identical**.

### `tests/_data/aserti3-2d/run11`

```text
repo    gitlab.com/bitcoin-cash-node/bchn-sw/qa-assets
path    test_vectors/aserti3-2d/run11
commit  1e153d75cdaaa21ca3988977e946a538c74751a2  2020-08-13
blob    b662ee5ac139a8c1af0205e5695ffa1d2cd4b53e
pulled  2026-11-15
behind  0 revisions on 2026-11-15
```

Verdict: **identical**.

### `tests/_data/aserti3-2d/run12`

```text
repo    gitlab.com/bitcoin-cash-node/bchn-sw/qa-assets
path    test_vectors/aserti3-2d/run12
commit  1e153d75cdaaa21ca3988977e946a538c74751a2  2020-08-13
blob    23d26482d94c887d573102d1114681ed00d4c731
pulled  2026-11-15
behind  0 revisions on 2026-11-15
```

Verdict: **identical**.
