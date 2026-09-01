# AGENTS.md

## Repository role

This repository is a downstream fork of `https://github.com/corazawaf/coraza`.

- `upstream` is the canonical Coraza repository.
- `origin` is the downstream repository.
- Keep `upstream/main` as a read-only reference and use `origin/main` as the
  maintained integration branch.
- Treat the `upstream` remote as fetch-only; never push to it accidentally.
- The module path is currently `github.com/corazawaf/coraza/v3`. Do not change
  it casually; a public module under a new namespace requires an intentional
  migration of imports and nested modules.

## Branches and changes

- Protect `main`; integrate changes through reviewed pull requests.
- Create `feature/*` branches for downstream work and `sync/*` branches for
  upstream synchronization.
- Keep downstream changes small, logically separate, and documented. Changes
  that are generally useful should be proposed upstream and removed here once
  upstream accepts them.
- Do not rewrite or force-push the shared `main` branch.

## Synchronizing upstream

Use a merge-based sync for the shared branch:

```bash
git fetch upstream --prune --tags
git switch main
git pull --ff-only origin main
git switch -c sync/upstream-<date>
git merge --no-ff upstream/main -m "chore: sync upstream main"
```

Resolve conflicts deliberately. In particular, do not blindly take `ours` or
`theirs` for `go.mod` or `go.sum`; verify the supported Go version and the
intentional `github.com/ZionOVO/libinjection-go` dependency. After resolving:

```bash
go mod tidy
go work sync
go run mage.go check
```

Push the sync branch and open a pull request against `main`. Review generated
dependency changes and run the relevant TinyGo, CRS, race, fuzz, and benchmark
checks when the affected code warrants them.

## Releases

- A GitHub Release made in this fork is downstream and unofficial; it does not
  create a release in the upstream repository.
- Never reuse or move an upstream tag. Tag a tested commit with a clearly
  distinct name (for example, `v3.7.0-zion.1` or
  `downstream-YYYY.MM.DD`). Prefer signed, immutable tags.
- Release notes must state the upstream base tag/SHA, downstream changes,
  dependency forks, compatibility differences, security fixes, and test
  results. Preserve the Apache-2.0 license and attribution.
- Because the module path still belongs to upstream, a fork tag is not an
  independent official version of `github.com/corazawaf/coraza/v3`. Internal
  consumers should use an explicit `replace` or a pinned checkout. Publish a
  first-class public Go module only after deliberately adopting a new module
  path and versioning policy.

## Repository hygiene

Before an independent public release, audit `CODEOWNERS`, CI permissions,
README badges and links, issue/security contacts, and any references to the
upstream organization. Keep dependency versions pinned and review security
advisories from both upstream and the maintained dependency forks.
