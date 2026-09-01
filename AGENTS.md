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

Record both the upstream release tag and the exact upstream commit that was
merged. `upstream/main` can move beyond the latest release tag, and a version
number alone is not enough to reproduce a downstream build.

## Forked dependencies

Publish a forked dependency before changing Coraza to consume it:

1. Test the dependency fork and create a distinct annotated tag/release there.
2. Wait for the tag to become available through the Go proxy and checksum
   database. A fresh Git tag can briefly return 404 from `proxy.golang.org` or
   `sum.golang.org`; `GOPROXY=direct GOSUMDB=off go mod download -json ...` is
   useful for diagnosis, but public-proxy resolution must be rechecked before
   announcing the release.
3. Update every affected `go.mod` and `go.sum`, including nested modules such
   as `testing/coreruleset` and `examples/http-server`. Do not assume a root
   `go mod tidy` updates them.
4. Run `go mod tidy`, `go work sync`, `go mod verify`, and inspect the complete
   diff before committing. Keep the fork's module path and the selected
   version explicit.

The `go.work` file contains independent modules. The CRS test module also has
an intentional local `replace` for the Coraza checkout, so its required Coraza
version and sums may look different from the root module. Update them only
when the test module actually needs the change, and run its tests separately.

## Releases

- A GitHub Release made in this fork is downstream and unofficial; it does not
  create a release in the upstream repository.
- A GitHub Release and a Go module release are different things: the Git tag
  determines the module version, while the GitHub Release carries notes and
  discoverability. Create and verify both (`gh release create --verify-tag`).
- Never reuse, move, delete, or overwrite an upstream or published tag. Tag the
  exact tested commit already merged to `origin/main` with a clearly distinct
  name (for example, `v3.7.0-zion.1`). Protect release tags from deletion and
  force-push where the hosting service allows it.
- Keep a predictable suffix: use `v<upstream-version>-<downstream-id>.<n>` and
  increment `<n>` for another build of the same upstream baseline. The suffix
  makes the version a SemVer prerelease, so consumers must pin it explicitly;
  `@latest` normally prefers a stable upstream version and will not select it.
- Release notes must state the upstream base tag/SHA, downstream changes,
  dependency forks, compatibility differences, security fixes, and test
  results. Preserve the Apache-2.0 license and attribution.
- Because the module path still belongs to upstream, a fork tag is not an
  independent official version of `github.com/corazawaf/coraza/v3`. Internal
  consumers importing that path need an explicit `replace` to the fork or a
  pinned local checkout; publishing a tag under the fork owner does not
  redirect the canonical module. Do not change the module path as part of a
  patch release. Publish a first-class public Go module only after deliberately
  adopting a new module path and versioning policy.
- Publish dependency releases first, then update Coraza, then tag Coraza. Do
  not tag a Coraza commit that still depends on an unpublished pseudo-version.
- Prefer signed annotated tags. If signing is unavailable, record that the tag
  is unsigned in the release checklist/notes and do not imply cryptographic
  verification.

For a manual release, the minimum sequence is:

```bash
git switch main
git pull --ff-only origin main
git rev-parse HEAD                 # save the release commit
git tag -a v3.7.0-zion.1 HEAD -m "Coraza v3.7.0-zion.1 (downstream)"
git push origin refs/tags/v3.7.0-zion.1
gh release create v3.7.0-zion.1 --verify-tag --prerelease \
  --title "v3.7.0-zion.1 (downstream)" --notes-file release-notes.md
```

Do not mix manual tags with release-please/GoReleaser automation until one
owner, tag format, permissions, and failure/retry policy have been chosen.

## Validation and CI lessons

- Do not release while the required `enforce-all-checks` check is pending. Save
  the tested commit SHA and the CI result in the release notes.
- Run the root and nested modules explicitly. At minimum use `go test ./...`,
  `go vet ./...`, `go mod verify`, the CRS and example tests, and the relevant
  no-memoize/TinyGo/FIPS/race/fuzz checks.
- In PowerShell, quote build tags such as
  `go test '-tags=coraza.no_memoize' ./...`; otherwise the tag can be parsed as
  a package argument and produce a misleading error.
- Local toolchains do not represent all CI coverage. This release could not
  run race tests locally because CGO/a C compiler was unavailable. Conversely,
  `go run mage.go check` with Go 1.27 exposed an export-data incompatibility in
  the pinned `golangci-lint` v2.6.2. Use the versions declared by CI, or update
  the tool in a separate reviewed change; never silently omit or misreport a
  failed check.

The first downstream release, `v3.7.0-zion.1`, is the reference example for
this process: its tag points at the merged, CI-tested commit, uses the
published `github.com/ZionOVO/libinjection-go v0.3.3-zion.1`, and is explicitly
marked as an unofficial prerelease.

## Repository hygiene

Before an independent public release, audit `CODEOWNERS`, CI permissions,
README badges and links, issue/security contacts, and any references to the
upstream organization. Keep dependency versions pinned and review security
advisories from both upstream and the maintained dependency forks.
