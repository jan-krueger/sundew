# Contributing

## Setup

Needs Docker and make. Everything builds and runs in containers; tests need
`--cap-add NET_ADMIN`, which the make targets pass. The host kernel must have
the `ip_set` modules loaded (`make` does not load them).

## Tasks

```bash
make build            # module and helper for NGINX_VERSION (default 1.30.8)
make test             # lifecycle and privileges
make test-async       # request suspension, aborts, resets, load
make test-features    # cache, allowlist, dryrun, status, stats
make test-all         # the three suites
make test-pid1        # nginx as PID 1 in a container
make unit             # helper unit and fuzz tests
make lint             # cargo fmt --check and clippy
make fmt              # format the helper (writes through a patch, the source stays read-only in the container)
make docs-build       # build the documentation the way CI will
make docs             # serve it on http://127.0.0.1:8000
make test-image       # build the release image and use it like a user would
make bench            # throughput of the release image: no check, cache hits, misses
make artifacts BASE=debian:trixie NGINX_VERSION=1.26.3 DISTRO_NGINX=1   # one release target into dist/

make test-all SAN=1                  # nginx and the module with ASan and UBSan
make test-all NGINX_VERSION=1.24.0
```

## Rules

- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/),
  subject line only.
- C follows nginx's style. Rust passes `cargo fmt` and `clippy -D warnings`.
- Keep comments short and factual.
- User-visible changes get a line in `CHANGELOG.md`.
- Clean room: do not copy text or code from the commercial
  `ngx_http_ipset_access_module` or its documentation.

## Releasing

1. Move the `[Unreleased]` entries in `CHANGELOG.md` under `## [X.Y.Z] - date`.
2. Set `SUNDEW_VERSION` in `src/ngx_sundew.h` and `version` in
   `helper/Cargo.toml`.
3. Tag `vX.Y.Z` and push the tag. `release.yml` runs CI, builds every module
   target and image on amd64 and arm64, and publishes the release with the
   changelog section as its notes.

`release/targets.json` lists the nginx builds Sundew ships for; CI, releases
and images all take their matrix from it. Every day `nginx-versions.yml` looks
for new nginx.org releases and distribution packages, pins their checksums in
`versions.mk`, tests them and opens a pull request. Merging it makes
`targets.yml` cut a patch release: the latest release's code with the new
target list, a version bump and a CHANGELOG entry, tagged `vX.Y.Z+1`, built and
published by `release.yml`, then recorded in `CHANGELOG.md` on `main`. Releases
are immutable, so a new nginx never changes an existing one. To ship for
another distribution, add a target by hand; merging that cuts a patch release
too.

If a patch release fails, its tag stays without a release; the next run uses
the following patch number. Delete the tag if it is in the way.
