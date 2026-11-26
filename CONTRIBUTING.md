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
make test-features    # cache, whitelist, dryrun, status, stats
make test-all         # the three suites
make test-pid1        # nginx as PID 1 in a container
make unit             # helper unit and fuzz tests
make lint             # cargo fmt --check and clippy
make fmt              # format the helper (writes through a patch, the source stays read-only in the container)
make docs-build       # build the documentation the way CI will
make docs             # serve it on http://127.0.0.1:8000

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
