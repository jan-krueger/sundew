# Security

## Reporting

Report vulnerabilities privately via GitHub's "Report a vulnerability" button
on the Security tab. Please do not open a public issue for a vulnerability.

## Supported versions

Fixes go to `main` and into a release of the latest minor version.

## Scope

In scope:

- A way for a worker, or a remote client through a worker, to make the helper
  do anything beyond answering lookups for the configured sets.
- A way to keep a banned client from being denied, other than the documented
  `ipset_cache_ttl` and `ipset_fail_open on` behaviour.
- Memory-safety bugs in the module or the helper.
- A helper that keeps capabilities or file descriptors it should not have.

The [security model](docs/concepts/security.md) describes what each process may do.
