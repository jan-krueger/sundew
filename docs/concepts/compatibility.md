# Compatibility

## Tested

Every change runs the full test suite on each of these:

| | |
| --- | --- |
| nginx | 1.18.0, 1.22.1, 1.24.0, 1.26.3, 1.30.8, 1.31.10 |
| Builds | Normal, and with AddressSanitizer and UndefinedBehaviorSanitizer |
| Protocols | HTTP/1.1, HTTP/2, HTTP/3 |
| Sets | ipset `hash:ip`, `hash:net`, `bitmap:ip`; nftables address sets, with and without `flags interval`; IPv4 and IPv6 |
| Linux | 7.2 |
| Images | nginx.org Debian and Alpine images |
| Packages | The nginx.org module in nginx.org's packages on Debian 12 and Ubuntu 22.04; each distribution module in its distribution's nginx |

Prebuilt modules are loaded into their nginx with `nginx -t` while they are
built.

## Requirements

| | Minimum | Why |
| --- | --- | --- |
| nginx | 1.18, built with `--with-compat` | Dynamic module ABI; the module must match the nginx version exactly |
| glibc | 2.34 for the prebuilt modules | Building from source works with older C libraries |
| Linux | 4.3, untested below 7.2 | Ambient capabilities |
| | 5.3 for best results | `pidfd_open`: without it nginx tracks the helper by process ID |
| | 5.13 for best results | Landlock: without it the helper runs with seccomp only |
| | `ip_set` or `nf_tables` module | For ipset or nftables sets; only the kind in use must be loaded |
| Architecture | x86_64, aarch64 | The helper's seccomp filter |

## Not supported

- nginx started without root, including rootless containers and
  `runAsNonRoot` pods.
- `master_process off`.
- Debian 11: it is past its end of life, and its glibc is older than the
  prebuilt modules need.
- SELinux in enforcing mode is untested; on RHEL-like systems the helper may
  need a policy.

## ngx_http_ipset_access_module

Sundew accepts the commercial module's directive names. See the
[migration guide](../guides/migrate.md) for what is supported and what behaves
differently.
