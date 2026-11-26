# Compatibility

## Tested

Every change runs the full test suite on each of these:

| | |
| --- | --- |
| nginx | 1.24.0, 1.30.8, 1.31.10 |
| Builds | Normal, and with AddressSanitizer and UndefinedBehaviorSanitizer |
| Protocols | HTTP/1.1, HTTP/2, HTTP/3 |
| Set types | `hash:ip`, `hash:net`, `bitmap:ip`, IPv4 and IPv6 |
| Linux | 7.2 |
| Images | nginx.org Debian and Alpine images |

Prebuilt modules are loaded into their nginx with `nginx -t` while they are
built.

## Requirements

| | Minimum | Why |
| --- | --- | --- |
| nginx | 1.24, built with `--with-compat` | Dynamic module ABI; the module must match the nginx version exactly |
| Linux | 4.3, untested below 7.2 | Ambient capabilities |
| | 5.3 for best results | `pidfd_open`: without it nginx tracks the helper by process ID |
| | 5.13 for best results | Landlock: without it the helper runs with seccomp only |
| Architecture | x86_64, aarch64 | The helper's seccomp filter |

## Not supported

- nginx started without root, including rootless containers and
  `runAsNonRoot` pods.
- `master_process off`.
- SELinux in enforcing mode is untested; on RHEL-like systems the helper may
  need a policy.

## ngx_http_ipset_access_module

Sundew accepts the commercial module's directive names. See the
[migration guide](../guides/migrate.md) for what is supported and what behaves
differently.
