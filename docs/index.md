---
hide:
  - navigation
  - toc
---

# Sundew

**Block or allow nginx clients by their address in a Linux ipset, without giving
nginx any privileges.**

```nginx
ipset_denylist bad_guys;
```

When fail2ban, CrowdSec, a cron job or an admin changes `bad_guys`, the next
request follows. nginx does not reload.

<div class="grid cards two" markdown>

-   :material-rocket-launch-outline:{ .lg .middle } **Get started**

    ---

    Install with Docker, a prebuilt module or from source, and block your first
    address in five minutes.

    [:octicons-arrow-right-24: Get started](get-started.md)

-   :material-book-open-variant:{ .lg .middle } **Guides**

    ---

    fail2ban, CDNs, admin areas, dry runs, Docker and Kubernetes, Prometheus,
    and moving over from the commercial module.

    [:octicons-arrow-right-24: Guides](guides/index.md)

-   :material-format-list-bulleted-square:{ .lg .middle } **Reference**

    ---

    Every directive, variable, metric and log message.

    [:octicons-arrow-right-24: Reference](reference/index.md)

-   :material-shield-lock-outline:{ .lg .middle } **Security model**

    ---

    What each process may do, and what an attacker who takes over a worker
    still cannot.

    [:octicons-arrow-right-24: Security model](concepts/security.md)

</div>

## Why in nginx, and not only in the firewall

| | Firewall | Sundew |
| --- | --- | --- |
| Address it sees | The TCP peer: often your CDN or load balancer | The client, after nginx's `realip` |
| Scope | Every port and path | Per `server` and `location` |
| What the client gets | Dropped packets | A status of your choice: 403, 503, 444… |
| Trying a list first | — | `ipset_dryrun on` logs instead of blocking |
| In your access log | — | `$ipset_result`, `$ipset_matched_set` |

Both can read the same set: the firewall can drop what nginx never needs to see.

## How it fits together

--8<-- "architecture.html"

## What makes it different

<div class="grid two" markdown>

!!! success "No privileges in nginx"
    Workers hold no capabilities. A separate helper holds `CAP_NET_ADMIN`,
    runs under seccomp and Landlock, and answers only for the sets in your
    configuration.

!!! success "Fast"
    Answers are cached in shared memory for all workers. A cache hit costs no
    measurable throughput; a miss waits for the kernel without blocking the
    worker.

!!! success "Safe to operate"
    A reload that names a missing set is rejected and the old configuration
    keeps running. While the helper is unavailable, cached bans keep applying.

!!! success "Drop-in"
    Configurations for the commercial `ipset_*` module work unchanged. HTTP/1.1,
    HTTP/2, HTTP/3, IPv4 and IPv6.

</div>

!!! note "Pre-release"
    Sundew is at 0.1.0-dev and these pages follow `main`. The
    [changelog](https://github.com/jan-krueger/sundew/blob/main/CHANGELOG.md)
    says what has shipped.
