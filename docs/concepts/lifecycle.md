---
hide:
  - toc
---

# Reloads and crashes

nginx starts the helper itself while it reads its configuration: there is no
separate service to install or keep running. `nginx -t` and `nginx -s` start
nothing.

## Reload

--8<-- "reload.html"

The previous helper answers old workers until they exit, or at most
[`sundew_helper_drain_timeout`](../reference/directives.md#sundew_helper_drain_timeout).

## Other events

| Event | What happens | Requests meanwhile |
| --- | --- | --- |
| Engine crashes | The keeper starts a new engine within 100 ms, backing off if it keeps crashing. After 6 quick crashes in a row it stops and logs why; the next reload starts a new helper | Lookups in flight time out; cached answers keep working |
| Whole helper killed | Workers log `helper channel closed`. A reload starts a new helper | Cached bans apply; everything else follows `ipset_fail_open` |
| Worker crashes | nginx starts a new worker on the same channel | Unaffected |
| Binary upgrade (`USR2`) | The new master starts its own helper; both run until the old master quits | Unaffected |
| `nginx -s quit` or `stop` | The helper exits with nginx | — |
| nginx killed | The helper exits once every worker is gone | — |

The cache lives in nginx's shared memory, not in the helper, so it survives a
crashed engine and a reload.
