# Log messages

Every message starts with `sundew:`. Search this page for the words after it.

## At start and reload

These stop nginx from starting. On a reload, nginx keeps the old configuration.

| Message | Cause | Fix |
| --- | --- | --- |
| `set "X": set does not exist; create it, …` | No set `X` in nginx's network namespace | `ipset create X hash:ip` before nginx starts |
| `set "X": unsupported set type …` | `X` is not `hash:ip`, `hash:net` or `bitmap:ip` | Use one of those types |
| `set "X": permission denied (CAP_NET_ADMIN missing?)` | The helper may not query sets | See `capability setup failed` |
| `helper startup failed: netlink unavailable …` | The `ip_set` kernel module is not loaded | `modprobe ip_set`; for containers, on the host |
| `helper startup failed: capability setup failed` | The helper could not keep `CAP_NET_ADMIN` | Docker: `--cap-add NET_ADMIN`. systemd: `CAP_NET_ADMIN` in `CapabilityBoundingSet=` |
| `helper startup failed: sandbox setup failed` | The helper binary is setuid or has file capabilities, or an outer seccomp policy blocks the helper's own sandbox | Reinstall the helper with mode 0755 and no capabilities; allow `seccomp`, `prctl` and `landlock_*` for nginx |
| `helper startup failed: invalid policy` | Module and helper come from different releases | Install both from the same release |
| `helper startup failed: unsupported kernel ipset protocol` | The kernel's ipset is older than protocol 6 | Upgrade the kernel |
| `helper user "X" does not exist; …` | No account for the helper | `useradd --system --no-create-home --shell /usr/sbin/nologin sundew`, or set [`sundew_helper_user`](directives.md#sundew_helper_user) |
| `helper user "X" must differ from the worker user and from root` | The helper would share an account with workers, or be root | Use a dedicated account |
| `cannot open helper "PATH"` | The helper binary is missing | Install it next to the module, or set [`sundew_helper_path`](directives.md#sundew_helper_path) |
| `helper "PATH" must be a regular file owned by root, …` | Wrong owner, mode, setuid bit | `chown root:root PATH && chmod 0755 PATH` |
| `directory "D" of the helper must be owned by root …` | A directory above the helper is writable by others | Fix `D`'s owner and mode |
| `helper did not become ready within N ms` | The helper did not confirm the sets in time | Look for a slow kernel (a huge `ipset list` running); raise [`sundew_handshake_timeout`](directives.md#sundew_handshake_timeout) |
| `helper exited during startup …` | The helper crashed or could not run | Check that `sundew-helper` runs on this system |
| `malformed READY from helper (module and helper versions differ?)` | Module and helper come from different releases | Install both from the same release |
| `requires "master_process on"` | `master_process off` | Remove it |
| `requires the nginx master to run as root; …` | nginx started without root | Start nginx as root and set `user` |
| `refuses to run with workers as root: …` | `user root;` or no `user` while root | Set `user` to an unprivileged account |
| `worker task T has CapEff=…; workers must hold no capabilities` | Something gave the workers capabilities | Remove `setcap` on nginx or `AmbientCapabilities=` in its unit |
| `too many helpers still draining (64); …` | Many reloads while old workers keep connections open | Set `worker_shutdown_timeout`, or lower [`sundew_helper_drain_timeout`](directives.md#sundew_helper_drain_timeout) |

Configuration mistakes are reported by `nginx -t`:

| Message | Fix |
| --- | --- |
| `invalid set name "X": must be 1-31 characters` | Shorten the name |
| `invalid character in set name "X"` | Use `A-Z a-z 0-9 _ . : -` |
| `too many sets (max 64)` | Combine sets, for example into a `hash:net` |
| `invalid status "X": use 4xx, 5xx or 444` | Fix [`ipset_status`](directives.md#ipset_status) |
| `"sundew_cache_size" must be at least 1m` | Raise [`sundew_cache_size`](directives.md#sundew_cache_size) |

## While running

Errors inside the helper arrive in nginx's error log through the workers; the
helper repeats the same message at most once a second.

| Message | Level | Means |
| --- | --- | --- |
| `deny ADDR (in denylist, set S)` | info | Denied: `ADDR` is in denylist set `S` |
| `deny ADDR (not in allowlist, set -)` | info | Denied: an allowlist applies and `ADDR` is in none of its sets |
| `deny ADDR (lookup timeout, set -)` | info | Denied without an answer; also `helper error`, `helper down`, `busy` |
| `allow ADDR (fail open: REASON)` | info | Allowed without an answer, under `ipset_fail_open on` |
| `dryrun, would deny ADDR (REASON, set S)` | notice | `ipset_dryrun on` let a request through |
| `lookup timed out (req_id N)` | info | The helper did not answer within [`sundew_lookup_timeout`](directives.md#sundew_lookup_timeout) |
| `helper channel closed; lookups now follow the fail policy` | alert | This worker lost its helper. Cached bans still apply; a reload starts a new helper |
| `send to helper failed` | error | A question could not be sent; the request follows the fail policy |
| `set "X" no longer exists; lookups in it fail until it is recreated` | error | The set was destroyed while nginx runs. Requests that need it follow the fail policy; recreate the set |
| `lookup in set "X" failed: kernel error N` | error | The kernel refused a lookup; the request follows the fail policy |
| `helper could not query the kernel` | error | Netlink failed (with the system error); the request follows the fail policy |
| `helper engine was killed by signal N, restarting` | error | The engine crashed and is being restarted. Lookups in flight time out |
| `helper engine was killed by seccomp (SIGSYS), restarting; please report this` | error | The engine made a system call its filter forbids: a bug, please report it |
| `helper closed this worker's channel after a request that was …` | alert | The worker sent something malformed. Its lookups follow the fail policy until it restarts; a bug, please report it |
| `Landlock is unavailable, the helper runs with seccomp only` | notice | The kernel has no Landlock (Linux before 5.13, or disabled) |
| `helper P started (generation G, N slots, M sets)` | notice | A helper started, at start or reload |
| `draining helper P (generation G, deadline Ds)` | notice | After a reload, the previous helper serves old workers until they exit |
| `helper P overstayed its drain deadline, killing it` | warn | An old helper did not exit in time |
