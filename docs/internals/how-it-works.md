# How it works

## Processes

```text
nginx master (root)
 ├── worker × N          no capabilities
 │     │  one unix socket pair per worker
 │     ▼
 └── sundew-keeper       sundew, CAP_NET_ADMIN, restarts the engine
       └── sundew-engine sundew, CAP_NET_ADMIN, seccomp + Landlock
             │  netlink
             ▼
           kernel ipset
```

- nginx starts the helper while it reads its configuration: double `fork()`
  then `execveat()` of the helper binary, with only the policy, a control
  socket and one socket per worker as file descriptors. `nginx -t` and
  `nginx -s` start nothing.
- The keeper drops privileges, then starts the engine with `execveat()` so
  every engine gets a fresh address space. If the engine dies, the keeper starts
  another within 100 ms (backing off to 30 s); requests in flight hit their
  timeout, cached answers keep working.
- The policy (set names and their numbers) is written by the master into a
  sealed memfd. Workers refer to sets by number only.

## A request

1. `realip` sets the client address.
2. Sundew looks each set up in the shared cache. A fresh answer decides
   without leaving the worker.
3. Otherwise the worker sends one 48-byte question for the sets the cache could
   not answer and suspends the request; nginx goes on serving others.
   Concurrent requests for the same address wait for the same question.
4. The answer is written to the cache, then every waiting request resumes and
   is allowed or denied. Without an answer within `sundew_lookup_timeout`, see
   [When there is no answer](../configuration.md#when-there-is-no-answer).

## The cache

- One shared memory zone, `sundew_cache`, for all workers; it survives reloads.
- Answers are keyed by address and by the set's name, family, type and
  revision. A set destroyed and recreated with another type is a new key.
- Buckets of 7 entries; an entry is evicted when it is the oldest in a full
  bucket. Bucket positions come from SipHash with a random key, so chosen
  addresses cannot pile into one bucket.
- Readers take no lock; writers take the zone's mutex. If a worker dies while
  writing, the next writer repairs the bucket.
- Both answers are cached: "not in the set" too, since most traffic matches
  nothing.

Changes made outside nginx (fail2ban, an admin) reach a cached address after
`ipset_cache_ttl`: the kernel does not announce set changes.

## Reloads, upgrades and shutdown

| Event | What happens |
| --- | --- |
| Reload | A new helper starts with the new configuration and must confirm every set, or the reload is rejected and the old configuration keeps running. The previous helper keeps answering old workers until they exit, or until `sundew_helper_drain_timeout` |
| Binary upgrade (`USR2`) | The new master starts its own helper; both run until the old master quits |
| Worker crash | nginx starts a new worker on the same socket |
| `quit`, `stop` | The helper exits when nginx does |
